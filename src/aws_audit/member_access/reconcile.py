"""Read metadata, review a plan, then reconcile only explicitly managed resources.

Clients are injected boto3-compatible clients. Importing or planning never loads
credentials. No code reads S3 objects, changes existing EC2 instance profiles,
starts instances, or deletes member resources. All revocations precede grants.
"""

import hashlib
import json
import re
from typing import Any, Dict, Mapping, Optional
from urllib.parse import unquote

from .models import (COMPONENT, MANAGED_BY, ROLE_PATH, STATE_POLICY_NAME,
                     MemberAccessConfig, managed_tags, owned, profile_arn,
                     role_arn, valid_username, validate_config)
from .policies import attached_policy_arns, role_state, trust_policy


class _AccountMismatch(RuntimeError):
    pass


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _canonical(item) for key, item in value.items()}
    if isinstance(value, list):
        # The lists inspected here are resource/tag sets, security groups,
        # policy actions/statements, or interfaces with explicit DeviceIndex.
        # Their ordering is not an AWS permission or launch-setting property.
        return sorted((_canonical(item) for item in value), key=_json)
    return value


def _same(left: Any, right: Any) -> bool:
    return _canonical(left) == _canonical(right)


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(_canonical(value)).encode()).hexdigest()


def _tags(rows: list) -> dict:
    return {row["Key"]: row["Value"] for row in rows}


def _tag_rows(tags: Mapping[str, str]) -> list:
    return [{"Key": key, "Value": value} for key, value in sorted(tags.items())]


def _missing(exc: Exception) -> bool:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    return code in {"NoSuchEntity", "NoSuchEntityException", "NoSuchBucket", "NoSuchTagSet",
                    "InvalidLaunchTemplateName.NotFoundException", "InvalidLaunchTemplateId.NotFound"}


def _diagnostic(exc: Exception) -> dict:
    def safe(value: Any, fallback: str) -> str:
        return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", value) else fallback
    response = getattr(exc, "response", {})
    error = response.get("Error", {}) if isinstance(response, dict) else {}
    code = error.get("Code") if isinstance(error, dict) else None
    return {"operation": safe(getattr(exc, "operation_name", None), "Reconcile"),
            "code": safe(code, safe(type(exc).__name__, "ReconcileError"))}


def _items(client: Any, method: str, field: str, **kwargs: Any) -> list:
    result, seen = [], set()
    while True:
        response = getattr(client, method)(**kwargs)
        result.extend(response.get(field, []))
        token = response.get("NextToken") or (response.get("Marker") if response.get("IsTruncated") else None)
        if not token:
            return result
        if token in seen:
            raise RuntimeError("AWS metadata pagination repeated a token")
        seen.add(token)
        kwargs["NextToken" if response.get("NextToken") else "Marker"] = token


def _document(value: Any) -> dict:
    return value if isinstance(value, dict) else json.loads(unquote(value))


def _group_members(iam: Any, config: MemberAccessConfig) -> list:
    try:
        rows, arguments, seen = [], {"GroupName": config.member_group}, set()
        while True:
            response = iam.get_group(**arguments)
            arn = response.get("Group", {}).get("Arn")
            if arn is not None and not arn.startswith("arn:aws:iam::" + config.account_id + ":group/"):
                raise _AccountMismatch("IAM group belongs to a different account")
            rows.extend(response.get("Users", []))
            if not response.get("IsTruncated"):
                break
            marker = response.get("Marker")
            if not marker or marker in seen:
                raise RuntimeError("invalid IAM group pagination")
            seen.add(marker)
            arguments["Marker"] = marker
        if any(row.get("Arn") is not None and not row["Arn"].startswith("arn:aws:iam::" + config.account_id + ":user/") for row in rows):
            raise _AccountMismatch("IAM group member belongs to a different account")
        names = [row["UserName"] for row in rows]
    except Exception as exc:
        if _missing(exc):
            return []
        raise
    if len(names) != len(set(names)) or any(not valid_username(name) for name in names):
        raise RuntimeError("IAM returned ambiguous current-member names")
    return sorted(names)


def _user(iam: Any, config: MemberAccessConfig, username: str) -> dict:
    try:
        response = iam.get_user(UserName=username)["User"]
        if not response.get("Arn", "").startswith("arn:aws:iam::" + config.account_id + ":user/"):
            raise _AccountMismatch("IAM client returned a different account")
        return {"exists": True, "tags": _tags(_items(iam, "list_user_tags", "Tags", UserName=username))}
    except Exception as exc:
        if isinstance(exc, _AccountMismatch):
            raise
        if _missing(exc):
            return {"exists": False, "tags": {}}
        return {"exists": None, "tags": {}, "read_error": _diagnostic(exc)}


def _role(iam: Any, config: MemberAccessConfig, name: str) -> Optional[dict]:
    try:
        row = iam.get_role(RoleName=name)["Role"]
    except Exception as exc:
        # Only this first lookup can establish that the role is absent. A
        # missing policy during later metadata reads does not erase the role.
        if _missing(exc):
            return None
        return {"name": name, "arn": "", "path": "", "tags": {}, "read_error": _diagnostic(exc)}
    if not row.get("Arn", "").startswith("arn:aws:iam::" + config.account_id + ":role/"):
        raise _AccountMismatch("IAM role belongs to a different account")
    result = {"name": name, "arn": row["Arn"], "path": row["Path"], "tags": {}}
    try:
        tags = _tags(_items(iam, "list_role_tags", "Tags", RoleName=name))
        result["tags"] = tags
        if owned(tags):
            if row["Arn"] != role_arn(config, name) or row["Path"] != ROLE_PATH:
                # A marker on an external namespace is not permission to take
                # it over, nor a reason to prevent unrelated offboarding.
                return result
            result.update({"trust": _document(row["AssumeRolePolicyDocument"]),
                           "boundary": row.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn"),
                           "attached": [], "inline_names": [], "state": None})
            result["attached"] = sorted(x["PolicyArn"] for x in _items(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name))
            result["inline_names"] = sorted(_items(iam, "list_role_policies", "PolicyNames", RoleName=name))
            if STATE_POLICY_NAME in result["inline_names"]:
                try:
                    result["state"] = _document(iam.get_role_policy(RoleName=name, PolicyName=STATE_POLICY_NAME)["PolicyDocument"])
                except Exception as exc:
                    if not _missing(exc):
                        raise
                    # A policy removed between ListRolePolicies/GetRolePolicy
                    # is a missing guard, never a missing role. PutRolePolicy
                    # will re-establish the required active/inactive guard.
        return result
    except Exception as exc:
        result["read_error"] = _diagnostic(exc)
        return result


def _profile(iam: Any, name: str) -> Optional[dict]:
    row = {}
    try:
        row = iam.get_instance_profile(InstanceProfileName=name)["InstanceProfile"]
        return {"name": name, "arn": row["Arn"], "path": row["Path"],
                "tags": _tags(_items(iam, "list_instance_profile_tags", "Tags", InstanceProfileName=name)),
                "roles": sorted(role["RoleName"] for role in row.get("Roles", []))}
    except Exception as exc:
        if _missing(exc):
            return None
        return {"name": name, "arn": row.get("Arn", ""), "path": row.get("Path", ""),
                "tags": {}, "roles": [], "read_error": _diagnostic(exc)}


def _bucket_tags(s3: Any, config: MemberAccessConfig, home: str) -> Optional[dict]:
    if s3 is None:
        return None
    try:
        return _tags(s3.get_bucket_tagging(Bucket=home, ExpectedBucketOwner=config.account_id).get("TagSet", []))
    except Exception as exc:
        if _missing(exc):
            return {}
        # One unreadable home must not prevent unrelated known offboarding.
        # It blocks this member's grant and disables its managed role instead.
        return {"_read_error": _diagnostic(exc)}


def _valid_home(home: Any) -> bool:
    return (isinstance(home, str) and bool(re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", home))
            and ".." not in home and not re.fullmatch(r"[0-9.]+", home))


def snapshot(iam: Any, config: MemberAccessConfig, *, s3: Any = None) -> dict:
    """Collect only IAM and S3-tag metadata. Failure never implies revocation."""
    validate_config(config)
    group = _group_members(iam, config)
    names = set(group) | {row["user_name"] for row in config.s3_manifest["users"]}
    role_names = names | {row["RoleName"] for row in _items(iam, "list_roles", "Roles", PathPrefix=ROLE_PATH)}
    profile_names = names | {row["InstanceProfileName"] for row in _items(iam, "list_instance_profiles", "InstanceProfiles", PathPrefix=ROLE_PATH)}
    roles = {name: _role(iam, config, name) for name in sorted(role_names)}
    profiles = {name: _profile(iam, name) for name in sorted(profile_names)}
    names |= {name for name, role in roles.items() if role and owned(role["tags"])}
    names |= {name for name, profile in profiles.items() if profile and owned(profile["tags"])}
    users = {name: _user(iam, config, name) for name in sorted(names) if valid_username(name)}
    homes = {user["tags"].get("HomeBucket") for user in users.values()}
    homes |= {row.get("home_bucket") for row in config.s3_manifest["users"]}
    buckets = {home: _bucket_tags(s3, config, home) for home in sorted(home for home in homes if _valid_home(home))}
    return {"account_id": config.account_id, "group_members": group, "users": users, "bucket_tags": buckets,
            "roles": roles, "profiles": profiles}


def _identity_problem(config: MemberAccessConfig, observed: dict, username: str) -> Optional[str]:
    if username not in observed["group_members"]:
        return "not in authoritative lab_members group"
    user = observed["users"].get(username, {})
    if user.get("read_error"):
        return "IAM user metadata could not be verified"
    if not user.get("exists"):
        return "IAM user no longer exists"
    row = next((row for row in config.s3_manifest["users"] if row["user_name"] == username), {})
    tags, home = user.get("tags", {}), row.get("home_bucket")
    if row.get("role") != "CurrentMember" or tags.get("AccessRole") != "CurrentMember":
        return "current-member access role metadata is missing or inconsistent"
    if not _valid_home(home) or tags.get("HomeBucket") != home:
        return "home bucket metadata is missing or inconsistent"
    bucket = next((row for row in config.s3_manifest["buckets"] if row["name"] == home), {})
    if bucket.get("scope") != "User" or bucket.get("owner") != username:
        return "manifest does not assign this personal home bucket"
    if sum(row.get("home_bucket") == home for row in config.s3_manifest["users"]) != 1:
        return "home bucket is assigned to multiple users"
    live = observed["bucket_tags"].get(home)
    if live is None:
        return "live bucket ownership verification requires an injected S3 client"
    if live.get("_read_error"):
        return "live bucket ownership metadata could not be verified"
    if any(live.get(key) != value for key, value in {"BucketScope": "User", "BucketOwner": username,
                                                   "OwnerAccessRole": "CurrentMember"}.items()):
        return "live bucket ownership/access-role tags do not match"
    return None


def _resource_problem(config: MemberAccessConfig, observed: dict, username: str, home: str) -> Optional[str]:
    for kind, rows, arn in (("role", observed["roles"], role_arn(config, username)),
                            ("profile", observed["profiles"], profile_arn(config, username))):
        item = rows.get(username)
        if not item:
            continue
        if item.get("read_error"):
            return kind + " metadata could not be verified"
        if not owned(item["tags"]):
            return "foreign nonmanaged " + kind + " name collision"
        if (item["arn"] != arn or item["path"] != ROLE_PATH or item["tags"].get("Owner") != username
                or item["tags"].get("HomeBucket") != home):
            return "managed " + kind + " ownership/home/path mismatch; administrator review required"
        if kind == "profile" and set(item["roles"]) - {username}:
            return "managed profile contains a different role; administrator review required"
        if kind == "role" and (set(item["inline_names"]) - {STATE_POLICY_NAME}
                                or set(item["attached"]) - set(attached_policy_arns(config.account_id))):
            return "managed role contains unapproved policies; administrator review required"
    return None


def plan(config: MemberAccessConfig, observed: dict) -> dict:
    """Build a deterministic, JSON-safe preview. No clients or AWS calls needed."""
    validate_config(config)
    if observed.get("account_id") != config.account_id:
        raise ValueError("snapshot account does not match configuration")
    desired, blocked, operations, resource_errors = {}, {}, [], {}
    for kind in ("roles", "profiles"):
        for name, item in observed[kind].items():
            if item and item.get("read_error"):
                blocked[name] = kind + " metadata could not be verified"
                resource_errors[name] = item["read_error"]
    for username in sorted(observed["group_members"]):
        problem = _identity_problem(config, observed, username)
        row = next((row for row in config.s3_manifest["users"] if row["user_name"] == username), {})
        home = row.get("home_bucket", "")
        if problem is None:
            problem = _resource_problem(config, observed, username, home)
        if problem:
            blocked[username] = problem
            continue
        item = {"username": username, "home_bucket": home, "active": True, "status": "active",
                "role_arn": role_arn(config, username), "profile_arn": profile_arn(config, username)}
        desired[username] = item
    # Revocations are a separate first phase, including deleted users and
    # metadata failures. Foreign, unmarked resources are never modified.
    revoke_names = {name for name, role in observed["roles"].items()
                    if _manageable_role(config, name, role) and (name not in desired or not desired[name]["active"])}
    for name in sorted(revoke_names):
        role = observed["roles"].get(name)
        if _manageable_role(config, name, role) and (not _same(role.get("state"), role_state(False))
                or not _same(role.get("trust"), trust_policy(False)) or role["tags"].get("AccessRole") != "Inactive"):
            operations.append({"phase": "revoke", "kind": "disable_role", "username": name})
    for name, item in desired.items():
        role, profile = observed["roles"].get(name), observed["profiles"].get(name)
        role_ok = (role is not None and set(role["attached"]) == set(attached_policy_arns(config.account_id))
                   and (config.permissions_boundary_arn is None or role.get("boundary") == config.permissions_boundary_arn))
        profile_ok = profile is not None and profile["roles"] == [name]
        if not role_ok or not profile_ok:
            operations.append({"phase": "provision", "kind": "ensure_resources", "username": name})
        if item["active"]:
            state_ok = role is not None and _same(role.get("state"), role_state(True, item["home_bucket"])) and _same(role.get("trust"), trust_policy(True))
            access_tag_ok = role is not None and role["tags"].get("AccessRole") == "CurrentMember"
            if not state_ok or not access_tag_ok or not role_ok or not profile_ok:
                operations.append({"phase": "activate", "kind": "activate_member", "username": name})
    result = {"schema_version": 1, "snapshot_sha256": _digest(observed), "desired": desired,
              "blocked": blocked, "operations": operations,
              "resource_read_errors": resource_errors,
              "counts": {"active": sum(item["active"] for item in desired.values()),
                         "blocked": len(blocked), "operations": len(operations)}}
    result["plan_sha256"] = _digest(result)
    return result


def _manageable_role(config: MemberAccessConfig, name: str, role: Optional[dict]) -> bool:
    return bool(role and owned(role["tags"]) and role["path"] == ROLE_PATH and role["arn"] == role_arn(config, name))


def _guard_role(iam: Any, config: MemberAccessConfig, username: str) -> dict:
    role = _role(iam, config, username)
    if not _manageable_role(config, username, role):
        raise RuntimeError("refusing to mutate a missing or foreign role: " + username)
    return role


def _disable(iam: Any, config: MemberAccessConfig, username: str) -> None:
    role = _guard_role(iam, config, username)
    if not _same(role.get("state"), role_state(False)):
        iam.put_role_policy(RoleName=username, PolicyName=STATE_POLICY_NAME, PolicyDocument=_json(role_state(False)))
    if not _same(role.get("trust"), trust_policy(False)):
        iam.update_assume_role_policy(RoleName=username, PolicyDocument=_json(trust_policy(False)))
    if role["tags"].get("AccessRole") != "Inactive":
        iam.tag_role(RoleName=username, Tags=_tag_rows({"AccessRole": "Inactive"}))


def _identity_guard(iam: Any, s3: Any,
                    config: MemberAccessConfig, item: dict) -> None:
    name, home = item["username"], item["home_bucket"]
    observed = {"group_members": _group_members(iam, config), "users": {name: _user(iam, config, name)},
                "bucket_tags": {home: _bucket_tags(s3, config, home)}}
    problem = _identity_problem(config, observed, name)
    if problem:
        raise RuntimeError("member identity changed before grant: " + name + ": " + problem)


def _ensure_resources(iam: Any, config: MemberAccessConfig, item: dict) -> None:
    name, home = item["username"], item["home_bucket"]
    role = _role(iam, config, name)
    if role is None:
        args = {"RoleName": name, "Path": ROLE_PATH, "AssumeRolePolicyDocument": _json(trust_policy(False)),
                "Tags": _tag_rows(managed_tags(name, home, active=False)), "MaxSessionDuration": 3600}
        if config.permissions_boundary_arn:
            args["PermissionsBoundary"] = config.permissions_boundary_arn
        iam.create_role(**args)
        # No trust Allow exists in the interval before the explicit Deny.
        iam.put_role_policy(RoleName=name, PolicyName=STATE_POLICY_NAME, PolicyDocument=_json(role_state(False)))
        role = _guard_role(iam, config, name)
    role = _guard_role(iam, config, name)
    if role["tags"].get("Owner") != name or role["tags"].get("HomeBucket") != home:
        raise RuntimeError("managed role ownership changed during apply")
    if config.permissions_boundary_arn and role.get("boundary") != config.permissions_boundary_arn:
        iam.put_role_permissions_boundary(RoleName=name, PermissionsBoundary=config.permissions_boundary_arn)
    for policy in attached_policy_arns(config.account_id):
        if policy not in role["attached"]:
            iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    profile = _profile(iam, name)
    if profile is None:
        iam.create_instance_profile(InstanceProfileName=name, Path=ROLE_PATH,
                                    Tags=_tag_rows(managed_tags(name, home, active=False)))
        profile = _profile(iam, name)
    if (not profile or not owned(profile["tags"]) or profile["arn"] != profile_arn(config, name)
            or profile["tags"].get("Owner") != name or profile["tags"].get("HomeBucket") != home
            or set(profile["roles"]) - {name}):
        raise RuntimeError("refusing foreign or mismatched instance profile")
    if name not in profile["roles"]:
        iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)


def _activate(iam: Any, s3: Any, config: MemberAccessConfig, item: dict) -> None:
    name, home = item["username"], item["home_bucket"]
    _identity_guard(iam, s3, config, item)
    role, profile = _guard_role(iam, config, name), _profile(iam, name)
    if (role["tags"].get("Owner") != name or role["tags"].get("HomeBucket") != home
            or set(role["attached"]) != set(attached_policy_arns(config.account_id))
            or set(role["inline_names"]) - {STATE_POLICY_NAME}
            or (config.permissions_boundary_arn and role.get("boundary") != config.permissions_boundary_arn)
            or not profile or profile["arn"] != profile_arn(config, name) or not owned(profile["tags"])
            or profile["tags"].get("Owner") != name or profile["tags"].get("HomeBucket") != home or profile["roles"] != [name]):
        raise RuntimeError("role/profile is not ready for activation")
    _identity_guard(iam, s3, config, item)
    if role["tags"].get("AccessRole") != "CurrentMember":
        iam.tag_role(RoleName=name, Tags=_tag_rows({"AccessRole": "CurrentMember"}))
    if profile["tags"].get("AccessRole") != "CurrentMember":
        iam.tag_instance_profile(InstanceProfileName=name, Tags=_tag_rows({"AccessRole": "CurrentMember"}))
    if not _same(role.get("state"), role_state(True, home)):
        iam.put_role_policy(RoleName=name, PolicyName=STATE_POLICY_NAME, PolicyDocument=_json(role_state(True, home)))
    if not _same(role.get("trust"), trust_policy(True)):
        iam.update_assume_role_policy(RoleName=name, PolicyDocument=_json(trust_policy(True)))
    _identity_guard(iam, s3, config, item)


def apply_plan(iam: Any, config: MemberAccessConfig,
               approved_plan: dict, *, s3: Any = None) -> dict:
    """Reject stale/tampered previews; revoke globally before any grants.

    AWS IAM changes are eventually consistent, so callers retry failures rather
    than treating partial provisioning as success. A grant failure removes this
    member's managed role, then continues with other
    members. Global membership/discovery failures abort before mutation; an
    unreadable personal identity/home blocks only that member.
    """
    fresh = plan(config, snapshot(iam, config, s3=s3))
    if fresh != approved_plan:
        raise RuntimeError("member access plan is stale or modified; preview again")
    applied, errors = [], dict(fresh["resource_read_errors"])
    for operation in fresh["operations"]:
        if operation["phase"] != "revoke":
            continue
        name = operation["username"]
        try:
            _disable(iam, config, name)
            applied.append(operation)
        except Exception as exc:
            errors[name] = _diagnostic(exc)
    # Attempt every known revoke, even when one user's metadata/API fails.
    # No grant may overtake a failed or unverified role revocation.
    if errors:
        return {"plan": fresh, "applied": applied, "errors": errors, "counts": fresh["counts"]}
    # Provisioning cannot attach a role to an existing EC2 instance.
    for name, item in fresh["desired"].items():
        operations = [row for row in fresh["operations"] if row["username"] == name and row["phase"] != "revoke"]
        if not operations:
            continue
        try:
            if item["active"]:
                _identity_guard(iam, s3, config, item)
            for operation in operations:
                if operation["kind"] == "ensure_resources":
                    _ensure_resources(iam, config, item)
                else:
                    _activate(iam, s3, config, item)
                applied.append(operation)
        except Exception as exc:
            # No unrelated member is revoked for one user's collision,
            # API failure, or concurrent identity change.
            errors[name] = _diagnostic(exc)
            role = _role(iam, config, name)
            if _manageable_role(config, name, role):
                _disable(iam, config, name)
    return {"plan": fresh, "applied": applied, "errors": errors, "counts": fresh["counts"]}


def reconcile(iam: Any, config: MemberAccessConfig, *,
              s3: Any = None, execute: bool = False) -> dict:
    """Preview by default; runtime can execute a freshly captured guarded plan."""
    preview = plan(config, snapshot(iam, config, s3=s3))
    if not execute:
        return preview
    if not preview["operations"]:
        # There is nothing to authorize or mutate. The runtime still rechecks
        # membership after this pass; a second full resource scan buys nothing.
        return {"plan": preview, "applied": [], "errors": preview["resource_read_errors"], "counts": preview["counts"]}
    return apply_plan(iam, config, preview, s3=s3)
