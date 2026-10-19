"""Live, event-driven member access reconciliation and offline deployment helpers.

The function environment contains approved infrastructure, never a membership registry. Every pass
derives members and home ownership from IAM and S3 metadata. No access keys,
object contents, event bodies, or full reconciliation plans are logged here.
"""

import io
import json
import os
import re
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from ..ec2_access.launch import build_launch_request
from ..ec2_access.policy import config_from_mapping as ec2_config_from_mapping


CONFIG_ENV = "WANGLAB_MEMBER_ACCESS_CONFIG"
CONTROL_REGION = "us-east-1"
HANDLER = "aws_audit.member_access.runtime.lambda_handler"
IAM_EVENTS = ("AddUserToGroup", "RemoveUserFromGroup", "TagUser", "UntagUser", "DeleteUser")
PACKAGE_FILES = (
    "aws_audit/__init__.py",
    "aws_audit/ec2_access/__init__.py",
    "aws_audit/ec2_access/policy.py",
    "aws_audit/ec2_access/launch.py",
    "aws_audit/member_access/__init__.py",
    "aws_audit/member_access/models.py",
    "aws_audit/member_access/policies.py",
    "aws_audit/member_access/reconcile.py",
    "aws_audit/member_access/runtime.py",
)


class RuntimeValidationError(ValueError):
    """An untrusted envelope or approved configuration failed validation."""


def _token(value: Any, fallback: str) -> str:
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.\-]{1,80}", value) else fallback


class ReconciliationError(RuntimeError):
    """A retryable reconciliation failure without sensitive exception text."""

    def __init__(self, message: str, diagnostic: Optional[dict] = None):
        self.diagnostic = ({"operation": _token(diagnostic.get("operation"), "Reconcile"),
                            "code": _token(diagnostic.get("code"), "UnknownError")} if diagnostic else None)
        if self.diagnostic:
            message += "; operation=%s code=%s" % (self.diagnostic["operation"], self.diagnostic["code"])
        super().__init__(message)


def _diagnostic(exc: Exception) -> dict:
    if isinstance(exc, ReconciliationError) and exc.diagnostic:
        return exc.diagnostic
    response = getattr(exc, "response", None)
    error = response.get("Error", {}) if isinstance(response, dict) else {}
    code = error.get("Code") if isinstance(error, dict) else None
    operation = getattr(exc, "operation_name", None)
    return {"operation": _token(operation, "Reconcile"),
            "code": _token(code, _token(type(exc).__name__, "UnknownError"))}


def _account(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{12}", value):
        raise RuntimeValidationError("invalid account context")
    return value


def validate_runtime_config(value: Any, *, account_id: str, region: str) -> Dict[str, Any]:
    """Validate infrastructure-only configuration, rejecting stale user manifests."""
    _account(account_id)
    if region != CONTROL_REGION:
        raise RuntimeValidationError("IAM reconciliation must run in us-east-1")
    if not isinstance(value, dict) or set(value) - {"ec2_config", "flavors", "member_group", "permissions_boundary_arn"}:
        raise RuntimeValidationError("runtime configuration accepts infrastructure only")
    if not {"ec2_config", "flavors"} <= set(value):
        raise RuntimeValidationError("runtime configuration requires EC2 sources and flavors")
    if value.get("member_group", "lab_members") != "lab_members":
        raise RuntimeValidationError("unexpected authoritative member group")
    try:
        ec2 = ec2_config_from_mapping(value["ec2_config"])
    except (TypeError, ValueError):
        raise RuntimeValidationError("invalid approved EC2 configuration") from None
    if ec2.account_id != account_id:
        raise RuntimeValidationError("configuration account differs from invocation account")
    boundary = value.get("permissions_boundary_arn")
    if not isinstance(boundary, str) or not re.fullmatch(r"arn:aws:iam::" + account_id + r":policy/[A-Za-z0-9_+=,.@/\-]+", boundary):
        raise RuntimeValidationError("runtime requires an exact same-account role permissions boundary")
    flavors = value["flavors"]
    expected = {"Ubuntu2404", "Al2023", "DL2204", "DL2404"}
    if not isinstance(flavors, list) or len(flavors) != len(expected):
        raise RuntimeValidationError("exactly four approved launch flavors are required")
    names = set()
    for flavor in flavors:
        fields = {"name", "region", "image_id", "instance_type", "subnet_id", "security_group_id"}
        if (not isinstance(flavor, dict) or set(flavor) != fields
                or any(not isinstance(item, str) for item in flavor.values()) or flavor["name"] not in expected):
            raise RuntimeValidationError("invalid launch flavor")
        names.add(flavor["name"])
        try:
            build_launch_request(ec2, username="RuntimeValidation", key_name="validation-only",
                                 instance_type=flavor["instance_type"], region=flavor["region"],
                                 image_id=flavor["image_id"], subnet_id=flavor["subnet_id"],
                                 security_group_id=flavor["security_group_id"])
        except (TypeError, ValueError):
            raise RuntimeValidationError("launch flavor is outside approved EC2 sources") from None
    if names != expected:
        raise RuntimeValidationError("launch flavor names must be unique and exact")
    return {"ec2_config": value["ec2_config"], "flavors": flavors, "member_group": "lab_members",
            "permissions_boundary_arn": boundary}


def load_runtime_config(*, account_id: str, region: str) -> Dict[str, Any]:
    """Validate the nonsecret configuration deployed with the function."""
    try:
        value = json.loads(os.environ[CONFIG_ENV])
    except (KeyError, TypeError, ValueError):
        raise RuntimeValidationError("configuration is not JSON") from None
    return validate_runtime_config(value, account_id=account_id, region=region)


def _iam_rows(client: Any, method: str, key: str, **arguments: Any) -> list:
    rows = []
    seen = set()
    while True:
        response = getattr(client, method)(**arguments)
        rows.extend(response.get(key, []))
        if not response.get("IsTruncated"):
            return rows
        marker = response.get("Marker")
        if not isinstance(marker, str) or not marker or marker in seen:
            raise ReconciliationError("invalid IAM pagination response")
        seen.add(marker)
        arguments["Marker"] = marker


def _tags(rows: Any) -> dict:
    result = {}
    if not isinstance(rows, list):
        raise RuntimeValidationError("invalid metadata tags")
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("Key"), str) or not isinstance(row.get("Value"), str):
            raise RuntimeValidationError("invalid metadata tag")
        if row["Key"] in result:
            raise RuntimeValidationError("duplicate metadata tag")
        result[row["Key"]] = row["Value"]
    return result


def _aws_error(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    return isinstance(response, dict) and isinstance(response.get("Error"), dict)


def _bucket_name(value: Any) -> bool:
    return bool(isinstance(value, str) and re.fullmatch(r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]", value)
                and ".." not in value and ".-" not in value and "-." not in value)


def live_member_manifest(iam: Any, s3: Any, *, account_id: str, member_group: str = "lab_members") -> dict:
    """Build the minimal reconciler manifest from live identity/ownership tags.

    Incomplete or unreadable per-member metadata creates a row without a home.
    The reconciler consequently revokes/blocks that member; it never inherits an
    older manifest's grant. ExpectedBucketOwner also prevents a foreign bucket
    with copied tags from becoming an approved personal home.
    """
    _account(account_id)
    if member_group != "lab_members":
        raise RuntimeValidationError("unexpected authoritative member group")
    try:
        members = _iam_rows(iam, "get_group", "Users", GroupName=member_group, MaxItems=100)
    except Exception as exc:
        response = getattr(exc, "response", {})
        if isinstance(response, dict) and response.get("Error", {}).get("Code") in ("NoSuchEntity", "NoSuchEntityException"):
            members = []
        else:
            raise
    names = set()
    users = []
    buckets = {}
    for member in sorted(members, key=lambda item: item.get("UserName", "")):
        name = member.get("UserName")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_+=,.@\-]{1,64}", name) or name in names:
            raise ReconciliationError("invalid or duplicate live IAM member")
        names.add(name)
        arn = member.get("Arn")
        if arn is not None and (not isinstance(arn, str) or not arn.startswith("arn:aws:iam::" + account_id + ":user/")):
            raise ReconciliationError("member belongs to a different account")
        row = {"user_name": name, "role": "CurrentMember"}
        users.append(row)
        try:
            tags = _tags(_iam_rows(iam, "list_user_tags", "Tags", UserName=name, MaxItems=100))
        except Exception as exc:
            if _aws_error(exc) or isinstance(exc, RuntimeValidationError):
                continue
            raise
        home = tags.get("HomeBucket")
        if tags.get("AccessRole") != "CurrentMember" or not _bucket_name(home):
            continue
        try:
            bucket_tags = _tags(s3.get_bucket_tagging(Bucket=home, ExpectedBucketOwner=account_id)["TagSet"])
        except Exception as exc:
            if _aws_error(exc) or isinstance(exc, (KeyError, RuntimeValidationError)):
                continue
            raise
        if (bucket_tags.get("BucketScope") != "User" or bucket_tags.get("BucketOwner") != name
                or bucket_tags.get("OwnerAccessRole") != "CurrentMember"):
            continue
        row["home_bucket"] = home
        buckets[home] = {"name": home, "scope": "User", "owner": name}
    return {"account_id": account_id,
            "groups": {"admin": "admin", "current_member": member_group, "alumni": "alumni"},
            "users": users, "buckets": [buckets[name] for name in sorted(buckets)]}


def _backend(iam: Any, ec2_by_region: dict, config: dict, s3: Any) -> Any:
    from .models import config_from_mapping
    from .reconcile import reconcile
    return reconcile(iam, ec2_by_region, config_from_mapping(config), s3=s3, execute=True)


def run_reconciliation(iam: Any, s3: Any, ec2_by_region: dict, config: dict, *,
                       account_id: str, region: str,
                       reconcile_call: Optional[Callable[..., Any]] = None,
                       max_passes: int = 3) -> dict:
    """Reconcile live state, rechecking membership/ownership after every pass.

    The backend performs every revoke before grants and revalidates each grant.
    If administrators continuously change membership during all passes, make one
    final grant-free pass, then fail for Lambda retry instead of keeping grants
    derived from an unstable identity snapshot.
    """
    config = validate_runtime_config(config, account_id=account_id, region=region)
    if set(ec2_by_region) != set(config["ec2_config"]["regions"]):
        raise RuntimeValidationError("EC2 clients must match the approved regions exactly")
    if not isinstance(max_passes, int) or not 1 <= max_passes <= 3:
        raise RuntimeValidationError("invalid reconciliation pass limit")
    backend = reconcile_call or _backend
    manifest = live_member_manifest(iam, s3, account_id=account_id)
    for attempt in range(1, max_passes + 1):
        configured = {**config, "s3_manifest": manifest}
        failure = None
        outcome = None
        try:
            outcome = backend(iam, ec2_by_region, configured, s3)
            if isinstance(outcome, dict) and outcome.get("errors"):
                errors = outcome["errors"]
                first = next(iter(errors.values())) if isinstance(errors, dict) else None
                raise ReconciliationError("member resource apply failed",
                                          first if isinstance(first, dict) else {"code": "MemberApplyFailed"})
        except Exception as exc:
            failure = _diagnostic(exc)
        final = live_member_manifest(iam, s3, account_id=account_id)
        if final == manifest:
            if failure:
                raise ReconciliationError("member access reconciliation failed", failure) from None
            eligible = sum("home_bucket" in row for row in final["users"])
            counts = outcome.get("counts", {}) if isinstance(outcome, dict) else {}
            counts = counts if isinstance(counts, dict) else {}
            progress = {target: counts[key] for key, target in
                        (("active", "planned_active"), ("pending_key", "pending_key"),
                         ("blocked", "resource_blocked"), ("operations", "planned_operations"))
                        if type(counts.get(key)) is int and counts[key] >= 0}
            return {"status": "reconciled", "passes": attempt,
                    "members": len(final["users"]), "metadata_ready": eligible,
                    "metadata_blocked": len(final["users"]) - eligible, **progress}
        manifest = final
    revoked = {**manifest, "users": [{"user_name": row["user_name"], "role": "CurrentMember"}
                                      for row in manifest["users"]], "buckets": []}
    try:
        outcome = backend(iam, ec2_by_region, {**config, "s3_manifest": revoked}, s3)
        if isinstance(outcome, dict) and outcome.get("errors"):
            raise ReconciliationError("grant-free reconciliation returned member errors")
    except Exception as exc:
        raise ReconciliationError("unstable member state; grant-free reconciliation failed", _diagnostic(exc)) from None
    raise ReconciliationError("unstable member state; managed grants disabled pending retry")


def _invocation(context: Any) -> Tuple[str, str]:
    arn = getattr(context, "invoked_function_arn", None)
    match = re.fullmatch(r"arn:aws:lambda:([^:]+):([0-9]{12}):function:[A-Za-z0-9_\-]+(?::[A-Za-z0-9_$\-]+)?", arn or "")
    if not match:
        raise RuntimeValidationError("a real Lambda invocation context is required")
    return match.group(2), match.group(1)


def _trigger(event: Any, account_id: str) -> str:
    if not isinstance(event, dict):
        raise RuntimeValidationError("invalid invocation envelope")
    if event.get("account", account_id) != account_id:
        raise RuntimeValidationError("event belongs to a different account")
    if not event or (event.get("source") == "wanglab.member-access" and event.get("action") == "reconcile"):
        return "manual"
    if event.get("source") == "aws.events" and event.get("detail-type") == "Scheduled Event":
        return "schedule"
    detail = event.get("detail", {})
    if (event.get("source") == "aws.iam" and event.get("detail-type") == "AWS API Call via CloudTrail"
            and isinstance(detail, dict) and detail.get("eventSource") == "iam.amazonaws.com"
            and detail.get("eventName") in IAM_EVENTS):
        if _self_pointer_event(detail, account_id):
            return "ignored"
        return "iam"
    return "ignored"


def _self_pointer_event(detail: dict, account_id: str) -> bool:
    """Avoid queuing another full pass for this controller's derived pointers.

    Events never authorize grants. A malformed/unexpected event still performs
    full live reconciliation, and periodic reconciliation repairs all pointers.
    """
    if detail.get("eventName") not in ("TagUser", "UntagUser"):
        return False
    identity = detail.get("userIdentity", {})
    if not isinstance(identity, dict) or identity.get("type") != "AssumedRole":
        return False
    session = identity.get("sessionContext", {})
    issuer = session.get("sessionIssuer", {}) if isinstance(session, dict) else {}
    if not isinstance(issuer, dict) or issuer.get("arn") != "arn:aws:iam::" + account_id + ":role/WangLabMemberAccessSync":
        return False
    request = detail.get("requestParameters", {})
    if not isinstance(request, dict):
        return False
    if detail["eventName"] == "TagUser":
        rows = request.get("tags", [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            return False
        keys = [row.get("key", row.get("Key")) for row in rows]
    else:
        keys = request.get("tagKeys", [])
    if not isinstance(keys, list) or any(not isinstance(key, str) for key in keys):
        return False
    from .models import USER_TAG_KEYS
    return len(keys) == len(USER_TAG_KEYS) and set(keys) == set(USER_TAG_KEYS)


def lambda_handler(event: Any, context: Any) -> dict:
    """AWS entry point; credentials come exclusively from the execution role."""
    account_id, region = _invocation(context)
    trigger = _trigger(event, account_id)
    if trigger == "ignored":
        return {"status": "ignored"}
    import boto3
    try:
        session = boto3.Session(region_name=region)
        config = load_runtime_config(account_id=account_id, region=region)
        result = run_reconciliation(session.client("iam"), session.client("s3"),
                                    {r: session.client("ec2", region_name=r) for r in config["ec2_config"]["regions"]},
                                    config, account_id=account_id, region=region)
    except Exception as exc:
        raise ReconciliationError("member access reconciliation failed; retry required", _diagnostic(exc)) from None
    return {**result, "trigger": trigger}


def build_runtime_package(source_root: Path) -> bytes:
    """Create a deterministic source-only ZIP using a fixed module allowlist.

    Lambda supplies Boto3. No partial SDK dependencies are included, preventing
    runtime SDK version misalignment. Root may instead package a complete pinned
    SDK separately. Local manifests, outputs, credentials and bytecode are never
    traversed by this helper.
    """
    root = Path(source_root).resolve()
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in PACKAGE_FILES:
            path = root / name
            parent = path
            while parent != root:
                if parent.is_symlink():
                    raise RuntimeValidationError("unsafe runtime package symlink")
                parent = parent.parent
            if not path.is_file():
                raise RuntimeValidationError("missing or unsafe runtime package module")
            if root not in path.resolve().parents:
                raise RuntimeValidationError("runtime package module escapes source root")
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    return data.getvalue()
