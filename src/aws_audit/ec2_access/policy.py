"""Build a complete replacement for member EC2FullAccess; never call AWS.

All documents returned by build_policy_bundle must be attached together to the
member group. Administrators must first verify the exact infrastructure and
exception inputs. This is deliberately an IAM-user policy, not a role policy.
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple


SELF = "${aws:username}"
READ_ACTIONS = ("ec2:Describe*",)
# These are exceptions to protection of someone else's resource, not an
# allowlist for a member's own work. Native EC2 APIs are allowed by default.
SOURCE_USE = {
    "key-pair": ("RunInstances",),
    "image": ("RunInstances", "CopyImage", "CreateReplaceRootVolumeTask"),
    "snapshot": ("RunInstances", "CreateVolume", "CopySnapshot"),
    "security-group": ("RunInstances", "CreateNetworkInterface", "CreateVpcEndpoint"),
    "subnet": ("RunInstances", "CreateNetworkInterface", "CreateNatGateway", "CreateVpcEndpoint"),
    "vpc": ("RunInstances", "CreateSecurityGroup", "CreateSubnet", "CreateRouteTable",
            "CreateNetworkAcl", "CreateVpcEndpoint", "CreateVpcPeeringConnection"),
    "launch-template": ("RunInstances", "CreateFleet"),
}
PROTECTED_KINDS = ("instance", "volume", "network-interface", "elastic-ip",
                   "route-table", "internet-gateway", "egress-only-internet-gateway", "natgateway",
                   "network-acl", "vpc-endpoint", "vpc-peering-connection", *SOURCE_USE)
# Exceptions intentionally cannot confer launch, key use, data attachment,
# deletion, or volume modification. Administrators handle those shared changes.
SHARED_ACTIONS = {"ec2:StartInstances", "ec2:StopInstances", "ec2:RebootInstances"}
VERSION = "2012-10-17"


@dataclass(frozen=True)
class SharedGrant:
    """Administrator-approved, time-limited access to one exact instance."""

    resource_arn: str
    principal_arns: Tuple[str, ...]
    actions: Tuple[str, ...]
    expires_at: str
    reason: str


@dataclass(frozen=True)
class MemberLaunchConfig:
    """Admin-controlled principal tags select templates without policy rewrites."""

    role_path: str
    instance_profile_path: str
    template_tag_keys: Tuple[str, ...]
    require_template: bool = True


@dataclass(frozen=True)
class MemberEc2Config:
    account_id: str
    regions: Tuple[str, ...]
    instance_types: Tuple[str, ...] = field(default_factory=tuple)
    approved_image_arns: Tuple[str, ...] = field(default_factory=tuple)
    approved_snapshot_arns: Tuple[str, ...] = field(default_factory=tuple)
    approved_subnet_arns: Tuple[str, ...] = field(default_factory=tuple)
    approved_security_group_arns: Tuple[str, ...] = field(default_factory=tuple)
    shared_grants: Tuple[SharedGrant, ...] = field(default_factory=tuple)
    member_launch: Optional[MemberLaunchConfig] = None


def policy_size(document: Mapping[str, Any]) -> int:
    """IAM's managed-policy size, excluding whitespace (ASCII-only inputs)."""
    return len(json.dumps(document, separators=(",", ":"), ensure_ascii=True))


def config_from_mapping(value: Mapping[str, Any]) -> MemberEc2Config:
    """Read an explicit JSON configuration; reject omissions and unknown fields."""
    optional = {"shared_grants", "member_launch", "instance_types", "approved_image_arns", "approved_snapshot_arns",
                "approved_subnet_arns", "approved_security_group_arns"}
    fields = {"account_id", "regions", "instance_types", "approved_image_arns", "approved_snapshot_arns",
              "approved_subnet_arns", "approved_security_group_arns"} | optional
    if not isinstance(value, dict) or set(value) - fields or fields - optional - set(value):
        raise ValueError("configuration contains unknown fields or missing required fields")
    kwargs = {"account_id": value["account_id"]}
    for key in ("regions", "instance_types", "approved_image_arns", "approved_snapshot_arns",
                "approved_subnet_arns", "approved_security_group_arns"):
        items = value.get(key, [])
        if not isinstance(items, list) or any(not isinstance(item, str) for item in items):
            raise ValueError(key + " must be an array of strings")
        kwargs[key] = tuple(items)
    grants = value.get("shared_grants", [])
    if not isinstance(grants, list):
        raise ValueError("shared_grants must be an array")
    normalized = []
    for grant in grants:
        expected = {"resource_arn", "principal_arns", "actions", "expires_at", "reason"}
        if not isinstance(grant, dict) or set(grant) != expected:
            raise ValueError("shared grant fields must be explicit and exact")
        if any(not isinstance(grant[key], str) for key in ("resource_arn", "expires_at", "reason")):
            raise ValueError("shared resource, expiry, and reason must be strings")
        if any(not isinstance(grant[key], list) or any(not isinstance(item, str) for item in grant[key])
               for key in ("principal_arns", "actions")):
            raise ValueError("shared principals and actions must be arrays of strings")
        normalized.append(SharedGrant(grant["resource_arn"], tuple(grant["principal_arns"]),
                                      tuple(grant["actions"]), grant["expires_at"], grant["reason"]))
    kwargs["shared_grants"] = tuple(normalized)
    member_launch = value.get("member_launch")
    if member_launch is not None:
        expected = {"role_path", "instance_profile_path", "template_tag_keys", "require_template"}
        if not isinstance(member_launch, dict) or set(member_launch) != expected:
            raise ValueError("member_launch requires exact explicit role/profile paths, template_tag_keys, and require_template")
        keys = member_launch["template_tag_keys"]
        if not isinstance(keys, list) or any(not isinstance(item, str) for item in keys):
            raise ValueError("template_tag_keys must be an array of strings")
        kwargs["member_launch"] = MemberLaunchConfig(member_launch["role_path"], member_launch["instance_profile_path"],
                                                    tuple(keys), member_launch["require_template"])
    result = MemberEc2Config(**kwargs)
    _validate(result)
    return result


def _validate(config: MemberEc2Config) -> None:
    if not isinstance(config.account_id, str) or not re.fullmatch(r"[0-9]{12}", config.account_id):
        raise ValueError("account_id must be an exact twelve-digit AWS account")
    for label, values in (("regions", config.regions), ("instance_types", config.instance_types)):
        if (label == "regions" and not values) or len(set(values)) != len(values):
            raise ValueError(label + " must be unique; regions must be nonempty")
    if any(not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", region) for region in config.regions):
        raise ValueError("regions must be exact region names")
    if any(not re.fullmatch(r"[a-z0-9-]+\.[a-z0-9]+", item) for item in config.instance_types):
        raise ValueError("instance_types must be exact types, without wildcards")
    for kind, values in (("image", config.approved_image_arns),
                         ("snapshot", config.approved_snapshot_arns),
                         ("subnet", config.approved_subnet_arns),
                         ("security-group", config.approved_security_group_arns)):
        if len(set(values)) != len(values):
            raise ValueError("approved " + kind + " ARNs must be unique")
        for arn in values:
            _validate_arn(config, arn, kind)
    seen = set()
    for grant in config.shared_grants:
        _validate_arn(config, grant.resource_arn, "instance")
        if grant.resource_arn in seen:
            raise ValueError("combine shared grants for each instance into one grant")
        seen.add(grant.resource_arn)
        if not grant.principal_arns or len(set(grant.principal_arns)) != len(grant.principal_arns):
            raise ValueError("shared principals must be nonempty and unique")
        for principal in grant.principal_arns:
            if not re.fullmatch(r"arn:aws:iam::" + config.account_id + r":user/[A-Za-z0-9_+=,.@/-]+", principal):
                raise ValueError("shared principals must be exact same-account IAM user ARNs")
        if not grant.actions or len(set(grant.actions)) != len(grant.actions) or not set(grant.actions) <= SHARED_ACTIONS:
            raise ValueError("shared grants permit only explicit Start/Stop/Reboot actions")
        if not isinstance(grant.reason, str) or not grant.reason.strip():
            raise ValueError("shared grants require an administrative reason")
        try:
            expiry = datetime.strptime(grant.expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (TypeError, ValueError) as exc:
            raise ValueError("shared expiry must be an exact UTC timestamp ending Z") from exc
        # Expired grants remain buildable so rebuilding cannot silently remove
        # the explicit expiration Deny. IAM evaluates expiry at request time.
        if expiry.year < 2020:
            raise ValueError("shared expiry is outside the supported range")
    if config.member_launch is not None:
        launch = config.member_launch
        if not isinstance(launch, MemberLaunchConfig) or not isinstance(launch.require_template, bool):
            raise ValueError("member_launch must be a MemberLaunchConfig with boolean require_template")
        for path in (launch.role_path, launch.instance_profile_path):
            if not isinstance(path, str) or not re.fullmatch(r"/(?:[A-Za-z0-9_+=,.@-]+/)+", path):
                raise ValueError("member launch IAM paths must be exact non-root paths ending in slash")
        if not 1 <= len(launch.template_tag_keys) <= 4 or len(set(launch.template_tag_keys)) != len(launch.template_tag_keys):
            raise ValueError("member launch requires one to four unique template tag keys")
        if any(not isinstance(key, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", key) for key in launch.template_tag_keys):
            raise ValueError("member template tag keys must be exact alphanumeric IAM tag names")


def _validate_arn(config: MemberEc2Config, arn: str, kind: str) -> None:
    account = "" if kind in ("image", "snapshot") else config.account_id
    prefix = {"image": "ami", "snapshot": "snap", "subnet": "subnet",
              "security-group": "sg", "instance": "i", "launch-template": "lt"}[kind]
    pattern = r"arn:aws:ec2:([^:]+):" + account + ":" + kind + "/" + prefix + r"-[a-f0-9]+"
    match = re.fullmatch(pattern, arn) if isinstance(arn, str) else None
    if not match or match.group(1) not in config.regions:
        raise ValueError("expected exact approved-region " + kind + " ARN: " + str(arn))


def _statement(sid: str, effect: str, actions: Sequence[str], resources: Any = "*",
               condition: Any = None, *, not_action: bool = False, not_resource: bool = False) -> Dict[str, Any]:
    result = {"Sid": sid, "Effect": effect,
              "NotAction" if not_action else "Action": list(actions),
              "NotResource" if not_resource else "Resource": resources}
    if condition:
        result["Condition"] = condition
    return result


def build_policy_bundle(config: MemberEc2Config, *, max_policy_size: int = 6144) -> Dict[str, Dict[str, Any]]:
    """Native EC2 console/API access; ownership and S3 profiles are reconciled later.

    Launching requires no template, request tags, profile, approved AMI/type,
    or special key workflow. Explicit guardrails protect known foreign resources
    after attribution. An untagged resource is not a tenant-isolation boundary.
    """
    _validate(config)
    if not isinstance(max_policy_size, int) or not 1024 <= max_policy_size <= 6144:
        raise ValueError("max_policy_size must be between 1024 and 6144")
    statements = []
    def add(*args: Any, **kwargs: Any) -> None:
        statements.append(_statement(*args, **kwargs))
    def arns(kind: str) -> list:
        account = "" if kind in ("image", "snapshot") else config.account_id
        return ["arn:aws:ec2:%s:%s:%s/*" % (region, account, kind) for region in sorted(config.regions)]
    foreign = {"Null": {"ec2:ResourceTag/wanglab:Owner": "false"},
               "StringNotEquals": {"ec2:ResourceTag/wanglab:Owner": SELF}}
    add("NativeEc2", "Allow", ["ec2:*", "pricing:GetProducts"])
    add("MutationRegions", "Deny", READ_ACTIONS,
        condition={"Null": {"ec2:Region": "false"},
                   "StringNotEquals": {"ec2:Region": sorted(config.regions)}}, not_action=True)
    add("IdentityRequired", "Deny", ["ec2:*", "iam:PassRole"],
        condition={"StringNotLike": {"aws:username": "?*"}})
    shared = sorted(grant.resource_arn for grant in config.shared_grants)
    # Untagged newly created resources remain usable during asynchronous
    # creator attribution. Existing canonical owners cannot be claimed.
    add("ForeignResources", "Deny", READ_ACTIONS,
        [arn for kind in SOURCE_USE for arn in arns(kind)] + shared,
        foreign, not_action=True, not_resource=True)
    for kind in SOURCE_USE:
        harmless = READ_ACTIONS + tuple("ec2:" + a for a in SOURCE_USE.get(kind, ()))
        add("Foreign" + kind.replace("-", "").title(), "Deny", harmless,
            arns(kind), foreign, not_action=True)
    for index, grant in enumerate(sorted(config.shared_grants, key=lambda item: item.resource_arn)):
        suffix = str(index + 1)
        principals = sorted(grant.principal_arns)
        add("OtherSharedPrincipal" + suffix, "Deny", READ_ACTIONS, grant.resource_arn,
            {**foreign, "ArnNotEquals": {"aws:PrincipalArn": principals}}, not_action=True)
        add("OtherSharedAction" + suffix, "Deny", READ_ACTIONS + tuple(sorted(grant.actions)),
            grant.resource_arn, foreign, not_action=True)
        add("ExpiredSharedGrant" + suffix, "Deny", READ_ACTIONS, grant.resource_arn,
            {**foreign, "DateGreaterThanEquals": {"aws:CurrentTime": grant.expires_at}}, not_action=True)
    # A new instance may omit a profile; only the caller's existing S3 profile
    # may be supplied explicitly. Background automation attaches it when absent.
    role = "arn:aws:iam::" + config.account_id + ":role/wanglab/member-s3/" + SELF
    profile = "arn:aws:iam::" + config.account_id + ":instance-profile/wanglab/member-s3/" + SELF
    add("PassOwnS3Role", "Allow", ["iam:PassRole"], role,
        {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}})
    add("ForeignPassRole", "Deny", ["iam:PassRole"], role, not_resource=True)
    add("OtherRoleService", "Deny", ["iam:PassRole"],
        condition={"StringNotEquals": {"iam:PassedToService": "ec2.amazonaws.com"}})
    add("ForeignLaunchProfile", "Deny", ["ec2:RunInstances"], arns("instance"),
        {"Null": {"ec2:InstanceProfile": "false"}, "ArnNotEquals": {"ec2:InstanceProfile": profile}})
    add("ConsoleIdentity", "Allow", ["iam:ListInstanceProfiles", "iam:GetUser", "iam:ListMFADevices",
        "iam:GetInstanceProfile", "iam:GetRole", "iam:ListInstanceProfilesForRole"])
    add("PublicAmiParameters", "Allow", ["ssm:GetParameter", "ssm:GetParameters"],
        ["arn:aws:ssm:%s::parameter/aws/service/*" % r for r in sorted(config.regions)])
    # Canonical ownership is supplied by the trusted CloudTrail reconciler.
    # Ordinary custom tags work on creation and existing resources.
    # Private provenance keys do not reserve ordinary Owner/Project/custom tags.
    add("ProtectAttribution", "Deny", ["ec2:CreateTags", "ec2:DeleteTags"],
        condition={"ForAnyValue:StringEqualsIgnoreCase": {"aws:TagKeys": ["wanglab:Owner", "wanglab:CreatorUserId"]}})
    add("ForeignTags", "Deny", ["ec2:CreateTags", "ec2:DeleteTags"], condition=foreign)
    add("SnapshotAccount", "Deny", ["ec2:DeleteSnapshot", "ec2:ModifySnapshotAttribute"],
        condition={"StringNotEquals": {"ec2:Owner": config.account_id}})
    add("PerVolumeLimit", "Deny", ["ec2:RunInstances", "ec2:CreateVolume", "ec2:ModifyVolume"],
        condition={"NumericGreaterThan": {"ec2:VolumeSize": "1024"}})
    # These change account-wide defaults or create prepaid commitments. They
    # are administrative decisions, unrelated to ordinary instance creation.
    add("AccountAndCommitments", "Deny", ["ec2:ModifyDefaultCreditSpecification", "ec2:DisableEbsEncryptionByDefault",
        "ec2:ModifyEbsDefaultKmsKeyId", "ec2:ResetEbsDefaultKmsKeyId", "ec2:DisableImageBlockPublicAccess",
        "ec2:DisableSnapshotBlockPublicAccess", "ec2:PurchaseReservedInstancesOffering",
        "ec2:PurchaseHostReservation", "ec2:PurchaseCapacityBlock", "ec2:AcceptReservedInstancesExchangeQuote"])
    # Account identity and data-role administration can bypass ownership guards.
    # Unrelated services are neither granted nor blanket-denied by this policy.
    add("ProtectIdentityAndDataRoles", "Deny", ["iam:TagUser", "iam:UntagUser", "sts:AssumeRole", "sts:TagSession",
        "iam:CreateRole", "iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy", "iam:AttachRolePolicy",
        "iam:AddRoleToInstanceProfile", "iam:RemoveRoleFromInstanceProfile", "iam:CreateInstanceProfile"])
    result = {}
    current = {"Version": VERSION, "Statement": []}
    for statement in statements:
        candidate = {"Version": VERSION, "Statement": current["Statement"] + [statement]}
        if policy_size(candidate) > max_policy_size:
            if not current["Statement"]:
                raise ValueError("one policy statement exceeds the managed-policy limit")
            result["WangLabMemberEC2%02d" % (len(result) + 1)] = current
            current = {"Version": VERSION, "Statement": [statement]}
            if policy_size(current) > max_policy_size:
                raise ValueError("one policy statement exceeds the managed-policy limit")
        else:
            current = candidate
    if current["Statement"]:
        result["WangLabMemberEC2%02d" % (len(result) + 1)] = current
    if len(result) > 6:
        raise ValueError("bundle exceeds six group attachments")
    return result
