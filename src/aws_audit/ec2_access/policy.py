"""Build a complete replacement for member EC2FullAccess; never call AWS.

All documents returned by build_policy_bundle must be attached together to the
member group. Administrators must first verify the exact infrastructure and
exception inputs. This is deliberately an IAM-user policy, not a role policy.
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Sequence, Tuple


SELF = "${aws:username}"
OWNED_ACTIONS = {
    "instance": ("ec2:StartInstances", "ec2:StopInstances", "ec2:RebootInstances",
                 "ec2:TerminateInstances", "ec2:AttachVolume", "ec2:DetachVolume"),
    "volume": ("ec2:AttachVolume", "ec2:DetachVolume", "ec2:DeleteVolume", "ec2:ModifyVolume"),
    "key-pair": ("ec2:RunInstances", "ec2:DeleteKeyPair"),
}
# Exceptions intentionally cannot confer launch, key use, data attachment,
# deletion, or volume modification. Administrators handle those shared changes.
SHARED_ACTIONS = {"ec2:StartInstances", "ec2:StopInstances", "ec2:RebootInstances"}
CREATE_ACTIONS = ("RunInstances", "CreateVolume", "ImportKeyPair")
MUTATIONS = tuple(sorted({action for actions in OWNED_ACTIONS.values() for action in actions}
                         | {"ec2:RunInstances", "ec2:CreateVolume", "ec2:ImportKeyPair", "ec2:CreateTags"}))
ALLOWED_ACTIONS = ("ec2:Describe*",) + MUTATIONS
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
class MemberEc2Config:
    account_id: str
    regions: Tuple[str, ...]
    instance_types: Tuple[str, ...]
    approved_image_arns: Tuple[str, ...]
    approved_snapshot_arns: Tuple[str, ...]
    approved_subnet_arns: Tuple[str, ...]
    approved_security_group_arns: Tuple[str, ...]
    shared_grants: Tuple[SharedGrant, ...] = field(default_factory=tuple)


def policy_size(document: Mapping[str, Any]) -> int:
    """IAM's managed-policy size, excluding whitespace (ASCII-only inputs)."""
    return len(json.dumps(document, separators=(",", ":"), ensure_ascii=True))


def config_from_mapping(value: Mapping[str, Any]) -> MemberEc2Config:
    """Read an explicit JSON configuration; reject omissions and unknown fields."""
    fields = {"account_id", "regions", "instance_types", "approved_image_arns", "approved_snapshot_arns",
              "approved_subnet_arns", "approved_security_group_arns", "shared_grants"}
    if not isinstance(value, dict) or set(value) - fields or fields - {"shared_grants"} - set(value):
        raise ValueError("configuration contains unknown fields or missing required fields")
    kwargs = {"account_id": value["account_id"]}
    for key in fields - {"account_id", "shared_grants"}:
        items = value[key]
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
    result = MemberEc2Config(**kwargs)
    _validate(result)
    return result


def _validate(config: MemberEc2Config) -> None:
    if not isinstance(config.account_id, str) or not re.fullmatch(r"[0-9]{12}", config.account_id):
        raise ValueError("account_id must be an exact twelve-digit AWS account")
    for label, values in (("regions", config.regions), ("instance_types", config.instance_types)):
        if not values or len(set(values)) != len(values):
            raise ValueError(label + " must be nonempty and unique")
    if any(not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", region) for region in config.regions):
        raise ValueError("regions must be exact region names")
    if any(not re.fullmatch(r"[a-z0-9-]+\.[a-z0-9]+", item) for item in config.instance_types):
        raise ValueError("instance_types must be exact types, without wildcards")
    for kind, values in (("image", config.approved_image_arns),
                         ("snapshot", config.approved_snapshot_arns),
                         ("subnet", config.approved_subnet_arns),
                         ("security-group", config.approved_security_group_arns)):
        if not values or len(set(values)) != len(values):
            raise ValueError("approved " + kind + " ARNs must be nonempty and unique")
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


def _validate_arn(config: MemberEc2Config, arn: str, kind: str) -> None:
    account = "" if kind in ("image", "snapshot") else config.account_id
    prefix = {"image": "ami", "snapshot": "snap", "subnet": "subnet",
              "security-group": "sg", "instance": "i"}[kind]
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
    """Return deployable managed-policy documents; attach EVERY returned policy.

    No default account, infrastructure, AMI, principal, or expiry is inferred.
    Shared grants cover only explicitly listed existing-instance lifecycle APIs.
    With the existing three S3/EBS managed policies, at most six generated
    policies fit the default group attachment quota after EC2FullAccess removal.
    """
    _validate(config)
    if not isinstance(max_policy_size, int) or not 1024 <= max_policy_size <= 6144:
        raise ValueError("max_policy_size must be between 1024 and 6144")
    statements = []
    def add(*args: Any, **kwargs: Any) -> None:
        statements.append(_statement(*args, **kwargs))
    def arns(kind: str) -> list:
        return ["arn:aws:ec2:%s:%s:%s/*" % (region, config.account_id, kind) for region in sorted(config.regions)]
    owned = {"StringEquals": {"ec2:ResourceTag/Owner": SELF}}
    foreign = {"StringNotEquals": {"ec2:ResourceTag/Owner": SELF}}
    new_tags = {"StringEquals": {"aws:RequestTag/Owner": SELF, "aws:RequestTag/Project": "personal"},
                "ForAllValues:StringEquals": {"aws:TagKeys": ["Owner", "Project", "Name"]}}

    add("Inventory", "Allow", ["ec2:Describe*"])
    # ec2:Region is EC2-only. The Null test prevents NotAction from denying
    # unrelated services, e.g. the member's existing S3 and password permissions.
    add("DenyOtherEc2Actions", "Deny", ALLOWED_ACTIONS,
        condition={"Null": {"ec2:Region": "false"}}, not_action=True)
    add("DenyMutationOutsideApprovedRegions", "Deny", MUTATIONS,
        condition={"StringNotEquals": {"ec2:Region": sorted(config.regions)}})
    add("DenyAlternateInfrastructureAndAccessPaths", "Deny", [
        "elasticloadbalancing:*", "autoscaling:*", "ebs:*", "iam:PassRole", "iam:CreateServiceLinkedRole",
        "iam:TagUser", "iam:UntagUser", "sts:AssumeRole", "sts:TagSession",
        "ssm:*", "ec2-instance-connect:*",
        "cloudwatch:PutMetricAlarm", "cloudwatch:PutCompositeAlarm", "cloudwatch:EnableAlarmActions",
        "cloudwatch:SetAlarmState", "cloudwatch:PutMetricData",
    ])

    shared_resources = sorted(grant.resource_arn for grant in config.shared_grants)
    for kind, actions in OWNED_ACTIONS.items():
        add("Owned" + kind.replace("-", "").title(), "Allow", actions, arns(kind), owned)
        # NotResource covers all foreign instances except explicit shared ones;
        # shared resources receive their own principal/action/expiry Denies below.
        add("DenyForeign" + kind.replace("-", "").title(), "Deny", actions,
            shared_resources if kind == "instance" and shared_resources else arns(kind),
            foreign, not_resource=bool(kind == "instance" and shared_resources))
    for index, grant in enumerate(sorted(config.shared_grants, key=lambda item: item.resource_arn)):
        suffix = str(index + 1)
        principals = sorted(grant.principal_arns)
        condition = {"ArnEquals": {"aws:PrincipalArn": principals},
                     "DateLessThan": {"aws:CurrentTime": grant.expires_at}}
        add("SharedLifecycle" + suffix, "Allow", sorted(grant.actions), grant.resource_arn, condition)
        # These restrictions apply even if an unrelated policy has a broad Allow.
        # Owners keep their ordinary owned-resource permissions; exceptions do
        # not remove legitimate ownership.
        add("DenyUnapprovedSharedPrincipal" + suffix, "Deny", OWNED_ACTIONS["instance"], grant.resource_arn,
            {"StringNotEquals": {"ec2:ResourceTag/Owner": SELF},
             "ArnNotEquals": {"aws:PrincipalArn": principals}})
        add("DenyUnapprovedSharedAction" + suffix, "Deny", sorted(set(OWNED_ACTIONS["instance"]) - set(grant.actions)),
            grant.resource_arn, foreign)
        add("DenyExpiredSharedGrant" + suffix, "Deny", OWNED_ACTIONS["instance"], grant.resource_arn,
            {"StringNotEquals": {"ec2:ResourceTag/Owner": SELF},
             "DateGreaterThanEquals": {"aws:CurrentTime": grant.expires_at}})

    # RunInstances is a multi-resource authorization. Check each destination
    # separately; attaching RequestTag/InstanceType to source images would break
    # normal launches and would not constrain the right resource.
    destinations = arns("instance") + arns("volume") + arns("network-interface")
    sources = sorted(config.approved_image_arns + config.approved_snapshot_arns
                     + config.approved_subnet_arns + config.approved_security_group_arns)
    add("ApprovedLaunchSources", "Allow", ["ec2:RunInstances"], sources)
    add("TaggedLaunchDestinations", "Allow", ["ec2:RunInstances"], destinations, new_tags)
    add("DenyUnapprovedLaunchResource", "Deny", ["ec2:RunInstances"],
        sources + destinations + arns("key-pair"), not_resource=True)
    add("DenyUnapprovedInstanceType", "Deny", ["ec2:RunInstances", "ec2:StartInstances"], arns("instance"),
        {"StringNotEquals": {"ec2:InstanceType": sorted(config.instance_types)}})
    add("DenyLaunchProfile", "Deny", ["ec2:RunInstances"], arns("instance"),
        {"Null": {"ec2:InstanceProfile": "false"}})
    add("DenyLaunchTemplate", "Deny", ["ec2:RunInstances"], arns("instance"),
        {"Null": {"ec2:LaunchTemplate": "false"}})
    # Unlike CreateNetworkInterface, RunInstances can refer to an existing ENI.
    # Never permit that source path, even if a competing Allow is introduced.
    add("DenyExistingLaunchInterface", "Deny", ["ec2:RunInstances"], arns("network-interface"),
        {"StringLike": {"ec2:NetworkInterfaceID": "eni-*"}})
    add("DenySpotLaunch", "Deny", ["ec2:RunInstances"], arns("instance"),
        {"StringNotEquals": {"ec2:InstanceMarketType": "on-demand"}})
    add("DenyDedicatedLaunch", "Deny", ["ec2:RunInstances"], arns("instance"),
        {"StringNotEquals": {"ec2:Tenancy": "default"}})
    add("DenyUnapprovedLaunchSnapshot", "Deny", ["ec2:RunInstances"], arns("volume"),
        {"Null": {"ec2:ParentSnapshot": "false"},
         "ArnNotEquals": {"ec2:ParentSnapshot": sorted(config.approved_snapshot_arns)}})

    add("CreateTaggedBlankVolume", "Allow", ["ec2:CreateVolume"], arns("volume"), new_tags)
    add("DenyVolumeSnapshotRestore", "Deny", ["ec2:CreateVolume"], arns("volume"),
        {"Null": {"ec2:ParentSnapshot": "false"}})
    add("ImportTaggedPublicKey", "Allow", ["ec2:ImportKeyPair"], arns("key-pair"), new_tags)

    creation_sets = [("Launch", ["ec2:RunInstances"], destinations),
                     ("Volume", ["ec2:CreateVolume"], arns("volume")),
                     ("Key", ["ec2:ImportKeyPair"], arns("key-pair"))]
    for suffix, actions, resources in creation_sets:
        for tag, value in (("Owner", SELF), ("Project", "personal")):
            add("DenyWrong" + tag + suffix, "Deny", actions, resources,
                {"StringNotEquals": {"aws:RequestTag/" + tag: value}})
        add("DenyUnknownTagKeys" + suffix, "Deny", actions, resources,
            {"ForAnyValue:StringNotEquals": {"aws:TagKeys": ["Owner", "Project", "Name"]}})

    tag_resources = destinations + arns("key-pair")
    add("TagsOnlyDuringApprovedCreation", "Allow", ["ec2:CreateTags"], tag_resources,
        {**new_tags, "StringEquals": {**new_tags["StringEquals"], "ec2:CreateAction": list(CREATE_ACTIONS)}})
    add("RenameOwnedResources", "Allow", ["ec2:CreateTags"], tag_resources,
        {"StringEquals": {"ec2:ResourceTag/Owner": SELF},
         "ForAllValues:StringEquals": {"aws:TagKeys": ["Name"]}})
    add("DenyDirectProtectedTagEdits", "Deny", ["ec2:CreateTags"],
        condition={"StringNotEquals": {"ec2:CreateAction": list(CREATE_ACTIONS)},
                   "ForAnyValue:StringNotEquals": {"aws:TagKeys": ["Name"]}})
    add("DenyForeignDirectTagEdits", "Deny", ["ec2:CreateTags"],
        condition={"StringNotEquals": {"ec2:CreateAction": list(CREATE_ACTIONS),
                                       "ec2:ResourceTag/Owner": SELF}})
    add("DenyDirectTagResourceOutsideOwnedKinds", "Deny", ["ec2:CreateTags"], tag_resources,
        condition={"StringNotEquals": {"ec2:CreateAction": list(CREATE_ACTIONS)}}, not_resource=True)
    # Name updates are the only direct tag edit. Owner, Project, tag-key casing,
    # and every other tag stay protected. DeleteTags remains denied entirely.
    # A live EC2 CreateTags pilot matched creation-only Denies in an existing-
    # resource check that exposed Owner but no request-tag context. Avoid Null
    # checks on CreateAction/TagKeys here. ForAllValues permits that owned-
    # resource check; the tag-specific context rejects every non-Name request.
    # Mandatory creation values are already enforced on the actual create APIs;
    # ec2:CreateAction is service-controlled, never a caller-supplied parameter.
    add("DenyOtherCreateTagKeys", "Deny", ["ec2:CreateTags"],
        condition={"ForAnyValue:StringNotEquals": {"aws:TagKeys": ["Owner", "Project", "Name"]}})
    add("DenyLargeEbsVolumes", "Deny", ["ec2:CreateVolume", "ec2:RunInstances", "ec2:ModifyVolume",
        "ec2:CreateFleet", "ec2:RequestSpotFleet", "ec2:RequestSpotInstances", "ec2:ImportVolume",
        "ec2:RestoreVolumeFromRecycleBin"],
        condition={"NumericGreaterThan": {"ec2:VolumeSize": "1024"}})

    result: Dict[str, Dict[str, Any]] = {}
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
        raise ValueError("bundle exceeds six group attachments; reduce reviewed inputs or request a quota review")
    return result
