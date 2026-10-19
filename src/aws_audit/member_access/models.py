"""Explicit approved infrastructure; live IAM membership is never configuration."""

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from aws_audit.ec2_access.launch import build_launch_request
from aws_audit.ec2_access.policy import MemberEc2Config, config_from_mapping as ec2_config_from_mapping


MANAGED_BY = "wanglab-aws-management"
COMPONENT = "member-launch"
ROLE_PATH = "/wanglab/member-s3/"
STATE_POLICY_NAME = "WangLabMemberRoleState"
FLAVOR_TAG_KEYS = {
    "Ubuntu2404": "MemberLaunchUbuntu2404",
    "Al2023": "MemberLaunchAl2023",
    "DL2204": "MemberLaunchDL2204",
    "DL2404": "MemberLaunchDL2404",
}
USER_TAG_KEYS = tuple(FLAVOR_TAG_KEYS.values())


@dataclass(frozen=True)
class LaunchFlavor:
    name: str
    region: str
    image_id: str
    instance_type: str
    subnet_id: str
    security_group_id: str


@dataclass(frozen=True)
class MemberLaunchConfig:
    s3_manifest: Dict[str, Any]
    ec2_config: MemberEc2Config
    flavors: Tuple[LaunchFlavor, ...]
    member_group: str = "lab_members"
    permissions_boundary_arn: Optional[str] = None

    @property
    def account_id(self) -> str:
        return self.ec2_config.account_id


def valid_username(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,64}", value))


def role_arn(config: MemberLaunchConfig, username: str) -> str:
    return "arn:aws:iam::%s:role%s%s" % (config.account_id, ROLE_PATH, username)


def profile_arn(config: MemberLaunchConfig, username: str) -> str:
    return "arn:aws:iam::%s:instance-profile%s%s" % (config.account_id, ROLE_PATH, username)


def template_name(username: str, flavor_name: str) -> str:
    # IAM permits @+=, but EC2 template names do not. Keep ordinary usernames
    # unchanged; hash the original when replacement is necessary so e.g. two
    # email-like names cannot collapse onto the same normalized template.
    safe = re.sub(r"[^A-Za-z0-9()._/-]", "-", username)
    if safe != username:
        safe += "-" + hashlib.sha256(username.encode("utf-8")).hexdigest()[:12]
    return "wanglab-member-%s-%s" % (safe, flavor_name)


def template_arn(config: MemberLaunchConfig, region: str, template_id: str) -> str:
    return "arn:aws:ec2:%s:%s:launch-template/%s" % (region, config.account_id, template_id)


def managed_tags(username: str, home: str, *, active: bool = True) -> Dict[str, str]:
    return {"ManagedBy": MANAGED_BY, "Component": COMPONENT, "Owner": username,
            "HomeBucket": home, "AccessRole": "CurrentMember" if active else "Inactive"}


def owned(tags: Mapping[str, str]) -> bool:
    return tags.get("ManagedBy") == MANAGED_BY and tags.get("Component") == COMPONENT


def validate_config(config: MemberLaunchConfig) -> None:
    if config.member_group != "lab_members":
        raise ValueError("member_group must be the authoritative lab_members group")
    if config.permissions_boundary_arn is not None and not re.fullmatch(
            r"arn:aws:iam::" + config.account_id + r":policy/[A-Za-z0-9_+=,.@/-]+", config.permissions_boundary_arn):
        raise ValueError("permissions_boundary_arn must be an exact same-account policy ARN")
    manifest = config.s3_manifest
    if not isinstance(manifest, dict) or manifest.get("account_id") != config.account_id:
        raise ValueError("S3 manifest and EC2 configuration must name the same exact account")
    if manifest.get("groups", {}).get("current_member") != config.member_group:
        raise ValueError("S3 current_member group must be lab_members")
    for collection, field in (("users", "user_name"), ("buckets", "name")):
        rows = manifest.get(collection)
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("S3 manifest " + collection + " must be an array of objects")
        names = [row.get(field) for row in rows]
        if any(not isinstance(name, str) or not name for name in names) or len(set(names)) != len(names):
            raise ValueError("S3 manifest " + collection + " needs exact unique names")
    if any(not valid_username(row["user_name"]) for row in manifest["users"]):
        raise ValueError("S3 user names must be exact IAM usernames")
    # A missing/invalid member home is a per-member blocked state, not a reason
    # to prevent other users from being revoked during the same run.
    if len(config.flavors) != len(FLAVOR_TAG_KEYS) or {f.name for f in config.flavors} != set(FLAVOR_TAG_KEYS):
        raise ValueError("flavors must contain exactly Ubuntu2404, Al2023, DL2204, DL2404")
    for flavor in config.flavors:
        build_launch_request(config.ec2_config, username="Validation_User", key_name="validation_key",
                             instance_type=flavor.instance_type, region=flavor.region, image_id=flavor.image_id,
                             subnet_id=flavor.subnet_id, security_group_id=flavor.security_group_id)


def config_from_mapping(value: Mapping[str, Any]) -> MemberLaunchConfig:
    allowed = {"s3_manifest", "ec2_config", "flavors", "member_group", "permissions_boundary_arn"}
    if not isinstance(value, dict) or set(value) - allowed or allowed - {"member_group", "permissions_boundary_arn"} - set(value):
        raise ValueError("member launch configuration needs s3_manifest, ec2_config, flavors, and optional member_group")
    fields = {"name", "region", "image_id", "instance_type", "subnet_id", "security_group_id"}
    rows = value["flavors"]
    if not isinstance(rows, list) or any(not isinstance(row, dict) or set(row) != fields
                                        or any(not isinstance(item, str) for item in row.values()) for row in rows):
        raise ValueError("each flavor must explicitly name its exact six source fields")
    result = MemberLaunchConfig(value["s3_manifest"], ec2_config_from_mapping(value["ec2_config"]),
                                tuple(LaunchFlavor(**row) for row in rows), value.get("member_group", "lab_members"),
                                value.get("permissions_boundary_arn"))
    validate_config(result)
    return result
