"""Personal S3 role configuration; live IAM membership remains authoritative."""

import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from aws_audit.ec2_access.policy import MemberEc2Config, config_from_mapping as ec2_config_from_mapping


MANAGED_BY = "wanglab-aws-management"
COMPONENT = "member-launch"
ROLE_PATH = "/wanglab/member-s3/"
STATE_POLICY_NAME = "WangLabMemberRoleState"
@dataclass(frozen=True)
class MemberAccessConfig:
    s3_manifest: Dict[str, Any]
    ec2_config: MemberEc2Config
    member_group: str = "lab_members"
    permissions_boundary_arn: Optional[str] = None

    @property
    def account_id(self) -> str:
        return self.ec2_config.account_id


def valid_username(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,64}", value))


def role_arn(config: MemberAccessConfig, username: str) -> str:
    return "arn:aws:iam::%s:role%s%s" % (config.account_id, ROLE_PATH, username)


def profile_arn(config: MemberAccessConfig, username: str) -> str:
    return "arn:aws:iam::%s:instance-profile%s%s" % (config.account_id, ROLE_PATH, username)


def managed_tags(username: str, home: str, *, active: bool = True) -> Dict[str, str]:
    return {"ManagedBy": MANAGED_BY, "Component": COMPONENT, "Owner": username,
            "HomeBucket": home, "AccessRole": "CurrentMember" if active else "Inactive"}


def owned(tags: Mapping[str, str]) -> bool:
    return tags.get("ManagedBy") == MANAGED_BY and tags.get("Component") == COMPONENT


def validate_config(config: MemberAccessConfig) -> None:
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


def config_from_mapping(value: Mapping[str, Any]) -> MemberAccessConfig:
    allowed = {"s3_manifest", "ec2_config", "member_group", "permissions_boundary_arn"}
    if not isinstance(value, dict) or set(value) - allowed or {"s3_manifest", "ec2_config"} - set(value):
        raise ValueError("member access configuration needs s3_manifest and ec2_config")
    result = MemberAccessConfig(value["s3_manifest"], ec2_config_from_mapping(value["ec2_config"]),
                                value.get("member_group", "lab_members"), value.get("permissions_boundary_arn"))
    validate_config(result)
    return result
