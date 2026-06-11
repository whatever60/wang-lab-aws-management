#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any


MANAGED_TAG_KEYS = {"AccessRole", "HomeBucket", "BucketScope", "BucketOwner"}
OBJECT_WRITE_ACTIONS = [
    "s3:AbortMultipartUpload",
    "s3:DeleteObject",
    "s3:DeleteObjectTagging",
    "s3:DeleteObjectVersion",
    "s3:DeleteObjectVersionTagging",
    "s3:ListMultipartUploadParts",
    "s3:PutObject",
    "s3:PutObjectTagging",
    "s3:PutObjectVersionTagging",
]
BUCKET_LIST_ACTIONS = [
    "s3:ListBucket",
    "s3:GetBucketLocation",
    "s3:GetBucketAcl",
    "s3:GetBucketOwnershipControls",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketTagging",
    "s3:GetBucketVersioning",
    "s3:GetEncryptionConfiguration",
    "s3:GetLifecycleConfiguration",
]
OBJECT_READ_ACTIONS = ["s3:GetObject", "s3:GetObjectVersion"]
POLICY_PREFIX = "AwsAuditS3Access"
READ_POLICY_NAME = f"{POLICY_PREFIX}ReadApproved"
MEMBER_WRITE_POLICY_NAME = f"{POLICY_PREFIX}CurrentMemberWriteOwn"
ADMIN_POLICY_NAME = f"{POLICY_PREFIX}AdminWriteSharedOpsAndReadService"
ALUMNI_BASE_POLICY_NAME = f"{POLICY_PREFIX}AlumniBase"
LEGACY_LAB_MEMBERS_S3_FULL_ACCESS_ARN = "arn:aws:iam::aws:policy/AmazonS3FullAccess"


def run_aws(args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run an AWS CLI command and return the completed process."""
    proc = subprocess.run(
        ["aws", *args, "--output", "json"],
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"AWS CLI command failed: aws {' '.join(args)}\n{proc.stderr.strip()}"
        )
    return proc


def run_aws_json(args: list[str]) -> dict[str, Any]:
    """Run an AWS CLI command that returns JSON."""
    proc = run_aws(args)
    return json.loads(proc.stdout or "{}")


def run_aws_list(args: list[str]) -> list[Any]:
    """Run an AWS CLI command that returns a JSON list."""
    proc = run_aws(args)
    return json.loads(proc.stdout or "[]")


def normalize_for_compare(value: Any) -> Any:
    """Normalize JSON-like data for policy comparison."""
    if isinstance(value, dict):
        return {key: normalize_for_compare(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        normalized = [normalize_for_compare(item) for item in value]
        if all(not isinstance(item, (dict, list)) for item in normalized):
            return sorted(normalized)
        return normalized
    return value


def compact_json(data: dict[str, Any]) -> str:
    """Return a deterministic compact JSON string."""
    return json.dumps(normalize_for_compare(data), sort_keys=True, separators=(",", ":"))


def load_manifest(path: Path) -> dict[str, Any]:
    """Load the S3 access manifest."""
    return expand_environment_values(json.loads(path.read_text(encoding="utf-8")))


def expand_environment_values(value: Any) -> Any:
    """Expand environment variables in nested JSON-compatible values."""
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, list):
        return [expand_environment_values(item) for item in value]
    if isinstance(value, dict):
        return {key: expand_environment_values(item) for key, item in value.items()}
    return value


def legacy_alumni_policy_arn(manifest: dict[str, Any]) -> str:
    """Return the legacy alumni policy ARN for the manifest account."""
    return f"arn:aws:iam::{manifest['account_id']}:policy/minimal-access"


def user_by_name(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return manifest users keyed by IAM user name."""
    return {user["user_name"]: user for user in manifest["users"]}


def bucket_by_name(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return manifest buckets keyed by bucket name."""
    return {bucket["name"]: bucket for bucket in manifest["buckets"]}


def buckets_by_scope(manifest: dict[str, Any], scopes: set[str]) -> list[str]:
    """Return sorted bucket names for the given bucket scopes."""
    return sorted(
        bucket["name"] for bucket in manifest["buckets"] if bucket["scope"] in scopes
    )


def arn_for_bucket(bucket: str) -> str:
    """Return the bucket ARN for an S3 bucket."""
    return f"arn:aws:s3:::{bucket}"


def arn_for_objects(bucket: str) -> str:
    """Return the object ARN pattern for an S3 bucket."""
    return f"arn:aws:s3:::{bucket}/*"


def current_iam_users() -> set[str]:
    """Return IAM user names in the current account."""
    users = run_aws_list(["iam", "list-users", "--query", "Users[].UserName"])
    return set(users)


def current_s3_buckets() -> set[str]:
    """Return S3 bucket names in the current account."""
    buckets = run_aws_list(["s3api", "list-buckets", "--query", "Buckets[].Name"])
    return set(buckets)


def current_group_users(group_name: str) -> set[str]:
    """Return users currently in an IAM group."""
    users = run_aws_list(
        ["iam", "get-group", "--group-name", group_name, "--query", "Users[].UserName"]
    )
    return set(users)


def validate_manifest(manifest: dict[str, Any]) -> None:
    """Validate that manifest users and buckets match the live account."""
    users = user_by_name(manifest)
    buckets = bucket_by_name(manifest)
    live_users = current_iam_users()
    live_buckets = current_s3_buckets()

    missing_users = sorted(set(users) - live_users)
    extra_users = sorted(live_users - set(users))
    missing_buckets = sorted(set(buckets) - live_buckets)
    extra_buckets = sorted(live_buckets - set(buckets))
    if missing_users or extra_users or missing_buckets or extra_buckets:
        raise RuntimeError(
            "Manifest does not match live account.\n"
            f"Missing users: {missing_users}\n"
            f"Extra users: {extra_users}\n"
            f"Missing buckets: {missing_buckets}\n"
            f"Extra buckets: {extra_buckets}"
        )

    for bucket in manifest["buckets"]:
        if bucket["scope"] == "User":
            owner = bucket["owner"]
            if owner not in users:
                raise RuntimeError(f"Bucket {bucket['name']} owner {owner} is not a user.")

    owned_buckets = {
        bucket["name"] for bucket in manifest["buckets"] if bucket["scope"] == "User"
    }
    for user in manifest["users"]:
        if "home_bucket" in user and user["home_bucket"] not in owned_buckets:
            raise RuntimeError(
                f"User {user['user_name']} home bucket {user['home_bucket']} is not a User bucket."
            )


def expected_group_members(manifest: dict[str, Any], role: str) -> set[str]:
    """Return expected users for a manifest role."""
    return {user["user_name"] for user in manifest["users"] if user["role"] == role}


def validate_group_memberships(manifest: dict[str, Any]) -> None:
    """Validate that live IAM group memberships match the manifest roles."""
    groups = manifest["groups"]
    checks = [
        ("Admin", groups["admin"]),
        ("CurrentMember", groups["current_member"]),
        ("Alumni", groups["alumni"]),
    ]
    mismatches = []
    for role, group_name in checks:
        expected = expected_group_members(manifest, role)
        current = current_group_users(group_name)
        if expected != current:
            mismatches.append(
                f"{group_name}: missing={sorted(expected - current)} extra={sorted(current - expected)}"
            )
    if mismatches:
        raise RuntimeError("IAM group memberships do not match manifest roles.\n" + "\n".join(mismatches))


def get_user_tags(user_name: str) -> dict[str, str]:
    """Return IAM user tags as a dictionary."""
    data = run_aws_json(["iam", "list-user-tags", "--user-name", user_name])
    return {tag["Key"]: tag["Value"] for tag in data["Tags"]}


def get_bucket_tags(bucket: str) -> dict[str, str]:
    """Return S3 bucket tags as a dictionary."""
    proc = run_aws(["s3api", "get-bucket-tagging", "--bucket", bucket], check=False)
    if proc.returncode != 0:
        if "NoSuchTagSet" in proc.stderr:
            return {}
        raise RuntimeError(
            f"AWS CLI command failed: aws s3api get-bucket-tagging --bucket {bucket}\n{proc.stderr.strip()}"
        )
    data = json.loads(proc.stdout or "{}")
    return {tag["Key"]: tag["Value"] for tag in data["TagSet"]}


def get_bucket_policy(bucket: str) -> dict[str, Any]:
    """Return an S3 bucket policy document or an empty policy."""
    proc = run_aws(["s3api", "get-bucket-policy", "--bucket", bucket], check=False)
    if proc.returncode != 0:
        if "NoSuchBucketPolicy" in proc.stderr:
            return {"Version": "2012-10-17", "Statement": []}
        raise RuntimeError(
            f"AWS CLI command failed: aws s3api get-bucket-policy --bucket {bucket}\n{proc.stderr.strip()}"
        )
    data = json.loads(proc.stdout or "{}")
    return json.loads(data["Policy"])


def get_account_id() -> str:
    """Return the AWS account ID for the current credentials."""
    data = run_aws_json(["sts", "get-caller-identity"])
    return data["Account"]


def policy_exists(policy_arn: str) -> bool:
    """Return whether an IAM managed policy exists."""
    proc = run_aws(["iam", "get-policy", "--policy-arn", policy_arn], check=False)
    return proc.returncode == 0


def get_policy_document(policy_arn: str) -> dict[str, Any]:
    """Return the default version document for a managed policy."""
    policy = run_aws_json(["iam", "get-policy", "--policy-arn", policy_arn])
    version_id = policy["Policy"]["DefaultVersionId"]
    version = run_aws_json(
        ["iam", "get-policy-version", "--policy-arn", policy_arn, "--version-id", version_id]
    )
    return version["PolicyVersion"]["Document"]


def list_policy_versions(policy_arn: str) -> list[dict[str, Any]]:
    """Return managed policy versions."""
    data = run_aws_json(["iam", "list-policy-versions", "--policy-arn", policy_arn])
    return data["Versions"]


def group_attached_policy_arns(group_name: str) -> set[str]:
    """Return policy ARNs attached to an IAM group."""
    policies = run_aws_list(
        [
            "iam",
            "list-attached-group-policies",
            "--group-name",
            group_name,
            "--query",
            "AttachedPolicies[].PolicyArn",
        ]
    )
    return set(policies)


def read_policy(manifest: dict[str, Any]) -> dict[str, Any]:
    """Build the read-approved-buckets policy."""
    readable = buckets_by_scope(manifest, {"User", "SharedOps"})
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ListBucketsForConsole",
                "Effect": "Allow",
                "Action": ["s3:ListAllMyBuckets"],
                "Resource": "*",
            },
            {
                "Sid": "ReadApprovedBucketListings",
                "Effect": "Allow",
                "Action": BUCKET_LIST_ACTIONS,
                "Resource": [arn_for_bucket(bucket) for bucket in readable],
            },
            {
                "Sid": "ReadApprovedObjects",
                "Effect": "Allow",
                "Action": OBJECT_READ_ACTIONS,
                "Resource": [arn_for_objects(bucket) for bucket in readable],
            },
        ],
    }


def member_write_policy() -> dict[str, Any]:
    """Build the current-member/admin own-bucket write policy."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "WriteOwnHomeBucket",
                "Effect": "Allow",
                "Action": OBJECT_WRITE_ACTIONS,
                "Resource": "arn:aws:s3:::${aws:PrincipalTag/HomeBucket}/*",
            }
        ],
    }


def admin_policy(manifest: dict[str, Any]) -> dict[str, Any]:
    """Build the admin shared/ops and service-managed policy."""
    admin_write = buckets_by_scope(manifest, {"SharedOps"})
    service = buckets_by_scope(manifest, {"ServiceManaged"})
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "WriteSharedOpsBuckets",
                "Effect": "Allow",
                "Action": OBJECT_WRITE_ACTIONS,
                "Resource": [arn_for_objects(bucket) for bucket in admin_write],
            },
            {
                "Sid": "ReadServiceManagedBuckets",
                "Effect": "Allow",
                "Action": BUCKET_LIST_ACTIONS,
                "Resource": [arn_for_bucket(bucket) for bucket in service],
            },
            {
                "Sid": "ReadServiceManagedObjects",
                "Effect": "Allow",
                "Action": OBJECT_READ_ACTIONS,
                "Resource": [arn_for_objects(bucket) for bucket in service],
            },
        ],
    }


def alumni_base_policy(manifest: dict[str, Any]) -> dict[str, Any]:
    """Build replacement alumni base policy with EC2 describe and S3 read-only access."""
    policy = read_policy(manifest)
    policy["Statement"].insert(
        0,
        {
            "Sid": "DenyDirectEc2Mutation",
            "Effect": "Deny",
            "Action": ["ec2:*"],
            "Resource": "*",
            "Condition": {"Bool": {"aws:ViaAWSService": "false"}},
        },
    )
    policy["Statement"].insert(
        1,
        {
            "Sid": "AllowEc2Describe",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeRegions",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeVpcs",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeImages",
                "ec2:DescribeSnapshots",
                "ec2:DescribeVolumes",
                "ec2:DescribeTags",
            ],
            "Resource": "*",
        },
    )
    return policy


def policy_arn(account_id: str, policy_name: str) -> str:
    """Return the ARN for an account-managed IAM policy."""
    return f"arn:aws:iam::{account_id}:policy/{policy_name}"


def put_policy_document(policy_arn_value: str, policy_name: str, document: dict[str, Any], apply: bool) -> list[str]:
    """Plan or apply an account-managed IAM policy document."""
    actions = []
    desired = compact_json(document)
    if not policy_exists(policy_arn_value):
        actions.append(f"create-policy {policy_name}")
        if apply:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as handle:
                handle.write(json.dumps(document, indent=2))
                handle.flush()
                run_aws(
                    [
                        "iam",
                        "create-policy",
                        "--policy-name",
                        policy_name,
                        "--policy-document",
                        f"file://{handle.name}",
                    ]
                )
        return actions

    current = compact_json(get_policy_document(policy_arn_value))
    if current == desired:
        return actions

    actions.append(f"update-policy {policy_name}")
    if apply:
        versions = list_policy_versions(policy_arn_value)
        non_default = [version for version in versions if not version["IsDefaultVersion"]]
        if len(versions) >= 5:
            oldest = sorted(non_default, key=lambda version: version["CreateDate"])[0]
            run_aws(
                [
                    "iam",
                    "delete-policy-version",
                    "--policy-arn",
                    policy_arn_value,
                    "--version-id",
                    oldest["VersionId"],
                ]
            )
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as handle:
            handle.write(json.dumps(document, indent=2))
            handle.flush()
            run_aws(
                [
                    "iam",
                    "create-policy-version",
                    "--policy-arn",
                    policy_arn_value,
                    "--policy-document",
                    f"file://{handle.name}",
                    "--set-as-default",
                ]
            )
    return actions


def ensure_group_attachment(group_name: str, policy_arn_value: str, apply: bool) -> list[str]:
    """Plan or apply an IAM group policy attachment."""
    if policy_arn_value in group_attached_policy_arns(group_name):
        return []
    action = f"attach {policy_arn_value} to group {group_name}"
    if apply:
        run_aws(
            [
                "iam",
                "attach-group-policy",
                "--group-name",
                group_name,
                "--policy-arn",
                policy_arn_value,
            ]
        )
    return [action]


def remove_group_attachment(group_name: str, policy_arn_value: str, apply: bool) -> list[str]:
    """Plan or apply an IAM group policy detachment."""
    if policy_arn_value not in group_attached_policy_arns(group_name):
        return []
    action = f"detach {policy_arn_value} from group {group_name}"
    if apply:
        run_aws(
            [
                "iam",
                "detach-group-policy",
                "--group-name",
                group_name,
                "--policy-arn",
                policy_arn_value,
            ]
        )
    return [action]


def desired_user_tags(user: dict[str, Any]) -> dict[str, str]:
    """Return managed tags desired for an IAM user."""
    tags = {"AccessRole": user["role"]}
    if "home_bucket" in user:
        tags["HomeBucket"] = user["home_bucket"]
    return tags


def desired_bucket_tags(bucket: dict[str, Any], users: dict[str, dict[str, Any]]) -> dict[str, str]:
    """Return managed tags desired for an S3 bucket."""
    tags = {"BucketScope": bucket["scope"]}
    if bucket["scope"] == "User":
        owner = bucket["owner"]
        tags["BucketOwner"] = owner
        tags["OwnerAccessRole"] = users[owner]["role"]
    return tags


def reconcile_user_tags(manifest: dict[str, Any], apply: bool) -> list[str]:
    """Plan or apply IAM user tag changes."""
    actions = []
    for user in manifest["users"]:
        user_name = user["user_name"]
        current = get_user_tags(user_name)
        desired = desired_user_tags(user)
        updates = {key: value for key, value in desired.items() if current.get(key) != value}
        removals = sorted(key for key in MANAGED_TAG_KEYS if key in current and key not in desired)
        if updates:
            actions.append(f"tag-user {user_name}: {updates}")
            if apply:
                run_aws(
                    [
                        "iam",
                        "tag-user",
                        "--user-name",
                        user_name,
                        "--tags",
                        *[f"Key={key},Value={value}" for key, value in updates.items()],
                    ]
                )
        if removals:
            actions.append(f"untag-user {user_name}: {removals}")
            if apply:
                run_aws(
                    [
                        "iam",
                        "untag-user",
                        "--user-name",
                        user_name,
                        "--tag-keys",
                        *removals,
                    ]
                )
    return actions


def reconcile_bucket_tags(manifest: dict[str, Any], apply: bool) -> list[str]:
    """Plan or apply S3 bucket tag changes."""
    actions = []
    users = user_by_name(manifest)
    for bucket in manifest["buckets"]:
        bucket_name = bucket["name"]
        current = get_bucket_tags(bucket_name)
        desired = desired_bucket_tags(bucket, users)
        merged = {
            key: value
            for key, value in current.items()
            if key not in MANAGED_TAG_KEYS and key != "OwnerAccessRole"
        }
        merged.update(desired)
        if current == merged:
            continue
        actions.append(f"put-bucket-tagging {bucket_name}: {desired}")
        if apply:
            tag_set = [{"Key": key, "Value": value} for key, value in sorted(merged.items())]
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as handle:
                handle.write(json.dumps({"TagSet": tag_set}, indent=2))
                handle.flush()
                run_aws(
                    [
                        "s3api",
                        "put-bucket-tagging",
                        "--bucket",
                        bucket_name,
                        "--tagging",
                        f"file://{handle.name}",
                    ]
                )
    return actions


def guardrail_sids() -> set[str]:
    """Return bucket policy statement IDs managed by this reconciler."""
    return {
        "AwsAuditDenyWriteUnlessHomeBucketMatches",
        "AwsAuditDenyWriteUnlessCurrentMemberOrAdmin",
        "AwsAuditDenyWriteUnlessAdmin",
    }


def user_bucket_guardrails(bucket_name: str) -> list[dict[str, Any]]:
    """Build bucket policy guardrails for a user bucket."""
    return [
        {
            "Sid": "AwsAuditDenyWriteUnlessHomeBucketMatches",
            "Effect": "Deny",
            "Principal": "*",
            "Action": OBJECT_WRITE_ACTIONS,
            "Resource": arn_for_objects(bucket_name),
            "Condition": {"StringNotEquals": {"aws:PrincipalTag/HomeBucket": bucket_name}},
        },
        {
            "Sid": "AwsAuditDenyWriteUnlessCurrentMemberOrAdmin",
            "Effect": "Deny",
            "Principal": "*",
            "Action": OBJECT_WRITE_ACTIONS,
            "Resource": arn_for_objects(bucket_name),
            "Condition": {
                "StringNotEquals": {
                    "aws:PrincipalTag/AccessRole": ["CurrentMember", "Admin"]
                }
            },
        },
    ]


def admin_only_guardrails(bucket_name: str) -> list[dict[str, Any]]:
    """Build bucket policy guardrails for admin-write-only buckets."""
    return [
        {
            "Sid": "AwsAuditDenyWriteUnlessAdmin",
            "Effect": "Deny",
            "Principal": "*",
            "Action": OBJECT_WRITE_ACTIONS,
            "Resource": arn_for_objects(bucket_name),
            "Condition": {"StringNotEquals": {"aws:PrincipalTag/AccessRole": "Admin"}},
        }
    ]


def desired_bucket_policy(bucket: dict[str, Any]) -> dict[str, Any]:
    """Return the desired bucket policy after merging managed guardrails."""
    bucket_name = bucket["name"]
    policy = get_bucket_policy(bucket_name)
    statements = policy["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    kept = [statement for statement in statements if statement.get("Sid") not in guardrail_sids()]
    managed: list[dict[str, Any]] = []
    if bucket["scope"] == "User":
        managed = user_bucket_guardrails(bucket_name)
    elif bucket["scope"] == "SharedOps":
        managed = admin_only_guardrails(bucket_name)
    else:
        managed = []
    return {"Version": policy.get("Version", "2012-10-17"), "Statement": kept + managed}


def reconcile_bucket_policies(manifest: dict[str, Any], apply: bool) -> list[str]:
    """Plan or apply S3 bucket policy guardrails."""
    actions = []
    for bucket in manifest["buckets"]:
        if bucket["scope"] == "ServiceManaged":
            continue
        bucket_name = bucket["name"]
        current = get_bucket_policy(bucket_name)
        desired = desired_bucket_policy(bucket)
        if compact_json(current) == compact_json(desired):
            continue
        actions.append(f"put-bucket-policy guardrails {bucket_name}")
        if apply:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as handle:
                handle.write(json.dumps(desired, indent=2))
                handle.flush()
                run_aws(
                    [
                        "s3api",
                        "put-bucket-policy",
                        "--bucket",
                        bucket_name,
                        "--policy",
                        f"file://{handle.name}",
                    ]
                )
    return actions


def reconcile_managed_policies(manifest: dict[str, Any], apply: bool) -> tuple[list[str], dict[str, str]]:
    """Plan or apply IAM managed policy documents."""
    account_id = manifest["account_id"]
    read_arn = policy_arn(account_id, READ_POLICY_NAME)
    member_write_arn = policy_arn(account_id, MEMBER_WRITE_POLICY_NAME)
    admin_arn = policy_arn(account_id, ADMIN_POLICY_NAME)
    alumni_base_arn = policy_arn(account_id, ALUMNI_BASE_POLICY_NAME)
    actions = []
    actions.extend(put_policy_document(read_arn, READ_POLICY_NAME, read_policy(manifest), apply))
    actions.extend(
        put_policy_document(
            member_write_arn, MEMBER_WRITE_POLICY_NAME, member_write_policy(), apply
        )
    )
    actions.extend(put_policy_document(admin_arn, ADMIN_POLICY_NAME, admin_policy(manifest), apply))
    actions.extend(
        put_policy_document(
            alumni_base_arn, ALUMNI_BASE_POLICY_NAME, alumni_base_policy(manifest), apply
        )
    )
    return actions, {
        "read": read_arn,
        "member_write": member_write_arn,
        "admin": admin_arn,
        "alumni_base": alumni_base_arn,
    }


def reconcile_group_policies(manifest: dict[str, Any], policy_arns: dict[str, str], apply: bool) -> list[str]:
    """Plan or apply IAM group policy attachments."""
    groups = manifest["groups"]
    actions = []
    actions.extend(ensure_group_attachment(groups["current_member"], policy_arns["read"], apply))
    actions.extend(
        ensure_group_attachment(groups["current_member"], policy_arns["member_write"], apply)
    )
    actions.extend(ensure_group_attachment(groups["admin"], policy_arns["read"], apply))
    actions.extend(ensure_group_attachment(groups["admin"], policy_arns["member_write"], apply))
    actions.extend(ensure_group_attachment(groups["admin"], policy_arns["admin"], apply))
    actions.extend(ensure_group_attachment(groups["alumni"], policy_arns["alumni_base"], apply))
    actions.extend(
        remove_group_attachment(
            groups["current_member"], LEGACY_LAB_MEMBERS_S3_FULL_ACCESS_ARN, apply
        )
    )
    actions.extend(remove_group_attachment(groups["alumni"], legacy_alumni_policy_arn(manifest), apply))
    return actions


def print_actions(title: str, actions: list[str]) -> None:
    """Print planned or applied actions for one section."""
    print(f"\n## {title}")
    if not actions:
        print("no changes")
        return
    for action in actions:
        print(f"- {action}")


def reconcile(manifest: dict[str, Any], apply: bool) -> None:
    """Run the full S3 access reconciliation."""
    validate_manifest(manifest)
    validate_group_memberships(manifest)
    account_id = get_account_id()
    if account_id != manifest["account_id"]:
        raise RuntimeError(f"Current account {account_id} does not match manifest account.")

    policy_actions, policy_arns = reconcile_managed_policies(manifest, apply)
    group_actions = reconcile_group_policies(manifest, policy_arns, apply)
    user_tag_actions = reconcile_user_tags(manifest, apply)
    bucket_tag_actions = reconcile_bucket_tags(manifest, apply)
    bucket_policy_actions = reconcile_bucket_policies(manifest, apply)

    mode = "APPLIED" if apply else "PLAN"
    print(f"# S3 access reconcile {mode}")
    print_actions("Managed policies", policy_actions)
    print_actions("Group policy attachments", group_actions)
    print_actions("IAM user tags", user_tag_actions)
    print_actions("S3 bucket tags", bucket_tag_actions)
    print_actions("S3 bucket policy guardrails", bucket_policy_actions)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["plan", "apply"])
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("config/s3_access_manifest.local.json"),
    )
    return parser.parse_args()


def main() -> None:
    """Run the command-line entry point."""
    args = parse_args()
    manifest = load_manifest(args.manifest)
    reconcile(manifest, args.command == "apply")


if __name__ == "__main__":
    main()
