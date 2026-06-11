#!/usr/bin/env python3
"""Run disposable IAM-user S3 access checks for the configured policy model."""

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ACCOUNT_ID = os.environ["AWS_AUDIT_TEST_ACCOUNT_ID"]
TARGET_USER_BUCKET = os.environ["AWS_AUDIT_TEST_USER_BUCKET"]
TARGET_SHARED_BUCKET = os.environ["AWS_AUDIT_TEST_SHARED_BUCKET"]
TEST_PREFIX = "codex-s3-access-test"
TEST_BODY = Path("/tmp/s3-access-test-body.txt")


def run_aws(
    args: list[str],
    env: dict[str, str],
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run an AWS CLI command and return the completed process."""
    proc = subprocess.run(
        ["aws", *args, "--output", "json"],
        capture_output=True,
        text=True,
        env=env,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"AWS CLI command failed: aws {' '.join(args)}\n{proc.stderr.strip()}"
        )
    return proc


def run_aws_json(args: list[str], env: dict[str, str]) -> dict[str, Any]:
    """Run an AWS CLI command and parse its JSON output."""
    proc = run_aws(args, env)
    if proc.stdout.strip():
        return json.loads(proc.stdout)
    return {}


def clean_env() -> dict[str, str]:
    """Return a clean AWS CLI environment for long-lived test-user keys."""
    env = dict(os.environ)
    if "AWS_SESSION_TOKEN" in env:
        del env["AWS_SESSION_TOKEN"]
    return env


def test_user_env(access_key: dict[str, str]) -> dict[str, str]:
    """Return an AWS CLI environment for a disposable IAM user."""
    env = clean_env()
    env["AWS_ACCESS_KEY_ID"] = access_key["AccessKeyId"]
    env["AWS_SECRET_ACCESS_KEY"] = access_key["SecretAccessKey"]
    return env


def create_user(
    user_name: str,
    group_name: str,
    access_role: str,
    admin_env: dict[str, str],
) -> dict[str, str]:
    """Create a tagged IAM user, add it to a group, and return its access key."""
    run_aws(
        [
            "iam",
            "create-user",
            "--user-name",
            user_name,
            "--tags",
            f"Key=AccessRole,Value={access_role}",
        ],
        admin_env,
    )
    run_aws(
        ["iam", "add-user-to-group", "--group-name", group_name, "--user-name", user_name],
        admin_env,
    )
    data = run_aws_json(["iam", "create-access-key", "--user-name", user_name], admin_env)
    return data["AccessKey"]


def cleanup_user(
    user_name: str,
    group_name: str,
    access_key_id: str,
    admin_env: dict[str, str],
) -> None:
    """Delete temp credentials, group membership, and IAM user."""
    run_aws(
        ["iam", "delete-access-key", "--user-name", user_name, "--access-key-id", access_key_id],
        admin_env,
        check=False,
    )
    run_aws(
        ["iam", "remove-user-from-group", "--group-name", group_name, "--user-name", user_name],
        admin_env,
        check=False,
    )
    run_aws(["iam", "delete-user", "--user-name", user_name], admin_env, check=False)


def attempt(
    actor: str,
    action: str,
    args: list[str],
    env: dict[str, str],
    expected: str,
) -> dict[str, str]:
    """Run one S3 request and return a compact result row."""
    proc = run_aws(args, env, check=False)
    actual = "allowed" if proc.returncode == 0 else "denied"
    status = "PASS" if actual == expected else "FAIL"
    error = proc.stderr.strip().replace("\n", " ")
    return {
        "actor": actor,
        "action": action,
        "expected": expected,
        "actual": actual,
        "status": status,
        "error": error,
    }


def print_rows(rows: list[dict[str, str]]) -> None:
    """Print test rows as a markdown table."""
    print("| Actor | Action | Expected | Actual | Status |")
    print("| --- | --- | --- | --- | --- |")
    for row in rows:
        print(
            "| "
            + " | ".join(
                [
                    row["actor"],
                    row["action"],
                    row["expected"],
                    row["actual"],
                    row["status"],
                ]
            )
            + " |"
        )
    failed = [row for row in rows if row["status"] != "PASS"]
    if failed:
        print("\nFailures:")
        for row in failed:
            print(f"- {row['actor']} {row['action']}: {row['error']}")
        raise RuntimeError("S3 temp-user access matrix failed.")


def main() -> None:
    """Create temp IAM users, run S3 access checks, and clean them up."""
    admin_env = clean_env()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    test_key = f"{TEST_PREFIX}/{timestamp}/admin-sharedops.txt"
    TEST_BODY.write_text(f"S3 access test {timestamp}\n", encoding="utf-8")
    specs = [
        {
            "actor": "temp lab_members",
            "user_name": f"CodexS3TestLab{timestamp}",
            "group": "lab_members",
            "role": "CurrentMember",
            "shared_write": "denied",
        },
        {
            "actor": "temp alumni",
            "user_name": f"CodexS3TestAlumni{timestamp}",
            "group": "alumni",
            "role": "Alumni",
            "shared_write": "denied",
        },
        {
            "actor": "temp admin",
            "user_name": f"CodexS3TestAdmin{timestamp}",
            "group": "admin",
            "role": "Admin",
            "shared_write": "allowed",
        },
    ]
    created: list[dict[str, Any]] = []
    rows: list[dict[str, str]] = []
    try:
        for spec in specs:
            access_key = create_user(
                spec["user_name"], spec["group"], spec["role"], admin_env
            )
            created.append(
                {
                    "user_name": spec["user_name"],
                    "group": spec["group"],
                    "access_key_id": access_key["AccessKeyId"],
                }
            )
            spec["env"] = test_user_env(access_key)
        time.sleep(12)
        for spec in specs:
            rows.append(
                attempt(
                    spec["actor"],
                    f"GetBucketLocation {TARGET_USER_BUCKET}",
                    ["s3api", "get-bucket-location", "--bucket", TARGET_USER_BUCKET],
                    spec["env"],
                    "allowed",
                )
            )
            rows.append(
                attempt(
                    spec["actor"],
                    f"ListBucket {TARGET_USER_BUCKET}",
                    [
                        "s3api",
                        "list-objects-v2",
                        "--bucket",
                        TARGET_USER_BUCKET,
                        "--max-keys",
                        "1",
                    ],
                    spec["env"],
                    "allowed",
                )
            )
            rows.append(
                attempt(
                    spec["actor"],
                    f"PutObject {TARGET_SHARED_BUCKET}/{test_key}",
                    [
                        "s3api",
                        "put-object",
                        "--bucket",
                        TARGET_SHARED_BUCKET,
                        "--key",
                        test_key,
                        "--body",
                        str(TEST_BODY),
                    ],
                    spec["env"],
                    spec["shared_write"],
                )
            )
        print_rows(rows)
    finally:
        for spec in specs:
            if spec["actor"] == "temp admin" and "env" in spec:
                run_aws(
                    [
                        "s3api",
                        "delete-object",
                        "--bucket",
                        TARGET_SHARED_BUCKET,
                        "--key",
                        test_key,
                    ],
                    spec["env"],
                    check=False,
                )
        for item in reversed(created):
            cleanup_user(
                item["user_name"],
                item["group"],
                item["access_key_id"],
                admin_env,
            )


if __name__ == "__main__":
    main()
