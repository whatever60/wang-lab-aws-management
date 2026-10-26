#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any



def run_command(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a command and return the completed process."""
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if check and proc.returncode != 0:
        raise SystemExit(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr.strip()}"
        )
    return proc


def run_aws(args: list[str], region: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run an AWS CLI command and return the completed process."""
    cmd = ["aws"] + args
    if "--output" not in args:
        cmd.extend(["--output", "json"])
    if region:
        cmd.extend(["--region", region])
    return run_command(cmd, check=check)


def aws_text(args: list[str], region: str | None = None, check: bool = True) -> str:
    """Run an AWS CLI command and return stripped text output."""
    proc = run_aws(args + ["--output", "text"], region=region, check=check)
    return proc.stdout.strip()


def aws_json(args: list[str], region: str | None = None) -> dict[str, Any]:
    """Run an AWS CLI command and return parsed JSON output."""
    proc = run_aws(args + ["--output", "json"], region=region, check=True)
    return json.loads(proc.stdout)


def parse_list_csv(value: str) -> list[str]:
    """Parse a comma-separated or whitespace-separated list string."""
    tokens: list[str] = []
    for part in value.replace(",", " ").split():
        cleaned = part.strip()
        if cleaned:
            tokens.append(cleaned)
    return tokens


def unique_in_order(values: list[str]) -> list[str]:
    """Return unique values preserving the first-seen order."""
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            out.append(value)
            seen.add(value)
    return out


def resolve_target_regions(target_regions_arg: str, base_region: str) -> list[str]:
    """Default regional resources to the base region; expand only when requested."""
    selection = target_regions_arg.strip()
    if not selection:
        return [base_region]
    if selection != "all":
        regions = unique_in_order(parse_list_csv(selection))
        if not regions or "all" in regions:
            raise SystemExit("--target-regions requires a region list or 'all' by itself.")
        return regions
    regions_raw = aws_text(
        [
            "ec2",
            "describe-regions",
            "--all-regions",
            "--query",
            "Regions[?OptInStatus=='opt-in-not-required'||OptInStatus=='opted-in'].RegionName",
        ]
    )
    return unique_in_order(parse_list_csv(regions_raw))


def ensure_s3_bucket(bucket: str, region: str) -> None:
    """Create an S3 bucket if it does not already exist."""
    exists_proc = run_aws(["s3api", "head-bucket", "--bucket", bucket], check=False)
    if exists_proc.returncode == 0:
        return
    if region == "us-east-1":
        run_aws(["s3api", "create-bucket", "--bucket", bucket, "--region", region])
        return
    run_aws(
        [
            "s3api",
            "create-bucket",
            "--bucket",
            bucket,
            "--region",
            region,
            "--create-bucket-configuration",
            f"LocationConstraint={region}",
        ]
    )


def setup_cloudtrail(account_id: str, base_region: str, trail_name: str, trail_bucket: str) -> None:
    """Create or update the account CloudTrail trail and start logging."""
    ensure_s3_bucket(trail_bucket, base_region)
    source_arn = f"arn:aws:cloudtrail:{base_region}:{account_id}:trail/{trail_name}"

    trail_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{trail_bucket}",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceArn": source_arn
                    }
                },
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{trail_bucket}/AWSLogs/{account_id}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceArn": source_arn,
                    }
                },
            },
        ],
    }
    run_aws(
        [
            "s3api",
            "put-bucket-policy",
            "--bucket",
            trail_bucket,
            "--policy",
            json.dumps(trail_policy),
        ]
    )

    existing_trail_name = aws_text(
        [
            "cloudtrail",
            "describe-trails",
            "--trail-name-list",
            trail_name,
            "--query",
            "trailList[0].Name",
        ],
        region=base_region,
    )

    if existing_trail_name == trail_name:
        run_aws(
            [
                "cloudtrail",
                "update-trail",
                "--name",
                trail_name,
                "--s3-bucket-name",
                trail_bucket,
                "--is-multi-region-trail",
                "--enable-log-file-validation",
            ],
            region=base_region,
        )
    else:
        run_aws(
            [
                "cloudtrail",
                "create-trail",
                "--name",
                trail_name,
                "--s3-bucket-name",
                trail_bucket,
                "--is-multi-region-trail",
                "--enable-log-file-validation",
            ],
            region=base_region,
        )

    run_aws(["cloudtrail", "start-logging", "--name", trail_name], region=base_region)


def ensure_config_role(config_role_name: str) -> str:
    """Create AWS Config IAM role if needed and return role ARN."""
    role_proc = run_aws(["iam", "get-role", "--role-name", config_role_name], check=False)
    if role_proc.returncode != 0:
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "config.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        run_aws(
            [
                "iam",
                "create-role",
                "--role-name",
                config_role_name,
                "--assume-role-policy-document",
                json.dumps(trust_policy),
            ]
        )

    run_aws(
        [
            "iam",
            "attach-role-policy",
            "--role-name",
            config_role_name,
            "--policy-arn",
            "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole",
        ]
    )

    return aws_text(["iam", "get-role", "--role-name", config_role_name, "--query", "Role.Arn"])


def setup_config(
    account_id: str,
    base_region: str,
    regions: list[str],
    config_bucket: str,
    config_role_name: str,
    config_recorder_name: str,
    config_delivery_channel_name: str,
) -> None:
    """Set up AWS Config recorder and delivery channel in target regions."""
    ensure_s3_bucket(config_bucket, base_region)

    config_bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSConfigBucketPermissionsCheck",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": ["s3:GetBucketAcl", "s3:ListBucket"],
                "Resource": f"arn:aws:s3:::{config_bucket}",
                "Condition": {"StringEquals": {"AWS:SourceAccount": account_id}},
            },
            {
                "Sid": "AWSConfigBucketDelivery",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{config_bucket}/AWSLogs/{account_id}/Config/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "AWS:SourceAccount": account_id,
                    }
                },
            },
        ],
    }
    run_aws(
        [
            "s3api",
            "put-bucket-policy",
            "--bucket",
            config_bucket,
            "--policy",
            json.dumps(config_bucket_policy),
        ]
    )

    config_role_arn = ensure_config_role(config_role_name)

    for region in regions:
        recorder_payload = {
            "name": config_recorder_name,
            "roleARN": config_role_arn,
            "recordingGroup": {
                "allSupported": False,
                "includeGlobalResourceTypes": False,
                "resourceTypes": ["AWS::EC2::Instance", "AWS::EC2::Volume"],
            },
        }
        run_aws(
            [
                "configservice",
                "put-configuration-recorder",
                "--configuration-recorder",
                json.dumps(recorder_payload),
            ],
            region=region,
        )

        delivery_payload = {
            "name": config_delivery_channel_name,
            "s3BucketName": config_bucket,
            "configSnapshotDeliveryProperties": {"deliveryFrequency": "TwentyFour_Hours"},
        }
        run_aws(
            [
                "configservice",
                "put-delivery-channel",
                "--delivery-channel",
                json.dumps(delivery_payload),
            ],
            region=region,
        )

        run_aws(
            [
                "configservice",
                "start-configuration-recorder",
                "--configuration-recorder-name",
                config_recorder_name,
            ],
            region=region,
        )


def print_summary(account_id: str, args: argparse.Namespace, regions: list[str], trail_bucket: str, config_bucket: str) -> None:
    """Print a concise setup execution summary."""
    print(f"Account: {account_id}")
    print(f"Command: {args.command}")
    print(f"Base region: {args.base_region}")
    print(f"Target regions: {' '.join(regions)}")
    print(f"Trail bucket: {trail_bucket}")
    print(f"Config bucket: {config_bucket}")



def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Set up quiet CloudTrail and AWS Config recording.")
    parser.add_argument("command", nargs="?", default="all", choices=["all", "cloudtrail", "config"])
    parser.add_argument("--base-region", default=os.environ.get("BASE_REGION", "us-east-1"))
    parser.add_argument("--target-regions", default=os.environ.get("TARGET_REGIONS", ""),
                        help="Config regions; defaults to the base region. Explicit 'all' discovers enabled regions.")
    parser.add_argument("--trail-name", default=os.environ.get("TRAIL_NAME", "account-audit-trail"))
    parser.add_argument("--trail-bucket", default=os.environ.get("TRAIL_BUCKET", ""))
    parser.add_argument("--config-bucket", default=os.environ.get("CONFIG_BUCKET", ""))
    parser.add_argument("--config-role-name", default=os.environ.get("CONFIG_ROLE_NAME", "AWSConfigRecorderRole"))
    parser.add_argument("--config-recorder-name", default=os.environ.get("CONFIG_RECORDER_NAME", "default"))
    parser.add_argument("--config-delivery-channel-name", default=os.environ.get("CONFIG_DELIVERY_CHANNEL_NAME", "default"))
    return parser.parse_args()


def main() -> int:
    os.environ["AWS_PAGER"] = ""
    args = parse_args()
    account_id = aws_text(["sts", "get-caller-identity", "--query", "Account"])
    regions = resolve_target_regions(args.target_regions, args.base_region)
    trail_bucket = args.trail_bucket or f"my-{account_id}-cloudtrail-audit"
    config_bucket = args.config_bucket or f"my-{account_id}-config-history"
    print_summary(account_id, args, regions, trail_bucket, config_bucket)
    if args.command in ("all", "cloudtrail"):
        setup_cloudtrail(account_id, args.base_region, args.trail_name, trail_bucket)
    if args.command in ("all", "config"):
        setup_config(account_id=account_id, base_region=args.base_region, regions=regions,
                     config_bucket=config_bucket, config_role_name=args.config_role_name,
                     config_recorder_name=args.config_recorder_name,
                     config_delivery_channel_name=args.config_delivery_channel_name)
    print("Done. CloudTrail and Config recording have no routine notification pipeline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
