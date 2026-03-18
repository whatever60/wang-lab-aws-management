#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from typing import Any

EVENT_PATTERN = {
    "source": ["aws.ec2"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
        "eventSource": ["ec2.amazonaws.com"],
        "eventName": [
            "RunInstances",
            "StartInstances",
            "StopInstances",
            "TerminateInstances",
            "CreateVolume",
            "AttachVolume",
            "DetachVolume",
            "ModifyVolume",
            "DeleteVolume",
            "CreateSnapshot",
            "CreateSnapshots",
            "CopySnapshot",
            "DeleteSnapshot",
            "ModifySnapshotAttribute",
            "ModifySnapshotTier",
            "RestoreSnapshotTier",
            "CreateImage",
            "RegisterImage",
            "CopyImage",
            "DeregisterImage",
            "ModifyImageAttribute",
        ],
    },
}


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


def parse_optional_bool(value: str | None) -> bool | None:
    """Parse optional true/false string into bool or None."""
    if value is None:
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    raise SystemExit("Boolean options must be 'true' or 'false'.")


def resolve_target_regions(target_regions_arg: str) -> list[str]:
    """Resolve target AWS regions from argument or account-enabled regions."""
    if target_regions_arg:
        return parse_list_csv(target_regions_arg)
    regions_raw = aws_text(
        [
            "ec2",
            "describe-regions",
            "--all-regions",
            "--query",
            "Regions[?OptInStatus=='opt-in-not-required'||OptInStatus=='opted-in'].RegionName",
        ]
    )
    return parse_list_csv(regions_raw)


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


def ensure_sns_topic(topic_name: str, region: str) -> str:
    """Create or get an SNS topic and return its ARN."""
    return aws_text(["sns", "create-topic", "--name", topic_name, "--query", "TopicArn"], region=region)


def ensure_email_subscription(topic_arn: str, email_endpoint: str, region: str) -> None:
    """Create email subscription on an SNS topic if it is not already present."""
    existing_sub_arn = aws_text(
        [
            "sns",
            "list-subscriptions-by-topic",
            "--topic-arn",
            topic_arn,
            "--query",
            f"Subscriptions[?Protocol=='email' && Endpoint=='{email_endpoint}'].SubscriptionArn | [0]",
        ],
        region=region,
    )
    if existing_sub_arn == "None":
        run_aws(
            [
                "sns",
                "subscribe",
                "--topic-arn",
                topic_arn,
                "--protocol",
                "email",
                "--notification-endpoint",
                email_endpoint,
            ],
            region=region,
        )


def set_sns_topic_policy_for_eventbridge(account_id: str, topic_arn: str, region: str) -> None:
    """Set SNS topic policy to allow EventBridge publish in this account."""
    topic_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgePublish",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sns:Publish",
                "Resource": topic_arn,
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            },
        ],
    }
    run_aws(
        [
            "sns",
            "set-topic-attributes",
            "--topic-arn",
            topic_arn,
            "--attribute-name",
            "Policy",
            "--attribute-value",
            json.dumps(topic_policy),
        ],
        region=region,
    )


def build_slack_input_transformer() -> dict[str, Any]:
    """Build EventBridge input transformer for Amazon Q custom Slack notifications."""
    input_paths_map = {
        "event_id": "$.id",
        "event_time": "$.time",
        "account": "$.account",
        "region": "$.region",
        "detail_type": "$.detail-type",
        "event_name": "$.detail.eventName",
        "event_source": "$.detail.eventSource",
        "actor_arn": "$.detail.userIdentity.arn",
        "key_name": "$.detail.requestParameters.keyName",
        "instance_type": "$.detail.requestParameters.instanceType",
        "volume_size_gib_req": "$.detail.requestParameters.size",
        "volume_size_gib_resp": "$.detail.responseElements.size",
        "volume_type_req": "$.detail.requestParameters.volumeType",
        "volume_type_resp": "$.detail.responseElements.volumeType",
        "snapshot_tier_req": "$.detail.requestParameters.storageTier",
        "snapshot_tier_resp": "$.detail.responseElements.storageTier",
    }
    input_template_payload = {
        "version": "1.0",
        "source": "custom",
        "id": "<event_id>",
        "content": {
            "textType": "client-markdown",
            "title": ":satellite: EC2/EBS/AMI API event: <event_name>",
            "description": (
                "*Event:* `<event_name>`\n"
                "*Service:* `<event_source>`\n"
                "*Detail Type:* `<detail_type>`\n"
                "*Account:* `<account>`\n"
                "*Region:* `<region>`\n"
                "*Time:* `<event_time>`\n"
                "*Actor:* `<actor_arn>`\n"
                "*EC2 Key Name:* `<key_name>`\n"
                "*Instance Type:* `<instance_type>`\n"
                "*Volume Size GiB (req/resp):* `<volume_size_gib_req>` / `<volume_size_gib_resp>`\n"
                "*Volume Type (req/resp):* `<volume_type_req>` / `<volume_type_resp>`\n"
                "*Snapshot Tier (req/resp):* `<snapshot_tier_req>` / `<snapshot_tier_resp>`\n"
                "*Event ID:* `<event_id>`"
            ),
            "keywords": ["ec2-audit", "cloudtrail", "<event_name>"],
        },
        "metadata": {
            "threadId": "ec2-ebs-ami-audit-<account>-<region>",
            "summary": "<event_name> in <region>",
            "additionalContext": {
                "eventSource": "<event_source>",
                "detailType": "<detail_type>",
                "account": "<account>",
                "region": "<region>",
                "eventTime": "<event_time>",
                "actorArn": "<actor_arn>",
                "keyName": "<key_name>",
                "instanceType": "<instance_type>",
                "volumeSizeGiBRequest": "<volume_size_gib_req>",
                "volumeSizeGiBResponse": "<volume_size_gib_resp>",
                "volumeTypeRequest": "<volume_type_req>",
                "volumeTypeResponse": "<volume_type_resp>",
                "snapshotTierRequest": "<snapshot_tier_req>",
                "snapshotTierResponse": "<snapshot_tier_resp>",
                "eventId": "<event_id>",
            },
            "enableCustomActions": True,
        },
    }
    return {
        "InputPathsMap": input_paths_map,
        "InputTemplate": json.dumps(input_template_payload),
    }


def setup_eventbridge_and_sns(
    account_id: str,
    regions: list[str],
    topic_name: str,
    rule_name: str,
    alert_destination: str,
    email_endpoint: str,
) -> list[str]:
    """Set up SNS topics and EventBridge rules for EC2/EBS/AMI audit events."""
    topic_arns: list[str] = []
    for region in regions:
        topic_arn = ensure_sns_topic(topic_name, region)
        topic_arns.append(topic_arn)
        if alert_destination == "email":
            ensure_email_subscription(topic_arn, email_endpoint, region)
        set_sns_topic_policy_for_eventbridge(account_id, topic_arn, region)
        target = {"Id": "sns1", "Arn": topic_arn}
        if alert_destination == "slack":
            target["InputTransformer"] = build_slack_input_transformer()
        run_aws(
            [
                "events",
                "put-rule",
                "--name",
                rule_name,
                "--event-pattern",
                json.dumps(EVENT_PATTERN),
                "--state",
                "ENABLED",
            ],
            region=region,
        )
        run_aws(
            [
                "events",
                "put-targets",
                "--rule",
                rule_name,
                "--targets",
                json.dumps([target]),
            ],
            region=region,
        )
    return unique_in_order(topic_arns)


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


def ensure_chatbot_role(role_name: str, role_arn_override: str, role_policy_arn: str) -> str:
    """Create or resolve the IAM role used by Amazon Q Developer chat applications."""
    if role_arn_override:
        return role_arn_override

    role_proc = run_aws(["iam", "get-role", "--role-name", role_name], check=False)
    if role_proc.returncode != 0:
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "q.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        run_aws(
            [
                "iam",
                "create-role",
                "--role-name",
                role_name,
                "--assume-role-policy-document",
                json.dumps(trust_policy),
            ]
        )

    if role_policy_arn:
        run_aws(
            [
                "iam",
                "attach-role-policy",
                "--role-name",
                role_name,
                "--policy-arn",
                role_policy_arn,
            ]
        )

    return aws_text(["iam", "get-role", "--role-name", role_name, "--query", "Role.Arn"])


def build_chatbot_create_or_update_args(
    command: str,
    chat_configuration_arn: str,
    configuration_name: str,
    slack_channel_id: str,
    slack_channel_name: str,
    slack_team_id: str,
    iam_role_arn: str,
    sns_topic_arns: list[str],
    logging_level: str,
    guardrail_policy_arns: list[str],
    user_authorization_required: bool,
) -> list[str]:
    """Build CLI args for create/update Slack channel configuration."""
    if command == "create":
        args = [
            "chatbot",
            "create-slack-channel-configuration",
            "--configuration-name",
            configuration_name,
            "--slack-team-id",
            slack_team_id,
            "--slack-channel-id",
            slack_channel_id,
            "--iam-role-arn",
            iam_role_arn,
            "--sns-topic-arns",
            *sns_topic_arns,
        ]
    else:
        args = [
            "chatbot",
            "update-slack-channel-configuration",
            "--chat-configuration-arn",
            chat_configuration_arn,
            "--slack-channel-id",
            slack_channel_id,
            "--iam-role-arn",
            iam_role_arn,
            "--sns-topic-arns",
            *sns_topic_arns,
        ]

    if slack_channel_name:
        args.extend(["--slack-channel-name", slack_channel_name])

    if logging_level:
        args.extend(["--logging-level", logging_level])

    if guardrail_policy_arns:
        args.extend(["--guardrail-policy-arns", *guardrail_policy_arns])

    if user_authorization_required:
        args.append("--user-authorization-required")
    else:
        args.append("--no-user-authorization-required")

    return args


def setup_slack_channel_configuration(
    chatbot_region: str,
    configuration_name: str,
    slack_team_id: str,
    slack_channel_id: str,
    slack_channel_name_arg: str,
    iam_role_arn: str,
    topic_arns: list[str],
    logging_level_arg: str | None,
    guardrail_policy_arns_arg: list[str],
    user_authorization_required_arg: bool | None,
) -> None:
    """Create or update Slack channel configuration and link SNS topics."""
    configurations = aws_json(["chatbot", "describe-slack-channel-configurations"], region=chatbot_region)[
        "SlackChannelConfigurations"
    ]

    matched_configs: list[dict[str, Any]] = []
    for config in configurations:
        if config["ConfigurationName"] == configuration_name:
            matched_configs.append(config)

    if not matched_configs:
        logging_level = logging_level_arg if logging_level_arg else "ERROR"
        guardrail_policy_arns = (
            guardrail_policy_arns_arg
            if guardrail_policy_arns_arg
            else ["arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"]
        )
        user_authorization_required = (
            user_authorization_required_arg if user_authorization_required_arg is not None else False
        )
        slack_channel_name = slack_channel_name_arg

        create_args = build_chatbot_create_or_update_args(
            command="create",
            chat_configuration_arn="",
            configuration_name=configuration_name,
            slack_channel_id=slack_channel_id,
            slack_channel_name=slack_channel_name,
            slack_team_id=slack_team_id,
            iam_role_arn=iam_role_arn,
            sns_topic_arns=topic_arns,
            logging_level=logging_level,
            guardrail_policy_arns=guardrail_policy_arns,
            user_authorization_required=user_authorization_required,
        )
        run_aws(create_args, region=chatbot_region)
        return

    existing = matched_configs[0]
    existing_topics = existing["SnsTopicArns"]
    combined_topics = unique_in_order(existing_topics + topic_arns)

    existing_channel_id = existing["SlackChannelId"]
    existing_channel_name = existing["SlackChannelName"]
    existing_logging_level = existing["LoggingLevel"]
    existing_guardrails = existing["GuardrailPolicyArns"]
    existing_user_auth = existing["UserAuthorizationRequired"]
    chat_configuration_arn = existing["ChatConfigurationArn"]

    if slack_channel_name_arg:
        effective_channel_name = slack_channel_name_arg
    else:
        effective_channel_name = existing_channel_name

    if logging_level_arg:
        effective_logging_level = logging_level_arg
    else:
        effective_logging_level = existing_logging_level

    if guardrail_policy_arns_arg:
        effective_guardrails = guardrail_policy_arns_arg
    else:
        effective_guardrails = existing_guardrails

    if not effective_guardrails:
        effective_guardrails = ["arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"]

    if user_authorization_required_arg is None:
        effective_user_auth = existing_user_auth
    else:
        effective_user_auth = user_authorization_required_arg

    update_args = build_chatbot_create_or_update_args(
        command="update",
        chat_configuration_arn=chat_configuration_arn,
        configuration_name=configuration_name,
        slack_channel_id=existing_channel_id,
        slack_channel_name=effective_channel_name,
        slack_team_id=slack_team_id,
        iam_role_arn=iam_role_arn,
        sns_topic_arns=combined_topics,
        logging_level=effective_logging_level,
        guardrail_policy_arns=effective_guardrails,
        user_authorization_required=effective_user_auth,
    )
    run_aws(update_args, region=chatbot_region)


def ensure_chatbot_command_available() -> None:
    """Ensure local AWS CLI supports chatbot commands."""
    proc = run_aws(["chatbot", "help"], check=False)
    if proc.returncode != 0:
        raise SystemExit(
            "AWS CLI does not support chatbot command. Use AWS CLI v2 or a v1 build that includes chatbot."
        )


def resolve_slack_topic_arns(
    explicit_topic_arns: str,
    regions: list[str],
    event_topic_name: str,
) -> list[str]:
    """Resolve SNS topic ARNs to be linked to Slack."""
    if explicit_topic_arns:
        return unique_in_order(parse_list_csv(explicit_topic_arns))
    topic_arns: list[str] = []
    for region in regions:
        topic_arn = ensure_sns_topic(event_topic_name, region)
        topic_arns.append(topic_arn)
    return unique_in_order(topic_arns)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the setup tool."""
    parser = argparse.ArgumentParser(
        description="Setup EC2/EBS/AMI audit baseline with modular commands."
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="all",
        choices=["all", "cloudtrail", "events", "config", "slack"],
        help="Which setup block to run.",
    )

    parser.add_argument("--alert-destination", choices=["email", "slack"], default="email")
    parser.add_argument("--email-endpoint", default="")

    parser.add_argument("--base-region", default="us-east-1")
    parser.add_argument("--target-regions", default="")

    parser.add_argument("--trail-name", default="account-audit-trail")
    parser.add_argument("--trail-bucket", default="")

    parser.add_argument("--event-topic-name", default="asset-audit-events")
    parser.add_argument("--rule-name", default="ec2-ebs-ami-audit")

    parser.add_argument("--config-bucket", default="")
    parser.add_argument("--config-role-name", default="AWSConfigRecorderRole")
    parser.add_argument("--config-recorder-name", default="default")
    parser.add_argument("--config-delivery-channel-name", default="default")

    parser.add_argument("--chatbot-region", default="")
    parser.add_argument("--slack-channel-configuration-name", default="test-configuration")
    parser.add_argument("--slack-team-id", default="T09CK3AAC")
    parser.add_argument("--slack-channel-id", default="C0AMDBXTDHC")
    parser.add_argument("--slack-channel-name", default="")
    parser.add_argument("--chatbot-role-name", default="ChatbotSlackRole")
    parser.add_argument("--chatbot-role-arn", default="")
    parser.add_argument(
        "--chatbot-role-policy-arn",
        default="arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess",
    )
    parser.add_argument("--chatbot-logging-level", choices=["ERROR", "INFO", "NONE"], default=None)
    parser.add_argument("--chatbot-guardrail-policy-arns", default="")
    parser.add_argument("--chatbot-user-authorization-required", choices=["true", "false"], default=None)
    parser.add_argument("--sns-topic-arns", default="")

    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    """Validate argument combinations before running setup."""
    if args.command in ["all", "events"] and args.alert_destination == "email" and not args.email_endpoint:
        raise SystemExit("--email-endpoint is required for email destination when running all/events.")


def print_summary(account_id: str, args: argparse.Namespace, regions: list[str], trail_bucket: str, config_bucket: str) -> None:
    """Print a concise setup execution summary."""
    print(f"Account: {account_id}")
    print(f"Command: {args.command}")
    print(f"Base region: {args.base_region}")
    print(f"Target regions: {' '.join(regions)}")
    print(f"Trail bucket: {trail_bucket}")
    print(f"Config bucket: {config_bucket}")
    print(f"Alert destination: {args.alert_destination}")


def main() -> int:
    """Run the modular AWS audit setup command selected by user arguments."""
    os.environ["AWS_PAGER"] = ""

    args = parse_args()
    validate_args(args)

    account_id = aws_text(["sts", "get-caller-identity", "--query", "Account"])
    regions = resolve_target_regions(args.target_regions)

    trail_bucket = args.trail_bucket if args.trail_bucket else f"my-{account_id}-cloudtrail-audit"
    config_bucket = args.config_bucket if args.config_bucket else f"my-{account_id}-config-history"

    print_summary(account_id, args, regions, trail_bucket, config_bucket)

    if args.command in ["all", "cloudtrail"]:
        setup_cloudtrail(account_id, args.base_region, args.trail_name, trail_bucket)

    topic_arns: list[str] = []
    if args.command in ["all", "events"]:
        topic_arns = setup_eventbridge_and_sns(
            account_id=account_id,
            regions=regions,
            topic_name=args.event_topic_name,
            rule_name=args.rule_name,
            alert_destination=args.alert_destination,
            email_endpoint=args.email_endpoint,
        )

    if args.command in ["all", "slack"]:
        if args.alert_destination != "slack":
            raise SystemExit("Slack setup requires --alert-destination slack.")

        ensure_chatbot_command_available()
        chatbot_region = args.chatbot_region if args.chatbot_region else args.base_region

        slack_topic_arns = topic_arns
        if not slack_topic_arns:
            slack_topic_arns = resolve_slack_topic_arns(
                explicit_topic_arns=args.sns_topic_arns,
                regions=regions,
                event_topic_name=args.event_topic_name,
            )

        iam_role_arn = ensure_chatbot_role(
            role_name=args.chatbot_role_name,
            role_arn_override=args.chatbot_role_arn,
            role_policy_arn=args.chatbot_role_policy_arn,
        )

        guardrail_arns = parse_list_csv(args.chatbot_guardrail_policy_arns)
        user_auth_required = parse_optional_bool(args.chatbot_user_authorization_required or None)

        setup_slack_channel_configuration(
            chatbot_region=chatbot_region,
            configuration_name=args.slack_channel_configuration_name,
            slack_team_id=args.slack_team_id,
            slack_channel_id=args.slack_channel_id,
            slack_channel_name_arg=args.slack_channel_name,
            iam_role_arn=iam_role_arn,
            topic_arns=slack_topic_arns,
            logging_level_arg=args.chatbot_logging_level,
            guardrail_policy_arns_arg=guardrail_arns,
            user_authorization_required_arg=user_auth_required,
        )

    if args.command in ["all", "config"]:
        setup_config(
            account_id=account_id,
            base_region=args.base_region,
            regions=regions,
            config_bucket=config_bucket,
            config_role_name=args.config_role_name,
            config_recorder_name=args.config_recorder_name,
            config_delivery_channel_name=args.config_delivery_channel_name,
        )

    if args.command in ["all", "cloudtrail"]:
        print("CloudTrail status:")
        run_aws(
            [
                "cloudtrail",
                "get-trail-status",
                "--name",
                args.trail_name,
                "--output",
                "table",
            ],
            region=args.base_region,
        )

    if args.command in ["all", "config"]:
        print("AWS Config recorder status by region:")
        for region in regions:
            print(f"--- {region} ---")
            run_aws(
                [
                    "configservice",
                    "describe-configuration-recorder-status",
                    "--query",
                    "ConfigurationRecordersStatus[0].[name,recording,lastStatus,lastStatusChangeTime]",
                    "--output",
                    "table",
                ],
                region=region,
            )

    if args.alert_destination == "email" and args.command in ["all", "events"]:
        print(f"Done. Confirm SNS email subscription: {args.email_endpoint}")
    elif args.alert_destination == "slack" and args.command in ["all", "slack"]:
        chatbot_region = args.chatbot_region if args.chatbot_region else args.base_region
        print(
            f"Done. SNS topics are linked to Slack configuration '{args.slack_channel_configuration_name}' in {chatbot_region}."
        )
    else:
        print("Done.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
