#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import tempfile
import zipfile
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


def ensure_event_rule(rule_name: str, region: str) -> str:
    """Create or update the EventBridge rule and return the rule ARN."""
    output = aws_json(
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
    return output["RuleArn"]


def sync_rule_targets(rule_name: str, desired_targets: list[dict[str, Any]], region: str) -> None:
    """Set desired EventBridge rule targets and remove stale target IDs."""
    desired_ids = [target["Id"] for target in desired_targets]
    current_targets = aws_json(["events", "list-targets-by-rule", "--rule", rule_name], region=region)["Targets"]
    remove_ids: list[str] = []
    for target in current_targets:
        target_id = target["Id"]
        if target_id not in desired_ids:
            remove_ids.append(target_id)

    if remove_ids:
        run_aws(["events", "remove-targets", "--rule", rule_name, "--ids", *remove_ids], region=region)

    run_aws(
        [
            "events",
            "put-targets",
            "--rule",
            rule_name,
            "--targets",
            json.dumps(desired_targets),
        ],
        region=region,
    )


def ensure_lambda_invoke_permission(
    function_name: str,
    statement_id: str,
    source_arn: str,
    region: str,
) -> None:
    """Ensure EventBridge can invoke the Lambda function for this rule."""
    policy_proc = run_aws(["lambda", "get-policy", "--function-name", function_name], region=region, check=False)
    if policy_proc.returncode == 0:
        policy_outer = json.loads(policy_proc.stdout)
        policy_doc = json.loads(policy_outer["Policy"])
        for statement in policy_doc["Statement"]:
            if statement["Sid"] == statement_id:
                return

    run_aws(
        [
            "lambda",
            "add-permission",
            "--function-name",
            function_name,
            "--statement-id",
            statement_id,
            "--action",
            "lambda:InvokeFunction",
            "--principal",
            "events.amazonaws.com",
            "--source-arn",
            source_arn,
        ],
        region=region,
    )


def ensure_enricher_role(enricher_role_name: str, account_id: str, topic_name: str, thread_table_name: str) -> str:
    """Create or update Lambda enricher role and return role ARN."""
    role_proc = run_aws(["iam", "get-role", "--role-name", enricher_role_name], check=False)
    if role_proc.returncode != 0:
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        run_aws(
            [
                "iam",
                "create-role",
                "--role-name",
                enricher_role_name,
                "--assume-role-policy-document",
                json.dumps(trust_policy),
            ]
        )

    run_aws(
        [
            "iam",
            "attach-role-policy",
            "--role-name",
            enricher_role_name,
            "--policy-arn",
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        ]
    )

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeInstances",
                    "ec2:DescribeVolumes",
                    "ec2:DescribeSnapshots",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["sns:Publish"],
                "Resource": f"arn:aws:sns:*:{account_id}:{topic_name}",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                ],
                "Resource": f"arn:aws:dynamodb:*:{account_id}:table/{thread_table_name}",
            },
        ],
    }
    run_aws(
        [
            "iam",
            "put-role-policy",
            "--role-name",
            enricher_role_name,
            "--policy-name",
            "EC2EBSAMIAuditEnricherPublishPolicy",
            "--policy-document",
            json.dumps(inline_policy),
        ]
    )
    return aws_text(["iam", "get-role", "--role-name", enricher_role_name, "--query", "Role.Arn"])


def ensure_enricher_thread_table(region: str, thread_table_name: str) -> None:
    """Create or reuse DynamoDB thread-state table for actor-based Slack threading."""
    table_proc = run_aws(["dynamodb", "describe-table", "--table-name", thread_table_name], region=region, check=False)
    if table_proc.returncode != 0:
        run_aws(
            [
                "dynamodb",
                "create-table",
                "--table-name",
                thread_table_name,
                "--attribute-definitions",
                "AttributeName=ActorKey,AttributeType=S",
                "--key-schema",
                "AttributeName=ActorKey,KeyType=HASH",
                "--billing-mode",
                "PAY_PER_REQUEST",
            ],
            region=region,
        )
    run_aws(["dynamodb", "wait", "table-exists", "--table-name", thread_table_name], region=region)


def build_enricher_zip(enricher_source_path: str) -> str:
    """Package Lambda enricher source into a temporary zip and return path."""
    tmp = tempfile.NamedTemporaryFile(prefix="ec2-audit-enricher-", suffix=".zip", delete=False)
    tmp.close()
    with zipfile.ZipFile(tmp.name, "w", compression=zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.write(enricher_source_path, arcname="ec2_audit_enricher_lambda.py")
    return tmp.name


def ensure_enricher_lambda_function(
    region: str,
    function_name: str,
    role_arn: str,
    topic_arn: str,
    thread_table_name: str,
    zip_path: str,
) -> str:
    """Create or update Lambda enricher function and return function ARN."""
    environment = {
        "Variables": {
            "TOPIC_ARN": topic_arn,
            "THREAD_STATE_TABLE": thread_table_name,
        }
    }
    function_proc = run_aws(["lambda", "get-function", "--function-name", function_name], region=region, check=False)
    if function_proc.returncode != 0:
        run_aws(
            [
                "lambda",
                "create-function",
                "--function-name",
                function_name,
                "--runtime",
                "python3.12",
                "--handler",
                "ec2_audit_enricher_lambda.handler",
                "--role",
                role_arn,
                "--timeout",
                "30",
                "--memory-size",
                "256",
                "--environment",
                json.dumps(environment),
                "--zip-file",
                f"fileb://{zip_path}",
            ],
            region=region,
        )
    else:
        run_aws(
            [
                "lambda",
                "update-function-configuration",
                "--function-name",
                function_name,
                "--role",
                role_arn,
                "--runtime",
                "python3.12",
                "--handler",
                "ec2_audit_enricher_lambda.handler",
                "--timeout",
                "30",
                "--memory-size",
                "256",
                "--environment",
                json.dumps(environment),
            ],
            region=region,
        )
        run_aws(["lambda", "wait", "function-updated", "--function-name", function_name], region=region)
        run_aws(
            [
                "lambda",
                "update-function-code",
                "--function-name",
                function_name,
                "--zip-file",
                f"fileb://{zip_path}",
            ],
            region=region,
        )
        run_aws(["lambda", "wait", "function-updated", "--function-name", function_name], region=region)

    run_aws(["lambda", "wait", "function-active", "--function-name", function_name], region=region)
    return aws_text(
        ["lambda", "get-function", "--function-name", function_name, "--query", "Configuration.FunctionArn"],
        region=region,
    )


def setup_eventbridge_and_sns(
    account_id: str,
    regions: list[str],
    topic_name: str,
    rule_name: str,
    alert_destination: str,
    email_endpoint: str,
    enricher_function_name: str,
    enricher_role_name: str,
    enricher_source_path: str,
    enricher_thread_table_name: str,
) -> list[str]:
    """Set up SNS topics and EventBridge rules for EC2/EBS/AMI audit events."""
    topic_arns: list[str] = []
    enricher_zip_path = ""
    enricher_role_arn = ""

    if alert_destination == "slack":
        enricher_zip_path = build_enricher_zip(enricher_source_path)
        enricher_role_arn = ensure_enricher_role(
            enricher_role_name=enricher_role_name,
            account_id=account_id,
            topic_name=topic_name,
            thread_table_name=enricher_thread_table_name,
        )

    for region in regions:
        topic_arn = ensure_sns_topic(topic_name, region)
        topic_arns.append(topic_arn)
        if alert_destination == "email":
            ensure_email_subscription(topic_arn, email_endpoint, region)

        rule_arn = ensure_event_rule(rule_name=rule_name, region=region)

        if alert_destination == "slack":
            ensure_enricher_thread_table(region=region, thread_table_name=enricher_thread_table_name)
            function_arn = ensure_enricher_lambda_function(
                region=region,
                function_name=enricher_function_name,
                role_arn=enricher_role_arn,
                topic_arn=topic_arn,
                thread_table_name=enricher_thread_table_name,
                zip_path=enricher_zip_path,
            )
            sync_rule_targets(
                rule_name=rule_name,
                desired_targets=[{"Id": "enricher1", "Arn": function_arn}],
                region=region,
            )
            ensure_lambda_invoke_permission(
                function_name=enricher_function_name,
                statement_id=f"{rule_name}-InvokePermission",
                source_arn=rule_arn,
                region=region,
            )
        else:
            set_sns_topic_policy_for_eventbridge(account_id, topic_arn, region)
            sync_rule_targets(
                rule_name=rule_name,
                desired_targets=[{"Id": "sns1", "Arn": topic_arn}],
                region=region,
            )

    if enricher_zip_path:
        os.remove(enricher_zip_path)
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
    parser.add_argument("--enricher-function-name", default="ec2-ebs-ami-audit-enricher")
    parser.add_argument("--enricher-role-name", default="EC2EBSAMIAuditEnricherRole")
    parser.add_argument("--enricher-source-path", default="ec2_audit_enricher_lambda.py")
    parser.add_argument("--enricher-thread-table-name", default="ec2-ebs-ami-audit-thread-state")

    parser.add_argument("--config-bucket", default="")
    parser.add_argument("--config-role-name", default="AWSConfigRecorderRole")
    parser.add_argument("--config-recorder-name", default="default")
    parser.add_argument("--config-delivery-channel-name", default="default")

    parser.add_argument("--chatbot-region", default="")
    parser.add_argument("--slack-channel-configuration-name", default="test-configuration")
    parser.add_argument("--slack-team-id", default="")
    parser.add_argument("--slack-channel-id", default="")
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
    if args.command in ["all", "slack"] and args.alert_destination == "slack":
        if not args.slack_team_id or not args.slack_channel_id:
            raise SystemExit("--slack-team-id and --slack-channel-id are required for Slack setup.")


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
        enricher_source_path = args.enricher_source_path
        if not os.path.isabs(enricher_source_path):
            enricher_source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), enricher_source_path)
        topic_arns = setup_eventbridge_and_sns(
            account_id=account_id,
            regions=regions,
            topic_name=args.event_topic_name,
            rule_name=args.rule_name,
            alert_destination=args.alert_destination,
            email_endpoint=args.email_endpoint,
            enricher_function_name=args.enricher_function_name,
            enricher_role_name=args.enricher_role_name,
            enricher_source_path=enricher_source_path,
            enricher_thread_table_name=args.enricher_thread_table_name,
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
