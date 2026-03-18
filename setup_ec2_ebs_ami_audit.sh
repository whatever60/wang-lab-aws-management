#!/usr/bin/env bash
set -euo pipefail

show_help() {
  cat <<USAGE
Usage:
  ./setup_ec2_ebs_ami_audit.sh [options]

Core options:
  --alert-destination <email|slack>                Default: email
  --email-endpoint <email>                         Required for email mode
  --base-region <region>                           Default: us-east-1
  --target-regions <r1,r2,...>                     Default: all enabled regions

CloudTrail options:
  --trail-name <name>                              Default: account-audit-trail
  --trail-bucket <bucket>                          Default: my-<account>-cloudtrail-audit

EventBridge/SNS options:
  --event-topic-name <name>                        Default: asset-audit-events
  --rule-name <name>                               Default: ec2-ebs-ami-audit

AWS Config options:
  --config-bucket <bucket>                         Default: my-<account>-config-history
  --config-role-name <name>                        Default: AWSConfigRecorderRole
  --config-recorder-name <name>                    Default: default
  --config-delivery-channel-name <name>            Default: default

Slack / Amazon Q Developer in chat applications options:
  --chatbot-region <region>                        Default: base region
  --slack-channel-configuration-name <name>        Default: test-configuration
  --slack-team-id <id>                             Default: T09CK3AAC
  --slack-channel-id <id>                          Default: C0AMDBXTDHC
  --slack-channel-name <name>                      Optional
  --chatbot-role-name <name>                       Default: ChatbotSlackRole
  --chatbot-role-arn <arn>                         Optional override; skips role creation
  --chatbot-role-policy-arn <arn>                  Default: arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess
  --chatbot-logging-level <ERROR|INFO|NONE>        Default for new config: ERROR
  --chatbot-guardrail-policy-arns <arn1,arn2,...>  Optional; default for new config: CloudWatchReadOnlyAccess
  --chatbot-user-authorization-required <true|false> Optional; default for new config: false

Examples:
  ./setup_ec2_ebs_ami_audit.sh \
    --alert-destination email \
    --email-endpoint you@example.com

  ./setup_ec2_ebs_ami_audit.sh \
    --alert-destination slack \
    --slack-channel-configuration-name test-configuration \
    --slack-team-id T09CK3AAC \
    --slack-channel-id C0AMDBXTDHC \
    --target-regions us-east-1,us-east-2,us-west-2
USAGE
}

BASE_REGION="${BASE_REGION:-us-east-1}"
TARGET_REGIONS="${TARGET_REGIONS:-}"
TRAIL_NAME="${TRAIL_NAME:-account-audit-trail}"
TRAIL_BUCKET="${TRAIL_BUCKET:-}"
CONFIG_BUCKET="${CONFIG_BUCKET:-}"
EVENT_TOPIC_NAME="${EVENT_TOPIC_NAME:-asset-audit-events}"
RULE_NAME="${RULE_NAME:-ec2-ebs-ami-audit}"
CONFIG_ROLE_NAME="${CONFIG_ROLE_NAME:-AWSConfigRecorderRole}"
CONFIG_RECORDER_NAME="${CONFIG_RECORDER_NAME:-default}"
CONFIG_DELIVERY_CHANNEL_NAME="${CONFIG_DELIVERY_CHANNEL_NAME:-default}"

ALERT_DESTINATION="${ALERT_DESTINATION:-email}"
EMAIL_ENDPOINT="${EMAIL_ENDPOINT:-}"

SLACK_CHANNEL_CONFIGURATION_NAME="${SLACK_CHANNEL_CONFIGURATION_NAME:-test-configuration}"
SLACK_TEAM_ID="${SLACK_TEAM_ID:-T09CK3AAC}"
SLACK_CHANNEL_ID="${SLACK_CHANNEL_ID:-C0AMDBXTDHC}"
SLACK_CHANNEL_NAME="${SLACK_CHANNEL_NAME:-}"
CHATBOT_REGION="${CHATBOT_REGION:-${BASE_REGION}}"
CHATBOT_ROLE_NAME="${CHATBOT_ROLE_NAME:-ChatbotSlackRole}"
CHATBOT_ROLE_ARN="${CHATBOT_ROLE_ARN:-}"
CHATBOT_ROLE_POLICY_ARN="${CHATBOT_ROLE_POLICY_ARN:-arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess}"
CHATBOT_LOGGING_LEVEL="${CHATBOT_LOGGING_LEVEL:-}"
CHATBOT_GUARDRAIL_POLICY_ARNS="${CHATBOT_GUARDRAIL_POLICY_ARNS:-}"
CHATBOT_USER_AUTHORIZATION_REQUIRED="${CHATBOT_USER_AUTHORIZATION_REQUIRED:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help
      exit 0
      ;;
    --alert-destination)
      ALERT_DESTINATION="$2"
      shift 2
      ;;
    --email-endpoint)
      EMAIL_ENDPOINT="$2"
      shift 2
      ;;
    --base-region)
      BASE_REGION="$2"
      shift 2
      ;;
    --target-regions)
      TARGET_REGIONS="$2"
      shift 2
      ;;
    --trail-name)
      TRAIL_NAME="$2"
      shift 2
      ;;
    --trail-bucket)
      TRAIL_BUCKET="$2"
      shift 2
      ;;
    --config-bucket)
      CONFIG_BUCKET="$2"
      shift 2
      ;;
    --event-topic-name)
      EVENT_TOPIC_NAME="$2"
      shift 2
      ;;
    --rule-name)
      RULE_NAME="$2"
      shift 2
      ;;
    --config-role-name)
      CONFIG_ROLE_NAME="$2"
      shift 2
      ;;
    --config-recorder-name)
      CONFIG_RECORDER_NAME="$2"
      shift 2
      ;;
    --config-delivery-channel-name)
      CONFIG_DELIVERY_CHANNEL_NAME="$2"
      shift 2
      ;;
    --chatbot-region)
      CHATBOT_REGION="$2"
      shift 2
      ;;
    --slack-channel-configuration-name)
      SLACK_CHANNEL_CONFIGURATION_NAME="$2"
      shift 2
      ;;
    --slack-team-id)
      SLACK_TEAM_ID="$2"
      shift 2
      ;;
    --slack-channel-id)
      SLACK_CHANNEL_ID="$2"
      shift 2
      ;;
    --slack-channel-name)
      SLACK_CHANNEL_NAME="$2"
      shift 2
      ;;
    --chatbot-role-name)
      CHATBOT_ROLE_NAME="$2"
      shift 2
      ;;
    --chatbot-role-arn)
      CHATBOT_ROLE_ARN="$2"
      shift 2
      ;;
    --chatbot-role-policy-arn)
      CHATBOT_ROLE_POLICY_ARN="$2"
      shift 2
      ;;
    --chatbot-logging-level)
      CHATBOT_LOGGING_LEVEL="$2"
      shift 2
      ;;
    --chatbot-guardrail-policy-arns)
      CHATBOT_GUARDRAIL_POLICY_ARNS="$2"
      shift 2
      ;;
    --chatbot-user-authorization-required)
      CHATBOT_USER_AUTHORIZATION_REQUIRED="$2"
      shift 2
      ;;
    *)
      echo "ERROR: Unknown argument: $1" >&2
      show_help >&2
      exit 1
      ;;
  esac
done

TARGET_REGIONS="${TARGET_REGIONS//,/ }"
CHATBOT_GUARDRAIL_POLICY_ARNS="${CHATBOT_GUARDRAIL_POLICY_ARNS//,/ }"

if [[ "${ALERT_DESTINATION}" != "email" && "${ALERT_DESTINATION}" != "slack" ]]; then
  echo "ERROR: --alert-destination must be 'email' or 'slack'." >&2
  exit 1
fi

if [[ "${ALERT_DESTINATION}" == "email" && -z "${EMAIL_ENDPOINT}" ]]; then
  echo "ERROR: --email-endpoint is required when --alert-destination=email." >&2
  exit 1
fi

if [[ -n "${CHATBOT_LOGGING_LEVEL}" && "${CHATBOT_LOGGING_LEVEL}" != "ERROR" && "${CHATBOT_LOGGING_LEVEL}" != "INFO" && "${CHATBOT_LOGGING_LEVEL}" != "NONE" ]]; then
  echo "ERROR: --chatbot-logging-level must be ERROR, INFO, or NONE." >&2
  exit 1
fi

if [[ -n "${CHATBOT_USER_AUTHORIZATION_REQUIRED}" && "${CHATBOT_USER_AUTHORIZATION_REQUIRED}" != "true" && "${CHATBOT_USER_AUTHORIZATION_REQUIRED}" != "false" ]]; then
  echo "ERROR: --chatbot-user-authorization-required must be true or false." >&2
  exit 1
fi

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"

if [[ -z "${TRAIL_BUCKET}" ]]; then
  TRAIL_BUCKET="my-${ACCOUNT_ID}-cloudtrail-audit"
fi

if [[ -z "${CONFIG_BUCKET}" ]]; then
  CONFIG_BUCKET="my-${ACCOUNT_ID}-config-history"
fi

if [[ -z "${TARGET_REGIONS}" ]]; then
  TARGET_REGIONS="$(aws ec2 describe-regions --all-regions --query "Regions[?OptInStatus=='opt-in-not-required'||OptInStatus=='opted-in'].RegionName" --output text)"
fi

echo "Account: ${ACCOUNT_ID}"
echo "Base region: ${BASE_REGION}"
echo "Target regions: ${TARGET_REGIONS}"
echo "Trail bucket: ${TRAIL_BUCKET}"
echo "Config bucket: ${CONFIG_BUCKET}"
echo "Alert destination: ${ALERT_DESTINATION}"
if [[ "${ALERT_DESTINATION}" == "email" ]]; then
  echo "Email endpoint: ${EMAIL_ENDPOINT}"
fi
if [[ "${ALERT_DESTINATION}" == "slack" ]]; then
  echo "Slack config name: ${SLACK_CHANNEL_CONFIGURATION_NAME}"
  echo "Slack team/channel: ${SLACK_TEAM_ID}/${SLACK_CHANNEL_ID}"
  echo "Chatbot region: ${CHATBOT_REGION}"
fi

SLACK_CHAT_CONFIGURATION_ARN=""
SLACK_IAM_ROLE_ARN=""
SLACK_LOGGING_LEVEL_EFFECTIVE=""
SLACK_USER_AUTH_REQUIRED_EFFECTIVE=""
SLACK_GUARDRAIL_POLICY_ARNS_EFFECTIVE=""
SLACK_SNS_TOPIC_ARNS_RAW=""

if [[ "${ALERT_DESTINATION}" == "slack" ]]; then
  if ! aws help 2>&1 | grep -qE '(^|[[:space:]])chatbot([[:space:]]|$)'; then
    echo "ERROR: This AWS CLI does not include the chatbot command." >&2
    echo "Install AWS CLI v2 (or CLI v1 that includes chatbot commands)." >&2
    exit 1
  fi

  if [[ -z "${CHATBOT_ROLE_ARN}" ]]; then
    if aws iam get-role --role-name "${CHATBOT_ROLE_NAME}" >/dev/null 2>&1; then
      echo "Chatbot IAM role exists: ${CHATBOT_ROLE_NAME}"
    else
      cat > /tmp/q-chat-trust-policy.json <<'TRUST'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "q.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
TRUST

      aws iam create-role \
        --role-name "${CHATBOT_ROLE_NAME}" \
        --assume-role-policy-document file:///tmp/q-chat-trust-policy.json
    fi

    if [[ -n "${CHATBOT_ROLE_POLICY_ARN}" ]]; then
      aws iam attach-role-policy \
        --role-name "${CHATBOT_ROLE_NAME}" \
        --policy-arn "${CHATBOT_ROLE_POLICY_ARN}"
    fi

    CHATBOT_ROLE_ARN="$(aws iam get-role --role-name "${CHATBOT_ROLE_NAME}" --query 'Role.Arn' --output text)"
  fi

  SLACK_CHAT_CONFIGURATION_ARN="$(aws chatbot describe-slack-channel-configurations \
    --region "${CHATBOT_REGION}" \
    --query "SlackChannelConfigurations[?ConfigurationName=='${SLACK_CHANNEL_CONFIGURATION_NAME}'].ChatConfigurationArn | [0]" \
    --output text)"

  if [[ "${SLACK_CHAT_CONFIGURATION_ARN}" != "None" && -n "${SLACK_CHAT_CONFIGURATION_ARN}" ]]; then
    SLACK_CHANNEL_ID="$(aws chatbot describe-slack-channel-configurations \
      --region "${CHATBOT_REGION}" \
      --query "SlackChannelConfigurations[?ConfigurationName=='${SLACK_CHANNEL_CONFIGURATION_NAME}'].SlackChannelId | [0]" \
      --output text)"
    SLACK_CHANNEL_NAME="$(aws chatbot describe-slack-channel-configurations \
      --region "${CHATBOT_REGION}" \
      --query "SlackChannelConfigurations[?ConfigurationName=='${SLACK_CHANNEL_CONFIGURATION_NAME}'].SlackChannelName | [0]" \
      --output text)"
    SLACK_IAM_ROLE_ARN="$(aws chatbot describe-slack-channel-configurations \
      --region "${CHATBOT_REGION}" \
      --query "SlackChannelConfigurations[?ConfigurationName=='${SLACK_CHANNEL_CONFIGURATION_NAME}'].IamRoleArn | [0]" \
      --output text)"
    SLACK_LOGGING_LEVEL_EFFECTIVE="$(aws chatbot describe-slack-channel-configurations \
      --region "${CHATBOT_REGION}" \
      --query "SlackChannelConfigurations[?ConfigurationName=='${SLACK_CHANNEL_CONFIGURATION_NAME}'].LoggingLevel | [0]" \
      --output text)"
    SLACK_USER_AUTH_REQUIRED_EFFECTIVE="$(aws chatbot describe-slack-channel-configurations \
      --region "${CHATBOT_REGION}" \
      --query "SlackChannelConfigurations[?ConfigurationName=='${SLACK_CHANNEL_CONFIGURATION_NAME}'].UserAuthorizationRequired | [0]" \
      --output text)"
    SLACK_GUARDRAIL_POLICY_ARNS_EFFECTIVE="$(aws chatbot describe-slack-channel-configurations \
      --region "${CHATBOT_REGION}" \
      --query "SlackChannelConfigurations[?ConfigurationName=='${SLACK_CHANNEL_CONFIGURATION_NAME}'].GuardrailPolicyArns[] | []" \
      --output text)"
    SLACK_SNS_TOPIC_ARNS_RAW="$(aws chatbot describe-slack-channel-configurations \
      --region "${CHATBOT_REGION}" \
      --query "SlackChannelConfigurations[?ConfigurationName=='${SLACK_CHANNEL_CONFIGURATION_NAME}'].SnsTopicArns[] | []" \
      --output text)"

    if [[ -n "${CHATBOT_ROLE_ARN}" ]]; then
      SLACK_IAM_ROLE_ARN="${CHATBOT_ROLE_ARN}"
    fi
    if [[ -n "${CHATBOT_LOGGING_LEVEL}" ]]; then
      SLACK_LOGGING_LEVEL_EFFECTIVE="${CHATBOT_LOGGING_LEVEL}"
    fi
    if [[ -n "${CHATBOT_USER_AUTHORIZATION_REQUIRED}" ]]; then
      SLACK_USER_AUTH_REQUIRED_EFFECTIVE="${CHATBOT_USER_AUTHORIZATION_REQUIRED}"
    fi
    if [[ -n "${CHATBOT_GUARDRAIL_POLICY_ARNS}" ]]; then
      SLACK_GUARDRAIL_POLICY_ARNS_EFFECTIVE="${CHATBOT_GUARDRAIL_POLICY_ARNS}"
    fi
  else
    SLACK_CHAT_CONFIGURATION_ARN=""
    SLACK_IAM_ROLE_ARN="${CHATBOT_ROLE_ARN}"
    if [[ -n "${CHATBOT_LOGGING_LEVEL}" ]]; then
      SLACK_LOGGING_LEVEL_EFFECTIVE="${CHATBOT_LOGGING_LEVEL}"
    else
      SLACK_LOGGING_LEVEL_EFFECTIVE="ERROR"
    fi
    if [[ -n "${CHATBOT_USER_AUTHORIZATION_REQUIRED}" ]]; then
      SLACK_USER_AUTH_REQUIRED_EFFECTIVE="${CHATBOT_USER_AUTHORIZATION_REQUIRED}"
    else
      SLACK_USER_AUTH_REQUIRED_EFFECTIVE="false"
    fi
    if [[ -n "${CHATBOT_GUARDRAIL_POLICY_ARNS}" ]]; then
      SLACK_GUARDRAIL_POLICY_ARNS_EFFECTIVE="${CHATBOT_GUARDRAIL_POLICY_ARNS}"
    else
      SLACK_GUARDRAIL_POLICY_ARNS_EFFECTIVE="arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
    fi
  fi
fi

# Create CloudTrail bucket (idempotent)
if aws s3api head-bucket --bucket "${TRAIL_BUCKET}" >/dev/null 2>&1; then
  echo "CloudTrail bucket exists: ${TRAIL_BUCKET}"
else
  if [[ "${BASE_REGION}" == "us-east-1" ]]; then
    aws s3api create-bucket --bucket "${TRAIL_BUCKET}" --region "${BASE_REGION}"
  else
    aws s3api create-bucket \
      --bucket "${TRAIL_BUCKET}" \
      --region "${BASE_REGION}" \
      --create-bucket-configuration "LocationConstraint=${BASE_REGION}"
  fi
fi

cat > /tmp/cloudtrail-bucket-policy.json <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::${TRAIL_BUCKET}",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudtrail:*:${ACCOUNT_ID}:trail/${TRAIL_NAME}"
        }
      }
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${TRAIL_BUCKET}/AWSLogs/${ACCOUNT_ID}/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control",
          "AWS:SourceArn": "arn:aws:cloudtrail:*:${ACCOUNT_ID}:trail/${TRAIL_NAME}"
        }
      }
    }
  ]
}
POLICY

aws s3api put-bucket-policy --bucket "${TRAIL_BUCKET}" --policy file:///tmp/cloudtrail-bucket-policy.json

EXISTING_TRAIL_NAME="$(aws cloudtrail describe-trails --trail-name-list "${TRAIL_NAME}" --region "${BASE_REGION}" --query 'trailList[0].Name' --output text 2>/dev/null || true)"
if [[ "${EXISTING_TRAIL_NAME}" == "${TRAIL_NAME}" ]]; then
  aws cloudtrail update-trail \
    --name "${TRAIL_NAME}" \
    --s3-bucket-name "${TRAIL_BUCKET}" \
    --is-multi-region-trail \
    --enable-log-file-validation \
    --region "${BASE_REGION}"
else
  aws cloudtrail create-trail \
    --name "${TRAIL_NAME}" \
    --s3-bucket-name "${TRAIL_BUCKET}" \
    --is-multi-region-trail \
    --enable-log-file-validation \
    --region "${BASE_REGION}"
fi

aws cloudtrail start-logging --name "${TRAIL_NAME}" --region "${BASE_REGION}"

cat > /tmp/ec2-ebs-ami-audit-pattern.json <<'PATTERN'
{
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
      "CreateImage",
      "RegisterImage",
      "CopyImage",
      "DeregisterImage",
      "ModifyImageAttribute"
    ]
  }
}
PATTERN

for REGION in ${TARGET_REGIONS}; do
  echo "Setting up EventBridge + SNS in ${REGION}"

  EVENT_TOPIC_ARN="$(aws sns create-topic --name "${EVENT_TOPIC_NAME}" --query TopicArn --output text --region "${REGION}")"

  if [[ "${ALERT_DESTINATION}" == "email" ]]; then
    SUB_ARN="$(aws sns list-subscriptions-by-topic --topic-arn "${EVENT_TOPIC_ARN}" --region "${REGION}" --query "Subscriptions[?Protocol=='email' && Endpoint=='${EMAIL_ENDPOINT}'].SubscriptionArn | [0]" --output text)"
    if [[ "${SUB_ARN}" == "None" ]]; then
      aws sns subscribe \
        --topic-arn "${EVENT_TOPIC_ARN}" \
        --protocol email \
        --notification-endpoint "${EMAIL_ENDPOINT}" \
        --region "${REGION}"
    fi
  fi

  if [[ "${ALERT_DESTINATION}" == "slack" ]]; then
    if [[ -z "${SLACK_CHAT_CONFIGURATION_ARN}" ]]; then
      SLACK_CREATE_ARGS=( \
        --configuration-name "${SLACK_CHANNEL_CONFIGURATION_NAME}" \
        --slack-team-id "${SLACK_TEAM_ID}" \
        --slack-channel-id "${SLACK_CHANNEL_ID}" \
        --iam-role-arn "${SLACK_IAM_ROLE_ARN}" \
        --sns-topic-arns "${EVENT_TOPIC_ARN}" \
      )

      if [[ -n "${SLACK_CHANNEL_NAME}" && "${SLACK_CHANNEL_NAME}" != "None" ]]; then
        SLACK_CREATE_ARGS+=( --slack-channel-name "${SLACK_CHANNEL_NAME}" )
      fi
      if [[ -n "${SLACK_LOGGING_LEVEL_EFFECTIVE}" && "${SLACK_LOGGING_LEVEL_EFFECTIVE}" != "None" ]]; then
        SLACK_CREATE_ARGS+=( --logging-level "${SLACK_LOGGING_LEVEL_EFFECTIVE}" )
      fi
      if [[ -n "${SLACK_GUARDRAIL_POLICY_ARNS_EFFECTIVE}" ]]; then
        SLACK_CREATE_ARGS+=( --guardrail-policy-arns )
        for GUARDRAIL_POLICY_ARN in ${SLACK_GUARDRAIL_POLICY_ARNS_EFFECTIVE}; do
          SLACK_CREATE_ARGS+=( "${GUARDRAIL_POLICY_ARN}" )
        done
      fi

      if [[ "${SLACK_USER_AUTH_REQUIRED_EFFECTIVE}" == "true" || "${SLACK_USER_AUTH_REQUIRED_EFFECTIVE}" == "True" ]]; then
        SLACK_CREATE_ARGS+=( --user-authorization-required )
      else
        SLACK_CREATE_ARGS+=( --no-user-authorization-required )
      fi

      aws chatbot create-slack-channel-configuration \
        "${SLACK_CREATE_ARGS[@]}" \
        --region "${CHATBOT_REGION}"

      SLACK_CHAT_CONFIGURATION_ARN="$(aws chatbot describe-slack-channel-configurations \
        --region "${CHATBOT_REGION}" \
        --query "SlackChannelConfigurations[?ConfigurationName=='${SLACK_CHANNEL_CONFIGURATION_NAME}'].ChatConfigurationArn | [0]" \
        --output text)"
      SLACK_SNS_TOPIC_ARNS_RAW="$(aws chatbot describe-slack-channel-configurations \
        --region "${CHATBOT_REGION}" \
        --query "SlackChannelConfigurations[?ConfigurationName=='${SLACK_CHANNEL_CONFIGURATION_NAME}'].SnsTopicArns[] | []" \
        --output text)"
    else
      SLACK_TOPIC_ALREADY_ATTACHED="false"
      for SNS_TOPIC_ARN in ${SLACK_SNS_TOPIC_ARNS_RAW}; do
        if [[ "${SNS_TOPIC_ARN}" == "${EVENT_TOPIC_ARN}" ]]; then
          SLACK_TOPIC_ALREADY_ATTACHED="true"
        fi
      done

      if [[ "${SLACK_TOPIC_ALREADY_ATTACHED}" == "false" ]]; then
        if [[ -z "${SLACK_SNS_TOPIC_ARNS_RAW}" ]]; then
          SLACK_SNS_TOPIC_ARNS_RAW="${EVENT_TOPIC_ARN}"
        else
          SLACK_SNS_TOPIC_ARNS_RAW="${SLACK_SNS_TOPIC_ARNS_RAW} ${EVENT_TOPIC_ARN}"
        fi

        SLACK_UPDATE_ARGS=( \
          --chat-configuration-arn "${SLACK_CHAT_CONFIGURATION_ARN}" \
          --slack-channel-id "${SLACK_CHANNEL_ID}" \
          --iam-role-arn "${SLACK_IAM_ROLE_ARN}" \
          --sns-topic-arns \
        )

        for SNS_TOPIC_ARN in ${SLACK_SNS_TOPIC_ARNS_RAW}; do
          SLACK_UPDATE_ARGS+=( "${SNS_TOPIC_ARN}" )
        done

        if [[ "${SLACK_CHANNEL_NAME}" != "None" && -n "${SLACK_CHANNEL_NAME}" ]]; then
          SLACK_UPDATE_ARGS+=( --slack-channel-name "${SLACK_CHANNEL_NAME}" )
        fi
        if [[ "${SLACK_LOGGING_LEVEL_EFFECTIVE}" != "None" && -n "${SLACK_LOGGING_LEVEL_EFFECTIVE}" ]]; then
          SLACK_UPDATE_ARGS+=( --logging-level "${SLACK_LOGGING_LEVEL_EFFECTIVE}" )
        fi
        if [[ -n "${SLACK_GUARDRAIL_POLICY_ARNS_EFFECTIVE}" ]]; then
          SLACK_UPDATE_ARGS+=( --guardrail-policy-arns )
          for GUARDRAIL_POLICY_ARN in ${SLACK_GUARDRAIL_POLICY_ARNS_EFFECTIVE}; do
            SLACK_UPDATE_ARGS+=( "${GUARDRAIL_POLICY_ARN}" )
          done
        fi
        if [[ "${SLACK_USER_AUTH_REQUIRED_EFFECTIVE}" == "True" || "${SLACK_USER_AUTH_REQUIRED_EFFECTIVE}" == "true" ]]; then
          SLACK_UPDATE_ARGS+=( --user-authorization-required )
        else
          SLACK_UPDATE_ARGS+=( --no-user-authorization-required )
        fi

        aws chatbot update-slack-channel-configuration \
          "${SLACK_UPDATE_ARGS[@]}" \
          --region "${CHATBOT_REGION}"
      fi
    fi
  fi

  cat > /tmp/sns-topic-policy-${REGION}.json <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOwnerFullControl",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::${ACCOUNT_ID}:root"},
      "Action": "SNS:*",
      "Resource": "${EVENT_TOPIC_ARN}"
    },
    {
      "Sid": "AllowEventBridgePublish",
      "Effect": "Allow",
      "Principal": {"Service": "events.amazonaws.com"},
      "Action": "sns:Publish",
      "Resource": "${EVENT_TOPIC_ARN}",
      "Condition": {
        "StringEquals": {
          "AWS:SourceAccount": "${ACCOUNT_ID}"
        }
      }
    }
  ]
}
POLICY

  aws sns set-topic-attributes \
    --topic-arn "${EVENT_TOPIC_ARN}" \
    --attribute-name Policy \
    --attribute-value file:///tmp/sns-topic-policy-${REGION}.json \
    --region "${REGION}"

  aws events put-rule \
    --name "${RULE_NAME}" \
    --event-pattern file:///tmp/ec2-ebs-ami-audit-pattern.json \
    --state ENABLED \
    --region "${REGION}"

  aws events put-targets \
    --rule "${RULE_NAME}" \
    --targets "Id"="sns1","Arn"="${EVENT_TOPIC_ARN}" \
    --region "${REGION}"
done

# Create Config bucket (idempotent)
if aws s3api head-bucket --bucket "${CONFIG_BUCKET}" >/dev/null 2>&1; then
  echo "Config bucket exists: ${CONFIG_BUCKET}"
else
  if [[ "${BASE_REGION}" == "us-east-1" ]]; then
    aws s3api create-bucket --bucket "${CONFIG_BUCKET}" --region "${BASE_REGION}"
  else
    aws s3api create-bucket \
      --bucket "${CONFIG_BUCKET}" \
      --region "${BASE_REGION}" \
      --create-bucket-configuration "LocationConstraint=${BASE_REGION}"
  fi
fi

cat > /tmp/config-bucket-policy.json <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSConfigBucketPermissionsCheck",
      "Effect": "Allow",
      "Principal": {"Service": "config.amazonaws.com"},
      "Action": ["s3:GetBucketAcl", "s3:ListBucket"],
      "Resource": "arn:aws:s3:::${CONFIG_BUCKET}",
      "Condition": {
        "StringEquals": {
          "AWS:SourceAccount": "${ACCOUNT_ID}"
        }
      }
    },
    {
      "Sid": "AWSConfigBucketDelivery",
      "Effect": "Allow",
      "Principal": {"Service": "config.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${CONFIG_BUCKET}/AWSLogs/${ACCOUNT_ID}/Config/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control",
          "AWS:SourceAccount": "${ACCOUNT_ID}"
        }
      }
    }
  ]
}
POLICY

aws s3api put-bucket-policy --bucket "${CONFIG_BUCKET}" --policy file:///tmp/config-bucket-policy.json

if aws iam get-role --role-name "${CONFIG_ROLE_NAME}" >/dev/null 2>&1; then
  echo "Config IAM role exists: ${CONFIG_ROLE_NAME}"
else
  cat > /tmp/aws-config-trust-policy.json <<'TRUST'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "config.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}
TRUST

  aws iam create-role \
    --role-name "${CONFIG_ROLE_NAME}" \
    --assume-role-policy-document file:///tmp/aws-config-trust-policy.json
fi

aws iam attach-role-policy \
  --role-name "${CONFIG_ROLE_NAME}" \
  --policy-arn "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"

CONFIG_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${CONFIG_ROLE_NAME}"

for REGION in ${TARGET_REGIONS}; do
  echo "Setting up AWS Config in ${REGION}"

  cat > /tmp/config-recorder-${REGION}.json <<RECORDER
{
  "name": "${CONFIG_RECORDER_NAME}",
  "roleARN": "${CONFIG_ROLE_ARN}",
  "recordingGroup": {
    "allSupported": false,
    "includeGlobalResourceTypes": false,
    "resourceTypes": [
      "AWS::EC2::Instance",
      "AWS::EC2::Volume"
    ]
  },
  "recordingMode": {
    "recordingFrequency": "CONTINUOUS"
  }
}
RECORDER

  aws configservice put-configuration-recorder \
    --configuration-recorder file:///tmp/config-recorder-${REGION}.json \
    --region "${REGION}"

  cat > /tmp/config-delivery-channel-${REGION}.json <<CHANNEL
{
  "name": "${CONFIG_DELIVERY_CHANNEL_NAME}",
  "s3BucketName": "${CONFIG_BUCKET}",
  "configSnapshotDeliveryProperties": {
    "deliveryFrequency": "TwentyFour_Hours"
  }
}
CHANNEL

  aws configservice put-delivery-channel \
    --delivery-channel file:///tmp/config-delivery-channel-${REGION}.json \
    --region "${REGION}"

  aws configservice start-configuration-recorder \
    --configuration-recorder-name "${CONFIG_RECORDER_NAME}" \
    --region "${REGION}"
done

echo ""
echo "CloudTrail status (${BASE_REGION}):"
aws cloudtrail get-trail-status --name "${TRAIL_NAME}" --region "${BASE_REGION}"

echo ""
echo "AWS Config recorder status by region:"
for REGION in ${TARGET_REGIONS}; do
  echo "--- ${REGION} ---"
  aws configservice describe-configuration-recorder-status \
    --region "${REGION}" \
    --query 'ConfigurationRecordersStatus[0].[name,recording,lastStatus,lastStatusChangeTime]' \
    --output table
done

echo ""
if [[ "${ALERT_DESTINATION}" == "email" ]]; then
  echo "Done. Confirm the SNS email subscription from ${EMAIL_ENDPOINT} to start receiving alerts."
fi
if [[ "${ALERT_DESTINATION}" == "slack" ]]; then
  echo "Done. SNS topics are linked to Slack channel configuration '${SLACK_CHANNEL_CONFIGURATION_NAME}' in ${CHATBOT_REGION}."
fi
