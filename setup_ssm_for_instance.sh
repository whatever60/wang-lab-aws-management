#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./setup_ssm_for_instance.sh <instance-id> <region> [role-name] [instance-profile-name]

Example:
  ./setup_ssm_for_instance.sh i-0123456789abcdef0 us-east-1 SSMRoleForManagedInstance SSMInstanceProfile

Notes:
  - Creates the IAM role/profile if they do not exist
  - Attaches AmazonSSMManagedInstanceCore to the role
  - Associates or replaces the instance profile on the instance
  - Waits for the instance to appear in SSM
EOF
}

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

main() {
  require_cmd aws

  if [[ $# -lt 2 || $# -gt 4 ]]; then
    usage
    exit 1
  fi

  local instance_id="$1"
  local region="$2"
  local role_name="${3:-SSMRoleForManagedInstance}"
  local instance_profile_name="${4:-SSMInstanceProfile}"
  local managed_policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  local wait_seconds=600

  local aws_cli=(aws --region "$region")

  log "Checking instance exists"
  "${aws_cli[@]}" ec2 describe-instances \
    --instance-ids "$instance_id" \
    --query 'Reservations[0].Instances[0].InstanceId' \
    --output text >/dev/null

  log "Ensuring IAM role exists: $role_name"
  if ! aws iam get-role --role-name "$role_name" >/dev/null 2>&1; then
    cat >/tmp/ssm-trust-policy.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "ec2.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

    aws iam create-role \
      --role-name "$role_name" \
      --assume-role-policy-document file:///tmp/ssm-trust-policy.json >/dev/null

    log "Created role: $role_name"
  fi

  log "Attaching AmazonSSMManagedInstanceCore to role"
  aws iam attach-role-policy \
    --role-name "$role_name" \
    --policy-arn "$managed_policy_arn" >/dev/null || true

  log "Ensuring instance profile exists: $instance_profile_name"
  if ! aws iam get-instance-profile --instance-profile-name "$instance_profile_name" >/dev/null 2>&1; then
    aws iam create-instance-profile \
      --instance-profile-name "$instance_profile_name" >/dev/null
    log "Created instance profile: $instance_profile_name"
    sleep 10
  fi

  log "Ensuring role is in instance profile"
  if ! aws iam get-instance-profile \
    --instance-profile-name "$instance_profile_name" \
    --query "InstanceProfile.Roles[?RoleName=='${role_name}'] | length(@)" \
    --output text | grep -q '^1$'; then
    aws iam add-role-to-instance-profile \
      --instance-profile-name "$instance_profile_name" \
      --role-name "$role_name" >/dev/null
    log "Added role to instance profile"
    sleep 10
  fi

  log "Checking current instance profile association"
  local association_id
  association_id="$("${aws_cli[@]}" ec2 describe-iam-instance-profile-associations \
    --filters "Name=instance-id,Values=${instance_id}" \
    --query 'IamInstanceProfileAssociations[0].AssociationId' \
    --output text)"

  if [[ -z "$association_id" || "$association_id" == "None" ]]; then
    log "Associating instance profile with instance"
    "${aws_cli[@]}" ec2 associate-iam-instance-profile \
      --instance-id "$instance_id" \
      --iam-instance-profile "Name=${instance_profile_name}" >/dev/null
  else
    log "Replacing existing instance profile association"
    "${aws_cli[@]}" ec2 replace-iam-instance-profile-association \
      --association-id "$association_id" \
      --iam-instance-profile "Name=${instance_profile_name}" >/dev/null
  fi

  log "Waiting for instance to register with SSM"
  local deadline
  deadline=$(( $(date +%s) + wait_seconds ))

  while (( $(date +%s) < deadline )); do
    local count
    count="$("${aws_cli[@]}" ssm describe-instance-information \
      --query "length(InstanceInformationList[?InstanceId=='${instance_id}'])" \
      --output text 2>/dev/null || echo 0)"

    if [[ "$count" != "0" ]]; then
      log "Success: instance is now managed by SSM"
      "${aws_cli[@]}" ssm describe-instance-information \
        --query "InstanceInformationList[?InstanceId=='${instance_id}'].[InstanceId,PingStatus,PlatformType,AgentVersion]" \
        --output table
      exit 0
    fi

    sleep 15
  done

  echo
  echo "The IAM/profile setup is complete, but the instance did not appear in SSM within ${wait_seconds}s."
  echo "Most likely causes:"
  echo "  1) SSM Agent is not installed or not running"
  echo "  2) The instance cannot reach SSM endpoints over HTTPS"
  echo "  3) IAM credential refresh has not completed yet"
  echo
  echo "Next checks on the instance:"
  echo "  sudo systemctl status amazon-ssm-agent"
  echo
  echo "Network must allow outbound HTTPS to:"
  echo "  ssm.${region}.amazonaws.com"
  echo "  ssmmessages.${region}.amazonaws.com"
  echo "  ec2messages.${region}.amazonaws.com"
  exit 2
}

main "$@"