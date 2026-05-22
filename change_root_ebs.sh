#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF_USAGE'
Usage:
  ./change_root_ebs.sh <instance_id> <region> <target_gib>

Examples:
  ./change_root_ebs.sh i-0123456789abcdef0 us-east-1 4096

Optional environment variables:
  CREATE_SNAPSHOT=true|false    default: false
  KEEP_SNAPSHOT=true|false      default: false

What it does:
  1) finds the root EBS volume for the instance
  2) validates target_gib is larger than current size
  3) checks that the volume is not already modifying/optimizing
  4) optionally creates an extra safety snapshot
  5) runs AWS-ExtendEbsVolume through SSM automation
EOF_USAGE
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

wait_for_automation() {
  local automation_id="$1"
  local region="$2"

  while true; do
    local status
    status="$(
      aws ssm get-automation-execution \
        --region "$region" \
        --automation-execution-id "$automation_id" \
        --query 'AutomationExecution.AutomationExecutionStatus' \
        --output text
  )"

    log "Automation status: $status"

    case "$status" in
      Success)
        return 0
        ;;
      Failed|Cancelled|TimedOut|Cancelling)
        echo "SSM Automation failed with status: $status" >&2
        aws ssm get-automation-execution \
          --region "$region" \
          --automation-execution-id "$automation_id" \
          --output json
        exit 1
        ;;
    esac

    sleep 15
  done
}

main() {
  require_cmd aws

  if [[ $# -ne 3 ]]; then
    usage
    exit 1
  fi

  local instance_id="$1"
  local region="$2"
  local target_gib="$3"

  local create_snapshot="${CREATE_SNAPSHOT:-false}"
  local keep_snapshot="${KEEP_SNAPSHOT:-false}"

  if ! [[ "$target_gib" =~ ^[0-9]+$ ]] || (( target_gib <= 0 )); then
    echo "target_gib must be a positive integer." >&2
    exit 1
  fi

  log "Resolving root device and root EBS volume"

  local root_device
  root_device="$(
    aws ec2 describe-instances \
      --region "$region" \
      --instance-ids "$instance_id" \
      --query 'Reservations[0].Instances[0].RootDeviceName' \
      --output text
  )"

  local volume_id
  volume_id="$(
    aws ec2 describe-instances \
      --region "$region" \
      --instance-ids "$instance_id" \
      --query "Reservations[0].Instances[0].BlockDeviceMappings[?DeviceName=='${root_device}'].Ebs.VolumeId | [0]" \
      --output text
  )"

  local current_size volume_type
  current_size="$(
    aws ec2 describe-volumes \
      --region "$region" \
      --volume-ids "$volume_id" \
      --query 'Volumes[0].Size' \
      --output text
  )"

  volume_type="$(
    aws ec2 describe-volumes \
      --region "$region" \
      --volume-ids "$volume_id" \
      --query 'Volumes[0].VolumeType' \
      --output text
  )"

  if (( target_gib <= current_size )); then
    echo "target_gib (${target_gib}) must be greater than current size (${current_size})." >&2
    exit 1
  fi

  local volume_modification_state
  volume_modification_state="$(
    aws ec2 describe-volumes-modifications \
      --region "$region" \
      --volume-ids "$volume_id" \
      --query 'VolumesModifications[0].ModificationState' \
      --output text
  )"

  if [[ "$volume_modification_state" == "modifying" || "$volume_modification_state" == "optimizing" ]]; then
    echo "Volume ${volume_id} is currently ${volume_modification_state}. Wait until it is not modifying before resizing again." >&2
    exit 1
  fi

  if [[ "$volume_modification_state" == "failed" ]]; then
    echo "Volume ${volume_id} has failed modification state. Resolve that state before resizing again." >&2
    exit 1
  fi

  log "Instance ID:      $instance_id"
  log "Region:           $region"
  log "Root device:      $root_device"
  log "Root volume ID:   $volume_id"
  log "Current size:     ${current_size} GiB"
  log "Target size:      ${target_gib} GiB"
  log "Current type:     $volume_type"
  log "Modification:     $volume_modification_state"

  if [[ "$create_snapshot" == "true" ]]; then
    log "Creating safety snapshot"
    local snapshot_id
    snapshot_id="$(
      aws ec2 create-snapshot \
        --region "$region" \
        --volume-id "$volume_id" \
        --description "Pre-growth snapshot for ${volume_id} on ${instance_id} at $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --query 'SnapshotId' \
        --output text
  )"
    log "Snapshot started: $snapshot_id"
  fi

  log "Checking SSM management status"
  local ssm_managed_count
  ssm_managed_count="$(
    aws ssm describe-instance-information \
      --region "$region" \
      --query "length(InstanceInformationList[?InstanceId=='${instance_id}'])" \
      --output text
  )"

  if [[ "$ssm_managed_count" == "0" ]]; then
    echo "Instance ${instance_id} is not managed by SSM in ${region}." >&2
    exit 1
  fi

  log "Running AWS-ExtendEbsVolume"
  local automation_id
  automation_id="$(
    aws ssm start-automation-execution \
      --region "$region" \
      --document-name "AWS-ExtendEbsVolume" \
      --parameters "InstanceId=${instance_id},VolumeId=${volume_id},MountPoint=/,SizeGib=${target_gib},keepSnapShot=${keep_snapshot}" \
      --query 'AutomationExecutionId' \
      --output text
  )"

  log "Started automation: $automation_id"
  wait_for_automation "$automation_id" "$region"

  log "Done. Verify with:"
  echo "  df -h / && lsblk"
}

main "$@"
