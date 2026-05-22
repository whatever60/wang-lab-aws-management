#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./grow_root_ebs.sh <instance_id> <region> [extra_gib]

Examples:
  ./grow_root_ebs.sh i-0123456789abcdef0 us-east-1
  ./grow_root_ebs.sh i-0123456789abcdef0 us-east-1 1024

Defaults:
  extra_gib = 1024

Optional environment variables:
  CREATE_SNAPSHOT=true|false              default: false
  KEEP_SNAPSHOT=true|false                default: false
  ALLOW_STOP_START_FALLBACK=true|false    default: false

What it does:
  1) finds the root EBS volume for the instance
  2) calculates new_size = current_size + extra_gib
  3) if the instance is managed by SSM, runs AWS-ExtendEbsVolume
     so AWS handles both the EBS resize and filesystem extension
  4) otherwise, modifies the EBS volume live and prints the exact
     Linux commands you should run inside the instance to grow /
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

wait_for_volume_usable() {
  local volume_id="$1"
  local region="$2"

  while true; do
    local state
    state="$(
      aws ec2 describe-volumes-modifications \
        --region "$region" \
        --volume-ids "$volume_id" \
        --query 'VolumesModifications[0].ModificationState' \
        --output text
    )"

    log "Volume modification state: $state"

    case "$state" in
      optimizing|completed)
        return 0
        ;;
      failed)
        echo "Volume modification failed." >&2
        exit 1
        ;;
    esac

    sleep 15
  done
}

wait_for_volume_complete() {
  local volume_id="$1"
  local region="$2"

  while true; do
    local state
    state="$(
      aws ec2 describe-volumes-modifications \
        --region "$region" \
        --volume-ids "$volume_id" \
        --query 'VolumesModifications[0].ModificationState' \
        --output text
    )"

    log "Volume modification state: $state"

    case "$state" in
      completed)
        return 0
        ;;
      failed)
        echo "Volume modification failed." >&2
        exit 1
        ;;
    esac

    sleep 15
  done
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
          --output json || true
        exit 1
        ;;
    esac

    sleep 15
  done
}

main() {
  require_cmd aws

  if [[ $# -lt 2 || $# -gt 3 ]]; then
    usage
    exit 1
  fi

  local instance_id="$1"
  local region="$2"
  local extra_gib="${3:-1024}"

  local create_snapshot="${CREATE_SNAPSHOT:-false}"
  local keep_snapshot="${KEEP_SNAPSHOT:-false}"
  local allow_stop_start_fallback="${ALLOW_STOP_START_FALLBACK:-false}"

  if ! [[ "$extra_gib" =~ ^[0-9]+$ ]] || (( extra_gib <= 0 )); then
    echo "extra_gib must be a positive integer." >&2
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

  if [[ -z "$root_device" || "$root_device" == "None" || -z "$volume_id" || "$volume_id" == "None" ]]; then
    echo "Could not determine root device or root volume." >&2
    exit 1
  fi

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

  local new_size
  new_size="$(( current_size + extra_gib ))"

  log "Instance ID:      $instance_id"
  log "Region:           $region"
  log "Root device:      $root_device"
  log "Root volume ID:   $volume_id"
  log "Current size:     ${current_size} GiB"
  log "Requested add:    ${extra_gib} GiB"
  log "Target size:      ${new_size} GiB"
  log "Current type:     $volume_type"

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

  log "Checking whether the instance is managed by SSM"
  local ssm_managed_count
  ssm_managed_count="$(
    aws ssm describe-instance-information \
      --region "$region" \
      --query "length(InstanceInformationList[?InstanceId=='${instance_id}'])" \
      --output text 2>/dev/null || echo 0
  )"

  if [[ "$ssm_managed_count" != "0" ]]; then
    log "SSM detected. Using AWS-ExtendEbsVolume for full one-click resize."

    local automation_id
    automation_id="$(
      aws ssm start-automation-execution \
        --region "$region" \
        --document-name "AWS-ExtendEbsVolume" \
        --parameters \
          "InstanceId=${instance_id},VolumeId=${volume_id},MountPoint=/,SizeGib=${new_size},keepSnapShot=${keep_snapshot}" \
        --query 'AutomationExecutionId' \
        --output text
    )"

    log "Started automation: $automation_id"
    wait_for_automation "$automation_id" "$region"

    log "Done. Verify with:"
    echo "  ssh into the instance and run: df -h / && lsblk"
    exit 0
  fi

  log "SSM not available. Falling back to AWS-side live EBS resize only."
  log "This will enlarge the EBS volume while the instance stays running if supported."

  local modify_output
  if ! modify_output="$(
    aws ec2 modify-volume \
      --region "$region" \
      --volume-id "$volume_id" \
      --size "$new_size" \
      --volume-type gp3 2>&1
  )"; then
    echo "$modify_output" >&2

    if [[ "$allow_stop_start_fallback" == "true" ]]; then
      log "Trying stop -> modify -> start fallback"

      aws ec2 stop-instances \
        --region "$region" \
        --instance-ids "$instance_id" >/dev/null

      aws ec2 wait instance-stopped \
        --region "$region" \
        --instance-ids "$instance_id"

      aws ec2 modify-volume \
        --region "$region" \
        --volume-id "$volume_id" \
        --size "$new_size" \
        --volume-type gp3 >/dev/null

      aws ec2 start-instances \
        --region "$region" \
        --instance-ids "$instance_id" >/dev/null

      aws ec2 wait instance-running \
        --region "$region" \
        --instance-ids "$instance_id"

      log "Instance restarted after fallback path"
    else
      echo
      echo "Live modification failed."
      echo "Re-run with ALLOW_STOP_START_FALLBACK=true to automate stop/modify/start."
      exit 1
    fi
  else
    log "EBS modify-volume request accepted"
  fi

  wait_for_volume_usable "$volume_id" "$region"
  wait_for_volume_complete "$volume_id" "$region"

  cat <<'EOF'

AWS-side resize is complete.

Now grow the partition/filesystem inside the Linux instance.

Run these commands on the instance:

  findmnt -no SOURCE /
  findmnt -no FSTYPE /
  lsblk

Typical Nitro example if root is /dev/nvme0n1p1:
  sudo growpart /dev/nvme0n1 1

Then:
  if filesystem is xfs:
    sudo xfs_growfs /
  if filesystem is ext4:
    sudo resize2fs /dev/nvme0n1p1

Finally verify:
  df -h /
  lsblk

EOF
}

main "$@"
