#!/usr/bin/env bash
set -euo pipefail

LAB_GROUP="hpc-users"
LAB_GID="2000"
SLURM_POLICY_TOKEN="--install-slurm-policy-only"
LOGIN_GUARDRAIL_TOKEN="--enforce-head-login-limits"
HEAD_LOGIN_LIMIT_CPUS="200%"
HEAD_LOGIN_LIMIT_MEMORY="16G"
HEAD_LOGIN_MAX_FILE_SIZE="40G"
HEAD_LOGIN_LIMIT_PROCS="512"
HEAD_LOGIN_MAX_SESSIONS="4"
HEAD_LOGIN_MAX_OPEN_FILES="8192"
HEAD_LOGIN_CPU_TIME_SECONDS="14400"
ACTIVE_INSTANCE_TYPES_PATH="/etc/aws-audit/active_instance_types.txt"

install_aws_audit_sbatch_wrapper() {
  cat <<'BASH' >/usr/local/bin/aws-audit-sbatch
#!/usr/bin/env bash
set -euo pipefail

active_instance_types_path="/etc/aws-audit/active_instance_types.txt"
instance_type=""
resource_arg_seen=0
constraint_arg_seen=0
passthrough=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --instance-type)
      if [ -n "${instance_type}" ]; then
        echo "Use --instance-type only once." >&2
        exit 2
      fi
      shift
      if [ "$#" -eq 0 ]; then
        echo "--instance-type requires an EC2 instance type." >&2
        exit 2
      fi
      instance_type="$1"
      ;;
    --instance-type=*)
      if [ -n "${instance_type}" ]; then
        echo "Use --instance-type only once." >&2
        exit 2
      fi
      instance_type="${1#*=}"
      ;;
    --constraint|-C)
      constraint_arg_seen=1
      option="$1"
      passthrough+=("${option}")
      shift
      if [ "$#" -eq 0 ]; then
        echo "${option} requires a value." >&2
        exit 2
      fi
      passthrough+=("$1")
      ;;
    --constraint=*|-C*)
      constraint_arg_seen=1
      passthrough+=("$1")
      ;;
    --cpus-per-task|--mem|--mem-per-cpu|-c)
      resource_arg_seen=1
      option="$1"
      passthrough+=("${option}")
      shift
      if [ "$#" -eq 0 ]; then
        echo "${option} requires a value." >&2
        exit 2
      fi
      passthrough+=("$1")
      ;;
    --cpus-per-task=*|--mem=*|--mem-per-cpu=*|-c*)
      resource_arg_seen=1
      passthrough+=("$1")
      ;;
    --)
      passthrough+=("$1")
      shift
      while [ "$#" -gt 0 ]; do
        passthrough+=("$1")
        shift
      done
      break
      ;;
    *)
      passthrough+=("$1")
      ;;
  esac
  shift
done

if [ -n "${instance_type}" ] && [ "${resource_arg_seen}" -eq 1 ]; then
  echo "Use either --instance-type or explicit --cpus-per-task plus --mem/--mem-per-cpu, not both." >&2
  exit 2
fi

if [ -n "${instance_type}" ] && [ "${constraint_arg_seen}" -eq 1 ]; then
  echo "Use either --instance-type or Slurm --constraint, not both." >&2
  exit 2
fi

if [ -n "${instance_type}" ] && [[ ! "${instance_type}" =~ ^[A-Za-z0-9-]+\.[A-Za-z0-9]+$ ]]; then
  echo "--instance-type must look like an EC2 instance type, for example t3.micro or c7g.2xlarge." >&2
  exit 2
fi

if [ -n "${instance_type}" ] && ! grep -Fxq "${instance_type}" "${active_instance_types_path}"; then
  echo "${instance_type} is not available in this active ParallelCluster config." >&2
  echo "This cluster only accepts instance types listed in ${active_instance_types_path}." >&2
  echo "Cross-architecture requests are rejected because ParallelCluster requires one architecture per cluster." >&2
  exit 2
fi

if [ -n "${instance_type}" ]; then
  exec sbatch --constraint="${instance_type}" "${passthrough[@]}"
fi

exec sbatch "${passthrough[@]}"
BASH
  chmod 0755 /usr/local/bin/aws-audit-sbatch
}

install_active_instance_types() {
  active_instance_types_uri="${1}"
  install -d -m 0755 /etc/aws-audit
  aws s3 cp "${active_instance_types_uri}" "${ACTIVE_INSTANCE_TYPES_PATH}"
  chmod 0644 "${ACTIVE_INSTANCE_TYPES_PATH}"
}

install_slurm_submit_policy() {
  install -d -m 0755 /opt/slurm/etc
  cat <<'LUA' >/opt/slurm/etc/job_submit.lua
local function missing(value)
  return value == nil or value == 0 or value == slurm.NO_VAL or value == slurm.NO_VAL16 or value == slurm.NO_VAL64
end

local function has_instance_type_constraint(value)
  if value == nil or value == "" then
    return false
  end
  return string.match(value, "^[A-Za-z0-9%-]+%.[A-Za-z0-9]+$") ~= nil
end

function slurm_job_submit(job_desc, part_list, submit_uid)
  if has_instance_type_constraint(job_desc.features) then
    return slurm.SUCCESS
  end
  if missing(job_desc.cpus_per_task) then
    slurm.log_user("Jobs must specify --cpus-per-task so Slurm can choose an appropriate node.")
    return slurm.ERROR
  end
  if missing(job_desc.pn_min_memory) then
    slurm.log_user("Jobs must specify --mem or --mem-per-cpu so Slurm can choose an appropriate node.")
    return slurm.ERROR
  end
  return slurm.SUCCESS
end

function slurm_job_modify(job_desc, job_rec, part_list, modify_uid)
  return slurm.SUCCESS
end
LUA
  chmod 0644 /opt/slurm/etc/job_submit.lua
  install_aws_audit_sbatch_wrapper
}

if [ "${1-}" = "${SLURM_POLICY_TOKEN}" ]; then
  install_active_instance_types "${2}"
  install_slurm_submit_policy
  exit 0
fi

USER_SPEC="${1}"

if ! getent group "${LAB_GROUP}" >/dev/null; then
  groupadd --gid "${LAB_GID}" "${LAB_GROUP}"
fi

enforce_head_limits() {
  install -d -m 0755 /etc/security/limits.d
  cat <<EOF >/etc/security/limits.d/95-aws-audit-login-limits.conf
@${LAB_GROUP} hard nproc ${HEAD_LOGIN_LIMIT_PROCS}
@${LAB_GROUP} soft nproc $((HEAD_LOGIN_LIMIT_PROCS - 20))
@${LAB_GROUP} hard fsize ${HEAD_LOGIN_MAX_FILE_SIZE}
@${LAB_GROUP} soft fsize ${HEAD_LOGIN_MAX_FILE_SIZE}
@${LAB_GROUP} hard cpu ${HEAD_LOGIN_CPU_TIME_SECONDS}
@${LAB_GROUP} soft cpu ${HEAD_LOGIN_CPU_TIME_SECONDS}
@${LAB_GROUP} hard nofile ${HEAD_LOGIN_MAX_OPEN_FILES}
@${LAB_GROUP} soft nofile ${HEAD_LOGIN_MAX_OPEN_FILES}
@${LAB_GROUP} hard maxlogins ${HEAD_LOGIN_MAX_SESSIONS}
EOF

  for item in "${USERS[@]}"; do
    linux_user="${item%%:*}"
    user_uid="$(id -u "${linux_user}")"
    dropin_dir="/etc/systemd/system/user-${user_uid}.slice.d"
    dropin_file="${dropin_dir}/95-aws-audit-login-limits.conf"
    mkdir -p "${dropin_dir}"
    cat <<EOF >/tmp/pc-head-login.slice.conf
[Slice]
CPUAccounting=yes
CPUQuota=${HEAD_LOGIN_LIMIT_CPUS}
MemoryAccounting=yes
MemoryMax=${HEAD_LOGIN_LIMIT_MEMORY}
TasksAccounting=yes
TasksMax=${HEAD_LOGIN_LIMIT_PROCS}
EOF
    cat /tmp/pc-head-login.slice.conf >"${dropin_file}"
  done

  rm -f /tmp/pc-head-login.slice.conf
  systemctl daemon-reload
}

IFS=',' read -ra USERS <<< "${USER_SPEC}"
for item in "${USERS[@]}"; do
  linux_user="${item%%:*}"
  uid="${item##*:}"
  if ! id "${linux_user}" >/dev/null 2>&1; then
    useradd \
      --uid "${uid}" \
      --gid "${LAB_GROUP}" \
      --create-home \
      --shell /bin/bash \
      "${linux_user}"
  fi
  usermod --append --groups "${LAB_GROUP}" "${linux_user}"
  install -d -m 0700 -o "${linux_user}" -g "${LAB_GROUP}" "/home/${linux_user}/.ssh"
  touch "/home/${linux_user}/.ssh/authorized_keys"
  chown "${linux_user}:${LAB_GROUP}" "/home/${linux_user}/.ssh/authorized_keys"
  chmod 0600 "/home/${linux_user}/.ssh/authorized_keys"
done

if [ "${2-}" = "${LOGIN_GUARDRAIL_TOKEN}" ]; then
  enforce_head_limits
fi

install -d -m 1777 /scratch
