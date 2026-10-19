#!/usr/bin/env bash
set -euo pipefail

SLURM_POLICY_TOKEN="--install-slurm-policy-only"
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

# Account state is intentionally fetched at runtime: never freeze IAM users in YAML.
if [ "${1-}" != "--sync-users" ] || [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
  echo "Usage: $0 --sync-users <s3-current-uri> <cluster-name> <head|compute> [expected-revision]" >&2
  exit 2
fi

python3 - "$0" "$2" "$3" "$4" "${5-}" <<'PYTHON'
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

bootstrap, uri, cluster, role, expected = sys.argv[1:]
if os.geteuid() != 0:
    raise SystemExit("HPC lifecycle bootstrap requires root")
# Standard Ubuntu AMIs may package the agent either as a systemd or snap service.
if not any(subprocess.run(["systemctl", "is-active", "--quiet", service], check=False).returncode == 0
           for service in ["amazon-ssm-agent", "snap.amazon-ssm-agent.amazon-ssm-agent"]):
    raise SystemExit("An active Amazon SSM Agent service is required; provision the AMI/agent and retry")
if not re.fullmatch(r"s3://[a-z0-9.-]+/[A-Za-z0-9._/-]+", uri):
    raise SystemExit("Expected a concrete S3 lifecycle URI")
if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,59}", cluster) or role not in {"head", "compute"}:
    raise SystemExit("Invalid cluster/node role")
if expected and not re.fullmatch(r"[0-9a-f]{64}", expected):
    raise SystemExit("Invalid expected revision")
bucket, current_key = uri[5:].split("/", 1)
runtime = None
base_args = ["--manifest-uri", uri, "--cluster-name", cluster, "--node-role", role]

def fetch(key, path, version=""):
    command = ["aws", "s3api", "get-object", "--bucket", bucket, "--key", key]
    if version:
        command += ["--version-id", version]
    result = subprocess.run(command + [str(path)], check=True, capture_output=True, text=True)
    metadata = json.loads(result.stdout)
    if metadata.get("VersionId") in {None, "", "null"}:
        raise ValueError("Lifecycle bucket must have versioning enabled")

def atomic(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("Refusing managed path symlink")
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

try:
    with tempfile.TemporaryDirectory(prefix="hpc-install-", dir="/run") as temporary:
        directory = Path(temporary)
        fetch(current_key, directory / "current.json")
        pointer = json.loads((directory / "current.json").read_text())
        if pointer.get("schema_version") != 1 or pointer.get("cluster_name") != cluster:
            raise ValueError("Unexpected lifecycle release")
        if expected and pointer.get("registry_sha256") != expected:
            raise ValueError("Roster changed while rollout was dispatched; retry reviewed rollout")
        if hashlib.sha256(Path(bootstrap).read_bytes()).hexdigest() != pointer.get("bootstrap_sha256"):
            raise ValueError("Bootstrap release changed; use current published bootstrap")
        runtime_key = pointer.get("runtime_key", "")
        if not runtime_key.startswith(current_key.rsplit("/", 1)[0] + "/releases/code/"):
            raise ValueError("Runtime outside lifecycle prefix")
        fetch(runtime_key, directory / "runtime.py", pointer["runtime_version_id"])
        content = (directory / "runtime.py").read_bytes()
        if hashlib.sha256(content).hexdigest() != pointer.get("runtime_sha256"):
            raise ValueError("Runtime checksum mismatch")
        runtime_sha = pointer.get("runtime_sha256", "")
        if not re.fullmatch(r"[0-9a-f]{64}", runtime_sha):
            raise ValueError("Invalid runtime content hash")
        # Immutable installed paths prevent an already-running older interpreter from
        # mistaking newly replaced source bytes for its own code during an upgrade.
        runtime = Path("/usr/local/libexec/aws-audit-hpc") / runtime_sha / "user_sync.py"
        atomic(runtime, content, 0o755)
    # Run both immediately and every two minutes; the service never reads IAM or EFS keys.
    command = shlex.join(["/usr/bin/python3", str(runtime), *base_args])
    service = ("[Unit]\nDescription=Reconcile managed HPC users\nAfter=network-online.target\nWants=network-online.target\n"
               "[Service]\nType=oneshot\nUser=root\nUMask=0077\nTimeoutStartSec=300\nExecStart=" + command + "\n")
    timer = ("[Unit]\nDescription=Refresh managed HPC users\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=2min\n"
             "RandomizedDelaySec=15s\nUnit=aws-audit-hpc-users.service\n[Install]\nWantedBy=timers.target\n")
    atomic(Path("/etc/systemd/system/aws-audit-hpc-users.service"), service.encode())
    atomic(Path("/etc/systemd/system/aws-audit-hpc-users.timer"), timer.encode())
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "aws-audit-hpc-users.timer"], check=True)
    subprocess.run(["/usr/bin/python3", str(runtime), *base_args,
                    *(["--expected-revision", expected] if expected else [])], check=True)
except Exception:
    # Keep existing valid access on download/install errors. Fresh nodes have no grants.
    # The failed service/SSM result is visible to the administrator; retry explicitly.
    raise
PYTHON

# Shared scratch remains a data directory; account revocation never removes home data.
install -d -m 1777 /scratch
