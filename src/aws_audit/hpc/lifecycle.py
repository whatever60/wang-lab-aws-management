"""Administrative publishing and SSM rollout of the HPC public identity registry."""
import copy
import json
import os
import re
import shlex
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any
from . import user_sync


def s3_location(uri: str) -> tuple[str, str]:
    match = re.fullmatch(r"s3://([^/]+)/(.+)", uri)
    if not match or "${" in uri:
        raise ValueError("Configure lifecycle.current_s3_uri with a real S3 URI")
    return match.groups()


def aws_json(command: list[str]) -> Any:
    result = subprocess.run(["aws", *command, "--output", "json"], check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def release_asset(manifest: dict[str, Any], kind: str) -> tuple[Path, str]:
    settings = manifest["user_lifecycle"]
    path = Path(settings[f"{kind}_local_path"])
    # Names include full content hashes: a roster update never changes bootstrap code in place.
    # Generation may retain env placeholders; publication validates the concrete URI.
    bucket, current_key = settings["current_s3_uri"][5:].split("/", 1)
    key = current_key.rsplit("/", 1)[0] + f"/releases/code/{user_sync.digest(path.read_bytes())}/{path.name}"
    return path, f"s3://{bucket}/{key}"


def load_release(manifest: dict[str, Any], directory: Path, allow_missing: bool = False) -> tuple[Any, Any]:
    bucket, key = s3_location(manifest["user_lifecycle"]["current_s3_uri"])
    try:
        metadata = user_sync.get_versioned_object(bucket, key, directory / "current.json")
    except subprocess.CalledProcessError as exc:
        # Do not mistake AccessDenied/network/service errors for an empty registry.
        if allow_missing and ("NoSuchKey" in (exc.stderr or "") or "(404)" in (exc.stderr or "")):
            return None, None
        raise
    pointer = json.loads((directory / "current.json").read_text())
    if pointer.get("schema_version") != user_sync.SCHEMA_VERSION or pointer.get("cluster_name") != manifest["parallelcluster"]["cluster_name"]:
        raise ValueError("Unexpected existing HPC lifecycle release")
    registry_key = pointer.get("registry_key", "")
    if not registry_key.startswith(key.rsplit("/", 1)[0] + "/releases/"):
        raise ValueError("Existing registry is outside the lifecycle prefix")
    user_sync.get_versioned_object(bucket, registry_key, directory / "previous.json", pointer["registry_version_id"])
    content = (directory / "previous.json").read_bytes()
    if user_sync.digest(content) != pointer["registry_sha256"]:
        raise ValueError("Existing registry checksum mismatch")
    previous = json.loads(content)
    user_sync.validate_registry(previous, pointer["cluster_name"])
    return {"pointer": pointer, "registry": previous}, metadata


def checked_admin_path(path: Path) -> Path:
    """Reject symlinks and paths another local user could replace or modify."""
    path = path.expanduser().absolute()
    trusted_owners = {0, os.geteuid()}
    for parent in reversed(path.parents):
        metadata = parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in trusted_owners:
            raise ValueError("Public-key/preview parent directories must be administrator-owned and not symlinks")
        # A root-owned sticky temporary directory cannot be used to replace an
        # administrator-owned child. All other writable ancestors are rejected.
        sticky_root = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
        if metadata.st_mode & 0o022 and not sticky_root:
            raise ValueError("Public-key/preview parent directories must not be group/other writable")
    return path


def read_admin_file(path: Path, limit: int = 2 * 1024 * 1024) -> bytes:
    """Read one administrator-controlled regular file without following a symlink."""
    path = checked_admin_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid not in {0, os.geteuid()}
                or metadata.st_mode & 0o022 or metadata.st_nlink != 1):
            raise ValueError("Public-key/preview files must be administrator-owned regular files, not writable by group/others or hardlinked")
        content = handle.read(limit + 1)
    if len(content) > limit:
        raise ValueError("Public-key/preview file exceeds its safety size limit")
    return content


def write_admin_preview(path: Path, content: bytes) -> None:
    """Atomically write a public preview; never overwrite through an unsafe path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path = checked_admin_path(path)
    if path.exists() or path.is_symlink():
        read_admin_file(path)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".hpc-preview-")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def public_key_source(manifest: dict[str, Any], user: dict[str, Any]) -> dict[str, str]:
    """Every initial key and rotation needs an explicit administrator-approved pin."""
    source = manifest["user_lifecycle"].get("public_key_sources", {}).get(user["iam_user"])
    if not isinstance(source, dict):
        raise ValueError(f"Configure an explicit public key source and public_key_sha256 pin for {user['iam_user']}")
    if set(source) not in ({"local_public_key_path", "public_key_sha256"}, {"ec2_key_name", "public_key_sha256"}):
        raise ValueError(f"Choose exactly one public key source plus public_key_sha256 for {user['iam_user']}")
    pin = source.get("public_key_sha256")
    if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin):
        raise ValueError(f"Configure an approved lowercase SHA-256 public_key_sha256 pin for {user['iam_user']}")
    source_key = "local_public_key_path" if "local_public_key_path" in source else "ec2_key_name"
    if not isinstance(source[source_key], str) or not source[source_key]:
        raise ValueError(f"Public key source is empty for {user['iam_user']}")
    return dict(source)


def public_key_for_user(manifest: dict[str, Any], user: dict[str, Any]) -> str:
    source = public_key_source(manifest, user)
    if "local_public_key_path" in source:
        path = Path(source["local_public_key_path"]).expanduser()
        if path.suffix != ".pub":
            raise ValueError("Explicit local public key source must end in .pub")
        value = read_admin_file(path, limit=65536).decode("utf-8")
    else:
        response = aws_json(["ec2", "describe-key-pairs", "--region", manifest["parallelcluster"]["region"],
                             "--key-names", source["ec2_key_name"], "--include-public-key"])
        pairs = response.get("KeyPairs", [])
        if len(pairs) != 1 or not pairs[0].get("PublicKey"):
            raise ValueError(f"No EC2 public key available for {user['iam_user']}")
        value = pairs[0]["PublicKey"]
    key = user_sync.public_key(value)
    # Hash the normalized algorithm + base64 payload, with no comment/newline.
    # A key-pair name or ID alone is not an administrator's approval of its key.
    if user_sync.digest(key.encode("utf-8")) != source["public_key_sha256"]:
        raise ValueError(f"Public key differs from the administrator-approved pin for {user['iam_user']}; review its source and rotation")
    # Validate RSA/ECDSA mathematical key structure too; never derive/read a private key.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pub") as handle:
        handle.write(key + "\n")
        handle.flush()
        subprocess.run(["ssh-keygen", "-l", "-f", handle.name], check=True, capture_output=True, text=True)
    return key


def desired_registry(manifest: dict[str, Any], users: list[dict[str, Any]], previous: dict[str, Any]) -> dict[str, Any]:
    """Merge tombstones; never silently rename/reassign an existing managed identity."""
    old_by_iam = {user["iam_user"]: user for user in previous.get("users", [])}
    current = {}
    adoption = set(manifest["user_lifecycle"].get("adopt_existing_users", []))
    for user in users:
        row = dict(user, active=True, public_keys=[public_key_for_user(manifest, user)], adopt_existing=user["iam_user"] in adoption)
        old = old_by_iam.get(user["iam_user"])
        if old and any(old[field] != row[field] for field in ["uid", "linux_user"]):
            raise ValueError(f"Managed identity cannot be changed: {user['iam_user']}")
        current[user["iam_user"]] = row
    for iam_user, old in old_by_iam.items():
        if iam_user not in current:
            current[iam_user] = dict(old, active=False, public_keys=[], adopt_existing=False)
    limits = copy.deepcopy(manifest["login_guardrails"])
    # Normalize PAM fsize units in the public registry.
    size = str(limits.pop("max_file_size"))
    match = re.fullmatch(r"([1-9][0-9]*)([MG])", size)
    if not match:
        raise ValueError("max_file_size must be an integer M/G size")
    limits["max_file_size_kib"] = int(match[1]) * (1024 if match[2] == "M" else 1024 * 1024)
    result = {"schema_version": 1, "cluster_name": manifest["parallelcluster"]["cluster_name"],
              "users": sorted(current.values(), key=lambda row: row["linux_user"]), "head_limits": limits,
              "staleness_policy": manifest["user_lifecycle"].get("staleness_policy", {"on_fetch_failure": "retain", "warn_after_seconds": 3600})}
    user_sync.validate_registry(result, result["cluster_name"])
    user_sync.validate_transition(previous, result)
    return result


def put_file(bucket: str, key: str, path: Path, **conditions: str) -> dict[str, Any]:
    command = ["s3api", "put-object", "--bucket", bucket, "--key", key, "--body", str(path),
               "--server-side-encryption", "AES256"]
    for name, value in conditions.items():
        command += ["--" + name.replace("_", "-"), value]
    result = aws_json(command)
    if not result.get("VersionId") or result["VersionId"] == "null":
        raise ValueError("Publish did not return a version ID; require enabled bucket versioning")
    return result


def publish_users(manifest: dict[str, Any], users: list[dict[str, Any]], preview_path: Path,
                  execute: bool = False, approved_preview_sha256: str = "") -> dict[str, Any]:
    """Publish only a matching reviewed preview; then CAS-update the release pointer."""
    approved_preview = None
    if execute:
        if not re.fullmatch(r"[0-9a-f]{64}", approved_preview_sha256):
            raise ValueError("--execute requires an explicit --approved-preview-sha256 from the reviewed preview")
        approved_preview = json.loads(read_admin_file(preview_path))
        if user_sync.digest(user_sync.canonical_bytes(approved_preview)) != approved_preview_sha256:
            raise ValueError("Preview does not match --approved-preview-sha256; no files or AWS objects were updated")
    elif approved_preview_sha256:
        raise ValueError("--approved-preview-sha256 is only valid with --execute")
    bucket, current_key = s3_location(manifest["user_lifecycle"]["current_s3_uri"])
    if aws_json(["s3api", "get-bucket-versioning", "--bucket", bucket]).get("Status") != "Enabled":
        raise ValueError("Enable S3 versioning on the lifecycle assets bucket before publication")
    with tempfile.TemporaryDirectory(prefix="hpc-users-") as temporary:
        directory = Path(temporary)
        old, metadata = load_release(manifest, directory, allow_missing=True)
        previous = old["registry"] if old else {"users": []}
        desired = desired_registry(manifest, users, previous)
        content = user_sync.canonical_bytes(desired)
        registry_sha = user_sync.digest(content)
        code_assets = {}
        for kind in ["runtime", "bootstrap"]:
            path, _ = release_asset(manifest, kind)
            code_content = path.read_bytes()
            code_sha = user_sync.digest(code_content)
            key = current_key.rsplit("/", 1)[0] + f"/releases/code/{code_sha}/{path.name}"
            code_assets[kind] = {"key": key, "sha256": code_sha, "content": code_content}
        preview = {"preview_schema_version": 1, "current_s3_uri": manifest["user_lifecycle"]["current_s3_uri"],
                   "previous_pointer_etag": metadata["ETag"] if metadata else None,
                   "registry": desired, "registry_sha256": registry_sha,
                   "public_key_sources": {user["iam_user"]: public_key_source(manifest, user) for user in users},
                   "code": {kind: {"key": asset["key"], "sha256": asset["sha256"]} for kind, asset in code_assets.items()}}
        preview_sha = user_sync.digest(user_sync.canonical_bytes(preview))
        if not execute:
            write_admin_preview(preview_path, user_sync.canonical_bytes(preview))
            return {"preview_path": str(preview_path), "preview_sha256": preview_sha, "preview": preview}
        if preview != approved_preview or preview_sha != approved_preview_sha256:
            raise ValueError("IAM membership, keys/source pins, code, destination or current release changed since approval; prepare and review a new preview")
        # Freeze the approved bytes in a private temporary directory. Execution
        # never overwrites the reviewed preview or reopens mutable source files.
        registry_path = directory / "users.json"
        registry_path.write_bytes(content)
        # Version-pinned object releases are immutable to consumers, even if a key is overwritten.
        registry_key = current_key.rsplit("/", 1)[0] + f"/releases/users/{registry_sha}.json"
        registry_version = put_file(bucket, registry_key, registry_path)["VersionId"]
        pointer = {"schema_version": 1, "cluster_name": desired["cluster_name"], "registry_key": registry_key,
                   "registry_version_id": registry_version, "registry_sha256": registry_sha}
        for kind, asset in code_assets.items():
            path = directory / (kind + ".release")
            path.write_bytes(asset["content"])
            pointer[f"{kind}_key"] = asset["key"]
            pointer[f"{kind}_sha256"] = asset["sha256"]
            pointer[f"{kind}_version_id"] = put_file(bucket, asset["key"], path)["VersionId"]
        pointer_path = directory / "pointer.json"
        pointer_path.write_bytes(user_sync.canonical_bytes(pointer))
        # A conflicting administrator publishes first -> PreconditionFailed, no lost tombstones.
        condition = {"if_match": metadata["ETag"]} if metadata else {"if_none_match": "*"}
        put_file(bucket, current_key, pointer_path, **condition)
        return pointer


def describe_cluster(manifest: dict[str, Any]) -> dict[str, Any]:
    """Read trusted ParallelCluster metadata; never print its presigned config URL."""
    result = subprocess.run(["pcluster", "describe-cluster", "--cluster-name", manifest["parallelcluster"]["cluster_name"],
                             "--region", manifest["parallelcluster"]["region"]],
                            check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def trusted_cluster_resources(manifest: dict[str, Any], cluster: dict[str, Any]) -> dict[str, Any]:
    """Resolve instance/profile/template identities from the cluster's real CFN graph."""
    region = manifest["parallelcluster"]["region"]
    cluster_name = manifest["parallelcluster"]["cluster_name"]
    head_id = cluster.get("headNode", {}).get("instanceId", "")
    stack_arn = cluster.get("cloudformationStackArn", "")
    arn = re.fullmatch(r"arn:(aws[a-z-]*):cloudformation:([^:]+):([0-9]{12}):stack/[^/]+/[^/]+", stack_arn)
    if (cluster.get("clusterName") != cluster_name or cluster.get("region", region) != region
            or not re.fullmatch(r"i-(?:[0-9a-f]{8}|[0-9a-f]{17})", head_id)
            or not arn or arn[2] != region):
        raise ValueError("ParallelCluster did not return a matching trusted head instance and CloudFormation stack ARN")
    if cluster.get("cloudFormationStackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"}:
        raise ValueError("Cluster CloudFormation stack must be stable before discovering synchronization targets")
    prefix = f"arn:{arn[1]}:cloudformation:{region}:{arn[3]}:stack/"
    pending, visited, resources = [stack_arn], set(), []
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        if not current.startswith(prefix) or len(visited) >= 100:
            raise ValueError("Unexpected nested stack identity or excessive cluster resource graph")
        visited.add(current)
        response = aws_json(["cloudformation", "list-stack-resources", "--region", region, "--stack-name", current])
        for resource in response["StackResourceSummaries"]:
            if resource.get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"}:
                continue
            physical_id = resource.get("PhysicalResourceId")
            if not physical_id:
                continue
            resources.append(resource)
            if resource["ResourceType"] == "AWS::CloudFormation::Stack":
                pending.append(physical_id)
    owned_instances = {item["PhysicalResourceId"] for item in resources if item["ResourceType"] == "AWS::EC2::Instance"}
    if head_id not in owned_instances:
        raise ValueError("ParallelCluster head instance is not owned by its trusted CloudFormation stack")
    return {"head_id": head_id, "account_id": arn[3], "partition": arn[1],
            "profile_names": {item["PhysicalResourceId"].rsplit("/", 1)[-1] for item in resources if item["ResourceType"] == "AWS::IAM::InstanceProfile"},
            "role_names": {item["PhysicalResourceId"].rsplit("/", 1)[-1] for item in resources if item["ResourceType"] == "AWS::IAM::Role"},
            "launch_template_ids": {item["PhysicalResourceId"] for item in resources if item["ResourceType"] == "AWS::EC2::LaunchTemplate"}}


def trusted_cluster_profiles(trust: dict[str, Any]) -> dict[str, str]:
    profiles = []
    for name in sorted(trust["profile_names"]):
        profiles.append(aws_json(["iam", "get-instance-profile", "--instance-profile-name", name])["InstanceProfile"])
    # Some deployments create a role in CFN but use an external profile containing
    # it. Membership of that trusted role is authoritative; profile tags are not.
    if not profiles:
        for role in sorted(trust["role_names"]):
            profiles.extend(aws_json(["iam", "list-instance-profiles-for-role", "--role-name", role])["InstanceProfiles"])
    prefix = f"arn:{trust['partition']}:iam::{trust['account_id']}:instance-profile/"
    result = {profile["Arn"]: profile["InstanceProfileId"] for profile in profiles
              if profile.get("Arn", "").startswith(prefix) and profile.get("InstanceProfileId")}
    if not result:
        raise ValueError("No trusted cluster instance profiles/roles were resolved for compute-node synchronization")
    return result


def sync_targets(manifest: dict[str, Any]) -> list[dict[str, str]]:
    cluster_name = manifest["parallelcluster"]["cluster_name"]
    region = manifest["parallelcluster"]["region"]
    trust = trusted_cluster_resources(manifest, describe_cluster(manifest))
    result = aws_json(["ec2", "describe-instances", "--region", region, "--filters",
                       "Name=instance-state-name,Values=running,stopped", f"Name=tag:parallelcluster:cluster-name,Values={cluster_name}"])
    targets = []
    trusted_profiles = None
    seen = set()
    for reservation in result["Reservations"]:
        for instance in reservation["Instances"]:
            tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
            role = {"HeadNode": "head", "Compute": "compute"}.get(tags.get("parallelcluster:node-type"))
            if role is None:
                raise ValueError(f"Unrecognized node role for {instance['InstanceId']}")
            instance_id = instance["InstanceId"]
            if tags.get("parallelcluster:cluster-name") != cluster_name or instance_id in seen:
                raise ValueError("Unexpected cluster tag or duplicate instance in synchronization targets")
            seen.add(instance_id)
            if role == "head":
                if instance_id != trust["head_id"]:
                    raise ValueError(f"Refusing forged/untrusted head-node target {instance_id}")
            else:
                if trusted_profiles is None:
                    trusted_profiles = trusted_cluster_profiles(trust)
                profile = instance.get("IamInstanceProfile", {})
                if (instance_id == trust["head_id"]
                        or tags.get("aws:ec2launchtemplate:id") not in trust["launch_template_ids"]
                        or not re.fullmatch(r"[1-9][0-9]*", tags.get("aws:ec2launchtemplate:version", ""))
                        or not profile.get("Id") or trusted_profiles.get(profile.get("Arn")) != profile["Id"]):
                    raise ValueError(f"Refusing forged/untrusted compute target {instance_id}; require a CFN launch template and trusted profile identity")
            targets.append({"instance_id": instance["InstanceId"], "node_role": role, "state": instance["State"]["Name"]})
    if not any(target["node_role"] == "head" for target in targets):
        raise ValueError("Trusted ParallelCluster head node was not found in the running/stopped target inventory")
    return sorted(targets, key=lambda item: item["instance_id"])


def verify_cluster_hooks(manifest: dict[str, Any], pointer: dict[str, Any]) -> None:
    """Prevent a partial migration that leaves newly launched compute nodes on old hooks."""
    import yaml
    cluster_name = manifest["parallelcluster"]["cluster_name"]
    url = describe_cluster(manifest)["clusterConfiguration"]["url"]
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("ParallelCluster configuration URL must use HTTPS")
    # The presigned URL is never printed, persisted, or included in exception messages.
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            if urllib.parse.urlparse(response.geturl()).scheme != "https":
                raise ValueError("Unexpected configuration redirect")
            source = response.read(2 * 1024 * 1024)
            if response.read(1):
                raise ValueError("Cluster configuration exceeds the 2 MiB safety bound")
            config = yaml.safe_load(source)
    except Exception:
        raise ValueError("Unable to fetch deployed ParallelCluster configuration") from None
    bucket, _ = s3_location(manifest["user_lifecycle"]["current_s3_uri"])
    script = f"s3://{bucket}/{pointer['bootstrap_key']}"
    for section, role in [(config["HeadNode"], "head"), *[(queue, "compute") for queue in config["Scheduling"]["SlurmQueues"]]]:
        action = section.get("CustomActions", {}).get("OnNodeConfigured", {})
        expected_args = ["--sync-users", manifest["user_lifecycle"]["current_s3_uri"], cluster_name, role]
        if action.get("Script") != script or action.get("Args") != expected_args:
            raise ValueError("Deployed user bootstrap is stale. Migrate HeadNode and every queue CustomActions.OnNodeConfigured "
                             "using pcluster update-cluster before sync-users --execute; do not replace the existing compute catalog.")


def ensure_published_users(manifest: dict[str, Any], users: list[dict[str, Any]]) -> None:
    """Cluster creation must not silently use a stale identity or code release."""
    with tempfile.TemporaryDirectory(prefix="hpc-check-") as temporary:
        old, _ = load_release(manifest, Path(temporary))
    expected = desired_registry(manifest, users, old["registry"])
    if user_sync.digest(user_sync.canonical_bytes(expected)) != old["pointer"]["registry_sha256"]:
        raise ValueError("IAM membership, keys, or limits changed; review and publish-users --execute first")
    for kind in ["runtime", "bootstrap"]:
        if user_sync.digest(release_asset(manifest, kind)[0].read_bytes()) != old["pointer"][f"{kind}_sha256"]:
            raise ValueError("Local lifecycle code has not been published")


def rollout_users(manifest: dict[str, Any], execute: bool = False) -> dict[str, Any]:
    """Explicit cluster-tagged SSM rollout; no discovery of arbitrary personal EC2 instances."""
    region = manifest["parallelcluster"]["region"]
    cluster_name = manifest["parallelcluster"]["cluster_name"]
    uri = manifest["user_lifecycle"]["current_s3_uri"]
    bucket, _ = s3_location(uri)
    with tempfile.TemporaryDirectory(prefix="hpc-rollout-") as temporary:
        old, _ = load_release(manifest, Path(temporary))
    pointer = old["pointer"]
    for kind in ["runtime", "bootstrap"]:
        if pointer[f"{kind}_sha256"] != user_sync.digest(release_asset(manifest, kind)[0].read_bytes()):
            raise ValueError("Published code differs from this checkout; publish reviewed code first")
    targets = sync_targets(manifest)
    plan = {"cluster_name": cluster_name, "revision": pointer["registry_sha256"], "targets": targets}
    if not execute:
        return plan
    if not targets:
        raise ValueError("No cluster nodes found; nothing was dispatched")
    if any(target["state"] != "running" for target in targets):
        raise ValueError("Stopped nodes cannot be migrated with SSM. Start them through an authorized operation or retire them before rollout")
    verify_cluster_hooks(manifest, pointer)
    online = aws_json(["ssm", "describe-instance-information", "--region", region, "--filters",
                       "Key=InstanceIds,Values=" + ",".join(target["instance_id"] for target in targets)])
    online_ids = {item["InstanceId"] for item in online["InstanceInformationList"] if item["PingStatus"] == "Online"}
    missing = {target["instance_id"] for target in targets} - online_ids
    if missing:
        raise ValueError("All target nodes must be SSM Online before rollout: " + ", ".join(sorted(missing)))
    dispatched = []
    for target in targets:
        bootstrap_cmd = ["bash", "$hpc_script", "--sync-users", uri, cluster_name, target["node_role"], pointer["registry_sha256"]]
        command = ("set -eu\n"
                   "hpc_script=$(mktemp /run/hpc-bootstrap.XXXXXX)\ntrap 'rm -f \"$hpc_script\"' EXIT\n"
                   f"aws s3api get-object --bucket {shlex.quote(bucket)} --key {shlex.quote(pointer['bootstrap_key'])} "
                   f"--version-id {shlex.quote(pointer['bootstrap_version_id'])} \"$hpc_script\" >/dev/null\n"
                   f"echo {shlex.quote(pointer['bootstrap_sha256'] + '  ')}\"$hpc_script\" | sha256sum -c -\n"
                   "bash \"$hpc_script\" " + shlex.join(bootstrap_cmd[2:]) + "\n")
        response = aws_json(["ssm", "send-command", "--region", region, "--instance-ids", target["instance_id"],
                             "--document-name", "AWS-RunShellScript", "--parameters", json.dumps({"commands": [command], "executionTimeout": ["300"]}),
                             "--comment", "aws-audit HPC user lifecycle " + pointer["registry_sha256"][:12]])
        dispatched.append({"command_id": response["Command"]["CommandId"], **target})
    deadline = time.monotonic() + 360
    pending = list(dispatched)
    failures = []
    while pending and time.monotonic() < deadline:
        for invocation in list(pending):
            try:
                result = aws_json(["ssm", "get-command-invocation", "--region", region, "--command-id", invocation["command_id"],
                                   "--instance-id", invocation["instance_id"]])
            except subprocess.CalledProcessError as exc:
                if "InvocationDoesNotExist" in (exc.stderr or ""):
                    continue
                raise
            status = result["Status"]
            if status in {"Pending", "InProgress", "Delayed"}:
                continue
            pending.remove(invocation)
            if status != "Success":
                failures.append(f"{invocation['instance_id']}: {status}: {result.get('StandardErrorContent', '')}")
        if pending:
            time.sleep(3)
    if pending or failures:
        raise RuntimeError("Incomplete HPC user rollout; inspect SSM commands: " + json.dumps(dispatched) + "; " + "; ".join(failures))
    return dict(plan, commands=dispatched, status="Success")
