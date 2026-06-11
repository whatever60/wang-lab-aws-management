#!/usr/bin/env python3
import argparse
import copy
import json
import math
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional, TextIO


DEFAULT_MANIFEST_PATH = Path("config/hpc_workflow_manifest.json")
PRICING_REGION = "us-east-1"
QUEUE_ORDER = ["cpu", "gpu"]
NO_GPU_MANUFACTURER = "none"
NO_GPU_COUNT = 0
CLUSTER_ARCHITECTURES = ["x86_64", "arm64"]


def load_manifest(path: Path) -> dict[str, Any]:
    """Load the AWS HPC workflow manifest."""
    return expand_environment_values(json.loads(path.read_text(encoding="utf-8")))


def expand_environment_values(value: Any) -> Any:
    """Expand environment variables in nested JSON-compatible values."""
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, list):
        return [expand_environment_values(item) for item in value]
    if isinstance(value, dict):
        return {key: expand_environment_values(item) for key, item in value.items()}
    return value


def manifest_with_cluster_architecture(
    manifest: dict[str, Any], cluster_architecture: Optional[str]
) -> dict[str, Any]:
    """Return a manifest with an optional active cluster architecture override."""
    if cluster_architecture is None:
        return manifest
    if cluster_architecture not in manifest["ec2_selection"]["catalog_architectures"]:
        raise ValueError(f"Unsupported cluster architecture {cluster_architecture}")
    configured = copy.deepcopy(manifest)
    configured["ec2_selection"]["cluster_architecture"] = cluster_architecture
    return configured


def load_configured_manifest(args: argparse.Namespace) -> dict[str, Any]:
    """Load a manifest and apply any CLI cluster architecture override."""
    return manifest_with_cluster_architecture(
        load_manifest(args.manifest), getattr(args, "cluster_architecture", None)
    )


def head_node_instance_type(manifest: dict[str, Any]) -> str:
    """Return the head/login instance type for the active cluster architecture."""
    cluster_architecture = manifest["ec2_selection"]["cluster_architecture"]
    return manifest["parallelcluster"]["head_node"]["instance_type_by_architecture"][
        cluster_architecture
    ]


def run_json(command: list[str]) -> Any:
    """Run a command that prints JSON and return the parsed payload."""
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        env=command_environment(),
    )
    return json.loads(completed.stdout)


def run_command(command: list[str]) -> None:
    """Run a command and stream its output to the current terminal."""
    print_command(command)
    subprocess.run(command, check=True, env=command_environment())


def command_environment() -> dict[str, str]:
    """Return an environment that can run pcluster's local Node.js dependency."""
    env = os.environ.copy()
    node_bin = str(Path.home() / ".local" / "node" / "bin")
    env["PATH"] = f"{node_bin}:{env['PATH']}"
    return env


def pricing_location(region: str) -> str:
    """Return the AWS Pricing API location name for a region."""
    locations = {
        "us-east-1": "US East (N. Virginia)",
        "us-east-2": "US East (Ohio)",
        "us-west-1": "US West (N. California)",
        "us-west-2": "US West (Oregon)",
    }
    return locations[region]


def family_prefix(instance_type: str) -> str:
    """Return the leading family prefix from an EC2 instance type."""
    family = instance_type.split(".", 1)[0]
    chars: list[str] = []
    for char in family:
        if not char.isalpha():
            break
        chars.append(char)
    return "".join(chars)


def linux_user_from_iam_user(user_name: str) -> str:
    """Convert a lab IAM user name into a deterministic Linux user name."""
    base = user_name
    for suffix in ["_User", "_user", "-User", "-user"]:
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    base = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", base)
    base = base.replace("-", "_")
    base = re.sub(r"[^A-Za-z0-9_]", "_", base)
    base = re.sub(r"_+", "_", base).strip("_").lower()
    if not base[0].isalpha():
        base = f"u_{base}"
    return base


def selected_iam_users(manifest: dict[str, Any]) -> list[str]:
    """Return IAM users from configured include groups, excluding configured users."""
    selection = manifest["iam_user_selection"]
    users: set[str] = set()
    for group_name in selection["include_groups"]:
        group_users = run_json(
            [
                "aws",
                "iam",
                "get-group",
                "--group-name",
                group_name,
                "--query",
                "Users[].UserName",
            ]
        )
        users.update(group_users)
    for user_name in selection["exclude_users"]:
        users.discard(user_name)
    return sorted(users, key=linux_user_from_iam_user)


def lab_users_from_iam(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Build Linux user records from selected IAM users."""
    starting_uid = manifest["iam_user_selection"]["starting_uid"]
    rows: list[dict[str, Any]] = []
    for index, iam_user in enumerate(selected_iam_users(manifest)):
        rows.append(
            {
                "iam_user": iam_user,
                "linux_user": linux_user_from_iam_user(iam_user),
                "uid": starting_uid + index,
            }
        )
    return rows


def user_spec(users: list[dict[str, Any]]) -> str:
    """Render bootstrap user argument from user rows."""
    return ",".join(f"{user['linux_user']}:{user['uid']}" for user in users)


def queue_summary_rows(manifest: dict[str, Any]) -> list[dict[str, str]]:
    """Build printable queue summary rows from the manifest."""
    rows: list[dict[str, str]] = []
    for queue in manifest["queue_policy"]:
        rows.append(
            {
                "queue": queue["name"],
                "capacity": manifest["ec2_selection"]["capacity_type"],
                "instances": "generated from EC2 catalog/pricing",
                "max": str(queue["max_count_per_resource"]),
                "purpose": queue["purpose"],
            }
        )
    return rows


def storage_summary_rows(manifest: dict[str, Any]) -> list[dict[str, str]]:
    """Build printable storage summary rows from the manifest."""
    rows: list[dict[str, str]] = []
    for storage in manifest["storage"]:
        rows.append(
            {
                "name": storage["name"],
                "type": storage["storage_type"],
                "mount": storage["mount_dir"],
                "policy": storage["deletion_policy"],
                "role": storage["role"],
            }
        )
    return rows


def lab_user_rows(users: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Build printable lab user rows."""
    rows: list[dict[str, str]] = []
    for user in users:
        rows.append(
            {
                "iam_user": user["iam_user"],
                "linux_user": user["linux_user"],
                "uid": str(user["uid"]),
            }
        )
    return rows


def slurm_job_rows(manifest: dict[str, Any]) -> list[dict[str, str]]:
    """Build printable Slurm test job rows from the manifest."""
    rows: list[dict[str, str]] = []
    for job in manifest["slurm_test_jobs"]:
        rows.append(
            {
                "name": job["name"],
                "partition": job["partition"],
                "gpu": str(job["requires_gpu"]),
                "expected": job["expected_result"],
                "script": job["script"],
            }
        )
    return rows


def future_alternative_rows(manifest: dict[str, Any]) -> list[dict[str, str]]:
    """Build printable future alternative rows from the manifest."""
    rows: list[dict[str, str]] = []
    for item in manifest["future_alternatives"]:
        rows.append(
            {
                "name": item["name"],
                "status": item["status"],
                "when": item["when_to_revisit"],
            }
        )
    return rows


def instance_catalog_rows(manifest: dict[str, Any], active_cluster_only: bool) -> list[dict[str, str]]:
    """Build printable rows for the allowed EC2 instance catalog."""
    rows: list[dict[str, str]] = []
    for row in sorted(
        generic_candidate_rows(manifest, active_cluster_only),
        key=lambda item: (item["Queue"], item["Architecture"], item["Vcpus"], item["MemoryMiB"], item["HourlyPrice"], item["InstanceType"]),
    ):
        gpu_count = row["GpuCount"] or 0
        rows.append(
            {
                "queue": row["Queue"],
                "arch": row["Architecture"],
                "instance": row["InstanceType"],
                "vcpu": str(row["Vcpus"]),
                "memory_gib": f"{row['MemoryMiB'] / 1024:.1f}",
                "gpu": str(gpu_count),
                "usd_hr": f"{row['HourlyPrice']:.6f}",
                "current": str(row["CurrentGeneration"]),
            }
        )
    return rows


def format_table(rows: list[dict[str, str]], columns: list[tuple[str, str]]) -> str:
    """Format rows as a simple fixed-width table."""
    widths: list[int] = []
    for key, title in columns:
        width = len(title)
        for row in rows:
            width = max(width, len(row[key]))
        widths.append(width)

    header = " | ".join(
        title.ljust(widths[index]) for index, (_, title) in enumerate(columns)
    )
    divider = "-+-".join("-" * width for width in widths)
    lines = [header, divider]
    for row in rows:
        lines.append(
            " | ".join(
                row[key].ljust(widths[index])
                for index, (key, _) in enumerate(columns)
            )
        )
    return "\n".join(lines)


def pcluster_create_command(
    manifest: dict[str, Any], dryrun: bool, cluster_name: Optional[str] = None
) -> list[str]:
    """Build the ParallelCluster create-cluster command."""
    pcluster = manifest["parallelcluster"]
    target_cluster_name = cluster_name or pcluster["cluster_name"]
    command = [
        "pcluster",
        "create-cluster",
        "--cluster-name",
        target_cluster_name,
        "--cluster-configuration",
        pcluster["config_path"],
        "--region",
        pcluster["region"],
    ]
    if dryrun:
        command.extend(["--dryrun", "true"])
    return command


def pcluster_delete_command(manifest: dict[str, Any]) -> list[str]:
    """Build the ParallelCluster delete-cluster command."""
    pcluster = manifest["parallelcluster"]
    return [
        "pcluster",
        "delete-cluster",
        "--cluster-name",
        pcluster["cluster_name"],
        "--region",
        pcluster["region"],
    ]


def pcluster_describe_command(manifest: dict[str, Any]) -> list[str]:
    """Build the ParallelCluster describe-cluster command."""
    pcluster = manifest["parallelcluster"]
    return [
        "pcluster",
        "describe-cluster",
        "--cluster-name",
        pcluster["cluster_name"],
        "--region",
        pcluster["region"],
    ]


def pcluster_ssh_command(manifest: dict[str, Any]) -> list[str]:
    """Build the ParallelCluster SSH command for the head/login node."""
    pcluster = manifest["parallelcluster"]
    return [
        "pcluster",
        "ssh",
        "--cluster-name",
        pcluster["cluster_name"],
        "--region",
        pcluster["region"],
    ]


def bootstrap_upload_command(manifest: dict[str, Any]) -> list[str]:
    """Build the AWS CLI command to upload the ParallelCluster bootstrap script."""
    pcluster = manifest["parallelcluster"]
    return [
        "aws",
        "s3",
        "cp",
        pcluster["bootstrap_script_local_path"],
        pcluster["bootstrap_script_s3_uri"],
    ]


def active_instance_types_upload_command(manifest: dict[str, Any]) -> list[str]:
    """Build the AWS CLI command to upload the active instance type allowlist."""
    pcluster = manifest["parallelcluster"]
    return [
        "aws",
        "s3",
        "cp",
        pcluster["active_instance_types_local_path"],
        pcluster["active_instance_types_s3_uri"],
    ]


def bootstrap_upload_commands(manifest: dict[str, Any]) -> list[list[str]]:
    """Build all AWS CLI commands needed to upload node bootstrap assets."""
    return [
        bootstrap_upload_command(manifest),
        active_instance_types_upload_command(manifest),
    ]


def run_bootstrap_upload_commands(manifest: dict[str, Any]) -> None:
    """Upload all node bootstrap assets to S3."""
    for command in bootstrap_upload_commands(manifest):
        run_command(command)


def slurm_submit_commands(
    manifest: dict[str, Any], include_gpu: bool, include_expected_failures: bool
) -> list[list[str]]:
    """Build sbatch commands for repo-provided Slurm smoke tests."""
    commands: list[list[str]] = []
    for job in manifest["slurm_test_jobs"]:
        if job["requires_gpu"] and not include_gpu:
            continue
        if job["expected_result"] != "success" and not include_expected_failures:
            continue
        commands.append(["sbatch", job["script"]])
    return commands


def provision_plan_commands(manifest: dict[str, Any]) -> list[tuple[str, list[str]]]:
    """Build the ordered ParallelCluster provision and cleanup command plan."""
    architecture_args = [
        "--cluster-architecture",
        manifest["ec2_selection"]["cluster_architecture"],
    ]
    commands: list[tuple[str, list[str]]] = [
        (
            "validate generated ParallelCluster config",
            [
                "uv",
                "run",
                "aws-audit",
                "hpc",
                "execute-pcluster-dryrun",
                *architecture_args,
            ],
        ),
        (
            "create cluster",
            [
                "uv",
                "run",
                "aws-audit",
                "hpc",
                "create-cluster",
                *architecture_args,
            ],
        ),
        ("describe cluster", pcluster_describe_command(manifest)),
        ("ssh to head/login node", pcluster_ssh_command(manifest)),
    ]
    for command in slurm_submit_commands(manifest, True, True):
        commands.append(("submit Slurm smoke test", command))
    commands.append(
        (
            "delete cluster and tagged test storage after validation",
            [
                "uv",
                "run",
                "aws-audit",
                "hpc",
                "delete-cluster",
            ],
        )
    )
    return commands


def print_command(command: list[str]) -> None:
    """Print a shell-quoted command."""
    print(shlex.join(command))


def print_describe(manifest: dict[str, Any], stream: TextIO) -> None:
    """Print the adapted workflow plan from the manifest."""
    decision = manifest["decision"]
    pcluster = manifest["parallelcluster"]
    guardrails = manifest["login_guardrails"]
    print(f"Workflow: {manifest['name']} (v{manifest['version']})", file=stream)
    print(f"Scheduler: {decision['scheduler']}", file=stream)
    print(f"Cluster: {pcluster['cluster_name']}", file=stream)
    print(f"Region: {pcluster['region']}", file=stream)
    print(
        "Head/login node: "
        f"{head_node_instance_type(manifest)} "
        f"({pcluster['head_node']['root_volume_gib']} GiB root)",
        file=stream,
    )
    print(
        "Login guardrails: "
        f"{guardrails['cpu_quota']} CPU quota, "
        f"{guardrails['memory_max']} memory, "
        f"{guardrails['max_logins']} logins per user",
        file=stream,
    )
    print(f"/home: {decision['home_storage']} ({manifest['storage'][0]['deletion_policy']})", file=stream)
    print(f"/scratch: {decision['scratch_storage']} ({manifest['storage'][1]['deletion_policy']})", file=stream)
    print(f"Compute idle policy: {decision['compute_idle_policy']}", file=stream)
    print(f"Active cluster architecture: {manifest['ec2_selection']['cluster_architecture']}", file=stream)
    print(
        "Allowed catalog architectures: "
        f"{', '.join(manifest['ec2_selection']['catalog_architectures'])}",
        file=stream,
    )
    print("", file=stream)
    queue_columns = [
        ("queue", "Queue"),
        ("capacity", "Capacity"),
        ("instances", "Instance Types"),
        ("max", "Max"),
        ("purpose", "Purpose"),
    ]
    print(format_table(queue_summary_rows(manifest), queue_columns), file=stream)
    print("", file=stream)
    storage_columns = [
        ("name", "Name"),
        ("type", "Type"),
        ("mount", "Mount"),
        ("policy", "Deletion"),
        ("role", "Role"),
    ]
    print(format_table(storage_summary_rows(manifest), storage_columns), file=stream)


def ec2_instance_type_rows(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Fetch normalized EC2 instance type rows from the AWS EC2 API."""
    region = manifest["parallelcluster"]["region"]
    architectures = ",".join(manifest["ec2_selection"]["catalog_architectures"])
    return run_json(
        [
            "aws",
            "ec2",
            "describe-instance-types",
            "--region",
            region,
            "--filters",
            f"Name=processor-info.supported-architecture,Values={architectures}",
            "--query",
            (
                "InstanceTypes[].{"
                "InstanceType:InstanceType,"
                "Vcpus:VCpuInfo.DefaultVCpus,"
                "MemoryMiB:MemoryInfo.SizeInMiB,"
                "Architectures:ProcessorInfo.SupportedArchitectures,"
                "GpuCount:GpuInfo.Gpus[0].Count,"
                "GpuManufacturer:GpuInfo.Gpus[0].Manufacturer,"
                "BareMetal:BareMetal,"
                "CurrentGeneration:CurrentGeneration,"
                "SupportedUsageClasses:SupportedUsageClasses,"
                "NetworkCards:NetworkInfo.MaximumNetworkCards"
                "}"
            ),
        ]
    )


def available_instance_types(manifest: dict[str, Any]) -> set[str]:
    """Fetch instance types offered in the cluster region."""
    region = manifest["parallelcluster"]["region"]
    offerings = run_json(
        [
            "aws",
            "ec2",
            "describe-instance-type-offerings",
            "--region",
            region,
            "--location-type",
            "region",
            "--filters",
            f"Name=location,Values={region}",
            "--query",
            "InstanceTypeOfferings[].InstanceType",
        ]
    )
    return set(offerings)


def linux_on_demand_prices(manifest: dict[str, Any]) -> dict[str, float]:
    """Fetch Linux on-demand hourly prices by instance type from AWS Pricing."""
    region = manifest["parallelcluster"]["region"]
    filters = [
        {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Compute Instance"},
        {"Type": "TERM_MATCH", "Field": "location", "Value": pricing_location(region)},
        {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
        {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
        {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
        {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
    ]
    data = run_json(
        [
            "aws",
            "pricing",
            "get-products",
            "--region",
            PRICING_REGION,
            "--service-code",
            "AmazonEC2",
            "--filters",
            json.dumps(filters),
        ]
    )
    prices: dict[str, float] = {}
    for raw_item in data["PriceList"]:
        item = json.loads(raw_item)
        instance_type = item["product"]["attributes"]["instanceType"]
        on_demand_terms = item["terms"]["OnDemand"]
        for term in on_demand_terms.values():
            for dimension in term["priceDimensions"].values():
                if dimension["unit"] == "Hrs":
                    prices[instance_type] = float(dimension["pricePerUnit"]["USD"])
    return prices


def instance_queue(row: dict[str, Any], manifest: dict[str, Any]) -> str:
    """Return the queue name for an EC2 instance type row."""
    prefix = family_prefix(row["InstanceType"])
    gpu_count = row["GpuCount"]
    if gpu_count is not None and gpu_count > 0:
        if prefix in manifest["ec2_selection"]["gpu_prefixes"]:
            return "gpu"
        return "excluded"
    if prefix in manifest["ec2_selection"]["cpu_prefixes"]:
        return "cpu"
    return "excluded"


def row_architecture(row: dict[str, Any], manifest: dict[str, Any]) -> str:
    """Return the configured architecture bucket for an instance row."""
    for architecture in manifest["ec2_selection"]["catalog_architectures"]:
        if architecture in row["Architectures"]:
            return architecture
    return "excluded"


def is_generic_candidate(
    row: dict[str, Any],
    manifest: dict[str, Any],
    offered_types: set[str],
    prices: dict[str, float],
    cluster_architecture_only: bool,
) -> bool:
    """Return whether an instance type should be part of the generated cluster."""
    instance_type = row["InstanceType"]
    prefix = family_prefix(instance_type)
    architecture = row_architecture(row, manifest)
    if architecture == "excluded":
        return False
    if cluster_architecture_only and architecture != manifest["ec2_selection"]["cluster_architecture"]:
        return False
    if instance_type not in offered_types:
        return False
    if instance_type not in prices:
        return False
    if prefix in manifest["ec2_selection"]["excluded_prefixes"]:
        return False
    if row["BareMetal"]:
        return False
    if row["NetworkCards"] != 1:
        return False
    if "on-demand" not in row["SupportedUsageClasses"]:
        return False
    if row["Vcpus"] not in manifest["ec2_selection"]["vcpu_values"]:
        return False
    if row["MemoryMiB"] > manifest["ec2_selection"]["max_memory_mib"]:
        return False
    if instance_queue(row, manifest) == "excluded":
        return False
    gpu_count = row["GpuCount"]
    if gpu_count is not None and gpu_count > manifest["ec2_selection"]["max_gpu_count"]:
        return False
    if gpu_count is not None and gpu_count > 0 and row["GpuManufacturer"] != "NVIDIA":
        return False
    return True


def generic_candidate_rows(
    manifest: dict[str, Any], cluster_architecture_only: bool
) -> list[dict[str, Any]]:
    """Return all allowed EC2 candidates after policy, availability, and price filters."""
    offered_types = available_instance_types(manifest)
    prices = linux_on_demand_prices(manifest)
    rows: list[dict[str, Any]] = []
    for row in ec2_instance_type_rows(manifest):
        if is_generic_candidate(row, manifest, offered_types, prices, cluster_architecture_only):
            normalized = row.copy()
            normalized["HourlyPrice"] = prices[row["InstanceType"]]
            normalized["Queue"] = instance_queue(row, manifest)
            normalized["Architecture"] = row_architecture(row, manifest)
            normalized["GpuCountNormalized"] = row["GpuCount"] or NO_GPU_COUNT
            normalized["GpuManufacturerNormalized"] = (
                row["GpuManufacturer"] or NO_GPU_MANUFACTURER
            )
            rows.append(normalized)
    return rows


def cheapest_group_price(group: list[dict[str, Any]]) -> float:
    """Return the cheapest hourly price in a candidate group."""
    return min(row["HourlyPrice"] for row in group)


def priority_from_price(hourly_price: float) -> int:
    """Convert an hourly price into a Slurm dynamic node priority."""
    return max(1, math.ceil(hourly_price * 100000))


def compute_resource_name(queue: str, vcpus: int, memory_mib: int, gpu_count: int) -> str:
    """Build a compact ParallelCluster compute resource name."""
    if gpu_count == NO_GPU_COUNT:
        return f"{queue}-v{vcpus}-m{memory_mib}"
    return f"{queue}-v{vcpus}-m{memory_mib}-g{gpu_count}"


def grouped_candidates(manifest: dict[str, Any]) -> dict[str, list[list[dict[str, Any]]]]:
    """Return candidate EC2 instance groups keyed by Slurm queue."""
    rows = generic_candidate_rows(manifest, True)
    groups: dict[tuple[str, int, int, int, str], list[dict[str, Any]]] = {}
    for row in rows:
        key = (
            row["Queue"],
            row["Vcpus"],
            row["MemoryMiB"],
            row["GpuCountNormalized"],
            row["GpuManufacturerNormalized"],
        )
        if key not in groups:
            groups[key] = []
        groups[key].append(row)

    queue_groups: dict[str, list[list[dict[str, Any]]]] = {name: [] for name in QUEUE_ORDER}
    for key, group in groups.items():
        queue_name = key[0]
        group.sort(key=lambda item: (item["HourlyPrice"], item["InstanceType"]))
        queue_groups[queue_name].append(group[: manifest["ec2_selection"]["instances_per_shape"]])

    selected: dict[str, list[list[dict[str, Any]]]] = {name: [] for name in QUEUE_ORDER}
    for queue_name in QUEUE_ORDER:
        by_vcpu: dict[int, list[list[dict[str, Any]]]] = {}
        for group in queue_groups[queue_name]:
            vcpus = group[0]["Vcpus"]
            if vcpus not in by_vcpu:
                by_vcpu[vcpus] = []
            by_vcpu[vcpus].append(group)
        for vcpus in sorted(by_vcpu):
            candidate_groups = by_vcpu[vcpus]
            candidate_groups.sort(key=lambda group: (group[0]["MemoryMiB"], cheapest_group_price(group)))
            selected[queue_name].extend(
                candidate_groups[: manifest["ec2_selection"]["shapes_per_vcpu"]]
            )
    return selected


def queue_policy(manifest: dict[str, Any], queue_name: str) -> dict[str, Any]:
    """Return the configured queue policy for a queue name."""
    for queue in manifest["queue_policy"]:
        if queue["name"] == queue_name:
            return queue
    raise ValueError(f"Unknown queue {queue_name}")


def build_compute_resources(
    manifest: dict[str, Any], queue_name: str, groups: list[list[dict[str, Any]]]
) -> list[dict[str, Any]]:
    """Build ParallelCluster ComputeResources from generated instance groups."""
    policy = queue_policy(manifest, queue_name)
    resources: list[dict[str, Any]] = []
    for group in sorted(groups, key=lambda item: cheapest_group_price(item)):
        first = group[0]
        gpu_count = first["GpuCountNormalized"]
        resource: dict[str, Any] = {
            "Name": compute_resource_name(
                queue_name,
                first["Vcpus"],
                first["MemoryMiB"],
                gpu_count,
            ),
            "Instances": [
                {"InstanceType": item["InstanceType"]}
                for item in sorted(group, key=lambda row: (row["HourlyPrice"], row["InstanceType"]))
            ],
            "MinCount": 0,
            "MaxCount": policy["max_count_per_resource"],
            "DynamicNodePriority": priority_from_price(cheapest_group_price(group)),
            "SchedulableMemory": math.floor(first["MemoryMiB"] * 0.95),
        }
        if queue_name == "gpu":
            resource["HealthChecks"] = {"Gpu": {"Enabled": True}}
        resources.append(resource)
    return resources


def shared_storage_config(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Build the ParallelCluster SharedStorage section."""
    storage_items: list[dict[str, Any]] = []
    for item in manifest["storage"]:
        if item["storage_type"] == "Efs":
            storage_items.append(
                {
                    "Name": item["name"],
                    "StorageType": "Efs",
                    "MountDir": item["mount_dir"],
                    "EfsSettings": {
                        "Encrypted": True,
                        "EncryptionInTransit": True,
                        "PerformanceMode": "generalPurpose",
                        "ThroughputMode": "bursting",
                        "DeletionPolicy": item["deletion_policy"],
                    },
                }
            )
        if item["storage_type"] == "FsxLustre":
            storage_items.append(
                {
                    "Name": item["name"],
                    "StorageType": "FsxLustre",
                    "MountDir": item["mount_dir"],
                    "FsxLustreSettings": {
                        "StorageCapacity": item["storage_capacity_gib"],
                        "DeploymentType": item["deployment_type"],
                        "StorageType": item["fsx_storage_type"],
                        "DataCompressionType": "LZ4",
                        "DeletionPolicy": item["deletion_policy"],
                    },
                }
            )
    return storage_items


def custom_action_config(manifest: dict[str, Any], users: list[dict[str, Any]], head: bool) -> dict[str, Any]:
    """Build a ParallelCluster custom action for node user bootstrap."""
    args = [user_spec(users)]
    if head:
        args.append("--enforce-head-login-limits")
    return {
        "OnNodeConfigured": {
            "Script": manifest["parallelcluster"]["bootstrap_script_s3_uri"],
            "Args": args,
        }
    }


def head_custom_action_config(manifest: dict[str, Any], users: list[dict[str, Any]]) -> dict[str, Any]:
    """Build head-node custom actions for early Slurm policy and later login setup."""
    configured = custom_action_config(manifest, users, True)["OnNodeConfigured"]
    return {
        "OnNodeStart": {
            "Script": manifest["parallelcluster"]["bootstrap_script_s3_uri"],
            "Args": [
                "--install-slurm-policy-only",
                manifest["parallelcluster"]["active_instance_types_s3_uri"],
            ],
        },
        "OnNodeConfigured": configured,
    }


def queue_config(
    manifest: dict[str, Any],
    users: list[dict[str, Any]],
    queue_name: str,
    compute_resources: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a ParallelCluster Slurm queue."""
    queue = queue_policy(manifest, queue_name)
    pcluster = manifest["parallelcluster"]
    return {
        "Name": queue_name,
        "CapacityType": manifest["ec2_selection"]["capacity_type"],
        "AllocationStrategy": "lowest-price",
        "Networking": {
            "SubnetIds": pcluster["subnet_ids"],
        },
        "ComputeSettings": {
            "LocalStorage": {
                "RootVolume": {
                    "Size": pcluster["compute_root_volume_gib"],
                    "Encrypted": True,
                    "VolumeType": "gp3",
                },
                "EphemeralVolume": {"MountDir": "/local_scratch"},
            }
        },
        "CustomActions": custom_action_config(manifest, users, False),
        "Iam": {
            "AdditionalIamPolicies": [
                {"Policy": pcluster["assets_read_policy_arn"]},
            ]
        },
        "ComputeResources": compute_resources,
        "CustomSlurmSettings": {
            "DefMemPerCPU": queue["default_mem_per_cpu_mib"],
            "MaxMemPerCPU": queue["max_mem_per_cpu_mib"],
        },
    }


def generated_cluster_config(manifest: dict[str, Any]) -> dict[str, Any]:
    """Build a complete generated ParallelCluster configuration."""
    users = lab_users_from_iam(manifest)
    pcluster = manifest["parallelcluster"]
    generated_groups = grouped_candidates(manifest)
    slurm_queues: list[dict[str, Any]] = []
    for queue_name in QUEUE_ORDER:
        resources = build_compute_resources(manifest, queue_name, generated_groups[queue_name])
        slurm_queues.append(queue_config(manifest, users, queue_name, resources))

    return {
        "Region": pcluster["region"],
        "Image": {"Os": "ubuntu2204"},
        "Tags": [
            {"Key": "Project", "Value": pcluster["cluster_name"]},
            {"Key": "ManagedBy", "Value": "aws-parallelcluster"},
        ],
        "HeadNode": {
            "InstanceType": head_node_instance_type(manifest),
            "Networking": {
                "SubnetId": pcluster["subnet_ids"][0],
                "ElasticIp": False,
            },
            "Ssh": {
                "KeyName": pcluster["ssh"]["key_name"],
                "AllowedIps": pcluster["ssh"]["allowed_ips"],
            },
            "LocalStorage": {
                "RootVolume": {
                    "Size": pcluster["head_node"]["root_volume_gib"],
                    "Encrypted": True,
                    "VolumeType": "gp3",
                    "DeleteOnTermination": True,
                }
            },
            "Dcv": {"Enabled": False},
            "CustomActions": head_custom_action_config(manifest, users),
            "Iam": {
                "AdditionalIamPolicies": [
                    {"Policy": pcluster["assets_read_policy_arn"]},
                ]
            },
        },
        "SharedStorage": shared_storage_config(manifest),
        "Scheduling": {
            "Scheduler": "slurm",
            "ScalingStrategy": "all-or-nothing",
            "SlurmSettings": {
                "ScaledownIdletime": manifest["slurm"]["scaledown_idletime_minutes"],
                "EnableMemoryBasedScheduling": True,
                "CustomSlurmSettings": [
                    {"JobSubmitPlugins": "lua"},
                    {"SelectTypeParameters": "CR_Core_Memory"},
                ],
            },
            "SlurmQueues": slurm_queues,
        },
    }


def yaml_scalar(value: Any) -> str:
    """Render a scalar as a YAML-compatible value."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(value)
    return json.dumps(value)


def render_yaml(value: Any, indent: int = 0) -> str:
    """Render nested dict/list/scalar data as simple YAML."""
    prefix = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.append(render_yaml(item, indent + 2))
            else:
                lines.append(f"{prefix}{key}: {yaml_scalar(item)}")
        return "\n".join(lines)
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}-")
                lines.append(render_yaml(item, indent + 2))
            else:
                lines.append(f"{prefix}- {yaml_scalar(item)}")
        return "\n".join(lines)
    return f"{prefix}{yaml_scalar(value)}"


def active_instance_types_from_config(config: dict[str, Any]) -> list[str]:
    """Return active compute instance types from a generated ParallelCluster config."""
    instance_types: set[str] = set()
    queues = config["Scheduling"]["SlurmQueues"]
    for queue in queues:
        for resource in queue["ComputeResources"]:
            for item in resource["Instances"]:
                instance_types.add(item["InstanceType"])
    return sorted(instance_types)


def write_active_instance_types(manifest: dict[str, Any], config: dict[str, Any]) -> None:
    """Write the active compute instance type allowlist used by the login wrapper."""
    instance_types_path = Path(manifest["parallelcluster"]["active_instance_types_local_path"])
    text = "\n".join(active_instance_types_from_config(config)) + "\n"
    instance_types_path.write_text(text, encoding="utf-8")


def write_generated_config(manifest: dict[str, Any]) -> None:
    """Generate and write the ParallelCluster config file."""
    config = generated_cluster_config(manifest)
    config_path = Path(manifest["parallelcluster"]["config_path"])
    config_path.write_text(render_yaml(config) + "\n", encoding="utf-8")
    write_active_instance_types(manifest, config)


def wait_for_cluster_absent(manifest: dict[str, Any], timeout_seconds: int) -> None:
    """Wait until the configured cluster no longer appears in pcluster list output."""
    pcluster = manifest["parallelcluster"]
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        clusters = run_json(
            [
                "pcluster",
                "list-clusters",
                "--region",
                pcluster["region"],
            ]
        )["clusters"]
        names = [cluster["clusterName"] for cluster in clusters]
        if pcluster["cluster_name"] not in names:
            return
        time.sleep(30)
    raise TimeoutError(f"Timed out waiting for {pcluster['cluster_name']} deletion")


def wait_for_cluster_status(
    manifest: dict[str, Any], desired_status: str, timeout_seconds: int
) -> None:
    """Wait until the configured cluster reaches a target status."""
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        status = run_json(pcluster_describe_command(manifest))["clusterStatus"]
        if status == desired_status:
            return
        if status.endswith("FAILED") or status.endswith("ROLLBACK_COMPLETE"):
            raise RuntimeError(f"Cluster reached {status}")
        time.sleep(30)
    raise TimeoutError(f"Timed out waiting for {desired_status}")


def tagged_efs_ids(manifest: dict[str, Any]) -> list[str]:
    """Return EFS file systems tagged for the configured cluster."""
    pcluster = manifest["parallelcluster"]
    filesystems = run_json(
        [
            "aws",
            "efs",
            "describe-file-systems",
            "--region",
            pcluster["region"],
            "--query",
            (
                "FileSystems[?Tags[?Key==`parallelcluster:cluster-name` "
                f"&& Value==`{pcluster['cluster_name']}`]].FileSystemId"
            ),
        ]
    )
    return list(filesystems)


def tagged_fsx_ids(manifest: dict[str, Any]) -> list[str]:
    """Return FSx file systems tagged for the configured cluster."""
    pcluster = manifest["parallelcluster"]
    filesystems = run_json(
        [
            "aws",
            "fsx",
            "describe-file-systems",
            "--region",
            pcluster["region"],
            "--query",
            (
                "FileSystems[?Tags[?Key==`parallelcluster:cluster-name` "
                f"&& Value==`{pcluster['cluster_name']}`]].FileSystemId"
            ),
        ]
    )
    return list(filesystems)


def delete_efs_file_system(manifest: dict[str, Any], file_system_id: str) -> None:
    """Delete one EFS file system and its mount targets."""
    region = manifest["parallelcluster"]["region"]
    mount_targets = run_json(
        [
            "aws",
            "efs",
            "describe-mount-targets",
            "--region",
            region,
            "--file-system-id",
            file_system_id,
            "--query",
            "MountTargets[].MountTargetId",
        ]
    )
    for mount_target_id in mount_targets:
        run_command(
            [
                "aws",
                "efs",
                "delete-mount-target",
                "--region",
                region,
                "--mount-target-id",
                mount_target_id,
            ]
        )
    deadline = time.time() + 600
    while time.time() < deadline:
        remaining = run_json(
            [
                "aws",
                "efs",
                "describe-mount-targets",
                "--region",
                region,
                "--file-system-id",
                file_system_id,
                "--query",
                "MountTargets[].MountTargetId",
            ]
        )
        if len(remaining) == 0:
            break
        time.sleep(10)
    run_command(
        [
            "aws",
            "efs",
            "delete-file-system",
            "--region",
            region,
            "--file-system-id",
            file_system_id,
        ]
    )


def cleanup_tagged_storage(manifest: dict[str, Any]) -> None:
    """Delete tagged EFS and FSx storage left behind by test clusters."""
    region = manifest["parallelcluster"]["region"]
    for file_system_id in tagged_fsx_ids(manifest):
        run_command(
            [
                "aws",
                "fsx",
                "delete-file-system",
                "--region",
                region,
                "--file-system-id",
                file_system_id,
            ]
        )
    for file_system_id in tagged_efs_ids(manifest):
        delete_efs_file_system(manifest, file_system_id)


def add_cluster_architecture_argument(parser: argparse.ArgumentParser) -> None:
    """Add the active cluster architecture override argument to a subparser."""
    parser.add_argument(
        "--cluster-architecture",
        choices=CLUSTER_ARCHITECTURES,
        help="Override the active cluster architecture for generated head and compute nodes.",
    )


def handle_describe(args: argparse.Namespace) -> None:
    """Handle the describe subcommand."""
    manifest = load_configured_manifest(args)
    print_describe(manifest, sys.stdout)


def handle_generate_config(args: argparse.Namespace) -> None:
    """Handle the generate-config subcommand."""
    manifest = load_configured_manifest(args)
    write_generated_config(manifest)
    print(manifest["parallelcluster"]["config_path"])


def handle_list_users(args: argparse.Namespace) -> None:
    """Handle the list-users subcommand."""
    manifest = load_manifest(args.manifest)
    columns = [
        ("iam_user", "IAM User"),
        ("linux_user", "Linux User"),
        ("uid", "UID"),
    ]
    print(format_table(lab_user_rows(lab_users_from_iam(manifest)), columns))


def handle_list_slurm_jobs(args: argparse.Namespace) -> None:
    """Handle the list-slurm-jobs subcommand."""
    manifest = load_manifest(args.manifest)
    columns = [
        ("name", "Job"),
        ("partition", "Partition"),
        ("gpu", "GPU"),
        ("expected", "Expected"),
        ("script", "Script"),
    ]
    print(format_table(slurm_job_rows(manifest), columns))


def handle_list_instance_catalog(args: argparse.Namespace) -> None:
    """Handle the list-instance-catalog subcommand."""
    manifest = load_configured_manifest(args)
    columns = [
        ("queue", "Queue"),
        ("arch", "Arch"),
        ("instance", "Instance"),
        ("vcpu", "vCPU"),
        ("memory_gib", "GiB"),
        ("gpu", "GPU"),
        ("usd_hr", "USD/hr"),
        ("current", "Current"),
    ]
    print(format_table(instance_catalog_rows(manifest, args.active_cluster_only), columns))


def handle_future_alternatives(args: argparse.Namespace) -> None:
    """Handle the future-alternatives subcommand."""
    manifest = load_manifest(args.manifest)
    columns = [
        ("name", "Alternative"),
        ("status", "Status"),
        ("when", "When To Revisit"),
    ]
    print(format_table(future_alternative_rows(manifest), columns))


def handle_render_bootstrap_upload(args: argparse.Namespace) -> None:
    """Handle the render-bootstrap-upload subcommand."""
    manifest = load_manifest(args.manifest)
    for command in bootstrap_upload_commands(manifest):
        print_command(command)


def handle_render_pcluster_create(args: argparse.Namespace) -> None:
    """Handle the render-pcluster-create subcommand."""
    manifest = load_manifest(args.manifest)
    print_command(pcluster_create_command(manifest, args.dryrun))


def handle_render_pcluster_delete(args: argparse.Namespace) -> None:
    """Handle the render-pcluster-delete subcommand."""
    manifest = load_manifest(args.manifest)
    print_command(pcluster_delete_command(manifest))


def handle_render_slurm_tests(args: argparse.Namespace) -> None:
    """Handle the render-slurm-tests subcommand."""
    manifest = load_manifest(args.manifest)
    for command in slurm_submit_commands(
        manifest, args.include_gpu, args.include_expected_failures
    ):
        print_command(command)


def handle_render_provision_plan(args: argparse.Namespace) -> None:
    """Handle the render-provision-plan subcommand."""
    manifest = load_configured_manifest(args)
    for index, item in enumerate(provision_plan_commands(manifest), 1):
        label, command = item
        print(f"# {index}. {label}")
        print_command(command)
        print("")


def handle_execute_pcluster_dryrun(args: argparse.Namespace) -> None:
    """Handle the execute-pcluster-dryrun subcommand."""
    manifest = load_configured_manifest(args)
    write_generated_config(manifest)
    run_bootstrap_upload_commands(manifest)
    completed = subprocess.run(
        pcluster_create_command(
            manifest, True, f"{manifest['parallelcluster']['cluster_name']}-dryrun"
        ),
        capture_output=True,
        text=True,
        env=command_environment(),
    )
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr)
    if completed.returncode != 0 and "Request would have succeeded" not in completed.stdout:
        raise SystemExit(completed.returncode)


def handle_create_cluster(args: argparse.Namespace) -> None:
    """Handle the create-cluster subcommand."""
    manifest = load_configured_manifest(args)
    write_generated_config(manifest)
    run_bootstrap_upload_commands(manifest)
    run_command(pcluster_create_command(manifest, False))
    if args.wait:
        wait_for_cluster_status(manifest, "CREATE_COMPLETE", args.timeout_seconds)


def handle_delete_cluster(args: argparse.Namespace) -> None:
    """Handle the delete-cluster subcommand."""
    manifest = load_manifest(args.manifest)
    run_command(pcluster_delete_command(manifest))
    if args.wait:
        wait_for_cluster_absent(manifest, args.timeout_seconds)
    if args.cleanup_storage:
        cleanup_tagged_storage(manifest)


def handle_cleanup_storage(args: argparse.Namespace) -> None:
    """Handle the cleanup-storage subcommand."""
    manifest = load_manifest(args.manifest)
    cleanup_tagged_storage(manifest)


def build_parser() -> argparse.ArgumentParser:
    """Build the command line parser."""
    parser = argparse.ArgumentParser(
        description="Generate, create, test, and delete the AWS ParallelCluster Slurm workflow."
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help="Path to the AWS HPC workflow manifest.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    describe_parser = subparsers.add_parser(
        "describe", help="Print the ParallelCluster workflow plan."
    )
    add_cluster_architecture_argument(describe_parser)
    describe_parser.set_defaults(func=handle_describe)

    generate_parser = subparsers.add_parser(
        "generate-config",
        help="Generate the ParallelCluster config from IAM, EC2 catalog, and pricing.",
    )
    add_cluster_architecture_argument(generate_parser)
    generate_parser.set_defaults(func=handle_generate_config)

    users_parser = subparsers.add_parser(
        "list-users", help="Print Linux users generated from IAM groups."
    )
    users_parser.set_defaults(func=handle_list_users)

    jobs_parser = subparsers.add_parser(
        "list-slurm-jobs", help="Print repo-provided Slurm smoke-test jobs."
    )
    jobs_parser.set_defaults(func=handle_list_slurm_jobs)

    catalog_parser = subparsers.add_parser(
        "list-instance-catalog",
        help="Print allowed EC2 instance types from the live EC2 and Pricing catalogs.",
    )
    catalog_parser.add_argument(
        "--active-cluster-only",
        action="store_true",
        help="Only show instance types compatible with the generated cluster architecture.",
    )
    add_cluster_architecture_argument(catalog_parser)
    catalog_parser.set_defaults(func=handle_list_instance_catalog)

    alternatives_parser = subparsers.add_parser(
        "future-alternatives",
        help="Print future alternatives kept out of the active ParallelCluster path.",
    )
    alternatives_parser.set_defaults(func=handle_future_alternatives)

    upload_parser = subparsers.add_parser(
        "render-bootstrap-upload",
        help="Render the S3 upload command for the node bootstrap script.",
    )
    upload_parser.set_defaults(func=handle_render_bootstrap_upload)

    create_render_parser = subparsers.add_parser(
        "render-pcluster-create",
        help="Render the ParallelCluster create-cluster command.",
    )
    create_render_parser.add_argument("--dryrun", action="store_true")
    create_render_parser.set_defaults(func=handle_render_pcluster_create)

    delete_render_parser = subparsers.add_parser(
        "render-pcluster-delete",
        help="Render the ParallelCluster delete-cluster command.",
    )
    delete_render_parser.set_defaults(func=handle_render_pcluster_delete)

    slurm_parser = subparsers.add_parser(
        "render-slurm-tests",
        help="Render sbatch commands for Slurm smoke-test jobs.",
    )
    slurm_parser.add_argument("--include-gpu", action="store_true")
    slurm_parser.add_argument("--include-expected-failures", action="store_true")
    slurm_parser.set_defaults(func=handle_render_slurm_tests)

    plan_parser = subparsers.add_parser(
        "render-provision-plan",
        help="Render generate, upload, dry-run, create, test, and cleanup commands.",
    )
    add_cluster_architecture_argument(plan_parser)
    plan_parser.set_defaults(func=handle_render_provision_plan)

    dryrun_parser = subparsers.add_parser(
        "execute-pcluster-dryrun",
        help="Generate config, upload bootstrap, and run pcluster create-cluster --dryrun true.",
    )
    add_cluster_architecture_argument(dryrun_parser)
    dryrun_parser.set_defaults(func=handle_execute_pcluster_dryrun)

    create_parser = subparsers.add_parser(
        "create-cluster",
        help="One-command config generation, bootstrap upload, and cluster creation.",
    )
    add_cluster_architecture_argument(create_parser)
    create_parser.add_argument("--no-wait", action="store_false", dest="wait")
    create_parser.add_argument("--timeout-seconds", type=int, default=3600)
    create_parser.set_defaults(func=handle_create_cluster, wait=True)

    delete_parser = subparsers.add_parser(
        "delete-cluster",
        help="Delete the cluster and clean tagged test storage.",
    )
    delete_parser.add_argument("--no-wait", action="store_false", dest="wait")
    delete_parser.add_argument("--no-cleanup-storage", action="store_false", dest="cleanup_storage")
    delete_parser.add_argument("--timeout-seconds", type=int, default=3600)
    delete_parser.set_defaults(func=handle_delete_cluster, wait=True, cleanup_storage=True)

    cleanup_parser = subparsers.add_parser(
        "cleanup-storage",
        help="Delete EFS/FSx resources tagged for this test cluster.",
    )
    cleanup_parser.set_defaults(func=handle_cleanup_storage)

    return parser


def main() -> None:
    """Run the AWS ParallelCluster workflow helper CLI."""
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
