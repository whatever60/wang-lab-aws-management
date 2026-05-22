#!/usr/bin/env python3
import argparse
import csv
import json
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from openpyxl import Workbook

HOURS_PER_MONTH = 730
PRICING_CACHE_TTL_SECONDS = 24 * 60 * 60
PRICING_CACHE_VERSION = 2
AMI_CREATOR_EVENT_NAMES = ["CreateImage", "RegisterImage", "CopyImage"]
AMI_CREATOR_LOOKUP_DAYS = 90


def run_aws_json(args: List[str], region: Optional[str]) -> Dict[str, Any]:
    cmd = ["aws"] + args + ["--output", "json"]
    if region:
        cmd.extend(["--region", region])
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"AWS CLI command failed: {' '.join(cmd)}\n{proc.stderr.strip()}"
        )
    return json.loads(proc.stdout or "{}")


def detect_default_region() -> Optional[str]:
    proc = subprocess.run(
        ["aws", "configure", "get", "region"], capture_output=True, text=True
    )
    region = (proc.stdout or "").strip()
    return region if region else None


def list_enabled_regions() -> List[str]:
    """Return enabled EC2 region names for the current AWS account."""
    data = run_aws_json(["ec2", "describe-regions"], None)
    return sorted(region["RegionName"] for region in data["Regions"])


def parse_aws_datetime(value: str) -> datetime:
    """Parse an AWS ISO timestamp into a UTC datetime."""
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def pricing_cache_path(region: str) -> Path:
    return Path(".cache") / "aws-pricing" / f"{region}.json"


def load_cached_pricing(region: str, max_age_seconds: int) -> Optional[Dict[str, Any]]:
    path = pricing_cache_path(region)
    if not path.exists():
        return None
    age = time.time() - path.stat().st_mtime
    if age > max_age_seconds:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if data.get("cache_version") != PRICING_CACHE_VERSION:
        return None
    return data


def save_cached_pricing(region: str, data: Dict[str, Any]) -> None:
    path = pricing_cache_path(region)
    path.parent.mkdir(parents=True, exist_ok=True)
    to_cache = {"cache_version": PRICING_CACHE_VERSION, **data}
    path.write_text(json.dumps(to_cache), encoding="utf-8")


def fetch_json(url: str) -> Dict[str, Any]:
    with urllib.request.urlopen(url) as response:
        return json.loads(response.read().decode("utf-8"))


def usd_from_term(term: Dict[str, Any]) -> Optional[float]:
    for dim in term.get("priceDimensions", {}).values():
        if dim.get("unit") in {"Hrs", "GB-Mo"}:
            usd = dim.get("pricePerUnit", {}).get("USD")
            if usd is not None and usd != "":
                try:
                    return float(usd)
                except ValueError:
                    return None
    return None


def parse_pricing(region_code: str, region_data: Dict[str, Any]) -> Dict[str, Any]:
    products = region_data.get("products", {})
    terms = region_data.get("terms", {}).get("OnDemand", {})
    instance_hourly: Dict[str, float] = {}
    storage_monthly_per_gb: Dict[str, float] = {}

    for sku, product in products.items():
        attrs = product.get("attributes", {})
        if attrs.get("regionCode") != region_code:
            continue

        product_family = product.get("productFamily")
        sku_terms = terms.get(sku, {})
        if not sku_terms:
            continue
        term = next(iter(sku_terms.values()), None)
        if not term:
            continue
        price = usd_from_term(term)
        if price is None:
            continue

        if product_family == "Compute Instance":
            if attrs.get("operatingSystem") != "Linux":
                continue
            if attrs.get("tenancy") != "Shared":
                continue
            if attrs.get("preInstalledSw") not in {"NA", None, ""}:
                continue
            capacity_status = attrs.get("capacitystatus")
            if capacity_status not in {None, "", "Used"}:
                continue
            if price <= 0:
                continue
            instance_type = attrs.get("instanceType")
            if instance_type:
                current = instance_hourly.get(instance_type)
                if current is None or price < current:
                    instance_hourly[instance_type] = price
        elif product_family == "Storage":
            volume_api_name = attrs.get("volumeApiName")
            if volume_api_name and price > 0:
                current = storage_monthly_per_gb.get(volume_api_name)
                if current is None or price < current:
                    storage_monthly_per_gb[volume_api_name] = price

    return {
        "instance_hourly": instance_hourly,
        "storage_monthly_per_gb": storage_monthly_per_gb,
    }


def fetch_pricing_for_region(region: str, no_cache: bool = False) -> Dict[str, Any]:
    if not no_cache:
        cached = load_cached_pricing(region, PRICING_CACHE_TTL_SECONDS)
        if cached is not None:
            return cached

    region_index_url = (
        "https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/current/region_index.json"
    )
    region_index = fetch_json(region_index_url)
    region_entry = region_index.get("regions", {}).get(region)
    if not region_entry:
        raise RuntimeError(f"Region {region} not found in AWS public pricing index.")
    relative_url = region_entry.get("currentVersionUrl")
    if not relative_url:
        raise RuntimeError(f"Region {region} has no pricing data URL.")

    region_url = f"https://pricing.us-east-1.amazonaws.com{relative_url}"
    region_data = fetch_json(region_url)
    parsed = parse_pricing(region, region_data)
    save_cached_pricing(region, parsed)
    return parsed


def fmt_money(amount: Optional[float]) -> str:
    if amount is None:
        return ""
    return f"{amount:.5f}"


def tag_value(resource: Dict[str, Any], key: str) -> str:
    """Return a tag value by key for an AWS resource dict."""
    tags = resource.get("Tags", [])
    for tag in tags:
        if tag.get("Key") == key:
            return tag.get("Value", "")
    return ""


def print_rows(
    rows: List[Dict[str, Any]],
    columns: List[Tuple[str, str]],
    fmt: str,
    output: Optional[Path] = None,
) -> None:
    if output is not None:
        suffix = output.suffix.lower()
        if suffix == ".csv":
            fmt = "csv"
        elif suffix == ".json":
            fmt = "json"
        elif suffix == ".xlsx":
            fmt = "xlsx"
        elif suffix in {".txt", ".table"}:
            fmt = "table"
        else:
            raise RuntimeError(
                "Unsupported output extension. Use one of: .csv, .json, .xlsx, .txt, .table."
            )
        output.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        payload = json.dumps(rows, indent=2)
        if output is None:
            print(payload)
        else:
            output.write_text(payload + "\n", encoding="utf-8")
        return

    if fmt == "csv":
        if output is None:
            writer = csv.writer(sys.stdout)
            writer.writerow([col[0] for col in columns])
            for row in rows:
                writer.writerow([row.get(key, "") for key, _ in columns])
        else:
            with output.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow([col[0] for col in columns])
                for row in rows:
                    writer.writerow([row.get(key, "") for key, _ in columns])
        return

    if fmt == "xlsx":
        if output is None:
            raise RuntimeError("xlsx output requires --output with a .xlsx extension.")
        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "data"
        sheet.append([col[0] for col in columns])
        for row in rows:
            sheet.append([row.get(key, "") for key, _ in columns])
        workbook.save(output)
        return

    widths = []
    for key, title in columns:
        width = len(title)
        for row in rows:
            width = max(width, len(str(row.get(key, ""))))
        widths.append(width)

    header = " | ".join(
        title.ljust(widths[i]) for i, (_, title) in enumerate(columns)
    )
    divider = "-+-".join("-" * w for w in widths)
    lines = [header, divider]
    for row in rows:
        line = " | ".join(
            str(row.get(key, "")).ljust(widths[i]) for i, (key, _) in enumerate(columns)
        )
        lines.append(line)
    table_text = "\n".join(lines)
    if output is None:
        print(table_text)
    else:
        output.write_text(table_text + "\n", encoding="utf-8")


def build_instance_volume_rows(
    region: str, pricing: Dict[str, Any]
) -> List[Dict[str, Any]]:
    instances = run_aws_json(["ec2", "describe-instances"], region).get("Reservations", [])
    volumes = run_aws_json(["ec2", "describe-volumes"], region).get("Volumes", [])

    instance_by_id: Dict[str, Dict[str, Any]] = {}
    for reservation in instances:
        for instance in reservation.get("Instances", []):
            instance_by_id[instance["InstanceId"]] = instance

    instance_hourly = pricing.get("instance_hourly", {})
    storage_monthly_per_gb = pricing.get("storage_monthly_per_gb", {})

    rows: List[Dict[str, Any]] = []
    matched_instance_ids = set()

    for volume in volumes:
        attachments = volume.get("Attachments", [])
        if attachments:
            for attachment in attachments:
                iid = attachment.get("InstanceId", "")
                inst = instance_by_id.get(iid, {})
                matched_instance_ids.add(iid)
                instance_type = inst.get("InstanceType", "")
                instance_price_hour = instance_hourly.get(instance_type)
                volume_type = volume.get("VolumeType", "")
                vol_price_gb = storage_monthly_per_gb.get(volume_type)
                volume_size = volume.get("Size", 0)
                rows.append(
                    {
                        "key_name": inst.get("KeyName", ""),
                        "instance_name": tag_value(inst, "Name"),
                        "instance_id": iid,
                        "instance_type": instance_type,
                        "instance_state": (inst.get("State") or {}).get("Name", ""),
                        "volume_id": volume.get("VolumeId", ""),
                        "volume_name": tag_value(volume, "Name"),
                        "device": attachment.get("Device", ""),
                        "volume_type": volume_type,
                        "volume_size_gib": volume_size,
                        "ec2_price_per_hour_usd": fmt_money(instance_price_hour),
                        "ec2_price_per_month_usd": fmt_money(
                            instance_price_hour * HOURS_PER_MONTH
                            if instance_price_hour is not None
                            else None
                        ),
                        "storage_price_per_month_usd": fmt_money(
                            vol_price_gb * volume_size if vol_price_gb is not None else None
                        ),
                    }
                )
        else:
            volume_type = volume.get("VolumeType", "")
            vol_price_gb = storage_monthly_per_gb.get(volume_type)
            volume_size = volume.get("Size", 0)
            rows.append(
                {
                    "key_name": "",
                    "instance_name": "",
                    "instance_id": "",
                    "instance_type": "",
                    "instance_state": "",
                    "volume_id": volume.get("VolumeId", ""),
                    "volume_name": tag_value(volume, "Name"),
                    "device": "",
                    "volume_type": volume_type,
                    "volume_size_gib": volume_size,
                    "ec2_price_per_hour_usd": "",
                    "ec2_price_per_month_usd": "",
                    "storage_price_per_month_usd": fmt_money(
                        vol_price_gb * volume_size if vol_price_gb is not None else None
                    ),
                }
            )

    for iid, inst in instance_by_id.items():
        if iid in matched_instance_ids:
            continue
        instance_type = inst.get("InstanceType", "")
        instance_price_hour = instance_hourly.get(instance_type)
        rows.append(
            {
                "key_name": inst.get("KeyName", ""),
                "instance_name": tag_value(inst, "Name"),
                "instance_id": iid,
                "instance_type": instance_type,
                "instance_state": (inst.get("State") or {}).get("Name", ""),
                "volume_id": "",
                "volume_name": "",
                "device": "",
                "volume_type": "",
                "volume_size_gib": "",
                "ec2_price_per_hour_usd": fmt_money(instance_price_hour),
                "ec2_price_per_month_usd": fmt_money(
                    instance_price_hour * HOURS_PER_MONTH
                    if instance_price_hour is not None
                    else None
                ),
                "storage_price_per_month_usd": "",
            }
        )

    rows.sort(
        key=lambda row: (
            str(row.get("key_name", "")),
            float(row["ec2_price_per_hour_usd"]) if row["ec2_price_per_hour_usd"] else float("inf"),
        )
    )
    return rows


def build_snapshot_rows(region: str) -> List[Dict[str, Any]]:
    volumes = run_aws_json(["ec2", "describe-volumes"], region).get("Volumes", [])
    snapshots = run_aws_json(["ec2", "describe-snapshots", "--owner-ids", "self"], region).get(
        "Snapshots", []
    )
    images = run_aws_json(["ec2", "describe-images", "--owners", "self"], region).get(
        "Images", []
    )

    volume_by_id = {v["VolumeId"]: v for v in volumes}
    ami_refs: Dict[str, List[str]] = {}
    ami_name_by_id: Dict[str, str] = {}
    for image in images:
        image_id = image.get("ImageId", "")
        ami_name_by_id[image_id] = image.get("Name", "")
        for mapping in image.get("BlockDeviceMappings", []):
            ebs = mapping.get("Ebs") or {}
            snapshot_id = ebs.get("SnapshotId")
            if snapshot_id:
                ami_refs.setdefault(snapshot_id, []).append(image_id)

    rows: List[Dict[str, Any]] = []
    for snap in snapshots:
        snapshot_id = snap.get("SnapshotId", "")
        volume_id = snap.get("VolumeId", "")
        volume = volume_by_id.get(volume_id)
        attachments = (volume or {}).get("Attachments", [])
        attached_instance_ids = sorted(
            {att.get("InstanceId", "") for att in attachments if att.get("InstanceId")}
        )
        ami_ids = sorted(set(ami_refs.get(snapshot_id, [])))
        ami_names = [ami_name_by_id.get(ami_id, "") for ami_id in ami_ids]

        status_parts = []
        if attached_instance_ids:
            status_parts.append("ATTACHED_VOLUME")
        if ami_ids:
            status_parts.append("USED_BY_AMI")
        if volume and not attached_instance_ids:
            status_parts.append("EXISTING_VOLUME")
        if not status_parts:
            status_parts.append("DANGLING")

        rows.append(
            {
                "snapshot_id": snapshot_id,
                "snapshot_name": tag_value(snap, "Name"),
                "size_gib": snap.get("VolumeSize", ""),
                "volume_id": volume_id,
                "volume_name": tag_value(volume, "Name") if volume else "",
                "volume_exists": bool(volume),
                "attached_instance_ids": ";".join(attached_instance_ids),
                "ami_ids": ";".join(ami_ids),
                "ami_names": ";".join([name for name in ami_names if name]),
                "storage_tier": snap.get("StorageTier", ""),
                "start_time": snap.get("StartTime", ""),
                "description": (snap.get("Description", "") or "").replace("\n", " "),
                "status": ",".join(status_parts),
            }
        )

    rows.sort(key=lambda row: int(row.get("size_gib") or 0), reverse=True)
    return rows


def collect_ami_ids(value: Any) -> Set[str]:
    """Collect AMI IDs from nested CloudTrail response data."""
    ami_ids: Set[str] = set()
    if isinstance(value, str):
        if value.startswith("ami-"):
            ami_ids.add(value)
    elif isinstance(value, list):
        for item in value:
            ami_ids.update(collect_ami_ids(item))
    elif isinstance(value, dict):
        for item in value.values():
            ami_ids.update(collect_ami_ids(item))
    return ami_ids


def collect_snapshot_ids(images: List[Dict[str, Any]]) -> List[str]:
    """Collect EBS snapshot IDs referenced by AMI block device mappings."""
    snapshot_ids: Set[str] = set()
    for image in images:
        mappings = image["BlockDeviceMappings"] if "BlockDeviceMappings" in image else []
        for mapping in mappings:
            if "Ebs" in mapping and "SnapshotId" in mapping["Ebs"]:
                snapshot_ids.add(mapping["Ebs"]["SnapshotId"])
    return sorted(snapshot_ids)


def describe_snapshots_by_id(
    region: str, snapshot_ids: List[str]
) -> Dict[str, Dict[str, Any]]:
    """Load snapshot metadata for the given snapshot IDs."""
    snapshots: Dict[str, Dict[str, Any]] = {}
    if not snapshot_ids:
        return snapshots

    chunk_size = 200
    for start in range(0, len(snapshot_ids), chunk_size):
        chunk = snapshot_ids[start : start + chunk_size]
        data = run_aws_json(["ec2", "describe-snapshots", "--snapshot-ids", *chunk], region)
        for snapshot in data["Snapshots"]:
            snapshots[snapshot["SnapshotId"]] = snapshot
    return snapshots


def lookup_cloudtrail_events(region: str, event_name: str) -> List[Dict[str, Any]]:
    """Load recent CloudTrail events for one event name in one region."""
    start_time = (
        datetime.now(timezone.utc) - timedelta(days=AMI_CREATOR_LOOKUP_DAYS)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    base_args = [
        "cloudtrail",
        "lookup-events",
        "--lookup-attributes",
        f"AttributeKey=EventName,AttributeValue={event_name}",
        "--start-time",
        start_time,
    ]
    events: List[Dict[str, Any]] = []
    next_token = ""
    while True:
        args = list(base_args)
        if next_token:
            args.extend(["--next-token", next_token])
        data = run_aws_json(args, region)
        events.extend(data["Events"])
        if "NextToken" not in data:
            break
        next_token = data["NextToken"]
    return events


def load_creator_by_ami(region: str) -> Dict[str, Dict[str, str]]:
    """Load best-effort AMI creator information from recent CloudTrail events."""
    creators: Dict[str, Dict[str, str]] = {}
    for event_name in AMI_CREATOR_EVENT_NAMES:
        for event in lookup_cloudtrail_events(region, event_name):
            detail = json.loads(event["CloudTrailEvent"])
            response_elements = detail["responseElements"]
            if response_elements is None:
                continue
            image_ids = collect_ami_ids(response_elements)
            for image_id in image_ids:
                if image_id in creators:
                    continue
                creators[image_id] = {
                    "created_by_username": event["Username"],
                    "created_by_arn": detail["userIdentity"]["arn"],
                    "create_event_name": event_name,
                    "create_event_time": detail["eventTime"],
                    "cloudtrail_event_id": event["EventId"],
                    "creator_lookup_status": "found",
                }
    return creators


def ami_creator_missing_status(image: Dict[str, Any]) -> str:
    """Return why recent CloudTrail did not provide AMI creator details."""
    creation_time = parse_aws_datetime(image["CreationDate"])
    cutoff = datetime.now(timezone.utc) - timedelta(days=AMI_CREATOR_LOOKUP_DAYS)
    if creation_time < cutoff:
        return "unknown_cloudtrail_retention"
    return "unknown_cloudtrail_lookup"


def block_device_size_gib(
    mapping: Dict[str, Any], snapshots_by_id: Dict[str, Dict[str, Any]]
) -> int:
    """Return an EBS block device size in GiB."""
    if "Ebs" not in mapping:
        return 0
    ebs = mapping["Ebs"]
    if "VolumeSize" in ebs:
        return int(ebs["VolumeSize"])
    if "SnapshotId" in ebs:
        return int(snapshots_by_id[ebs["SnapshotId"]]["VolumeSize"])
    return 0


def describe_ami_block_devices(
    image: Dict[str, Any], snapshots_by_id: Dict[str, Dict[str, Any]]
) -> Tuple[int, int, str, str]:
    """Return total size, snapshot count, snapshot IDs, and compact device details."""
    total_size_gib = 0
    snapshot_ids: List[str] = []
    device_parts: List[str] = []
    mappings = image["BlockDeviceMappings"] if "BlockDeviceMappings" in image else []
    for mapping in mappings:
        size_gib = block_device_size_gib(mapping, snapshots_by_id)
        total_size_gib += size_gib
        snapshot_id = ""
        if "Ebs" in mapping and "SnapshotId" in mapping["Ebs"]:
            snapshot_id = mapping["Ebs"]["SnapshotId"]
            snapshot_ids.append(snapshot_id)
        if size_gib:
            device_parts.append(f"{mapping['DeviceName']}:{size_gib}GiB:{snapshot_id}")
    return total_size_gib, len(snapshot_ids), ";".join(snapshot_ids), ";".join(device_parts)


def optional_image_value(image: Dict[str, Any], key: str) -> str:
    """Return an optional AMI field as text."""
    if key in image:
        return str(image[key])
    return ""


def build_ami_rows(regions: List[str], include_creator: bool = True) -> List[Dict[str, Any]]:
    """Build AMI audit rows across regions."""
    rows: List[Dict[str, Any]] = []
    for region in regions:
        images = run_aws_json(["ec2", "describe-images", "--owners", "self"], region)["Images"]
        snapshots_by_id = describe_snapshots_by_id(region, collect_snapshot_ids(images))
        creator_by_ami = load_creator_by_ami(region) if include_creator else {}

        for image in images:
            image_id = image["ImageId"]
            total_size_gib, snapshot_count, snapshot_ids, block_devices = (
                describe_ami_block_devices(image, snapshots_by_id)
            )
            if image_id in creator_by_ami:
                creator = creator_by_ami[image_id]
            else:
                missing_status = ami_creator_missing_status(image)
                creator = {
                    "created_by_username": missing_status,
                    "created_by_arn": "",
                    "create_event_name": "",
                    "create_event_time": "",
                    "cloudtrail_event_id": "",
                    "creator_lookup_status": missing_status,
                }
            rows.append(
                {
                    "region": region,
                    "ami_id": image_id,
                    "name": optional_image_value(image, "Name"),
                    "total_size_gib": total_size_gib,
                    "snapshot_count": snapshot_count,
                    "creation_date": image["CreationDate"],
                    "last_launched_time": optional_image_value(image, "LastLaunchedTime"),
                    "created_by_username": creator["created_by_username"],
                    "created_by_arn": creator["created_by_arn"],
                    "create_event_name": creator["create_event_name"],
                    "create_event_time": creator["create_event_time"],
                    "creator_lookup_status": creator["creator_lookup_status"],
                    "source_instance_id": optional_image_value(image, "SourceInstanceId"),
                    "source_image_id": optional_image_value(image, "SourceImageId"),
                    "platform_details": optional_image_value(image, "PlatformDetails"),
                    "architecture": optional_image_value(image, "Architecture"),
                    "state": optional_image_value(image, "State"),
                    "public": optional_image_value(image, "Public"),
                    "root_device_name": optional_image_value(image, "RootDeviceName"),
                    "snapshot_ids": snapshot_ids,
                    "block_devices": block_devices,
                    "cloudtrail_event_id": creator["cloudtrail_event_id"],
                }
            )

    rows.sort(
        key=lambda row: (
            -int(row["total_size_gib"]),
            str(row["region"]),
            str(row["name"]),
            str(row["ami_id"]),
        )
    )
    return rows


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build joined EC2/EBS tables for cost and snapshot audit analysis."
    )
    parser.add_argument(
        "--region",
        default=detect_default_region(),
        help="AWS region. Defaults to configured aws CLI region.",
    )
    parser.add_argument(
        "--format",
        choices=["table", "csv", "json"],
        default="table",
        help="Output format.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    c1 = sub.add_parser("instance-volume-table", help="Generate instance/volume/cost table.")
    c1.add_argument(
        "--no-price-cache",
        action="store_true",
        help="Always refresh pricing from AWS pricing endpoint.",
    )
    c1.add_argument(
        "--output",
        type=Path,
        help=(
            "Write output to file and auto-detect format from extension "
            "(.csv, .json, .xlsx, .txt, .table)."
        ),
    )

    c2 = sub.add_parser(
        "snapshot-audit-table",
        help="Generate snapshot table joined with volumes and AMIs to find dangling snapshots.",
    )
    c2.add_argument(
        "--output",
        type=Path,
        help=(
            "Write output to file and auto-detect format from extension "
            "(.csv, .json, .xlsx, .txt, .table)."
        ),
    )

    c3 = sub.add_parser(
        "ami-audit-table",
        help="Generate an AMI table sorted by total EBS-backed image size.",
    )
    c3.add_argument(
        "--all-regions",
        action="store_true",
        help="Scan all enabled EC2 regions instead of only --region.",
    )
    c3.add_argument(
        "--skip-cloudtrail-creator",
        action="store_true",
        help="Skip CloudTrail lookup for best-effort AMI creator attribution.",
    )
    c3.add_argument(
        "--output",
        type=Path,
        help=(
            "Write output to file and auto-detect format from extension "
            "(.csv, .json, .xlsx, .txt, .table)."
        ),
    )
    return parser


def main() -> int:
    parser = get_parser()
    args = parser.parse_args()

    if not args.region and not (
        args.command == "ami-audit-table" and args.all_regions
    ):
        print(
            "No AWS region found. Set --region or configure one via `aws configure`.",
            file=sys.stderr,
        )
        return 2

    if args.command == "instance-volume-table":
        pricing = fetch_pricing_for_region(args.region, no_cache=args.no_price_cache)
        rows = build_instance_volume_rows(args.region, pricing)
        columns = [
            ("key_name", "key_name"),
            ("instance_name", "instance_name"),
            ("instance_id", "instance_id"),
            ("instance_type", "instance_type"),
            ("instance_state", "instance_state"),
            ("volume_id", "volume_id"),
            ("volume_name", "volume_name"),
            ("device", "device"),
            ("volume_type", "volume_type"),
            ("volume_size_gib", "volume_size_gib"),
            ("ec2_price_per_hour_usd", "ec2_price_per_hour_usd"),
            ("ec2_price_per_month_usd", "ec2_price_per_month_usd"),
            ("storage_price_per_month_usd", "storage_price_per_month_usd"),
        ]
        print_rows(rows, columns, args.format, args.output)
        return 0

    if args.command == "snapshot-audit-table":
        rows = build_snapshot_rows(args.region)
        columns = [
            ("snapshot_id", "snapshot_id"),
            ("snapshot_name", "snapshot_name"),
            ("size_gib", "size_gib"),
            ("volume_id", "volume_id"),
            ("volume_name", "volume_name"),
            ("volume_exists", "volume_exists"),
            ("attached_instance_ids", "attached_instance_ids"),
            ("ami_ids", "ami_ids"),
            ("ami_names", "ami_names"),
            ("storage_tier", "storage_tier"),
            ("start_time", "start_time"),
            ("status", "status"),
            ("description", "description"),
        ]
        print_rows(rows, columns, args.format, args.output)
        return 0

    if args.command == "ami-audit-table":
        regions = list_enabled_regions() if args.all_regions else [args.region]
        rows = build_ami_rows(
            regions, include_creator=not args.skip_cloudtrail_creator
        )
        columns = [
            ("region", "region"),
            ("ami_id", "ami_id"),
            ("name", "name"),
            ("total_size_gib", "total_size_gib"),
            ("snapshot_count", "snapshot_count"),
            ("creation_date", "creation_date"),
            ("last_launched_time", "last_launched_time"),
            ("created_by_username", "created_by_username"),
            ("created_by_arn", "created_by_arn"),
            ("create_event_name", "create_event_name"),
            ("create_event_time", "create_event_time"),
            ("creator_lookup_status", "creator_lookup_status"),
            ("source_instance_id", "source_instance_id"),
            ("source_image_id", "source_image_id"),
            ("platform_details", "platform_details"),
            ("architecture", "architecture"),
            ("state", "state"),
            ("public", "public"),
            ("root_device_name", "root_device_name"),
            ("snapshot_ids", "snapshot_ids"),
            ("block_devices", "block_devices"),
            ("cloudtrail_event_id", "cloudtrail_event_id"),
        ]
        print_rows(rows, columns, args.format, args.output)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
