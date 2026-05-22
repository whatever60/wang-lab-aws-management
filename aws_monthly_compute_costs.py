#!/usr/bin/env python3
import argparse
import csv
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Union


def run_aws_json(args: list[str]) -> dict[str, Any]:
    """Run an AWS CLI command and parse its JSON output."""
    completed = subprocess.run(
        ["aws", *args, "--output", "json"],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"AWS CLI command failed: aws {' '.join(args)} --output json\n"
            f"{completed.stderr.strip()}"
        )
    return json.loads(completed.stdout)


def parse_aws_time(value: str) -> datetime:
    """Parse an AWS timestamp into UTC."""
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def month_bounds(month: str) -> tuple[str, str, datetime, datetime]:
    """Return Cost Explorer date strings and UTC datetimes for a YYYY-MM month."""
    start = datetime.strptime(f"{month}-01", "%Y-%m-%d").replace(tzinfo=timezone.utc)
    if start.month == 12:
        end = start.replace(year=start.year + 1, month=1)
    else:
        end = start.replace(month=start.month + 1)
    return start.date().isoformat(), end.date().isoformat(), start, end


def load_compute_cost_by_region_type(
    start_date: str, end_date: str
) -> dict[tuple[str, str], dict[str, float]]:
    """Load actual EC2 instance-hour compute cost and hours from Cost Explorer."""
    data = run_aws_json(
        [
            "ce",
            "get-cost-and-usage",
            "--time-period",
            f"Start={start_date},End={end_date}",
            "--granularity",
            "MONTHLY",
            "--metrics",
            "UsageQuantity",
            "UnblendedCost",
            "--filter",
            '{"Dimensions":{"Key":"SERVICE","Values":["Amazon Elastic Compute Cloud - Compute"]}}',
            "--group-by",
            "Type=DIMENSION,Key=REGION",
            "Type=DIMENSION,Key=USAGE_TYPE",
        ]
    )
    rows: dict[tuple[str, str], dict[str, float]] = {}
    for group in data["ResultsByTime"][0]["Groups"]:
        region = group["Keys"][0]
        usage_type = group["Keys"][1]
        if usage_type.startswith("BoxUsage:"):
            instance_type = usage_type.split(":", 1)[1]
            rows[(region, instance_type)] = {
                "cost": float(group["Metrics"]["UnblendedCost"]["Amount"]),
                "hours": float(group["Metrics"]["UsageQuantity"]["Amount"]),
            }
    return rows


def load_creator_by_instance(
    region: str, lookup_start_date: str, end_date: str
) -> dict[str, dict[str, str]]:
    """Load RunInstances creator ARN and username mappings from CloudTrail."""
    data = run_aws_json(
        [
            "cloudtrail",
            "lookup-events",
            "--lookup-attributes",
            "AttributeKey=EventName,AttributeValue=RunInstances",
            "--start-time",
            f"{lookup_start_date}T00:00:00Z",
            "--end-time",
            f"{end_date}T00:00:00Z",
            "--region",
            region,
        ]
    )
    creators: dict[str, dict[str, str]] = {}
    for event in data["Events"]:
        detail = json.loads(event["CloudTrailEvent"])
        if detail["responseElements"] is None:
            continue
        if "instancesSet" not in detail["responseElements"]:
            continue
        arn = detail["userIdentity"]["arn"]
        username = event["Username"]
        for item in detail["responseElements"]["instancesSet"]["items"]:
            creators[item["instanceId"]] = {
                "creator_arn": arn,
                "creator_username": username,
            }
    return creators


def load_config_instance_ids(region: str) -> list[str]:
    """Load EC2 instance IDs known to AWS Config, including deleted resources."""
    data = run_aws_json(
        [
            "configservice",
            "list-discovered-resources",
            "--resource-type",
            "AWS::EC2::Instance",
            "--include-deleted-resources",
            "--region",
            region,
        ]
    )
    return [item["resourceId"] for item in data["resourceIdentifiers"]]


def load_config_history_for_month(
    region: str, instance_id: str, start_date: str, end_date: str
) -> list[dict[str, Any]]:
    """Load the latest pre-month item and in-month Config history for one instance."""
    before = run_aws_json(
        [
            "configservice",
            "get-resource-config-history",
            "--resource-type",
            "AWS::EC2::Instance",
            "--resource-id",
            instance_id,
            "--region",
            region,
            "--later-time",
            f"{start_date}T00:00:00Z",
            "--limit",
            "1",
            "--chronological-order",
            "Reverse",
        ]
    )["configurationItems"]
    during = run_aws_json(
        [
            "configservice",
            "get-resource-config-history",
            "--resource-type",
            "AWS::EC2::Instance",
            "--resource-id",
            instance_id,
            "--region",
            region,
            "--earlier-time",
            f"{start_date}T00:00:00Z",
            "--later-time",
            f"{end_date}T00:00:00Z",
            "--chronological-order",
            "Forward",
        ]
    )["configurationItems"]
    return list(reversed(before)) + during


def event_from_config_item(item: dict[str, Any]) -> dict[str, Union[str, datetime]]:
    """Convert one AWS Config item into an EC2 state timeline event."""
    capture_time = parse_aws_time(item["configurationItemCaptureTime"])
    if item["configurationItemStatus"] == "ResourceDeleted":
        return {
            "time": capture_time,
            "state": "terminated",
            "instance_type": "",
            "key_name": "",
            "instance_name": "",
        }

    configuration = json.loads(item["configuration"])
    state = configuration["state"]["name"]
    event_time = capture_time
    if state == "running":
        event_time = parse_aws_time(configuration["launchTime"])

    instance_name = ""
    if "tags" in item and "Name" in item["tags"]:
        instance_name = item["tags"]["Name"]

    key_name = ""
    if "keyName" in configuration:
        key_name = configuration["keyName"]

    return {
        "time": event_time,
        "state": state,
        "instance_type": configuration["instanceType"],
        "key_name": key_name,
        "instance_name": instance_name,
    }


def running_intervals_from_events(
    events: list[dict[str, Union[str, datetime]]], start: datetime, end: datetime
) -> list[dict[str, Any]]:
    """Calculate running intervals intersecting the target month."""
    intervals: list[dict[str, Any]] = []
    current_state = "stopped"
    current_type = ""
    current_key = ""
    current_name = ""
    current_start = start

    for event in sorted(events, key=lambda value: value["time"]):
        event_time = event["time"]
        if not isinstance(event_time, datetime):
            raise RuntimeError("Config event time was not parsed as datetime.")

        if event_time < start:
            current_state = str(event["state"])
            if event["instance_type"]:
                current_type = str(event["instance_type"])
            if event["key_name"]:
                current_key = str(event["key_name"])
            if event["instance_name"]:
                current_name = str(event["instance_name"])
            current_start = start
            continue

        if event_time >= end:
            break

        if current_state == "running":
            hours = (event_time - current_start).total_seconds() / 3600
            if hours > 0:
                intervals.append(
                    {
                        "instance_type": current_type,
                        "key_name": current_key,
                        "instance_name": current_name,
                        "config_running_hours": hours,
                    }
                )

        current_state = str(event["state"])
        if event["instance_type"]:
            current_type = str(event["instance_type"])
        if event["key_name"]:
            current_key = str(event["key_name"])
        if event["instance_name"]:
            current_name = str(event["instance_name"])
        current_start = event_time

    if current_state == "running":
        hours = (end - current_start).total_seconds() / 3600
        if hours > 0:
            intervals.append(
                {
                    "instance_type": current_type,
                    "key_name": current_key,
                    "instance_name": current_name,
                    "config_running_hours": hours,
                }
            )

    return intervals


def collect_instance_interval_rows(
    regions: list[str],
    start_date: str,
    end_date: str,
    start: datetime,
    end: datetime,
) -> list[dict[str, Any]]:
    """Collect monthly EC2 running intervals from AWS Config and CloudTrail."""
    rows: list[dict[str, Any]] = []
    lookup_start_date = (start - timedelta(days=90)).date().isoformat()
    for region in regions:
        creators = load_creator_by_instance(region, lookup_start_date, end_date)
        instance_ids = load_config_instance_ids(region)
        for index, instance_id in enumerate(instance_ids, start=1):
            if index == 1 or index % 25 == 0 or index == len(instance_ids):
                print(
                    f"{region}: config history {index}/{len(instance_ids)}",
                    file=sys.stderr,
                )
            history = load_config_history_for_month(
                region, instance_id, start_date, end_date
            )
            events = [event_from_config_item(item) for item in history]
            intervals = running_intervals_from_events(events, start, end)
            for interval in intervals:
                creator_username = "unknown_cloudtrail_retention"
                creator_arn = "unknown_cloudtrail_retention"
                if instance_id in creators:
                    creator_username = creators[instance_id]["creator_username"]
                    creator_arn = creators[instance_id]["creator_arn"]
                rows.append(
                    {
                        "region": region,
                        "instance_id": instance_id,
                        "instance_name": interval["instance_name"],
                        "key_name": interval["key_name"],
                        "creator_username": creator_username,
                        "creator_arn": creator_arn,
                        "instance_type": interval["instance_type"],
                        "config_running_hours": interval["config_running_hours"],
                    }
                )
    return rows


def allocate_costs(
    interval_rows: list[dict[str, Any]],
    compute_costs: dict[tuple[str, str], dict[str, float]],
) -> list[dict[str, Any]]:
    """Allocate Cost Explorer instance-type costs to instance running intervals."""
    hours_by_region_type: dict[tuple[str, str], float] = defaultdict(float)
    for row in interval_rows:
        key = (row["region"], row["instance_type"])
        hours_by_region_type[key] += float(row["config_running_hours"])

    allocated_rows: list[dict[str, Any]] = []
    for row in interval_rows:
        key = (row["region"], row["instance_type"])
        ce_hours = compute_costs[key]["hours"]
        ce_cost = compute_costs[key]["cost"]
        config_hours = hours_by_region_type[key]
        allocated = dict(row)
        allocated["allocated_ce_hours"] = (
            float(row["config_running_hours"]) / config_hours * ce_hours
        )
        allocated["allocated_compute_cost_usd"] = (
            float(row["config_running_hours"]) / config_hours * ce_cost
        )
        allocated_rows.append(allocated)

    for key, ce_data in compute_costs.items():
        if key in hours_by_region_type:
            continue
        region, instance_type = key
        allocated_rows.append(
            {
                "region": region,
                "instance_id": "unattributed_config_history_gap",
                "instance_name": "",
                "key_name": "unattributed_config_history_gap",
                "creator_username": "unknown",
                "creator_arn": "unknown",
                "instance_type": instance_type,
                "config_running_hours": 0.0,
                "allocated_ce_hours": ce_data["hours"],
                "allocated_compute_cost_usd": ce_data["cost"],
            }
        )

    return allocated_rows


def aggregate_rows(
    rows: list[dict[str, Any]], group_fields: list[str], set_fields: list[str]
) -> list[dict[str, Any]]:
    """Aggregate allocated compute rows by selected fields."""
    grouped: dict[tuple[str, ...], dict[str, Any]] = {}
    for row in rows:
        key = tuple(str(row[field]) for field in group_fields)
        if key not in grouped:
            grouped[key] = {
                field: row[field] for field in group_fields
            }
            grouped[key]["allocated_compute_cost_usd"] = 0.0
            grouped[key]["allocated_ce_hours"] = 0.0
            grouped[key]["config_running_hours"] = 0.0
            grouped[key]["instance_count"] = set()
            for field in set_fields:
                grouped[key][field] = set()

        grouped[key]["allocated_compute_cost_usd"] += float(
            row["allocated_compute_cost_usd"]
        )
        grouped[key]["allocated_ce_hours"] += float(row["allocated_ce_hours"])
        grouped[key]["config_running_hours"] += float(row["config_running_hours"])
        grouped[key]["instance_count"].add(row["instance_id"])
        for field in set_fields:
            grouped[key][field].add(row[field])

    output_rows: list[dict[str, Any]] = []
    for row in grouped.values():
        output = dict(row)
        output["instance_count"] = len(row["instance_count"])
        for field in set_fields:
            output[field] = ";".join(sorted(str(value) for value in row[field]))
        output_rows.append(output)
    output_rows.sort(key=lambda row: row["allocated_compute_cost_usd"], reverse=True)
    return output_rows


def aggregate_by_instance(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate interval rows into one row per instance."""
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        instance_id = row["instance_id"]
        if instance_id not in grouped:
            grouped[instance_id] = {
                "region": row["region"],
                "instance_id": instance_id,
                "instance_name": row["instance_name"],
                "key_name": row["key_name"],
                "creator_username": row["creator_username"],
                "creator_arn": row["creator_arn"],
                "instance_type": row["instance_type"],
                "config_running_hours": 0.0,
                "allocated_ce_hours": 0.0,
                "allocated_compute_cost_usd": 0.0,
            }
        grouped[instance_id]["config_running_hours"] += float(
            row["config_running_hours"]
        )
        grouped[instance_id]["allocated_ce_hours"] += float(row["allocated_ce_hours"])
        grouped[instance_id]["allocated_compute_cost_usd"] += float(
            row["allocated_compute_cost_usd"]
        )
    output_rows = list(grouped.values())
    output_rows.sort(key=lambda row: row["allocated_compute_cost_usd"], reverse=True)
    return output_rows


def build_reconciliation_rows(
    rows: list[dict[str, Any]],
    compute_costs: dict[tuple[str, str], dict[str, float]],
) -> list[dict[str, Any]]:
    """Build region/type reconciliation rows against Cost Explorer."""
    config_hours: dict[tuple[str, str], float] = defaultdict(float)
    allocated_costs: dict[tuple[str, str], float] = defaultdict(float)
    allocated_hours: dict[tuple[str, str], float] = defaultdict(float)
    for row in rows:
        key = (row["region"], row["instance_type"])
        config_hours[key] += float(row["config_running_hours"])
        allocated_costs[key] += float(row["allocated_compute_cost_usd"])
        allocated_hours[key] += float(row["allocated_ce_hours"])

    output_rows: list[dict[str, Any]] = []
    for key in sorted(compute_costs):
        region, instance_type = key
        output_rows.append(
            {
                "region": region,
                "instance_type": instance_type,
                "cost_explorer_compute_cost_usd": compute_costs[key]["cost"],
                "allocated_compute_cost_usd": allocated_costs[key],
                "cost_explorer_hours": compute_costs[key]["hours"],
                "allocated_ce_hours": allocated_hours[key],
                "config_running_hours": config_hours[key],
            }
        )
    return output_rows


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    """Write rows to a CSV file."""
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def get_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Allocate monthly EC2 instance compute cost from Cost Explorer to "
            "instance key names using AWS Config history."
        ),
        epilog=(
            "Method and caveats: Cost dollars come from Cost Explorer "
            "UnblendedCost grouped by region and EC2 BoxUsage instance type. "
            "Instance ownership and running hours come from AWS Config EC2 "
            "instance history, including deleted resources when Config recorded "
            "them. Costs are allocated across instances of the same region and "
            "instance type in proportion to Config running hours, so this is an "
            "allocation of actual billed totals, not direct per-instance billing. "
            "The allocation assumes same-type hours have the same effective "
            "hourly rate and does not separately model Savings Plans, Reserved "
            "Instances, credits, refunds, taxes, or other billing adjustments."
        ),
    )
    parser.add_argument("month", help="Billing month as YYYY-MM, for example 2026-04.")
    parser.add_argument("output_folder", type=Path, help="Folder for output CSV files.")
    return parser


def main() -> int:
    """Run the monthly EC2 compute allocation CLI."""
    parser = get_parser()
    args = parser.parse_args()
    start_date, end_date, start, end = month_bounds(args.month)
    args.output_folder.mkdir(parents=True, exist_ok=True)

    compute_costs = load_compute_cost_by_region_type(start_date, end_date)
    regions = sorted({region for region, _ in compute_costs})
    interval_rows = collect_instance_interval_rows(
        regions, start_date, end_date, start, end
    )
    allocated_interval_rows = allocate_costs(interval_rows, compute_costs)

    by_instance = aggregate_by_instance(allocated_interval_rows)
    by_key = aggregate_rows(
        allocated_interval_rows,
        ["key_name"],
        ["region", "instance_type", "creator_arn"],
    )
    by_creator = aggregate_rows(
        allocated_interval_rows,
        ["creator_arn"],
        ["region", "instance_type", "key_name"],
    )
    reconciliation = build_reconciliation_rows(allocated_interval_rows, compute_costs)

    prefix = args.month
    write_csv(
        args.output_folder / f"ec2_compute_by_key_{prefix}.csv",
        by_key,
        [
            "key_name",
            "allocated_compute_cost_usd",
            "allocated_ce_hours",
            "config_running_hours",
            "instance_count",
            "region",
            "instance_type",
            "creator_arn",
        ],
    )
    write_csv(
        args.output_folder / f"ec2_compute_by_creator_{prefix}.csv",
        by_creator,
        [
            "creator_arn",
            "allocated_compute_cost_usd",
            "allocated_ce_hours",
            "config_running_hours",
            "instance_count",
            "region",
            "instance_type",
            "key_name",
        ],
    )
    write_csv(
        args.output_folder / f"ec2_compute_by_instance_{prefix}.csv",
        by_instance,
        [
            "region",
            "instance_id",
            "instance_name",
            "key_name",
            "creator_username",
            "creator_arn",
            "instance_type",
            "config_running_hours",
            "allocated_ce_hours",
            "allocated_compute_cost_usd",
        ],
    )
    write_csv(
        args.output_folder / f"ec2_compute_by_instance_interval_{prefix}.csv",
        allocated_interval_rows,
        [
            "region",
            "instance_id",
            "instance_name",
            "key_name",
            "creator_username",
            "creator_arn",
            "instance_type",
            "config_running_hours",
            "allocated_ce_hours",
            "allocated_compute_cost_usd",
        ],
    )
    write_csv(
        args.output_folder / f"ec2_compute_type_reconciliation_{prefix}.csv",
        reconciliation,
        [
            "region",
            "instance_type",
            "cost_explorer_compute_cost_usd",
            "allocated_compute_cost_usd",
            "cost_explorer_hours",
            "allocated_ce_hours",
            "config_running_hours",
        ],
    )

    total = sum(row["cost"] for row in compute_costs.values())
    print(f"Wrote EC2 compute allocation for {args.month} to {args.output_folder}")
    print(f"Allocated Cost Explorer instance compute total: ${total:.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
