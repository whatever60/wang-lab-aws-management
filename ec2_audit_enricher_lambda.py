#!/usr/bin/env python3
"""Lambda enricher for EC2/EBS/AMI audit events routed from EventBridge."""

import json
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

EC2_CLIENT = boto3.client("ec2")
SNS_CLIENT = boto3.client("sns")
TOPIC_ARN = os.environ["TOPIC_ARN"]


def value_at_path(data: Any, path: list[Any]) -> Any:
    """Return nested value for a dict/list path, or empty string when missing."""
    current = data
    for part in path:
        if isinstance(part, int):
            if isinstance(current, list) and part < len(current):
                current = current[part]
                continue
            return ""
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        return ""
    return current


def unique_in_order(values: list[str]) -> list[str]:
    """Return first-seen unique non-empty strings in order."""
    unique_values: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            unique_values.append(value)
            seen.add(value)
    return unique_values


def first_non_empty(values: list[Any]) -> str:
    """Return first value that is not empty, converted to string."""
    for value in values:
        if value == "":
            continue
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return str(value)
    return ""


def collect_instance_ids(detail: dict[str, Any]) -> list[str]:
    """Collect candidate instance IDs from the CloudTrail event detail payload."""
    candidates: list[str] = []

    candidates.append(str(value_at_path(detail, ["requestParameters", "instanceId"])))
    candidates.append(str(value_at_path(detail, ["responseElements", "instanceId"])))

    req_items = value_at_path(detail, ["requestParameters", "instancesSet", "items"])
    if isinstance(req_items, list):
        for item in req_items:
            if isinstance(item, dict) and "instanceId" in item:
                candidates.append(str(item["instanceId"]))

    resp_items = value_at_path(detail, ["responseElements", "instancesSet", "items"])
    if isinstance(resp_items, list):
        for item in resp_items:
            if isinstance(item, dict) and "instanceId" in item:
                candidates.append(str(item["instanceId"]))

    return unique_in_order(candidates)


def collect_volume_ids(detail: dict[str, Any]) -> list[str]:
    """Collect candidate volume IDs from the CloudTrail event detail payload."""
    candidates: list[str] = []

    candidates.append(str(value_at_path(detail, ["requestParameters", "volumeId"])))
    candidates.append(str(value_at_path(detail, ["responseElements", "volumeId"])))
    candidates.append(str(value_at_path(detail, ["requestParameters", "ModifyVolumeRequest", "VolumeId"])))
    candidates.append(str(value_at_path(detail, ["responseElements", "ModifyVolumeResponse", "volumeModification", "volumeId"])))

    return unique_in_order(candidates)


def collect_snapshot_ids(detail: dict[str, Any]) -> list[str]:
    """Collect candidate snapshot IDs from the CloudTrail event detail payload."""
    candidates: list[str] = []

    candidates.append(str(value_at_path(detail, ["requestParameters", "snapshotId"])))
    candidates.append(str(value_at_path(detail, ["responseElements", "snapshotId"])))

    snapshot_items = value_at_path(detail, ["responseElements", "snapshotSet", "items"])
    if isinstance(snapshot_items, list):
        for item in snapshot_items:
            if isinstance(item, dict) and "snapshotId" in item:
                candidates.append(str(item["snapshotId"]))

    return unique_in_order(candidates)


def describe_instances(instance_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Describe EC2 instances and return an id->metadata map."""
    if not instance_ids:
        return {}

    try:
        response = EC2_CLIENT.describe_instances(InstanceIds=instance_ids)
    except ClientError:
        return {}

    mapping: dict[str, dict[str, Any]] = {}
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instance_id = instance["InstanceId"]
            key_name = ""
            if "KeyName" in instance and instance["KeyName"] is not None:
                key_name = str(instance["KeyName"])

            block_device_volume_ids: list[str] = []
            if "BlockDeviceMappings" in instance:
                for mapping_item in instance["BlockDeviceMappings"]:
                    if "Ebs" in mapping_item and isinstance(mapping_item["Ebs"], dict) and "VolumeId" in mapping_item["Ebs"]:
                        block_device_volume_ids.append(str(mapping_item["Ebs"]["VolumeId"]))

            mapping[instance_id] = {
                "keyName": key_name,
                "instanceType": str(instance["InstanceType"]),
                "volumeIds": unique_in_order(block_device_volume_ids),
            }

    return mapping


def describe_volumes(volume_ids: list[str]) -> dict[str, dict[str, str]]:
    """Describe EBS volumes and return an id->metadata map."""
    if not volume_ids:
        return {}

    try:
        response = EC2_CLIENT.describe_volumes(VolumeIds=volume_ids)
    except ClientError:
        return {}

    mapping: dict[str, dict[str, str]] = {}
    for volume in response["Volumes"]:
        mapping[str(volume["VolumeId"])] = {
            "size": str(volume["Size"]),
            "type": str(volume["VolumeType"]),
        }
    return mapping


def describe_snapshots(snapshot_ids: list[str]) -> dict[str, dict[str, str]]:
    """Describe EBS snapshots and return an id->metadata map."""
    if not snapshot_ids:
        return {}

    try:
        response = EC2_CLIENT.describe_snapshots(SnapshotIds=snapshot_ids, OwnerIds=["self"])
    except ClientError:
        return {}

    mapping: dict[str, dict[str, str]] = {}
    for snapshot in response["Snapshots"]:
        storage_tier = "standard"
        if "StorageTier" in snapshot and snapshot["StorageTier"]:
            storage_tier = str(snapshot["StorageTier"])
        mapping[str(snapshot["SnapshotId"])] = {
            "tier": storage_tier,
        }
    return mapping


def build_description_lines(message_fields: dict[str, str]) -> str:
    """Build markdown description text for Amazon Q custom notification content."""
    lines = [
        f"*Event:* `{message_fields['event_name']}`",
        f"*Service:* `{message_fields['event_source']}`",
        f"*Detail Type:* `{message_fields['detail_type']}`",
        f"*Account:* `{message_fields['account']}`",
        f"*Region:* `{message_fields['region']}`",
        f"*Time:* `{message_fields['event_time']}`",
        f"*Actor:* `{message_fields['actor_arn']}`",
        f"*Instance ID:* `{message_fields['instance_id']}`",
        f"*Volume ID:* `{message_fields['volume_id']}`",
        f"*Snapshot ID:* `{message_fields['snapshot_id']}`",
        f"*EC2 Key Name:* `{message_fields['key_name']}`",
        f"*Instance Type:* `{message_fields['instance_type']}`",
        f"*Volume Size GiB:* `{message_fields['volume_size_gib']}`",
        f"*Volume Type:* `{message_fields['volume_type']}`",
        f"*Snapshot Tier:* `{message_fields['snapshot_tier']}`",
        f"*CloudTrail Event ID:* `{message_fields['cloudtrail_event_id']}`",
        f"*EventBridge Event ID:* `{message_fields['eventbridge_event_id']}`",
    ]
    return "\n".join(lines)


def build_custom_payload(event: dict[str, Any]) -> dict[str, Any]:
    """Build Amazon Q custom notification payload from EventBridge event detail."""
    detail = event["detail"]
    request_parameters = detail["requestParameters"] if "requestParameters" in detail and isinstance(detail["requestParameters"], dict) else {}
    response_elements = detail["responseElements"] if "responseElements" in detail and isinstance(detail["responseElements"], dict) else {}

    instance_ids = collect_instance_ids(detail)
    volume_ids = collect_volume_ids(detail)
    snapshot_ids = collect_snapshot_ids(detail)

    instance_map = describe_instances(instance_ids)
    if instance_ids and instance_ids[0] in instance_map:
        for volume_id in instance_map[instance_ids[0]]["volumeIds"]:
            volume_ids.append(volume_id)
    volume_ids = unique_in_order(volume_ids)

    volume_map = describe_volumes(volume_ids)
    snapshot_map = describe_snapshots(snapshot_ids)

    instance_id = first_non_empty(instance_ids)
    volume_id = first_non_empty(volume_ids)
    snapshot_id = first_non_empty(snapshot_ids)

    key_name = first_non_empty(
        [
            value_at_path(request_parameters, ["keyName"]),
            value_at_path(instance_map, [instance_id, "keyName"]),
        ]
    )

    instance_type = first_non_empty(
        [
            value_at_path(request_parameters, ["instanceType"]),
            value_at_path(instance_map, [instance_id, "instanceType"]),
        ]
    )

    volume_size_gib = first_non_empty(
        [
            value_at_path(request_parameters, ["size"]),
            value_at_path(response_elements, ["size"]),
            value_at_path(request_parameters, ["ModifyVolumeRequest", "Size"]),
            value_at_path(response_elements, ["ModifyVolumeResponse", "volumeModification", "targetSize"]),
            value_at_path(volume_map, [volume_id, "size"]),
        ]
    )

    volume_type = first_non_empty(
        [
            value_at_path(request_parameters, ["volumeType"]),
            value_at_path(response_elements, ["volumeType"]),
            value_at_path(request_parameters, ["ModifyVolumeRequest", "VolumeType"]),
            value_at_path(response_elements, ["ModifyVolumeResponse", "volumeModification", "targetVolumeType"]),
            value_at_path(volume_map, [volume_id, "type"]),
        ]
    )

    snapshot_tier = first_non_empty(
        [
            value_at_path(request_parameters, ["storageTier"]),
            value_at_path(response_elements, ["storageTier"]),
            value_at_path(snapshot_map, [snapshot_id, "tier"]),
        ]
    )

    message_fields = {
        "event_name": str(detail["eventName"]),
        "event_source": str(detail["eventSource"]),
        "detail_type": str(event["detail-type"]),
        "account": str(event["account"]),
        "region": str(event["region"]),
        "event_time": str(event["time"]),
        "actor_arn": first_non_empty([value_at_path(detail, ["userIdentity", "arn"]), "unknown"]),
        "instance_id": first_non_empty([instance_id, ""]),
        "volume_id": first_non_empty([volume_id, ""]),
        "snapshot_id": first_non_empty([snapshot_id, ""]),
        "key_name": first_non_empty([key_name, ""]),
        "instance_type": first_non_empty([instance_type, ""]),
        "volume_size_gib": first_non_empty([volume_size_gib, ""]),
        "volume_type": first_non_empty([volume_type, ""]),
        "snapshot_tier": first_non_empty([snapshot_tier, ""]),
        "cloudtrail_event_id": first_non_empty([value_at_path(detail, ["eventID"]), ""]),
        "eventbridge_event_id": first_non_empty([value_at_path(event, ["id"]), ""]),
    }

    event_name = message_fields["event_name"]
    region = message_fields["region"]
    account = message_fields["account"]

    payload = {
        "version": "1.0",
        "source": "custom",
        "id": first_non_empty([message_fields["cloudtrail_event_id"], message_fields["eventbridge_event_id"]]),
        "content": {
            "textType": "client-markdown",
            "title": f":satellite: EC2/EBS/AMI API event: {event_name}",
            "description": build_description_lines(message_fields),
            "keywords": ["ec2-audit", "cloudtrail", event_name],
        },
        "metadata": {
            "threadId": f"ec2-ebs-ami-audit-{account}-{region}",
            "summary": f"{event_name} in {region}",
            "additionalContext": {
                "eventSource": message_fields["event_source"],
                "detailType": message_fields["detail_type"],
                "account": account,
                "region": region,
                "eventTime": message_fields["event_time"],
                "actorArn": message_fields["actor_arn"],
                "instanceId": message_fields["instance_id"],
                "volumeId": message_fields["volume_id"],
                "snapshotId": message_fields["snapshot_id"],
                "keyName": message_fields["key_name"],
                "instanceType": message_fields["instance_type"],
                "volumeSizeGiB": message_fields["volume_size_gib"],
                "volumeType": message_fields["volume_type"],
                "snapshotTier": message_fields["snapshot_tier"],
                "cloudTrailEventId": message_fields["cloudtrail_event_id"],
                "eventBridgeEventId": message_fields["eventbridge_event_id"],
            },
            "enableCustomActions": True,
        },
    }
    return payload


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Handle EventBridge event, enrich metadata, and publish to SNS."""
    _ = context
    payload = build_custom_payload(event)
    SNS_CLIENT.publish(TopicArn=TOPIC_ARN, Message=json.dumps(payload))
    return {"status": "ok", "published_to": TOPIC_ARN}
