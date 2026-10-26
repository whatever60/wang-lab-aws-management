"""Attribute native EC2 creation and attach bounded S3 roles after launch.

One existing controller handles both IAM lifecycle and EC2 creation. CloudTrail
is the creator record; names, SSH keys and caller-supplied Owner tags never
authorize profile attachment. No instances are launched, stopped or replaced.
"""

import json
import re
from datetime import datetime, timedelta, timezone

from .models import MANAGED_BY, ROLE_PATH


# Only the created target ID is read from each response. Referenced source
# VPCs/subnets/images must never be claimed by the creator of a child resource.
TARGET_FIELDS = {
    "CreateNetworkInterface": "networkInterfaceId", "CreateVpc": "vpcId",
    "CreateSubnet": "subnetId", "CreateRouteTable": "routeTableId",
    "CreateInternetGateway": "internetGatewayId", "CreateNatGateway": "natGatewayId",
    "CreateNetworkAcl": "networkAclId", "CreateVpcEndpoint": "vpcEndpointId",
    "CreateVpcPeeringConnection": "vpcPeeringConnectionId",
    "AllocateAddress": "allocationId", "CreateEgressOnlyInternetGateway": "egressOnlyInternetGatewayId",
    "CreateLaunchTemplate": "launchTemplateId", "CopySnapshot": "snapshotId", "CopyImage": "imageId",
}
NATIVE_EVENTS = ("RunInstances", "CreateVolume", "CreateKeyPair", "ImportKeyPair",
                 "CreateSecurityGroup", "CreateSnapshot", "CreateSnapshots", "CreateImage", *TARGET_FIELDS)
OWNER_TAG = "wanglab:Owner"
CREATOR_TAG = "wanglab:CreatorUserId"


def _date(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
    if not isinstance(result, datetime) or result.tzinfo is None:
        raise ValueError("an aware timestamp is required")
    return result


def _tags(rows):
    return {row["Key"]: row["Value"] for row in rows}


def _items(client, method, key, **args):
    while True:
        result = getattr(client, method)(**args)
        yield from result.get(key, [])
        if not result.get("NextToken"):
            return
        args["NextToken"] = result["NextToken"]


def _mark(ec2, resources, user, principal):
    if not resources:
        return
    # Existing ownership is never reassigned; the same verified creator is
    # idempotent. The controller alone can write these provenance markers.
    wanted = {OWNER_TAG: user, CREATOR_TAG: principal}
    ids = []
    for resource in resources:
        current = _tags(resource.get("Tags", []))
        if current.get(OWNER_TAG) not in (None, user) or current.get(CREATOR_TAG) not in (None, principal):
            raise RuntimeError("conflicting EC2 creator attribution")
        if any(current.get(key) != value for key, value in wanted.items()):
            ids.append(resource["Id"])
    if ids:
        ec2.create_tags(Resources=ids, Tags=[{"Key": key, "Value": value} for key, value in wanted.items()])


def _resources(ec2, event, since):
    """Return only newly created resources identified by an AWS audit response."""
    response = event.get("responseElements") or {}
    name = event["eventName"]
    if name == "CreateSnapshots":
        result = response.get("CreateSnapshotsResponse", response)
        snapshot_set = result.get("snapshotSet", {})
        rows = snapshot_set.get("item", snapshot_set.get("items", []))
        if isinstance(rows, dict):
            rows = [rows]
        ids = [row["snapshotId"] for row in rows]
        if not ids:
            return []
        rows = ec2.describe_snapshots(SnapshotIds=ids, OwnerIds=[event["recipientAccountId"]])["Snapshots"]
        return [{"Id": row["SnapshotId"], "Tags": row.get("Tags", [])} for row in rows]
    if name in TARGET_FIELDS:
        def targets(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == TARGET_FIELDS[name] and isinstance(item, str):
                        yield item
                    elif isinstance(item, (dict, list)):
                        yield from targets(item)
            elif isinstance(value, list):
                for item in value:
                    yield from targets(item)
        result = []
        for identifier in sorted(set(targets(response))):
            rows = _items(ec2, "describe_tags", "Tags", Filters=[{"Name": "resource-id", "Values": [identifier]}])
            result.append({"Id": identifier, "Tags": [{"Key": row["Key"], "Value": row["Value"]} for row in rows]})
        return result
    if name == "RunInstances":
        ids = [row["instanceId"] for row in response.get("instancesSet", {}).get("items", [])]
        if not ids:
            return []
        resources = []
        for reservation in ec2.describe_instances(InstanceIds=ids)["Reservations"]:
            for instance in reservation["Instances"]:
                # EC2 LaunchTime changes after stop/start. Use the immutable
                # original RunInstances event for disk/interface birth times.
                launch = _date(event["eventTime"])
                if launch < since or _date(instance["LaunchTime"]) < since or instance["State"]["Name"] in ("shutting-down", "terminated"):
                    continue
                resources.append({"Id": instance["InstanceId"], "Tags": instance.get("Tags", [])})
                volumes = [row["Ebs"]["VolumeId"] for row in instance.get("BlockDeviceMappings", []) if "Ebs" in row]
                if volumes:
                    for volume in ec2.describe_volumes(VolumeIds=volumes)["Volumes"]:
                        if abs((_date(volume["CreateTime"]) - launch).total_seconds()) <= 30:
                            resources.append({"Id": volume["VolumeId"], "Tags": volume.get("Tags", [])})
                # Do not adopt a pre-existing ENI explicitly supplied at launch.
                old = {row.get("networkInterfaceId") for row in
                       (event.get("requestParameters") or {}).get("networkInterfaceSet", {}).get("items", [])}
                for interface in instance.get("NetworkInterfaces", []):
                    attached = interface.get("Attachment", {})
                    if (interface["NetworkInterfaceId"] not in old and attached.get("AttachTime")
                            and abs((_date(attached["AttachTime"]) - launch).total_seconds()) <= 30):
                        metadata = ec2.describe_network_interfaces(NetworkInterfaceIds=[interface["NetworkInterfaceId"]])["NetworkInterfaces"][0]
                        resources.append({"Id": metadata["NetworkInterfaceId"], "Tags": metadata.get("TagSet", [])})
        return resources
    specifications = {
        "CreateVolume": ("volumeId", "describe_volumes", "VolumeIds", "Volumes", "VolumeId"),
        "CreateSnapshot": ("snapshotId", "describe_snapshots", "SnapshotIds", "Snapshots", "SnapshotId"),
        "CreateImage": ("imageId", "describe_images", "ImageIds", "Images", "ImageId"),
        "CreateSecurityGroup": ("groupId", "describe_security_groups", "GroupIds", "SecurityGroups", "GroupId"),
        "CreateKeyPair": ("keyPairId", "describe_key_pairs", "KeyPairIds", "KeyPairs", "KeyPairId"),
        "ImportKeyPair": ("keyPairId", "describe_key_pairs", "KeyPairIds", "KeyPairs", "KeyPairId"),
    }
    field, method, argument, collection, identifier = specifications[name]
    resource_id = response.get(field)
    if not resource_id:
        return []
    rows = getattr(ec2, method)(**{argument: [resource_id]})[collection]
    result = [{"Id": row[identifier], "Tags": row.get("Tags", [])} for row in rows]
    if name == "CreateImage":
        ids = [block["Ebs"]["SnapshotId"] for row in rows for block in row.get("BlockDeviceMappings", [])
               if block.get("Ebs", {}).get("SnapshotId")]
        if ids:
            for snapshot in ec2.describe_snapshots(SnapshotIds=ids, OwnerIds=[event["recipientAccountId"]])["Snapshots"]:
                if _date(snapshot["StartTime"]) >= _date(event["eventTime"]) - timedelta(seconds=5):
                    result.append({"Id": snapshot["SnapshotId"], "Tags": snapshot.get("Tags", [])})
    return result


def reconcile_native(iam, s3, ec2, cloudtrail, config, *, account_id, region, now=None, event_name=None):
    """Periodic repair replays recent successful creation, then fills blank profiles.

    The cutover timestamp prevents adopting historical instances. Persisted,
    protected CreatorUserId markers allow delayed profile repair without a DB.
    """
    from .runtime import live_member_manifest
    now = now or datetime.now(timezone.utc)
    since = _date(config["native_since"])
    start = max(since, now - timedelta(hours=24))
    users, errors = {}, []
    marked = 0
    # An EventBridge hint limits reads, but grants still use actual CloudTrail
    # records and live IAM identity. Scheduled passes repair the entire window.
    for name in (event_name,) if event_name in NATIVE_EVENTS else NATIVE_EVENTS:
        for row in _items(cloudtrail, "lookup_events", "Events",
                          LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}],
                          StartTime=start, EndTime=now, MaxResults=50):
            event = json.loads(row["CloudTrailEvent"])
            identity = event.get("userIdentity") or {}
            if (event.get("eventSource") != "ec2.amazonaws.com" or event.get("awsRegion") != region
                    or event.get("recipientAccountId") != account_id or event.get("errorCode")
                    or not event.get("responseElements") or _date(event["eventTime"]) < since
                    or identity.get("type") != "IAMUser" or identity.get("accountId") != account_id):
                continue
            user = identity.get("userName", "")
            if not re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,64}", user):
                continue
            try:
                if user not in users:
                    users[user] = iam.get_user(UserName=user)["User"]
                principal = users[user]["UserId"]
                if principal != identity.get("principalId"):
                    continue
                resources = _resources(ec2, event, since)
                _mark(ec2, resources, user, principal)
                marked += len(resources)
            except Exception as error:
                # A deleted resource/user is expected on a replay. Other failures
                # must surface so the existing alarm and Lambda retries work.
                code = getattr(error, "response", {}).get("Error", {}).get("Code", "")
                if not code.endswith(".NotFound") and code not in {"NoSuchEntity", "InvalidInstanceID.NotFound", "InvalidVolume.NotFound",
                                 "InvalidSnapshot.NotFound", "InvalidAMIID.NotFound", "InvalidGroup.NotFound",
                                 "InvalidKeyPair.NotFound", "InvalidNetworkInterfaceID.NotFound"}:
                    errors.append(type(error).__name__)
    manifest = live_member_manifest(iam, s3, account_id=account_id)
    eligible = {row["user_name"]: row["home_bucket"] for row in manifest["users"] if row.get("home_bucket")}
    attached = 0
    reservations = _items(ec2, "describe_instances", "Reservations", Filters=[
        {"Name": "tag:" + CREATOR_TAG, "Values": ["*"]},
        {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}])
    for reservation in reservations:
        for instance in reservation["Instances"]:
            tags = _tags(instance.get("Tags", []))
            user = tags.get(OWNER_TAG)
            if (user not in eligible or instance.get("IamInstanceProfile") or _date(instance["LaunchTime"]) < since
                    or instance["State"]["Name"] not in ("running", "stopped")):
                continue
            associations = ec2.describe_iam_instance_profile_associations(Filters=[
                {"Name": "instance-id", "Values": [instance["InstanceId"]]},
                {"Name": "state", "Values": ["associating", "associated"]}])["IamInstanceProfileAssociations"]
            if associations:
                continue
            identity = iam.get_user(UserName=user)["User"]
            if identity["UserId"] != tags.get(CREATOR_TAG):
                continue
            profile = iam.get_instance_profile(InstanceProfileName=user)["InstanceProfile"]
            expected = "arn:aws:iam::%s:instance-profile%s%s" % (account_id, ROLE_PATH, user)
            roles = profile.get("Roles", [])
            metadata = _tags(profile.get("Tags", []))
            if (profile["Arn"] != expected or len(roles) != 1 or roles[0]["RoleName"] != user
                    or roles[0]["Arn"] != "arn:aws:iam::%s:role%s%s" % (account_id, ROLE_PATH, user)
                    or metadata.get("ManagedBy") != MANAGED_BY or metadata.get("Owner") != user
                    or metadata.get("HomeBucket") != eligible[user]):
                raise RuntimeError("unverified personal instance profile")
            # Re-read live membership/home after all metadata calls. Offboarding
            # separately disables this role's already-issued credentials.
            fresh = live_member_manifest(iam, s3, account_id=account_id)
            if not any(row.get("user_name") == user and row.get("home_bucket") == eligible[user] for row in fresh["users"]):
                continue
            ec2.associate_iam_instance_profile(InstanceId=instance["InstanceId"], IamInstanceProfile={"Arn": expected})
            attached += 1
    if errors:
        raise RuntimeError("native creator reconciliation requires retry: " + ",".join(sorted(set(errors))))
    return {"attributed_resources": marked, "profiles_attached": attached}
