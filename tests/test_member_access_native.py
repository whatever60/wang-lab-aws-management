"""Native launch attribution, profile repair, and offboarding race regressions."""
import copy
import json
import unittest
from datetime import datetime, timedelta, timezone

from aws_audit.member_access.native import reconcile_native, _resources, OWNER_TAG, CREATOR_TAG
from aws_audit.member_access.models import MANAGED_BY
from test_member_access_runtime import Iam, S3, tags, ACCOUNT, REGION

NOW = datetime(2026, 10, 25, 22, tzinfo=timezone.utc)
LAUNCH = NOW - timedelta(minutes=1)
SINCE = NOW - timedelta(hours=1)
PRINCIPAL = "AIDAEXAMPLEALICE"
PROFILE = "arn:aws:iam::" + ACCOUNT + ":instance-profile/wanglab/member-s3/Alice"


class Identity(Iam):
    def __init__(self):
        super().__init__()
        self.principal = PRINCIPAL
        self.on_profile = None

    def get_user(self, **kwargs):
        return {"User": {"UserName": kwargs["UserName"], "UserId": self.principal}}

    def get_instance_profile(self, **kwargs):
        if self.on_profile:
            self.on_profile()
        return {"InstanceProfile": {"Arn": PROFILE,
                "Tags": tags({"ManagedBy": MANAGED_BY, "Owner": "Alice", "HomeBucket": "alice-home"}),
                "Roles": [{"RoleName": "Alice", "Arn": "arn:aws:iam::" + ACCOUNT + ":role/wanglab/member-s3/Alice"}]}}


class Compute:
    def __init__(self):
        self.instance = {"InstanceId": "i-111", "LaunchTime": LAUNCH, "State": {"Name": "running"}, "Tags": [],
                         "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-111"}}, {"Ebs": {"VolumeId": "vol-older"}}],
                         "NetworkInterfaces": [{"NetworkInterfaceId": "eni-111", "Attachment": {"AttachTime": LAUNCH}},
                                               {"NetworkInterfaceId": "eni-existing", "Attachment": {"AttachTime": LAUNCH}}]}
        self.volumes = [{"VolumeId": "vol-111", "CreateTime": LAUNCH, "Tags": []},
                        {"VolumeId": "vol-older", "CreateTime": SINCE - timedelta(days=1), "Tags": []}]
        self.interface = {"NetworkInterfaceId": "eni-111", "TagSet": []}
        self.tag_writes, self.associations = [], []

    def describe_instances(self, **kwargs):
        if "Filters" in kwargs:
            current = {row["Key"]: row["Value"] for row in self.instance["Tags"]}
            if not current.get(CREATOR_TAG):
                return {"Reservations": []}
        return {"Reservations": [{"Instances": [copy.deepcopy(self.instance)]}]}

    def describe_volumes(self, **kwargs):
        return {"Volumes": copy.deepcopy(self.volumes)}

    def describe_network_interfaces(self, **kwargs):
        return {"NetworkInterfaces": [copy.deepcopy(self.interface)]}

    def create_tags(self, **kwargs):
        self.tag_writes.append(kwargs)
        for resource in [self.instance, *self.volumes, self.interface]:
            identifier = next(resource[key] for key in ("InstanceId", "VolumeId", "NetworkInterfaceId") if key in resource)
            if identifier in kwargs["Resources"]:
                key = "TagSet" if "TagSet" in resource else "Tags"
                existing = {row["Key"]: row["Value"] for row in resource.get(key, [])}
                existing.update({row["Key"]: row["Value"] for row in kwargs["Tags"]})
                resource[key] = tags(existing)

    def associate_iam_instance_profile(self, **kwargs):
        self.associations.append(kwargs)
        self.instance["IamInstanceProfile"] = kwargs["IamInstanceProfile"]

    def describe_iam_instance_profile_associations(self, **kwargs):
        return {"IamInstanceProfileAssociations": []}


class History:
    def __init__(self):
        self.event = {"eventName": "RunInstances", "eventSource": "ec2.amazonaws.com", "awsRegion": REGION,
                      "recipientAccountId": ACCOUNT, "eventTime": LAUNCH.isoformat(),
                      "userIdentity": {"type": "IAMUser", "userName": "Alice", "accountId": ACCOUNT, "principalId": PRINCIPAL},
                      "requestParameters": {"networkInterfaceSet": {"items": [{"networkInterfaceId": "eni-existing"}]}},
                      "responseElements": {"instancesSet": {"items": [{"instanceId": "i-111"}]}}}
        self.enabled = True

    def lookup_events(self, **kwargs):
        events = [{"CloudTrailEvent": json.dumps(self.event)}] if self.enabled and kwargs["LookupAttributes"][0]["AttributeValue"] == "RunInstances" else []
        return {"Events": events}


class NativeAttributionTest(unittest.TestCase):
    def setUp(self):
        self.iam, self.s3, self.ec2, self.history = Identity(), S3(), Compute(), History()

    def run_sync(self):
        return reconcile_native(self.iam, self.s3, self.ec2, self.history, {"native_since": SINCE.isoformat()},
                                account_id=ACCOUNT, region=REGION, now=NOW)

    def test_raw_launch_is_attributed_and_personal_role_attached_without_caller_tags(self):
        result = self.run_sync()
        self.assertEqual(result["profiles_attached"], 1)
        self.assertEqual(self.ec2.associations, [{"InstanceId": "i-111", "IamInstanceProfile": {"Arn": PROFILE}}])
        resources = self.ec2.tag_writes[0]["Resources"]
        self.assertEqual(set(resources), {"i-111", "vol-111", "eni-111"})
        values = {row["Key"]: row["Value"] for row in self.ec2.instance["Tags"]}
        self.assertEqual(values[OWNER_TAG], "Alice")
        self.assertEqual(values[CREATOR_TAG], PRINCIPAL)

    def test_created_network_target_does_not_claim_its_existing_source_vpc(self):
        from unittest.mock import Mock
        ec2 = Mock()
        ec2.describe_tags.return_value = {"Tags": [{"Key": "Name", "Value": "native-subnet"}]}
        event = {"eventName": "CreateSubnet", "responseElements": {
            "subnet": {"subnetId": "subnet-new", "vpcId": "vpc-shared"}}}
        self.assertEqual(_resources(ec2, event, SINCE), [{"Id": "subnet-new", "Tags": tags({"Name": "native-subnet"})}])
        ec2.describe_tags.assert_called_once_with(Filters=[{"Name": "resource-id", "Values": ["subnet-new"]}])

    def test_multi_volume_snapshots_are_attributed_from_response_not_source_ids(self):
        from unittest.mock import Mock
        ec2 = Mock()
        ec2.describe_snapshots.return_value = {"Snapshots": [
            {"SnapshotId": "snap-new-a", "Tags": tags({"Name": "backup"})}, {"SnapshotId": "snap-new-b"}]}
        event = {"eventName": "CreateSnapshots", "recipientAccountId": ACCOUNT,
                 "responseElements": {"CreateSnapshotsResponse": {"snapshotSet": {"item": [
                     {"snapshotId": "snap-new-a", "volumeId": "vol-source-a"},
                     {"snapshotId": "snap-new-b", "volumeId": "vol-source-b"}]}}}}
        self.assertEqual(_resources(ec2, event, SINCE), [
            {"Id": "snap-new-a", "Tags": tags({"Name": "backup"})}, {"Id": "snap-new-b", "Tags": []}])
        ec2.describe_snapshots.assert_called_once_with(SnapshotIds=["snap-new-a", "snap-new-b"], OwnerIds=[ACCOUNT])

    def test_single_volume_create_snapshots_uses_cloudtrail_xml_object_shape(self):
        from unittest.mock import Mock
        ec2 = Mock()
        ec2.describe_snapshots.return_value = {"Snapshots": [{"SnapshotId": "snap-only"}]}
        event = {"eventName": "CreateSnapshots", "recipientAccountId": ACCOUNT,
                 "responseElements": {"CreateSnapshotsResponse": {"snapshotSet": {
                     "item": {"snapshotId": "snap-only", "volumeId": "vol-source"}}}}}
        self.assertEqual(_resources(ec2, event, SINCE), [{"Id": "snap-only", "Tags": []}])
        ec2.describe_snapshots.assert_called_once_with(SnapshotIds=["snap-only"], OwnerIds=[ACCOUNT])

    def test_event_hint_still_reads_the_actual_audit_record(self):
        from unittest.mock import Mock
        history = Mock()
        history.lookup_events.return_value = {"Events": []}
        reconcile_native(self.iam, self.s3, self.ec2, history, {"native_since": SINCE.isoformat()},
                         account_id=ACCOUNT, region=REGION, now=NOW, event_name="CreateVpc")
        self.assertEqual(history.lookup_events.call_count, 1)
        self.assertEqual(history.lookup_events.call_args.kwargs["LookupAttributes"][0]["AttributeValue"], "CreateVpc")
        self.assertFalse(self.ec2.tag_writes)

    def test_ordinary_owner_project_and_custom_tags_are_preserved(self):
        self.ec2.instance["Tags"] = tags({"Owner": "ResearchTeam", "Project": "paper-2026", "Name": "normal"})
        self.run_sync()
        current = {row["Key"]: row["Value"] for row in self.ec2.instance["Tags"]}
        self.assertEqual(current["Owner"], "ResearchTeam")
        self.assertEqual(current["Project"], "paper-2026")
        self.assertEqual(current[OWNER_TAG], "Alice")

    def test_pending_instance_waits_without_error_or_profile_attachment(self):
        self.ec2.instance["State"]["Name"] = "pending"
        self.run_sync()
        self.assertTrue(self.ec2.tag_writes)
        self.assertFalse(self.ec2.associations)

    def test_stop_start_before_attribution_keeps_original_disk_and_interface_ownership(self):
        self.ec2.instance["LaunchTime"] = NOW
        self.run_sync()
        resources = {identifier for write in self.ec2.tag_writes for identifier in write["Resources"]}
        self.assertIn("vol-111", resources)
        self.assertIn("eni-111", resources)

    def test_replay_is_idempotent_and_does_not_replace_existing_role(self):
        self.run_sync()
        self.run_sync()
        self.assertEqual(len(self.ec2.tag_writes), 1)
        self.assertEqual(len(self.ec2.associations), 1)

    def test_historical_instance_is_never_adopted(self):
        self.ec2.instance["LaunchTime"] = SINCE - timedelta(days=1)
        self.run_sync()
        self.assertFalse(self.ec2.tag_writes)
        self.assertFalse(self.ec2.associations)

    def test_existing_profile_is_preserved(self):
        self.ec2.instance["IamInstanceProfile"] = {"Arn": "existing-admin-reviewed-profile"}
        self.run_sync()
        self.assertFalse(self.ec2.associations)

    def test_offboarded_user_gets_no_new_profile(self):
        self.iam.members = []
        self.run_sync()
        self.assertFalse(self.ec2.associations)

    def test_home_ownership_mismatch_does_not_grant_role(self):
        self.s3.bucket_tags["alice-home"]["BucketOwner"] = "Bob"
        self.run_sync()
        self.assertFalse(self.ec2.associations)

    def test_principal_id_reuse_or_wrong_account_does_not_attribute(self):
        for field, value in (("principalId", "different-user-id"), ("accountId", "999999999999")):
            with self.subTest(field=field):
                self.history.event["userIdentity"][field] = value
                self.run_sync()
                self.assertFalse(self.ec2.tag_writes)
                self.assertFalse(self.ec2.associations)

    def test_conflicting_owner_is_not_silently_reassigned(self):
        self.ec2.instance["Tags"] = tags({OWNER_TAG: "Bob"})
        with self.assertRaises(RuntimeError):
            self.run_sync()
        self.assertFalse(self.ec2.tag_writes)
        self.assertFalse(self.ec2.associations)

    def test_membership_removal_during_profile_lookup_prevents_attachment(self):
        self.iam.on_profile = lambda: self.iam.members.clear()
        self.run_sync()
        self.assertFalse(self.ec2.associations)

    def test_persisted_provenance_repairs_profile_after_history_window(self):
        self.run_sync()
        self.ec2.associations.clear()
        self.ec2.instance.pop("IamInstanceProfile")
        self.history.enabled = False
        result = self.run_sync()
        self.assertEqual(result["profiles_attached"], 1)

    def test_new_identity_cannot_inherit_old_provenance_profile(self):
        self.run_sync()
        self.ec2.instance.pop("IamInstanceProfile")
        self.ec2.associations.clear()
        self.iam.principal = "new-user-with-same-name"
        self.history.enabled = False
        self.run_sync()
        self.assertFalse(self.ec2.associations)


if __name__ == "__main__":
    unittest.main()
