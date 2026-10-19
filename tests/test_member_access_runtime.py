"""Synthetic runtime tests; no account inventory, credentials, or AWS calls."""

import copy
import io
import json
import os
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from aws_audit.member_access import runtime


ACCOUNT = "123456789012"
REGION = "us-east-1"
PREFIX = "arn:aws:ec2:" + REGION + ":" + ACCOUNT + ":"


def configuration():
    ec2 = {"account_id": ACCOUNT, "regions": [REGION], "instance_types": ["t3.micro"],
           "approved_image_arns": ["arn:aws:ec2:" + REGION + "::image/ami-11111111111111111"],
           "approved_snapshot_arns": ["arn:aws:ec2:" + REGION + "::snapshot/snap-11111111111111111"],
           "approved_subnet_arns": [PREFIX + "subnet/subnet-11111111111111111"],
           "approved_security_group_arns": [PREFIX + "security-group/sg-11111111111111111"]}
    flavors = [{"name": name, "region": REGION, "image_id": "ami-11111111111111111",
                "instance_type": "t3.micro", "subnet_id": "subnet-11111111111111111",
                "security_group_id": "sg-11111111111111111"}
               for name in ("Ubuntu2404", "Al2023", "DL2204", "DL2404")]
    return {"ec2_config": ec2, "flavors": flavors, "member_group": "lab_members",
            "permissions_boundary_arn": "arn:aws:iam::" + ACCOUNT + ":policy/MemberS3Boundary"}


def tags(value):
    return [{"Key": key, "Value": item} for key, item in value.items()]


class MetadataError(Exception):
    def __init__(self, code="AccessDenied"):
        self.response = {"Error": {"Code": code}}


class Iam:
    def __init__(self, members=("Alice",), page_size=100):
        self.members = list(members)
        self.page_size = page_size
        self.user_tags = {name: {"AccessRole": "CurrentMember", "HomeBucket": name.lower() + "-home"}
                          for name in members}
        self.reads = []

    def get_group(self, **kwargs):
        self.reads.append(("get_group", kwargs))
        start = int(kwargs.get("Marker", "0"))
        page = self.members[start:start + self.page_size]
        answer = {"Users": [{"UserName": name, "Arn": "arn:aws:iam::" + ACCOUNT + ":user/" + name}
                            for name in page], "IsTruncated": start + len(page) < len(self.members)}
        if answer["IsTruncated"]:
            answer["Marker"] = str(start + len(page))
        return answer

    def list_user_tags(self, **kwargs):
        self.reads.append(("list_user_tags", kwargs))
        value = self.user_tags.get(kwargs["UserName"], {})
        if isinstance(value, Exception):
            raise value
        return {"Tags": tags(value), "IsTruncated": False}


class S3:
    def __init__(self, members=("Alice",)):
        self.bucket_tags = {name.lower() + "-home": {"BucketScope": "User", "BucketOwner": name,
                                                   "OwnerAccessRole": "CurrentMember"} for name in members}
        self.reads = []

    def get_bucket_tagging(self, **kwargs):
        self.reads.append(kwargs)
        value = self.bucket_tags.get(kwargs["Bucket"], MetadataError("NoSuchBucket"))
        if isinstance(value, Exception):
            raise value
        return {"TagSet": tags(value)}


class MemberAccessRuntimeTest(unittest.TestCase):
    def capture(self, iam, s3):
        return runtime.live_member_manifest(iam, s3, account_id=ACCOUNT)

    def run_sync(self, iam, s3, backend, **kwargs):
        return runtime.run_reconciliation(iam, s3, {REGION: object()}, configuration(),
                                          account_id=ACCOUNT, region=REGION,
                                          reconcile_call=backend, **kwargs)

    def test_configuration_is_infrastructure_only_and_account_bound(self):
        good = configuration()
        self.assertEqual(runtime.validate_runtime_config(good, account_id=ACCOUNT, region=REGION), good)
        for change in ({"s3_manifest": {"users": []}}, {"users": ["Alice"]},
                       {"member_group": "admin"}, {"permissions_boundary_arn": None},
                       {"permissions_boundary_arn": "arn:aws:iam::999999999999:policy/Other"}):
            with self.subTest(change=change), self.assertRaises(runtime.RuntimeValidationError):
                runtime.validate_runtime_config({**good, **change}, account_id=ACCOUNT, region=REGION)
        for region, account in (("eu-west-1", ACCOUNT), (REGION, "999999999999")):
            with self.assertRaises(runtime.RuntimeValidationError):
                runtime.validate_runtime_config(good, account_id=account, region=region)
        for change in ({"image_id": "ami-22222222222222222"}, {"region": "us-west-2"},
                       {"name": "Other"}, {"instance_type": "p5.48xlarge"}):
            value = copy.deepcopy(good)
            value["flavors"][0].update(change)
            with self.subTest(change=change), self.assertRaises(runtime.RuntimeValidationError):
                runtime.validate_runtime_config(value, account_id=ACCOUNT, region=REGION)

    def test_environment_config_is_json_and_missing_invalid_values_fail_closed(self):
        with mock.patch.dict("os.environ", {runtime.CONFIG_ENV: json.dumps(configuration())}):
            self.assertEqual(runtime.load_runtime_config(account_id=ACCOUNT, region=REGION), configuration())
        for value in (None, "not-json", "null", "{}", "/old/parameter/path"):
            with self.subTest(value=value), mock.patch.dict("os.environ", {}, clear=True):
                if value is not None:
                    os.environ[runtime.CONFIG_ENV] = value
                with self.assertRaises(runtime.RuntimeValidationError):
                    runtime.load_runtime_config(account_id=ACCOUNT, region=REGION)

    def test_live_membership_and_three_bucket_tags_are_authoritative(self):
        iam = Iam(("Alice", "Bob"), page_size=1)
        s3 = S3(("Alice", "Bob"))
        snapshot = self.capture(iam, s3)
        self.assertEqual([u["user_name"] for u in snapshot["users"]], ["Alice", "Bob"])
        self.assertEqual([u["home_bucket"] for u in snapshot["users"]], ["alice-home", "bob-home"])
        self.assertEqual(len(snapshot["buckets"]), 2)
        self.assertTrue(any("Marker" in kw for method, kw in iam.reads if method == "get_group"))
        self.assertTrue(all(call["ExpectedBucketOwner"] == ACCOUNT for call in s3.reads))
        # Removing group membership overrides otherwise valid user/bucket tags.
        iam.members.remove("Bob")
        self.assertEqual([u["user_name"] for u in self.capture(iam, s3)["users"]], ["Alice"])

    def test_incomplete_invalid_or_unreadable_metadata_never_inherits_a_home(self):
        for user_tags, bucket_tags in (
            ({}, None),
            ({"AccessRole": "Alumni", "HomeBucket": "alice-home"}, None),
            ({"AccessRole": "Admin", "HomeBucket": "alice-home"}, None),
            ({"AccessRole": "CurrentMember", "HomeBucket": "*"}, None),
            (MetadataError("NoSuchEntity"), None),
            (None, {"BucketScope": "User", "BucketOwner": "Bob", "OwnerAccessRole": "CurrentMember"}),
            (None, {"BucketScope": "ServiceManaged", "BucketOwner": "Alice", "OwnerAccessRole": "CurrentMember"}),
            (None, {"BucketScope": "User", "BucketOwner": "Alice", "OwnerAccessRole": "Alumni"}),
            (None, MetadataError()),
        ):
            with self.subTest(user_tags=user_tags, bucket_tags=bucket_tags):
                iam, s3 = Iam(), S3()
                if user_tags is not None:
                    iam.user_tags["Alice"] = user_tags
                if bucket_tags is not None:
                    s3.bucket_tags["alice-home"] = bucket_tags
                snapshot = self.capture(iam, s3)
                self.assertEqual(snapshot["users"], [{"user_name": "Alice", "role": "CurrentMember"}])
                self.assertEqual(snapshot["buckets"], [])

    def test_empty_or_deleted_group_means_no_members_and_never_discovers_admins(self):
        iam, s3 = Iam(()), S3(("Administrator",))
        iam.user_tags["Administrator"] = {"AccessRole": "Admin", "HomeBucket": "administrator-home"}
        self.assertEqual(self.capture(iam, s3)["users"], [])
        self.assertFalse(any(method == "list_user_tags" for method, _ in iam.reads))
        with mock.patch.object(iam, "get_group", side_effect=MetadataError("NoSuchEntity")):
            self.assertEqual(self.capture(iam, s3)["users"], [])

    def test_healthy_pass_revalidates_after_execution_and_returns_only_counts(self):
        iam, s3 = Iam(), S3()
        seen = []
        result = self.run_sync(iam, s3, lambda *args: seen.append(args[2]))
        self.assertEqual(result, {"status": "reconciled", "passes": 1, "members": 1,
                                  "metadata_ready": 1, "metadata_blocked": 0})
        self.assertEqual(len(seen), 1)
        self.assertEqual(sum(method == "get_group" for method, _ in iam.reads), 2)
        self.assertEqual(seen[0]["permissions_boundary_arn"], configuration()["permissions_boundary_arn"])
        self.assertNotIn("Alice", json.dumps(result))

    def test_membership_removed_mid_pass_is_reconciled_again_without_stale_member(self):
        iam, s3 = Iam(("Alice", "Bob")), S3(("Alice", "Bob"))
        seen = []

        def apply(*args):
            seen.append(copy.deepcopy(args[2]["s3_manifest"]))
            if len(seen) == 1:
                iam.members.remove("Bob")

        result = self.run_sync(iam, s3, apply)
        self.assertEqual(result["passes"], 2)
        self.assertEqual([u["user_name"] for u in seen[-1]["users"]], ["Alice"])

    def test_bucket_ownership_removed_mid_pass_triggers_inactive_reconciliation(self):
        iam, s3 = Iam(), S3()
        seen = []

        def apply(*args):
            seen.append(copy.deepcopy(args[2]["s3_manifest"]))
            if len(seen) == 1:
                s3.bucket_tags["alice-home"]["BucketOwner"] = "Bob"

        result = self.run_sync(iam, s3, apply)
        self.assertEqual(result["metadata_blocked"], 1)
        self.assertNotIn("home_bucket", seen[-1]["users"][0])

    def test_churn_ends_with_a_grant_free_pass_and_retryable_error(self):
        iam, s3 = Iam(("Alice", "Bob")), S3(("Alice", "Bob"))
        seen = []

        def apply(*args):
            seen.append(copy.deepcopy(args[2]["s3_manifest"]))
            if len(seen) <= 3:
                iam.members = ["Alice"] if len(iam.members) == 2 else ["Alice", "Bob"]

        with self.assertRaisesRegex(runtime.ReconciliationError, "grants disabled"):
            self.run_sync(iam, s3, apply)
        self.assertEqual(len(seen), 4)
        self.assertEqual(seen[-1]["buckets"], [])
        self.assertTrue(all("home_bucket" not in row for row in seen[-1]["users"]))

    def test_backend_exception_is_sanitized_and_region_clients_are_exact(self):
        def fail(*args):
            raise RuntimeError("private diagnostic payload must not escape")
        with self.assertRaises(runtime.ReconciliationError) as captured:
            self.run_sync(Iam(), S3(), fail)
        self.assertNotIn("private diagnostic", str(captured.exception))
        with self.assertRaises(runtime.RuntimeValidationError):
            runtime.run_reconciliation(Iam(), S3(), {"us-west-2": object()}, configuration(),
                                       account_id=ACCOUNT, region=REGION, reconcile_call=fail)

    def test_sdk_operation_and_code_survive_without_raw_diagnostics(self):
        error = MetadataError("AccessDenied")
        error.operation_name = "CreateRole"

        def fail(*args):
            raise error

        with self.assertRaises(runtime.ReconciliationError) as captured:
            self.run_sync(Iam(), S3(), fail)
        self.assertEqual(captured.exception.diagnostic, {"operation": "CreateRole", "code": "AccessDenied"})
        self.assertIn("operation=CreateRole code=AccessDenied", str(captured.exception))
        error.operation_name = "private / diagnostic"
        error.response["Error"]["Code"] = "private\ndiagnostic"
        with self.assertRaises(runtime.ReconciliationError) as captured:
            self.run_sync(Iam(), S3(), fail)
        self.assertNotIn("private", str(captured.exception))

    def test_returned_member_errors_are_failures_and_never_count_as_activated(self):
        failed = {"errors": {"Alice": {"operation": "CreateRole", "code": "AccessDenied"}},
                  "counts": {"active": 1}}
        with self.assertRaises(runtime.ReconciliationError) as captured:
            self.run_sync(Iam(), S3(), lambda *args: failed)
        self.assertEqual(captured.exception.diagnostic["code"], "AccessDenied")
        succeeded = {"errors": {}, "counts": {"active": 0, "pending_key": 1, "blocked": 0, "operations": 1}}
        result = self.run_sync(Iam(), S3(), lambda *args: succeeded)
        self.assertEqual(result["planned_active"], 0)
        self.assertEqual(result["pending_key"], 1)

    def test_lambda_envelope_does_not_supply_membership_or_log_its_contents(self):
        iam, s3 = Iam(), S3()
        clients = {"iam": iam, "s3": s3, "ec2": object()}
        session = types.SimpleNamespace(client=lambda service, **kwargs: clients[service])
        sdk = types.SimpleNamespace(Session=lambda **kwargs: session)
        context = types.SimpleNamespace(invoked_function_arn="arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:MemberSync")
        event = {"source": "aws.iam", "account": ACCOUNT, "detail-type": "AWS API Call via CloudTrail",
                 "detail": {"eventSource": "iam.amazonaws.com", "eventName": "RemoveUserFromGroup",
                            "requestParameters": {"userName": "Alice", "groupName": "lab_members"},
                            "unrelated": "do not log this event payload"}}
        seen = []
        with mock.patch.dict(sys.modules, {"boto3": sdk}), \
                mock.patch.dict("os.environ", {runtime.CONFIG_ENV: json.dumps(configuration())}), \
                mock.patch.object(runtime, "_backend", side_effect=lambda *args: seen.append(args[2])), \
                mock.patch("builtins.print") as printed:
            result = runtime.lambda_handler(event, context)
        self.assertEqual(result["trigger"], "iam")
        # A stale remove event cannot revoke a currently valid member by itself.
        self.assertEqual(seen[0]["s3_manifest"]["users"][0]["user_name"], "Alice")
        self.assertNotIn("requestParameters", json.dumps(result))
        printed.assert_not_called()
        with self.assertRaises(runtime.RuntimeValidationError):
            runtime.lambda_handler({**event, "account": "999999999999"}, context)
        self.assertEqual(runtime.lambda_handler({"source": "other"}, context), {"status": "ignored"})

    def test_schedule_and_manual_triggers_do_not_depend_on_cloudtrail_delivery(self):
        self.assertEqual(runtime._trigger({}, ACCOUNT), "manual")
        self.assertEqual(runtime._trigger({"source": "aws.events", "detail-type": "Scheduled Event"}, ACCOUNT), "schedule")
        self.assertEqual(runtime._trigger({"source": "wanglab.member-access", "action": "reconcile"}, ACCOUNT), "manual")

    def test_only_exact_controller_generated_pointer_events_are_ignored(self):
        from aws_audit.member_access.models import USER_TAG_KEYS
        event = {"source": "aws.iam", "account": ACCOUNT, "detail-type": "AWS API Call via CloudTrail",
                 "detail": {"eventSource": "iam.amazonaws.com", "eventName": "TagUser",
                            "userIdentity": {"type": "AssumedRole", "sessionContext": {"sessionIssuer": {
                                "arn": "arn:aws:iam::" + ACCOUNT + ":role/WangLabMemberAccessSync"}}},
                            "requestParameters": {"tags": [{"key": key, "value": "derived pointer"} for key in USER_TAG_KEYS]}}}
        self.assertEqual(runtime._trigger(event, ACCOUNT), "ignored")
        changed = copy.deepcopy(event)
        changed["detail"]["requestParameters"]["tags"].append({"key": "HomeBucket", "value": "new-home"})
        self.assertEqual(runtime._trigger(changed, ACCOUNT), "iam")
        changed = copy.deepcopy(event)
        changed["detail"]["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] += "Other"
        self.assertEqual(runtime._trigger(changed, ACCOUNT), "iam")
        changed = copy.deepcopy(event)
        changed["detail"]["eventName"] = "UntagUser"
        changed["detail"]["requestParameters"] = {"tagKeys": list(USER_TAG_KEYS)}
        self.assertEqual(runtime._trigger(changed, ACCOUNT), "ignored")

    def test_offline_package_uses_only_fixed_sources_and_is_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in runtime.PACKAGE_FILES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('"""Synthetic module."""\n')
            (root / "config").mkdir()
            (root / "config" / "ignored.json").write_text("excluded local metadata")
            (root / "aws_audit" / "member_access" / "extra.py").write_text("excluded = True")
            first = runtime.build_runtime_package(root)
            self.assertEqual(first, runtime.build_runtime_package(root))
            with zipfile.ZipFile(io.BytesIO(first)) as archive:
                self.assertEqual(archive.namelist(), list(runtime.PACKAGE_FILES))
                self.assertTrue(all(name.endswith(".py") for name in archive.namelist()))
            file = root / runtime.PACKAGE_FILES[-1]
            file.unlink()
            with self.assertRaises(runtime.RuntimeValidationError):
                runtime.build_runtime_package(root)
            file.symlink_to(root / runtime.PACKAGE_FILES[0])
            with self.assertRaises(runtime.RuntimeValidationError):
                runtime.build_runtime_package(root)



if __name__ == "__main__":
    unittest.main()
