"""Offline approval and target-provenance regressions; never contact AWS or nodes."""
import base64
import copy
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aws_audit.hpc import lifecycle, user_sync, workflow


def key_bytes(payload):
    return "ssh-ed25519 " + base64.b64encode(
        struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + payload
    ).decode()


APPROVED_KEY = key_bytes(bytes(range(32)))
OTHER_KEY = key_bytes(bytes(reversed(range(32))))
MEMBER = {"iam_user": "Alice_User", "linux_user": "alice", "uid": 2012}
STACK = "arn:aws:cloudformation:us-east-1:123456789012:stack/lab-hpc/00000000-0000-0000-0000-000000000001"
NESTED = "arn:aws:cloudformation:us-east-1:123456789012:stack/lab-hpc-compute/00000000-0000-0000-0000-000000000002"
HEAD = "i-00000000000000001"
COMPUTE = "i-00000000000000002"
FORGED = "i-00000000000000003"
PROFILE = "arn:aws:iam::123456789012:instance-profile/lab-hpc-compute"


def source_for(key=APPROVED_KEY):
    return {"ec2_key_name": "alice", "public_key_sha256": user_sync.digest(key.encode("utf-8"))}


def cfn_resource(kind, physical_id):
    return {"ResourceType": kind, "PhysicalResourceId": physical_id, "ResourceStatus": "CREATE_COMPLETE"}


def instance(instance_id, node_type):
    result = {"InstanceId": instance_id, "State": {"Name": "running"}, "Tags": [
        {"Key": "parallelcluster:cluster-name", "Value": "lab-hpc"},
        {"Key": "parallelcluster:node-type", "Value": node_type},
    ]}
    if node_type == "Compute":
        result["Tags"] += [
            {"Key": "aws:ec2launchtemplate:id", "Value": "lt-00000000000000001"},
            {"Key": "aws:ec2launchtemplate:version", "Value": "1"},
        ]
        result["IamInstanceProfile"] = {"Arn": PROFILE, "Id": "AIPATRUSTED00000001"}
    return result


class LifecycleSecurityTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hpc-security-")
        self.addCleanup(self.temporary.cleanup)
        # macOS /var may be a system symlink: deliberately configure the real path.
        self.directory = Path(self.temporary.name).resolve()
        self.manifest = workflow.load_manifest(Path("config/hpc_workflow_manifest.json"))
        self.manifest["user_lifecycle"]["current_s3_uri"] = "s3://approved-assets/users/current.json"
        self.manifest["user_lifecycle"]["public_key_sources"] = {"Alice_User": source_for()}
        for kind in ["runtime", "bootstrap"]:
            path = self.directory / (kind + ".source")
            path.write_text("reviewed " + kind + "\n")
            self.manifest["user_lifecycle"][kind + "_local_path"] = str(path)
        self.preview_path = self.directory / "preview.json"

    def publication_aws(self, command):
        if command[:2] == ["s3api", "get-bucket-versioning"]:
            return {"Status": "Enabled"}
        if command[:2] == ["ec2", "describe-key-pairs"]:
            return {"KeyPairs": [{"KeyName": "alice", "KeyPairId": "key-same-id", "PublicKey": APPROVED_KEY}]}
        raise AssertionError("Unexpected AWS call: " + repr(command))

    def prepare(self):
        with mock.patch.object(lifecycle, "aws_json", side_effect=self.publication_aws), mock.patch.object(
            lifecycle, "load_release", return_value=(None, None)
        ), mock.patch.object(lifecycle, "put_file") as put:
            result = lifecycle.publish_users(self.manifest, [MEMBER], self.preview_path)
            put.assert_not_called()
        return result

    def execute(self, approval):
        return lifecycle.publish_users(self.manifest, [MEMBER], self.preview_path,
                                       execute=True, approved_preview_sha256=approval)

    def test_initial_key_requires_explicit_source_and_digest_before_any_aws_read(self):
        for source in [None, {"ec2_key_name": "alice"}, {"ec2_key_name": "alice", "public_key_sha256": "bad"}]:
            with self.subTest(source=source):
                self.manifest["user_lifecycle"]["public_key_sources"] = {} if source is None else {"Alice_User": source}
                with mock.patch.object(lifecycle, "aws_json") as aws, self.assertRaisesRegex(ValueError, "pin|public_key_sha256"):
                    lifecycle.public_key_for_user(self.manifest, MEMBER)
                aws.assert_not_called()

    def test_same_ec2_name_and_id_cannot_authorize_a_replaced_public_key(self):
        with mock.patch.object(lifecycle, "aws_json", return_value={"KeyPairs": [
            {"KeyName": "alice", "KeyPairId": "key-same-id", "PublicKey": OTHER_KEY}
        ]}), self.assertRaisesRegex(ValueError, "administrator-approved pin"):
            lifecycle.public_key_for_user(self.manifest, MEMBER)

    def test_pin_uses_normalized_key_without_comment_or_newline(self):
        with mock.patch.object(lifecycle, "aws_json", return_value={"KeyPairs": [{"PublicKey": APPROVED_KEY + " Alice\n"}]}):
            self.assertEqual(lifecycle.public_key_for_user(self.manifest, MEMBER), APPROVED_KEY)

    def test_local_pub_requires_safe_file_and_parent_permissions(self):
        public = self.directory / "alice.pub"
        public.write_text(APPROVED_KEY + " reviewed\n")
        self.manifest["user_lifecycle"]["public_key_sources"]["Alice_User"] = {
            "local_public_key_path": str(public), "public_key_sha256": source_for()["public_key_sha256"],
        }
        self.assertEqual(lifecycle.public_key_for_user(self.manifest, MEMBER), APPROVED_KEY)
        for permissions in [0o664, 0o666]:
            with self.subTest(permissions=permissions):
                public.chmod(permissions)
                with self.assertRaisesRegex(ValueError, "group/others"):
                    lifecycle.public_key_for_user(self.manifest, MEMBER)
        public.chmod(0o644)
        self.directory.chmod(0o770)
        try:
            with self.assertRaisesRegex(ValueError, "parent directories"):
                lifecycle.public_key_for_user(self.manifest, MEMBER)
        finally:
            self.directory.chmod(0o700)

    def test_local_pub_rejects_symlink_hardlink_and_non_public_suffix(self):
        original = self.directory / "original.pub"
        original.write_text(APPROVED_KEY)
        alias = self.directory / "alias.pub"
        source = {"local_public_key_path": str(alias), "public_key_sha256": source_for()["public_key_sha256"]}
        self.manifest["user_lifecycle"]["public_key_sources"]["Alice_User"] = source
        alias.symlink_to(original)
        with self.assertRaises(OSError):
            lifecycle.public_key_for_user(self.manifest, MEMBER)
        alias.unlink()
        os.link(original, alias)
        with self.assertRaisesRegex(ValueError, "hardlinked"):
            lifecycle.public_key_for_user(self.manifest, MEMBER)
        source["local_public_key_path"] = str(self.directory / "private.pem")
        with mock.patch.object(lifecycle, "read_admin_file") as read, self.assertRaisesRegex(ValueError, ".pub"):
            lifecycle.public_key_for_user(self.manifest, MEMBER)
        read.assert_not_called()

    def test_preview_digest_is_stable_and_covers_the_full_review_envelope(self):
        first = self.prepare()
        original = self.preview_path.read_bytes()
        second = self.prepare()
        self.assertEqual(first["preview_sha256"], second["preview_sha256"])
        self.assertEqual(self.preview_path.read_bytes(), original)
        envelope = json.loads(original)
        self.assertEqual(user_sync.digest(user_sync.canonical_bytes(envelope)), first["preview_sha256"])
        self.assertEqual(envelope["public_key_sources"]["Alice_User"], source_for())
        self.assertEqual(set(envelope["code"]), {"runtime", "bootstrap"})
        self.assertEqual(self.preview_path.stat().st_mode & 0o777, 0o600)

    def test_execute_without_explicit_approval_does_not_read_aws_or_replace_preview(self):
        self.prepare()
        before = self.preview_path.read_bytes()
        with mock.patch.object(lifecycle, "aws_json") as aws, mock.patch.object(lifecycle, "put_file") as put:
            with self.assertRaisesRegex(ValueError, "approved-preview-sha256"):
                lifecycle.publish_users(self.manifest, [MEMBER], self.preview_path, execute=True)
            aws.assert_not_called()
            put.assert_not_called()
        self.assertEqual(self.preview_path.read_bytes(), before)

    def test_tampered_preview_is_rejected_without_any_aws_write(self):
        preview = self.prepare()
        changed = json.loads(self.preview_path.read_bytes())
        changed["registry"]["users"][0]["public_keys"] = [OTHER_KEY]
        self.preview_path.write_bytes(user_sync.canonical_bytes(changed))
        with mock.patch.object(lifecycle, "aws_json") as aws, mock.patch.object(lifecycle, "put_file") as put:
            with self.assertRaisesRegex(ValueError, "Preview does not match"):
                self.execute(preview["preview_sha256"])
            aws.assert_not_called()
            put.assert_not_called()

    def test_key_rotation_after_preview_cannot_be_silently_published(self):
        preview = self.prepare()
        before = self.preview_path.read_bytes()
        # Even an administrator-updated source pin needs a newly approved preview.
        self.manifest["user_lifecycle"]["public_key_sources"]["Alice_User"] = source_for(OTHER_KEY)
        def changed_source(command):
            response = self.publication_aws(command)
            if command[:2] == ["ec2", "describe-key-pairs"]:
                response["KeyPairs"][0]["PublicKey"] = OTHER_KEY
            return response
        with mock.patch.object(lifecycle, "aws_json", side_effect=changed_source), mock.patch.object(
            lifecycle, "load_release", return_value=(None, None)
        ), mock.patch.object(lifecycle, "put_file") as put, self.assertRaisesRegex(ValueError, "changed since approval"):
            self.execute(preview["preview_sha256"])
        put.assert_not_called()
        self.assertEqual(self.preview_path.read_bytes(), before)

    def test_code_destination_or_current_pointer_change_requires_new_approval(self):
        for changed_input in ["runtime", "destination", "etag"]:
            with self.subTest(changed_input=changed_input):
                original_manifest = copy.deepcopy(self.manifest)
                original_runtime = Path(self.manifest["user_lifecycle"]["runtime_local_path"]).read_bytes()
                preview = self.prepare()
                original_preview = self.preview_path.read_bytes()
                previous = (None, None)
                if changed_input == "runtime":
                    Path(self.manifest["user_lifecycle"]["runtime_local_path"]).write_text("unreviewed changed runtime\n")
                elif changed_input == "destination":
                    self.manifest["user_lifecycle"]["current_s3_uri"] = "s3://other-assets/users/current.json"
                else:
                    previous = ({"registry": preview["preview"]["registry"]}, {"ETag": '"new-release"'})
                with mock.patch.object(lifecycle, "aws_json", side_effect=self.publication_aws), mock.patch.object(
                    lifecycle, "load_release", return_value=previous
                ), mock.patch.object(lifecycle, "put_file") as put, self.assertRaisesRegex(ValueError, "changed since approval"):
                    self.execute(preview["preview_sha256"])
                put.assert_not_called()
                self.assertEqual(self.preview_path.read_bytes(), original_preview)
                self.manifest = original_manifest
                Path(self.manifest["user_lifecycle"]["runtime_local_path"]).write_bytes(original_runtime)

    def test_approved_execute_uploads_frozen_reviewed_bytes_then_conditional_pointer(self):
        preview = self.prepare()
        before = self.preview_path.read_bytes()
        uploaded = []
        def record_put(bucket, key, path, **conditions):
            uploaded.append((bucket, key, path.read_bytes(), conditions))
            return {"VersionId": "version-" + str(len(uploaded))}
        with mock.patch.object(lifecycle, "aws_json", side_effect=self.publication_aws), mock.patch.object(
            lifecycle, "load_release", return_value=(None, None)
        ), mock.patch.object(lifecycle, "put_file", side_effect=record_put):
            pointer = self.execute(preview["preview_sha256"])
        self.assertEqual(len(uploaded), 4)
        self.assertEqual(uploaded[-1][1], "users/current.json")
        self.assertEqual(uploaded[-1][3], {"if_none_match": "*"})
        self.assertEqual(user_sync.digest(uploaded[0][2]), pointer["registry_sha256"])
        self.assertEqual(user_sync.digest(uploaded[1][2]), pointer["runtime_sha256"])
        self.assertEqual(user_sync.digest(uploaded[2][2]), pointer["bootstrap_sha256"])
        self.assertEqual(self.preview_path.read_bytes(), before)

    def test_cli_exposes_explicit_preview_approval(self):
        args = workflow.build_parser().parse_args(["publish-users", "--execute", "--approved-preview-sha256", "a" * 64])
        self.assertEqual(args.approved_preview_sha256, "a" * 64)

    def target_fixture(self):
        cluster = {"clusterName": "lab-hpc", "region": "us-east-1", "cloudFormationStackStatus": "CREATE_COMPLETE",
                   "headNode": {"instanceId": HEAD}, "cloudformationStackArn": STACK}
        resources = {
            STACK: [cfn_resource("AWS::EC2::Instance", HEAD), cfn_resource("AWS::CloudFormation::Stack", NESTED)],
            NESTED: [cfn_resource("AWS::EC2::LaunchTemplate", "lt-00000000000000001"),
                     cfn_resource("AWS::IAM::InstanceProfile", "lab-hpc-compute")],
        }
        instances = [instance(HEAD, "HeadNode"), instance(COMPUTE, "Compute")]
        return cluster, resources, instances

    def target_aws(self, resources, instances):
        def read(command):
            if command[:2] == ["cloudformation", "list-stack-resources"]:
                return {"StackResourceSummaries": resources[command[command.index("--stack-name") + 1]]}
            if command[:2] == ["ec2", "describe-instances"]:
                return {"Reservations": [{"Instances": instances}]}
            if command[:2] == ["iam", "get-instance-profile"]:
                return {"InstanceProfile": {"Arn": PROFILE, "InstanceProfileId": "AIPATRUSTED00000001"}}
            raise AssertionError("Unexpected AWS call: " + repr(command))
        return read

    def test_real_head_and_nested_cfn_compute_profile_and_template_are_accepted(self):
        cluster, resources, instances = self.target_fixture()
        with mock.patch.object(lifecycle, "describe_cluster", return_value=cluster), mock.patch.object(
            lifecycle, "aws_json", side_effect=self.target_aws(resources, instances)
        ) as aws:
            self.assertEqual(lifecycle.sync_targets(self.manifest), [
                {"instance_id": HEAD, "node_role": "head", "state": "running"},
                {"instance_id": COMPUTE, "node_role": "compute", "state": "running"},
            ])
        self.assertTrue(any(NESTED in call.args[0] for call in aws.call_args_list))
        self.assertFalse(any(call.args[0][:2] == ["ssm", "send-command"] for call in aws.call_args_list))

    def test_forged_compute_tags_profile_or_protected_template_identity_are_rejected(self):
        for forgery in ["ordinary_tags_only", "other_template", "other_profile", "recreated_profile_id", "missing_version"]:
            with self.subTest(forgery=forgery):
                cluster, resources, instances = self.target_fixture()
                forged = instance(FORGED, "Compute")
                if forgery == "ordinary_tags_only":
                    forged["Tags"] = forged["Tags"][:2]
                elif forgery == "other_template":
                    forged["Tags"][2]["Value"] = "lt-personal"
                elif forgery == "other_profile":
                    forged["IamInstanceProfile"]["Arn"] = "arn:aws:iam::123456789012:instance-profile/personal"
                elif forgery == "recreated_profile_id":
                    forged["IamInstanceProfile"]["Id"] = "AIPAREPLACED000001"
                else:
                    forged["Tags"] = [tag for tag in forged["Tags"] if tag["Key"] != "aws:ec2launchtemplate:version"]
                instances.append(forged)
                with mock.patch.object(lifecycle, "describe_cluster", return_value=cluster), mock.patch.object(
                    lifecycle, "aws_json", side_effect=self.target_aws(resources, instances)
                ) as aws, self.assertRaisesRegex(ValueError, "forged/untrusted compute"):
                    lifecycle.sync_targets(self.manifest)
                self.assertFalse(any(call.args[0][:2] == ["ssm", "send-command"] for call in aws.call_args_list))

    def test_forged_head_cannot_replace_the_api_and_cfn_authoritative_instance(self):
        cluster, resources, instances = self.target_fixture()
        instances.append(instance(FORGED, "HeadNode"))
        with mock.patch.object(lifecycle, "describe_cluster", return_value=cluster), mock.patch.object(
            lifecycle, "aws_json", side_effect=self.target_aws(resources, instances)
        ), self.assertRaisesRegex(ValueError, "forged/untrusted head"):
            lifecycle.sync_targets(self.manifest)
        resources[STACK] = [resource for resource in resources[STACK] if resource["ResourceType"] != "AWS::EC2::Instance"]
        with mock.patch.object(lifecycle, "describe_cluster", return_value=cluster), mock.patch.object(
            lifecycle, "aws_json", side_effect=self.target_aws(resources, instances)
        ), self.assertRaisesRegex(ValueError, "head instance is not owned"):
            lifecycle.sync_targets(self.manifest)

    def test_wrong_account_nested_stack_or_incomplete_stack_fails_before_dispatch(self):
        cluster, resources, instances = self.target_fixture()
        resources[STACK][1]["PhysicalResourceId"] = NESTED.replace("123456789012", "999999999999")
        with mock.patch.object(lifecycle, "describe_cluster", return_value=cluster), mock.patch.object(
            lifecycle, "aws_json", side_effect=self.target_aws(resources, instances)
        ), self.assertRaisesRegex(ValueError, "Unexpected nested stack"):
            lifecycle.sync_targets(self.manifest)
        cluster["cloudFormationStackStatus"] = "UPDATE_IN_PROGRESS"
        with mock.patch.object(lifecycle, "describe_cluster", return_value=cluster), mock.patch.object(
            lifecycle, "aws_json"
        ) as aws, self.assertRaisesRegex(ValueError, "must be stable"):
            lifecycle.sync_targets(self.manifest)
        aws.assert_not_called()


if __name__ == "__main__":
    unittest.main()
