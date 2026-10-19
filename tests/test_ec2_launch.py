"""Offline launch requests must fit the approved sources and resource-tag policy."""

import contextlib
import io
import json
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import patch

from aws_audit.ec2_access.launch import build_launch_request, main
from aws_audit.ec2_access.policy import MemberEc2Config


ACCOUNT = "123456789012"
REGION = "us-east-1"


def source(region, kind, identifier, account=ACCOUNT):
    return "arn:aws:ec2:%s:%s:%s/%s" % (region, account, kind, identifier)


def config():
    return MemberEc2Config(ACCOUNT, (REGION, "us-east-2"), ("t3.micro", "t3.small"),
                           (source(REGION, "image", "ami-22222222222222222", ""),
                            source(REGION, "image", "ami-11111111111111111", ""),
                            source("us-east-2", "image", "ami-33333333333333333", "")),
                           (source(REGION, "snapshot", "snap-11111111111111111", ""),),
                           (source(REGION, "subnet", "subnet-11111111111111111"),
                            source("us-east-2", "subnet", "subnet-22222222222222222")),
                           (source(REGION, "security-group", "sg-11111111111111111"),
                            source("us-east-2", "security-group", "sg-22222222222222222")))


def request(**overrides):
    args = {"username": "Alice_User", "key_name": "alice_key", "instance_type": "t3.micro"}
    args.update(overrides)
    return build_launch_request(config(), **args)


class MemberEc2LaunchTest(unittest.TestCase):
    def test_defaults_create_one_instance_and_new_temporary_public_interface(self):
        result = request()
        self.assertEqual(result["ImageId"], "ami-22222222222222222")
        self.assertEqual((result["MinCount"], result["MaxCount"]), (1, 1))
        self.assertEqual(result["NetworkInterfaces"], [{
            "DeviceIndex": 0, "SubnetId": "subnet-11111111111111111", "Groups": ["sg-11111111111111111"],
            "AssociatePublicIpAddress": True, "DeleteOnTermination": True}])
        self.assertEqual(set(result), {"ImageId", "InstanceType", "KeyName", "MinCount", "MaxCount",
                                       "NetworkInterfaces", "TagSpecifications"})

    def test_all_three_destinations_receive_exact_owner_and_project(self):
        result = request(name="Alice console")
        self.assertEqual([item["ResourceType"] for item in result["TagSpecifications"]],
                         ["instance", "volume", "network-interface"])
        for item in result["TagSpecifications"]:
            self.assertEqual({tag["Key"]: tag["Value"] for tag in item["Tags"]},
                             {"Owner": "Alice_User", "Project": "personal", "Name": "Alice console"})
        result["TagSpecifications"][0]["Tags"][0]["Value"] = "changed"
        self.assertEqual(result["TagSpecifications"][1]["Tags"][0]["Value"], "Alice_User")
        self.assertEqual(request()["TagSpecifications"][0]["Tags"][0]["Value"], "Alice_User")

    def test_name_is_optional_and_cannot_inject_extra_tag_keys(self):
        for item in request()["TagSpecifications"]:
            self.assertEqual([tag["Key"] for tag in item["Tags"]], ["Owner", "Project"])
        result = request(name='Owner=Bob; "Project": "shared"')
        self.assertEqual(len(result["TagSpecifications"][0]["Tags"]), 3)
        self.assertEqual(result["TagSpecifications"][0]["Tags"][0]["Value"], "Alice_User")

    def test_explicit_choices_and_region_use_only_approved_sources(self):
        self.assertEqual(request(image_id="ami-11111111111111111")["ImageId"], "ami-11111111111111111")
        result = request(region="us-east-2", instance_type="t3.small")
        self.assertEqual(result["ImageId"], "ami-33333333333333333")
        self.assertEqual(result["NetworkInterfaces"][0]["SubnetId"], "subnet-22222222222222222")
        self.assertEqual(result["NetworkInterfaces"][0]["Groups"], ["sg-22222222222222222"])

    def test_unknown_or_cross_region_sources_and_types_are_rejected(self):
        for args in ({"region": "us-west-2"}, {"image_id": "ami-fffffffffffffffff"},
                     {"image_id": "ami-33333333333333333"},
                     {"subnet_id": "subnet-22222222222222222"},
                     {"security_group_id": "sg-22222222222222222"},
                     {"instance_type": "p5.48xlarge"}, {"instance_type": "t3.*"}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                request(**args)

    def test_missing_approved_source_in_selected_region_is_rejected(self):
        changed = replace(config(), approved_security_group_arns=(config().approved_security_group_arns[0],))
        with self.assertRaisesRegex(ValueError, "no approved security group"):
            build_launch_request(changed, username="Alice", key_name="alice_key", instance_type="t3.micro", region="us-east-2")

    def test_exact_username_key_and_display_name_validation(self):
        for name in ("", "Alice/*", "${aws:username}", "Alice User", "A" * 65, "Alice\n", None):
            with self.subTest(username=name), self.assertRaises(ValueError):
                request(username=name)
        for key in ("", " alice", "alice ", "alice\nkey", "alice*", "x" * 256, "非ASCII", None):
            with self.subTest(key_name=key), self.assertRaises(ValueError):
                request(key_name=key)
        for name in ("", " ", "x" * 257, "alice\nserver", "x\x7f"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                request(name=name)
        self.assertEqual(request(username="Alice+=,.@_-", name="分析 server")["KeyName"], "alice_key")

    def test_cli_stdout_is_only_json_and_stderr_identifies_selected_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(asdict(config())), encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                    patch("socket.socket", side_effect=AssertionError("must remain offline")), \
                    patch("subprocess.run", side_effect=AssertionError("must not invoke AWS CLI")):
                main([str(path), "--username", "Alice_User", "--key-name", "alice_key",
                      "--instance-type", "t3.micro", "--region", "us-east-2"])
            self.assertEqual(json.loads(out.getvalue()), request(region="us-east-2"))
            self.assertIn("region=us-east-2", err.getvalue())
            self.assertIn("ami-33333333333333333", err.getvalue())
            self.assertIn("--cli-input-json file://launch.json --dry-run", err.getvalue())
            self.assertIn("key Owner match --username", err.getvalue())

    def test_cli_bad_config_and_unapproved_request_emit_no_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for mapping, image_args in (({"unknown": True}, []), (asdict(config()), ["--image-id", "ami-fffffffffffffffff"])):
                path.write_text(json.dumps(mapping), encoding="utf-8")
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as raised:
                    main([str(path), "--username", "Alice_User", "--key-name", "alice_key",
                          "--instance-type", "t3.micro", *image_args])
                self.assertEqual(raised.exception.code, 2)
                self.assertEqual(out.getvalue(), "")
                self.assertIn("error:", err.getvalue())


if __name__ == "__main__":
    unittest.main()
