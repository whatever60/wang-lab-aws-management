"""Verify the single audit deployment entry point without contacting AWS."""

import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from aws_audit.audit import setup


class AuditSetupTest(unittest.TestCase):
    def test_default_targets_only_base_region_without_region_discovery(self):
        with patch.object(setup, "aws_text") as discover:
            self.assertEqual(setup.resolve_target_regions("", "us-east-1"), ["us-east-1"])
            self.assertEqual(setup.resolve_target_regions("  ", "us-west-2"), ["us-west-2"])
        discover.assert_not_called()

    def test_target_region_expansion_is_explicit(self):
        with patch.object(setup, "aws_text", return_value="us-east-1\tus-west-2") as discover:
            self.assertEqual(
                setup.resolve_target_regions("us-west-2, us-east-1 us-west-2", "us-east-1"),
                ["us-west-2", "us-east-1"],
            )
            discover.assert_not_called()
            self.assertEqual(setup.resolve_target_regions("all", "us-east-1"),
                             ["us-east-1", "us-west-2"])
            discover.assert_called_once()
            for selection in (",", "all,us-east-1"):
                with self.subTest(selection=selection), self.assertRaises(SystemExit):
                    setup.resolve_target_regions(selection, "us-east-1")

    def test_cloudtrail_keeps_multi_region_coverage_for_create_and_update(self):
        for existing in ("None", "example-trail"):
            with self.subTest(existing=existing), \
                    patch.object(setup, "ensure_s3_bucket"), \
                    patch.object(setup, "aws_text", return_value=existing), \
                    patch.object(setup, "run_aws") as run:
                setup.setup_cloudtrail("111122223333", "us-east-1", "example-trail", "example-trail-bucket")
            operation = "update-trail" if existing == "example-trail" else "create-trail"
            trail_calls = [call for call in run.call_args_list if call.args[0][:2] == ["cloudtrail", operation]]
            self.assertEqual(len(trail_calls), 1)
            self.assertIn("--is-multi-region-trail", trail_calls[0].args[0])
            self.assertEqual(trail_calls[0].kwargs["region"], "us-east-1")


    def test_shell_entry_point_forwards_arguments_from_another_directory(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            runner = temp / "python-runner"
            runner.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$AUDIT_WRAPPER_CAPTURE"\n')
            runner.chmod(0o700)
            capture = temp / "arguments.txt"
            env = {**os.environ, "AWS_AUDIT_PYTHON": str(runner),
                   "AUDIT_WRAPPER_CAPTURE": str(capture)}
            arguments = ["--base-region", "us-east-2", "--config-recorder-name", "example-recorder"]
            subprocess.run(["bash", str(root / "setup_ec2_ebs_ami_audit.sh"), *arguments],
                           cwd=temp, env=env, check=True)
            self.assertEqual(capture.read_text().splitlines(),
                             ["-m", "aws_audit.audit.setup", *arguments])


    def test_retired_notification_commands_cannot_recreate_resources(self):
        for command in ("events", "slack"):
            with self.subTest(command=command), patch("sys.argv", ["audit-setup", command]), \
                    patch("sys.stderr"), self.assertRaises(SystemExit):
                setup.parse_args()

    def test_all_records_without_notification_provisioning(self):
        with patch("sys.argv", ["audit-setup", "all"]), \
                patch.object(setup, "aws_text", return_value="123456789012"), \
                patch.object(setup, "setup_cloudtrail") as trail, \
                patch.object(setup, "setup_config") as config, patch("builtins.print"):
            self.assertEqual(setup.main(), 0)
        trail.assert_called_once()
        config.assert_called_once()
        self.assertFalse(hasattr(setup, "setup_eventbridge_and_sns"))
