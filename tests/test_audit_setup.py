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
    def test_invalid_environment_choices_are_rejected_before_setup(self):
        for name, value in {"ALERT_DESTINATION": "sms", "CHATBOT_LOGGING_LEVEL": "DEBUG",
                            "CHATBOT_USER_AUTHORIZATION_REQUIRED": "yes"}.items():
            with self.subTest(name=name), patch.dict(os.environ, {name: value}, clear=True), \
                    patch("sys.argv", ["audit-setup", "--email-endpoint", "audit@example.test"]):
                with self.assertRaises(SystemExit):
                    setup.validate_args(setup.parse_args())

    def test_legacy_environment_flags_and_packaged_enricher_source(self):
        with patch.dict(os.environ, {"BASE_REGION": "us-east-2", "EMAIL_ENDPOINT": "audit@example.test"}, clear=True), \
                patch("sys.argv", ["audit-setup", "--base-region", "us-west-2"]):
            args = setup.parse_args()
            setup.validate_args(args)
        self.assertEqual(args.base_region, "us-west-2")
        self.assertEqual(args.email_endpoint, "audit@example.test")
        self.assertEqual(args.chatbot_region, "us-east-2")
        source = Path(args.enricher_source_path)
        self.assertEqual(source, Path(setup.__file__).with_name("ec2_audit_enricher_lambda.py"))
        archive = Path(setup.build_enricher_zip(str(source)))
        try:
            with zipfile.ZipFile(archive) as zipped:
                self.assertEqual(zipped.namelist(), [source.name])
                self.assertEqual(zipped.read(source.name), source.read_bytes())
        finally:
            archive.unlink()

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
            arguments = ["--base-region", "us-east-2", "--email-endpoint", "audit@example.test"]
            subprocess.run(["bash", str(root / "setup_ec2_ebs_ami_audit.sh"), *arguments],
                           cwd=temp, env=env, check=True)
            self.assertEqual(capture.read_text().splitlines(),
                             ["-m", "aws_audit.audit.setup", *arguments])

    def test_no_notifications_only_disables_exact_existing_rules(self):
        rule = "example-audit-rule"
        with patch.object(setup, "aws_json", side_effect=[
            {"Rules": [{"Name": rule}, {"Name": rule + "-other"}]},
            {"Rules": [{"Name": rule + "-other"}]},
        ]), patch.object(setup, "run_aws") as run, patch.object(setup, "build_enricher_zip") as package:
            topics = setup.setup_eventbridge_and_sns(
                "111122223333", ["us-east-1", "us-west-2"], "example-topic", rule,
                "none", "", "example-function", "example-role", "unused.py", "example-state")
        self.assertEqual(topics, [])
        run.assert_called_once_with(["events", "disable-rule", "--name", rule], region="us-east-1")
        package.assert_not_called()

    def test_all_without_slack_still_sets_up_recording(self):
        for destination in ("none", "email"):
            arguments = ["audit-setup", "all"]
            if destination == "email":
                arguments += ["--alert-destination", "email", "--email-endpoint", "audit@example.test"]
            with self.subTest(destination=destination), patch.dict(os.environ, {}, clear=True), \
                    patch("sys.argv", arguments), patch.object(setup, "aws_text", return_value="111122223333"), \
                    patch.object(setup, "resolve_target_regions", return_value=["us-east-1"]), \
                    patch.object(setup, "setup_cloudtrail") as trail, \
                    patch.object(setup, "setup_config") as config, \
                    patch.object(setup, "setup_eventbridge_and_sns", return_value=[]) as events, \
                    patch.object(setup, "setup_slack_channel_configuration") as slack, \
                    patch.object(setup, "run_aws"), patch("builtins.print"):
                self.assertEqual(setup.main(), 0)
                trail.assert_called_once()
                config.assert_called_once()
                self.assertEqual(events.call_args.kwargs["alert_destination"], destination)
                slack.assert_not_called()
