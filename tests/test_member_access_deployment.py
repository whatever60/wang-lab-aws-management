import copy
import json
import unittest

from aws_audit.member_access.deployment import cloudformation_template, data_boundary, runtime_permissions


def approved():
    account = "111122223333"
    return {"ec2_config": {"account_id": account, "regions": ["us-east-1"]},
            "permissions_boundary_arn": "arn:aws:iam::" + account + ":policy/WangLabMemberS3Boundary"}


class DeploymentTest(unittest.TestCase):
    def test_control_plane_has_no_direct_compute_or_object_data_grant(self):
        config = approved()
        document = runtime_permissions("111122223333", "us-east-1", config["permissions_boundary_arn"])
        allows = [s for s in document["Statement"] if s["Effect"] == "Allow"]
        actions = {a for s in allows for a in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])}
        self.assertNotIn("ec2:RunInstances", actions)
        attachment = next(s for s in allows if s["Sid"] == "AttachDataProfileToNewNativeInstance")
        self.assertTrue(attachment["Resource"].endswith(":instance/*"))
        self.assertEqual(attachment["Condition"]["Null"]["ec2:ResourceTag/wanglab:CreatorUserId"], "false")
        self.assertNotIn("ec2:ReplaceIamInstanceProfileAssociation", actions)
        self.assertNotIn("ec2:DisassociateIamInstanceProfile", actions)
        self.assertNotIn("s3:GetObject", actions)
        self.assertNotIn("iam:CreateAccessKey", actions)
        create = next(s for s in allows if s["Sid"] == "CreateBoundedRoles")
        self.assertEqual(create["Condition"]["StringEquals"]["iam:PermissionsBoundary"], config["permissions_boundary_arn"])
        self.assertTrue(create["Resource"].endswith(":role/wanglab/member-s3/*"))
        self.assertNotIn("iam:TagUser", actions)
        self.assertNotIn("iam:UntagUser", actions)
        self.assertFalse(any(a.startswith("ec2:CreateLaunchTemplate") or a == "ec2:ModifyLaunchTemplate" for a in actions))

    def test_instance_role_ceiling_does_not_grant_administration(self):
        doc = data_boundary("111122223333")
        actions = {a for s in doc["Statement"] for a in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])}
        self.assertNotIn("s3:*", actions)
        self.assertNotIn("s3:PutBucketPolicy", actions)
        self.assertNotIn("s3:PutBucketAcl", actions)
        self.assertFalse(any(a.startswith(("ec2:", "iam:")) for a in actions))
        own = next(s for s in doc["Statement"] if s["Sid"] == "WriteOwnHomeData")
        self.assertEqual(own["Resource"], "arn:aws:s3:::${aws:PrincipalTag/HomeBucket}/*")
        self.assertEqual(own["Condition"]["StringEquals"]["s3:ResourceAccount"], "111122223333")

    def test_stack_uses_one_rule_for_events_and_periodic_repair(self):
        stack = cloudformation_template(approved(), artifact_bucket="example-artifacts", artifact_key="member-access/releases/reviewed.zip")
        resources = stack["Resources"]
        self.assertEqual(resources["Function"]["Properties"]["ReservedConcurrentExecutions"], 1)
        self.assertEqual(resources["IdentityChanges"]["Properties"]["ScheduleExpression"], "rate(5 minutes)")
        self.assertIn("RemoveUserFromGroup", resources["IdentityChanges"]["Properties"]["EventPattern"]["detail"]["eventName"])
        env = resources["Function"]["Properties"]["Environment"]["Variables"]
        self.assertEqual(json.loads(env["WANGLAB_MEMBER_ACCESS_CONFIG"]), approved())
        self.assertEqual(len(resources), 7)
        self.assertFalse(any(r["Type"] in ("AWS::SSM::Parameter", "AWS::SQS::Queue", "AWS::Lambda::EventInvokeConfig")
                             for r in resources.values()))
        self.assertNotIn("DeadLetterConfig", resources["Function"]["Properties"])
        self.assertIn("Errors", resources)
        self.assertEqual(resources["Boundary"]["DeletionPolicy"], "Retain")

    def test_oversized_configuration_is_rejected_before_deployment(self):
        config = copy.deepcopy(approved())
        config["ec2_config"]["shared_grants"] = [
            {"resource_arn": "arn:aws:ec2:us-east-1:111122223333:instance/i-%017x" % n,
             "principal_arns": ["arn:aws:iam::111122223333:user/Member"], "actions": ["ec2:StartInstances"],
             "expires_at": "2027-01-01T00:00:00Z", "reason": "x" * 200} for n in range(30)]
        with self.assertRaisesRegex(ValueError, "4 KB"):
            cloudformation_template(config, artifact_bucket="example-artifacts", artifact_key="member-access/releases/reviewed.zip")

    def test_deployment_rejects_unmanaged_artifacts_or_foreign_boundary(self):
        with self.assertRaises(ValueError):
            cloudformation_template(approved(), artifact_bucket="example-artifacts", artifact_key="private/credentials.zip")
        config = approved()
        config["permissions_boundary_arn"] = "arn:aws:iam::111122223333:policy/AnotherBoundary"
        with self.assertRaises(ValueError):
            cloudformation_template(config, artifact_bucket="example-artifacts", artifact_key="member-access/releases/reviewed.zip")
