import copy
import json
import unittest

from aws_audit.member_access.deployment import cloudformation_template, data_boundary, runtime_permissions


def approved():
    account = "111122223333"
    prefix = "arn:aws:ec2:us-east-1:"
    ec2 = {"account_id": account, "regions": ["us-east-1"], "instance_types": ["t3.micro"],
           "approved_image_arns": [prefix + ":image/ami-111"],
           "approved_snapshot_arns": [prefix + ":snapshot/snap-111"],
           "approved_subnet_arns": [prefix + account + ":subnet/subnet-111"],
           "approved_security_group_arns": [prefix + account + ":security-group/sg-111"],
           "member_launch": {"role_path": "/wanglab/member-s3/", "instance_profile_path": "/wanglab/member-s3/",
                             "template_tag_keys": ["MemberLaunchUbuntu2404", "MemberLaunchAl2023", "MemberLaunchDL2204", "MemberLaunchDL2404"], "require_template": True}}
    return {"ec2_config": ec2, "member_group": "lab_members",
            "permissions_boundary_arn": "arn:aws:iam::" + account + ":policy/WangLabMemberS3Boundary",
            "flavors": [{"name": name, "region": "us-east-1", "image_id": "ami-111", "instance_type": "t3.micro",
                         "subnet_id": "subnet-111", "security_group_id": "sg-111"}
                        for name in ["Ubuntu2404", "Al2023", "DL2204", "DL2404"]]}


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
        pointers = next(s for s in allows if s["Sid"] == "PublishOnlyTemplatePointers")
        self.assertEqual(set(pointers["Condition"]["ForAllValues:StringEquals"]["aws:TagKeys"]), set(config["ec2_config"]["member_launch"]["template_tag_keys"]))

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
        config["ec2_config"]["instance_types"] += ["t3.type" + str(n) for n in range(500)]
        with self.assertRaisesRegex(ValueError, "4 KB"):
            cloudformation_template(config, artifact_bucket="example-artifacts", artifact_key="member-access/releases/reviewed.zip")

    def test_deployment_rejects_unmanaged_artifacts_or_foreign_boundary(self):
        with self.assertRaises(ValueError):
            cloudformation_template(approved(), artifact_bucket="example-artifacts", artifact_key="private/credentials.zip")
        config = approved()
        config["permissions_boundary_arn"] = "arn:aws:iam::111122223333:policy/AnotherBoundary"
        with self.assertRaises(ValueError):
            cloudformation_template(config, artifact_bucket="example-artifacts", artifact_key="member-access/releases/reviewed.zip")
