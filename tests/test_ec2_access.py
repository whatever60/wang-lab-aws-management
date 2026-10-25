"""Offline IAM decision regressions; production also requires AWS simulation/DryRun.

The evaluator implements only the IAM operators emitted by this builder. It is
independent of the builder's statement layout and checks all participating
resources separately, including a competing AdministratorAccess-like Allow.
It cannot establish which context EC2 actually supplies; DryRun does that.
"""

import fnmatch
import re
import unittest
from dataclasses import asdict, replace
from datetime import datetime

from aws_audit.ec2_access import MemberEc2Config, SharedGrant, build_policy_bundle, config_from_mapping, policy_size
from aws_audit.ec2_access.policy import MemberLaunchConfig


ACCOUNT = "123456789012"
REGION = "us-east-1"
BASE = "arn:aws:ec2:" + REGION + ":" + ACCOUNT + ":"
INSTANCE = BASE + "instance/i-11111111111111111"
VOLUME = BASE + "volume/vol-11111111111111111"
INTERFACE = BASE + "network-interface/eni-11111111111111111"
KEY = BASE + "key-pair/key-11111111111111111"
IMAGE = "arn:aws:ec2:" + REGION + "::image/ami-11111111111111111"
SNAPSHOT = "arn:aws:ec2:" + REGION + "::snapshot/snap-11111111111111111"
SUBNET = BASE + "subnet/subnet-11111111111111111"
SG = BASE + "security-group/sg-11111111111111111"
ALICE = "arn:aws:iam::" + ACCOUNT + ":user/Alice"
TEMPLATE_KEYS = ("MemberLaunchUbuntu2404", "MemberLaunchAl2023", "MemberLaunchDL2204", "MemberLaunchDL2404")
TEMPLATES = tuple(BASE + "launch-template/lt-" + ("%017x" % item) for item in range(1, 5))
PROFILE = "arn:aws:iam::" + ACCOUNT + ":instance-profile/wanglab/member-s3/Alice"
ROLE = "arn:aws:iam::" + ACCOUNT + ":role/wanglab/member-s3/Alice"


def config():
    return MemberEc2Config(ACCOUNT, (REGION,), ("t3.small", "g6.xlarge"),
                           (IMAGE,), (SNAPSHOT,), (SUBNET,), (SG,))


def values(value):
    return value if isinstance(value, (tuple, list)) else [value]


def condition_matches(condition, context):
    def expand(value):
        return re.sub(r"\$\{([^}]+)\}", lambda match: str(context.get(match.group(1), "<missing>")), str(value))
    for operator, entries in condition.items():
        for key, expected in entries.items():
            actual = values(context[key]) if key in context else []
            wanted = [expand(value) for value in values(expected)]
            if operator == "Null":
                passed = (not actual) == (wanted[0] == "true")
            elif operator in ("StringEquals", "ArnEquals"):
                passed = any(str(item) in wanted for item in actual)
            elif operator in ("StringNotEquals", "ArnNotEquals"):
                passed = all(str(item) not in wanted for item in actual)
            elif operator in ("StringLike", "StringNotLike"):
                passed = any(fnmatch.fnmatchcase(str(item), pattern) for item in actual for pattern in wanted)
                if operator == "StringNotLike":
                    passed = not passed
            elif operator == "ForAnyValue:StringEqualsIgnoreCase":
                passed = any(str(item).lower() in [v.lower() for v in wanted] for item in actual)
            elif operator == "ForAnyValue:StringLike":
                passed = any(fnmatch.fnmatchcase(str(item), pattern) for item in actual for pattern in wanted)
            elif operator == "ForAllValues:StringEquals":
                passed = all(str(item) in wanted for item in actual)
            elif operator == "ForAnyValue:StringEquals":
                passed = any(str(item) in wanted for item in actual)
            elif operator == "ForAnyValue:StringNotEquals":
                passed = any(str(item) not in wanted for item in actual)
            elif operator == "NumericGreaterThan":
                passed = any(float(item) > float(wanted[0]) for item in actual)
            elif operator in ("DateLessThan", "DateGreaterThanEquals"):
                dates = [datetime.fromisoformat(str(item).replace("Z", "+00:00")) for item in actual]
                target = datetime.fromisoformat(wanted[0].replace("Z", "+00:00"))
                passed = any(item < target if operator == "DateLessThan" else item >= target for item in dates)
            else:
                raise AssertionError("unimplemented IAM operator: " + operator)
            if not passed:
                return False
    return True


def decision(bundle, action, resource="*", context=None, competing_allow=False):
    context = context or {}
    allowed = competing_allow
    for document in bundle.values():
        for statement in document["Statement"]:
            matches = lambda patterns, value: any(fnmatch.fnmatchcase(value, item) for item in values(patterns))
            if "Action" in statement and not matches(statement["Action"], action):
                continue
            if "NotAction" in statement and matches(statement["NotAction"], action):
                continue
            # IAM variables that cannot resolve can invalidate a statement.
            # Model the whole resource list as unusable, rather than replacing
            # a missing variable with a wildcard. Separate variable-free Denies
            # must still protect incomplete onboarding and offboarding.
            resource_key = "Resource" if "Resource" in statement else "NotResource"
            patterns = []
            unresolved = False
            for pattern in values(statement[resource_key]):
                variables = re.findall(r"\$\{([^}]+)\}", pattern)
                if any(key not in context or not context[key] for key in variables):
                    unresolved = True
                    break
                patterns.append(re.sub(r"\$\{([^}]+)\}", lambda match: str(context[match.group(1)]), pattern))
            if unresolved:
                continue
            if "Resource" in statement and not matches(patterns, resource):
                continue
            if "NotResource" in statement and matches(patterns, resource):
                continue
            if not condition_matches(statement.get("Condition", {}), context):
                continue
            if statement["Effect"] == "Deny":
                return "explicitDeny"
            allowed = True
    return "allowed" if allowed else "implicitDeny"


def member_context(**extra):
    return {"aws:username": "Alice", "aws:PrincipalArn": ALICE, "ec2:Region": REGION,
            "aws:CurrentTime": "2026-10-19T00:00:00Z", **extra}


def tagged(**extra):
    return member_context(**{"aws:RequestTag/Owner": "Alice", "aws:RequestTag/Project": "personal",
                             "aws:TagKeys": ["Owner", "Project", "Name"], **extra})


def owned(**extra):
    return member_context(**{"ec2:ResourceTag/wanglab:Owner": "Alice", **extra})


def managed_member_context(**extra):
    return tagged(**{"aws:PrincipalTag/AccessRole": "CurrentMember", "aws:PrincipalTag/HomeBucket": "member-home",
                      **{"aws:PrincipalTag/" + key: arn for key, arn in zip(TEMPLATE_KEYS, TEMPLATES)},
                      "ec2:InstanceType": "g6.xlarge", "ec2:InstanceMarketType": "on-demand", "ec2:Tenancy": "default",
                      "ec2:MetadataHttpTokens": "required", "ec2:InstanceProfile": PROFILE,
                      "ec2:LaunchTemplate": TEMPLATES[0], **extra})


class NativeMemberEc2PolicyTest(unittest.TestCase):
    def setUp(self):
        self.bundle = build_policy_bundle(config())

    def check(self, expected, action, resource="*", context=None, broad=False):
        self.assertEqual(expected, decision(self.bundle, action, resource,
                         member_context() if context is None else context, broad), (action, resource, context))

    def test_minimal_native_configuration_has_no_ami_type_template_registry(self):
        cfg = config_from_mapping({"account_id": ACCOUNT, "regions": [REGION]})
        self.assertFalse(cfg.approved_image_arns)
        self.assertFalse(cfg.instance_types)
        self.assertEqual(build_policy_bundle(cfg), build_policy_bundle(cfg))
        for doc in self.bundle.values():
            self.assertLessEqual(policy_size(doc), 6144)

    def test_plain_console_and_cli_launch_authorize_every_native_resource(self):
        # No template, profile, principal pointers, Owner/Project tags, metadata
        # options or hand-selected approved source is required.
        for resource in (INSTANCE, VOLUME, INTERFACE, KEY, IMAGE, SNAPSHOT, SUBNET, SG,
                         IMAGE.replace("ami-111", "ami-999")):
            self.check("allowed", "ec2:RunInstances", resource)
        self.check("allowed", "ec2:RunInstances", INSTANCE,
                   member_context(**{"ec2:InstanceType": "r7i.4xlarge"}))

    def test_normal_key_group_volume_creation_needs_no_extra_tags(self):
        for action, resource in (("ec2:CreateKeyPair", KEY), ("ec2:ImportKeyPair", KEY),
                                 ("ec2:CreateSecurityGroup", SG), ("ec2:CreateVolume", VOLUME)):
            self.check("allowed", action, resource)
        for creation, resource in (("RunInstances", INSTANCE), ("CreateKeyPair", KEY), ("CreateSecurityGroup", SG)):
            self.check("allowed", "ec2:CreateTags", resource,
                       member_context(**{"ec2:CreateAction": creation, "aws:TagKeys": ["Name"]}))

    def test_owned_lifecycle_works_and_known_foreign_resources_remain_protected(self):
        for action, resource in (("ec2:StartInstances", INSTANCE), ("ec2:StopInstances", INSTANCE),
                                 ("ec2:TerminateInstances", INSTANCE), ("ec2:ModifyInstanceAttribute", INSTANCE),
                                 ("ec2:AttachVolume", INSTANCE), ("ec2:AttachVolume", VOLUME),
                                 ("ec2:DeleteVolume", VOLUME), ("ec2:ModifyVolume", VOLUME),
                                 ("ec2:DeleteKeyPair", KEY),
                                 ("ec2:CreateImage", INSTANCE), ("ec2:CreateSnapshot", VOLUME),
                                 ("ec2:AuthorizeSecurityGroupIngress", SG), ("ec2:DeleteSecurityGroup", SG)):
            self.check("allowed", action, resource, owned())
            self.check("explicitDeny", action, resource, owned(**{"ec2:ResourceTag/wanglab:Owner": "Bob"}), broad=True)

    def test_untagged_new_resources_work_during_asynchronous_attribution(self):
        # The lab account is not a hard tenant boundary until attribution. This
        # keeps immediate native CLI sequences usable, without caller tagging.
        for action, resource in (("ec2:AttachVolume", VOLUME), ("ec2:AttachVolume", INSTANCE),
                                 ("ec2:StopInstances", INSTANCE), ("ec2:AuthorizeSecurityGroupIngress", SG)):
            self.check("allowed", action, resource)

    def test_custom_tags_work_but_canonical_ownership_cannot_be_forged(self):
        for action in ("ec2:CreateTags", "ec2:DeleteTags"):
            self.check("allowed", action, INSTANCE, owned(**{"aws:TagKeys": ["Name", "Experiment", "Owner", "Project", "ManagedBy"]}))
            self.check("explicitDeny", action, INSTANCE,
                       owned(**{"ec2:ResourceTag/wanglab:Owner": "Bob", "aws:TagKeys": ["Name"]}), broad=True)
            for tag in ("wanglab:Owner", "wanglab:CreatorUserId", "WANGLAB:OWNER", "WangLab:CreatorUserId"):
                self.check("explicitDeny", action, INSTANCE, owned(**{"aws:TagKeys": [tag]}), broad=True)
        self.check("allowed", "ec2:CreateTags", INSTANCE, tagged(**{"ec2:CreateAction": "RunInstances"}))
        self.check("allowed", "ec2:CreateTags", INSTANCE,
                   tagged(**{"ec2:CreateAction": "RunInstances", "aws:RequestTag/Owner": "ResearchTeam"}))
        self.check("explicitDeny", "ec2:CreateTags", INSTANCE,
                   tagged(**{"ec2:CreateAction": "RunInstances", "aws:TagKeys": ["wanglab:CreatorUserId"]}), broad=True)

    def test_role_optional_at_launch_and_foreign_roles_still_denied(self):
        self.check("allowed", "ec2:RunInstances", INSTANCE)
        self.check("allowed", "ec2:RunInstances", INSTANCE, member_context(**{"ec2:InstanceProfile": PROFILE}))
        self.check("explicitDeny", "ec2:RunInstances", INSTANCE,
                   member_context(**{"ec2:InstanceProfile": PROFILE.replace("Alice", "Bob")}), broad=True)
        context = member_context(**{"iam:PassedToService": "ec2.amazonaws.com"})
        self.check("allowed", "iam:PassRole", ROLE, context)
        self.check("explicitDeny", "iam:PassRole", ROLE.replace("Alice", "Bob"), context, broad=True)
        self.check("explicitDeny", "iam:PassRole", ROLE,
                   member_context(**{"iam:PassedToService": "lambda.amazonaws.com"}), broad=True)
        context.pop("aws:username")
        self.check("explicitDeny", "iam:PassRole", ROLE, context, broad=True)

    def test_region_and_per_volume_guards_survive_native_launch(self):
        for action, resource in (("ec2:RunInstances", INSTANCE), ("ec2:CreateVolume", VOLUME), ("ec2:ModifyVolume", VOLUME)):
            self.check("allowed", action, resource, owned(**{"ec2:VolumeSize": "1024"}))
            self.check("explicitDeny", action, resource, owned(**{"ec2:VolumeSize": "1025"}), broad=True)
            self.check("explicitDeny", action, resource, owned(**{"ec2:Region": "us-west-2"}), broad=True)
        self.check("allowed", "ec2:DescribeInstances", context=member_context(**{"ec2:Region": "us-west-2"}))

    def test_account_defaults_and_prepaid_commitments_require_administration(self):
        for action in ("ec2:DisableEbsEncryptionByDefault", "ec2:ModifyDefaultCreditSpecification",
                       "ec2:PurchaseReservedInstancesOffering", "ec2:PurchaseCapacityBlock"):
            self.check("explicitDeny", action, broad=True)

    def test_snapshot_deletion_account_and_canonical_owner_are_checked(self):
        self.check("allowed", "ec2:DeleteSnapshot", SNAPSHOT, owned(**{"ec2:Owner": ACCOUNT}))
        self.check("explicitDeny", "ec2:DeleteSnapshot", SNAPSHOT,
                   owned(**{"ec2:Owner": ACCOUNT, "ec2:ResourceTag/wanglab:Owner": "Bob"}), broad=True)
        self.check("explicitDeny", "ec2:DeleteSnapshot", SNAPSHOT,
                   owned(**{"ec2:Owner": "999999999999"}), broad=True)

    def test_explicit_shared_lifecycle_remains_exact_and_expires(self):
        grant = SharedGrant(INSTANCE, (ALICE,), ("ec2:StartInstances",), "2026-11-01T00:00:00Z", "Reviewed shared access")
        self.bundle = build_policy_bundle(replace(config(), shared_grants=(grant,)))
        foreign = owned(**{"ec2:ResourceTag/wanglab:Owner": "Bob"})
        self.check("allowed", "ec2:StartInstances", INSTANCE, foreign)
        self.check("explicitDeny", "ec2:TerminateInstances", INSTANCE, foreign, broad=True)
        self.check("explicitDeny", "ec2:StartInstances", INSTANCE,
                   {**foreign, "aws:CurrentTime": "2026-11-02T00:00:00Z"}, broad=True)

    def test_public_image_parameters_and_price_catalog_are_readable(self):
        self.check("allowed", "ssm:GetParameter", "arn:aws:ssm:us-east-1::parameter/aws/service/ami-amazon-linux-latest/example", {})
        self.check("implicitDeny", "ssm:GetParameter", "arn:aws:ssm:us-east-1:123456789012:parameter/private-secret", {})
        self.check("allowed", "pricing:GetProducts", context={})

    def test_ec2_default_allow_does_not_require_a_maintained_action_allowlist(self):
        for action in ("ec2:CreateVpc", "ec2:CreateSubnet", "ec2:AllocateAddress",
                       "ec2:AssociateIamInstanceProfile", "ec2:EnableVolumeIO", "ec2:ModifyInstanceMetadataOptions",
                       "ec2:FutureNativeFeature"):
            self.check("allowed", action)
        # Shared networks remain usable as sources in the ordinary wizard.
        foreign = owned(**{"ec2:ResourceTag/wanglab:Owner": "administrator-managed/unattributed"})
        for action, resource in (("ec2:RunInstances", SUBNET), ("ec2:RunInstances", SG),
                                 ("ec2:RunInstances", KEY),
                                 ("ec2:CreateSecurityGroup", BASE + "vpc/vpc-111"),
                                 ("ec2:CreateVolume", SNAPSHOT), ("ec2:RunInstances", IMAGE)):
            self.check("allowed", action, resource, foreign)
        for action, resource in (("ec2:DeleteSubnet", SUBNET), ("ec2:ModifyVpcAttribute", BASE + "vpc/vpc-111"),
                                 ("ec2:CreateRoute", BASE + "route-table/rtb-111"),
                                 ("ec2:ModifyImageAttribute", IMAGE), ("ec2:ReleaseAddress", BASE + "elastic-ip/eipalloc-111"),
                                 ("ec2:AssociateIamInstanceProfile", INSTANCE), ("ec2:ModifyInstanceMetadataOptions", INSTANCE)):
            self.check("explicitDeny", action, resource, foreign, broad=True)
            self.check("allowed", action, resource, owned())

    def test_unrelated_services_are_preserved_and_identity_bypasses_remain_blocked(self):
        for action in ("s3:GetObject", "s3:PutObject", "iam:ChangePassword", "ssm:StartSession",
                       "autoscaling:CreateAutoScalingGroup", "cloudwatch:PutMetricAlarm"):
            self.check("implicitDeny", action, context={})
            self.check("allowed", action, context={}, broad=True)
        for action in ("iam:TagUser", "iam:PutRolePolicy", "sts:AssumeRole"):
            self.check("explicitDeny", action, context={}, broad=True)

    def test_missing_identity_cannot_use_broad_ec2_grants(self):
        context = member_context()
        del context["aws:username"]
        self.check("explicitDeny", "ec2:RunInstances", INSTANCE, context, broad=True)


if __name__ == "__main__":
    unittest.main()
