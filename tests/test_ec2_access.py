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
            elif operator == "StringLike":
                passed = any(fnmatch.fnmatchcase(str(item), pattern) for item in actual for pattern in wanted)
            elif operator == "ForAllValues:StringEquals":
                passed = all(str(item) in wanted for item in actual)
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
            if "Resource" in statement and not matches(statement["Resource"], resource):
                continue
            if "NotResource" in statement and matches(statement["NotResource"], resource):
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
    return member_context(**{"ec2:ResourceTag/Owner": "Alice", **extra})


class MemberEc2PolicyTest(unittest.TestCase):
    def setUp(self):
        self.bundle = build_policy_bundle(config())

    def check(self, expected, action, resource="*", context=None, broad=False):
        self.assertEqual(expected, decision(self.bundle, action, resource, member_context() if context is None else context, broad),
                         (action, resource, context, broad))

    def test_all_documents_are_deterministic_sized_and_independent(self):
        self.assertEqual(self.bundle, build_policy_bundle(config()))
        self.assertLessEqual(len(self.bundle), 6)
        for document in self.bundle.values():
            self.assertLessEqual(policy_size(document), 6144)
            self.assertEqual(document["Version"], "2012-10-17")
        next(iter(self.bundle.values()))["Statement"][0]["Action"].append("ec2:*")
        self.assertNotEqual(self.bundle, build_policy_bundle(config()))

    def test_full_approved_launch_authorizes_every_resource(self):
        instance = tagged(**{"ec2:InstanceType": "t3.small", "ec2:InstanceMarketType": "on-demand", "ec2:Tenancy": "default"})
        contexts = {INSTANCE: instance, VOLUME: tagged(**{"ec2:ParentSnapshot": SNAPSHOT, "ec2:VolumeSize": 1024}),
                    INTERFACE: tagged(**{"ec2:NetworkInterfaceID": "*"}), KEY: owned(),
                    IMAGE: member_context(), SNAPSHOT: member_context(), SUBNET: member_context(), SG: member_context()}
        for resource, context in contexts.items():
            with self.subTest(resource=resource):
                self.check("allowed", "ec2:RunInstances", resource, context)
        self.check("allowed", "ec2:RunInstances", VOLUME, tagged(**{"ec2:VolumeSize": 10}))

    def test_create_tags_allowed_only_as_dependent_creation(self):
        for creation in ("RunInstances", "CreateVolume", "ImportKeyPair"):
            self.check("allowed", "ec2:CreateTags", INSTANCE, tagged(**{"ec2:CreateAction": creation}))
        for creation in (None, "CreateSnapshot", "CreateLaunchTemplate"):
            context = tagged(**({"ec2:CreateAction": creation} if creation else {}))
            self.check("explicitDeny", "ec2:CreateTags", INSTANCE, context, broad=True)
        self.check("explicitDeny", "ec2:DeleteTags", INSTANCE, owned(), broad=True)

    def test_owner_can_update_only_descriptive_name_on_existing_resources(self):
        context = owned(**{"aws:RequestTag/Name": "new display name", "aws:TagKeys": ["Name"]})
        for resource in (INSTANCE, VOLUME, INTERFACE, KEY):
            self.check("allowed", "ec2:CreateTags", resource, context)
        self.check("explicitDeny", "ec2:CreateTags", SG, context, broad=True)
        self.check("explicitDeny", "ec2:DeleteTags", INSTANCE, context, broad=True)

    def test_create_tags_existing_resource_phase_does_not_require_request_tag_context(self):
        # The real EC2 pilot exposed existing Owner but no request-tag context
        # in the resource check. Permit that preliminary owned-resource check;
        # protected-tag cases below exercise the separate tag-specific context.
        self.check("allowed", "ec2:CreateTags", KEY, owned())
        self.check("explicitDeny", "ec2:CreateTags", KEY,
                   member_context(**{"ec2:ResourceTag/Owner": "Bob"}), broad=True)
        for document in self.bundle.values():
            for statement in document["Statement"]:
                if "ec2:CreateTags" in statement.get("Action", []):
                    self.assertNotIn("ec2:CreateAction", statement.get("Condition", {}).get("Null", {}))

    def test_direct_tag_exception_cannot_claim_foreign_or_change_protected_tags(self):
        context = owned(**{"aws:RequestTag/Name": "new display name", "aws:TagKeys": ["Name"]})
        for owner in (None, "Bob"):
            changed = dict(context)
            changed.pop("ec2:ResourceTag/Owner")
            if owner:
                changed["ec2:ResourceTag/Owner"] = owner
            self.check("explicitDeny", "ec2:CreateTags", INSTANCE, changed, broad=True)
        for keys in (["Owner"], ["Project"], ["Name", "Owner"], ["Name", "Project"], ["name"], ["OWNER"], ["Environment"]):
            self.check("explicitDeny", "ec2:CreateTags", INSTANCE, {**context, "aws:TagKeys": keys}, broad=True)

    def test_creation_requires_both_correct_tags_on_each_destination(self):
        for action, resource in (("ec2:RunInstances", INSTANCE), ("ec2:RunInstances", VOLUME),
                                 ("ec2:RunInstances", INTERFACE), ("ec2:CreateVolume", VOLUME),
                                 ("ec2:ImportKeyPair", KEY)):
            for key, value in (("aws:RequestTag/Owner", "Bob"), ("aws:RequestTag/Project", "shared-project")):
                context = tagged(**{key: value})
                self.check("explicitDeny", action, resource, context, broad=True)
                context.pop(key)
                self.check("explicitDeny", action, resource, context, broad=True)
        context = tagged(**{"aws:TagKeys": ["owner", "Project"]})
        self.check("explicitDeny", "ec2:CreateVolume", VOLUME, context, broad=True)

    def test_new_volume_and_import_public_key(self):
        self.check("allowed", "ec2:CreateVolume", VOLUME, tagged(**{"ec2:VolumeSize": 1024}))
        self.check("allowed", "ec2:ImportKeyPair", KEY, tagged())
        self.check("explicitDeny", "ec2:CreateKeyPair", KEY, tagged(), broad=True)
        self.check("explicitDeny", "ec2:CreateVolume", VOLUME,
                   tagged(**{"ec2:ParentSnapshot": SNAPSHOT, "ec2:VolumeSize": 1}), broad=True)

    def test_data_sources_and_existing_interfaces_cannot_bypass(self):
        unknown_snapshot = SNAPSHOT.replace("snap-111", "snap-222")
        self.check("explicitDeny", "ec2:RunInstances", VOLUME,
                   tagged(**{"ec2:ParentSnapshot": unknown_snapshot}), broad=True)
        for resource in (unknown_snapshot, IMAGE.replace("ami-111", "ami-222"),
                         SG.replace("sg-111", "sg-222"), SUBNET.replace("subnet-111", "subnet-222"),
                         BASE + "launch-template/lt-11111111111111111"):
            self.check("explicitDeny", "ec2:RunInstances", resource, tagged(), broad=True)
        self.check("explicitDeny", "ec2:RunInstances", INTERFACE,
                   tagged(**{"ec2:NetworkInterfaceID": "eni-22222222222222222"}), broad=True)
        for action in ("ec2:CreateImage", "ec2:RegisterImage", "ec2:CopyImage", "ec2:CopySnapshot",
                       "ec2:CreateSnapshot", "ec2:CreateSnapshots", "ec2:CopyVolumes", "ec2:ImportVolume"):
            self.check("explicitDeny", action, VOLUME, owned(), broad=True)
        self.check("explicitDeny", "ebs:GetSnapshotBlock", SNAPSHOT, {}, broad=True)

    def test_owned_and_foreign_lifecycle_with_competing_allow(self):
        for action in ("ec2:StartInstances", "ec2:StopInstances", "ec2:RebootInstances", "ec2:TerminateInstances"):
            self.check("allowed", action, INSTANCE, owned(**{"ec2:InstanceType": "g6.xlarge"}))
            for owner in (None, "Bob"):
                context = member_context(**{"ec2:InstanceType": "g6.xlarge"})
                if owner:
                    context["ec2:ResourceTag/Owner"] = owner
                self.check("explicitDeny", action, INSTANCE, context, broad=True)
        self.check("allowed", "ec2:DeleteKeyPair", KEY, owned())
        self.check("explicitDeny", "ec2:RunInstances", KEY,
                   member_context(**{"ec2:ResourceTag/Owner": "Bob"}), broad=True)

    def test_attach_requires_ownership_of_both_volume_and_instance(self):
        for action in ("ec2:AttachVolume", "ec2:DetachVolume"):
            for resource in (INSTANCE, VOLUME):
                self.check("allowed", action, resource, owned())
                self.check("explicitDeny", action, resource,
                           member_context(**{"ec2:ResourceTag/Owner": "Bob"}), broad=True)

    def test_size_guard_does_not_block_start_of_legacy_large_volume_instance(self):
        for size in (1024, 1025):
            expected = "allowed" if size == 1024 else "explicitDeny"
            self.check(expected, "ec2:CreateVolume", VOLUME, tagged(**{"ec2:VolumeSize": size}))
            self.check(expected, "ec2:ModifyVolume", VOLUME, owned(**{"ec2:VolumeSize": size}))
        self.check("allowed", "ec2:StartInstances", INSTANCE,
                   owned(**{"ec2:InstanceType": "g6.xlarge", "ec2:VolumeSize": 5120}))

    def test_region_and_type_limit_only_selected_mutations(self):
        self.check("allowed", "ec2:DescribeInstances", context={"ec2:Region": "us-east-2"})
        self.check("explicitDeny", "ec2:StartInstances", INSTANCE,
                   owned(**{"ec2:Region": "us-east-2", "ec2:InstanceType": "t3.small"}), broad=True)
        for instance_type in ("p5.48xlarge", None):
            context = owned()
            if instance_type:
                context["ec2:InstanceType"] = instance_type
            self.check("explicitDeny", "ec2:StartInstances", INSTANCE, context, broad=True)

    def test_profile_template_spot_and_tenancy_are_denied(self):
        context = tagged(**{"ec2:InstanceType": "g6.xlarge", "ec2:InstanceMarketType": "on-demand", "ec2:Tenancy": "default"})
        for key, value in (("ec2:InstanceProfile", "arn:aws:iam::123456789012:instance-profile/Admin"),
                           ("ec2:LaunchTemplate", BASE + "launch-template/lt-11111111111111111"),
                           ("ec2:InstanceMarketType", "spot"), ("ec2:Tenancy", "host")):
            self.check("explicitDeny", "ec2:RunInstances", INSTANCE, {**context, key: value}, broad=True)

    def test_all_unapproved_ec2_mutations_and_cross_service_paths_are_denied(self):
        for action in ("ec2:ModifyInstanceAttribute", "ec2:ModifyNetworkInterfaceAttribute",
                       "ec2:AssociateIamInstanceProfile", "ec2:ReplaceIamInstanceProfileAssociation",
                       "ec2:CreateLaunchTemplateVersion", "ec2:CreateFleet", "ec2:RequestSpotInstances",
                       "ec2:AllocateAddress", "ec2:AuthorizeSecurityGroupIngress", "ec2:CreateVpc",
                       "ec2:FutureUnknownMutation", "iam:PassRole", "iam:TagUser", "sts:AssumeRole",
                       "autoscaling:CreateAutoScalingGroup", "elasticloadbalancing:CreateLoadBalancer",
                       "ssm:SendCommand", "ssm:StartSession", "ssm:ResumeSession", "ssm:StartAssociationsOnce",
                       "ssm:UpdateMaintenanceWindowTask", "ec2-instance-connect:SendSSHPublicKey",
                       "cloudwatch:PutMetricAlarm", "cloudwatch:SetAlarmState", "cloudwatch:PutMetricData"):
            self.check("explicitDeny", action, context=member_context(), broad=True)

    def test_s3_password_and_unrelated_service_behavior_not_granted_or_denied(self):
        for action in ("s3:GetObject", "s3:PutObject", "iam:ChangePassword", "cloudwatch:GetMetricData"):
            self.check("implicitDeny", action, context={})
            self.check("allowed", action, context={}, broad=True)

    def test_shared_grant_is_principal_action_resource_and_expiry_bound(self):
        shared = BASE + "instance/i-22222222222222222"
        grant = SharedGrant(shared, (ALICE,), ("ec2:StartInstances", "ec2:StopInstances"),
                            "2026-11-01T00:00:00Z", "Reviewed migration access")
        self.bundle = build_policy_bundle(replace(config(), shared_grants=(grant,)))
        context = member_context(**{"ec2:InstanceType": "g6.xlarge"})
        self.check("allowed", "ec2:StartInstances", shared, context)
        for action in ("ec2:RebootInstances", "ec2:TerminateInstances", "ec2:AttachVolume"):
            self.check("explicitDeny", action, shared, context, broad=True)
        for principal in ("arn:aws:iam::123456789012:user/Bob", "arn:aws:iam::123456789012:role/Alice"):
            self.check("explicitDeny", "ec2:StartInstances", shared, {**context, "aws:PrincipalArn": principal}, broad=True)
        self.check("explicitDeny", "ec2:StartInstances", INSTANCE, context, broad=True)
        for now in ("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z"):
            self.check("explicitDeny", "ec2:StartInstances", shared, {**context, "aws:CurrentTime": now}, broad=True)
        # A genuine owner keeps ordinary permissions when another member's
        # temporary exception expires; Project tags never authorize membership.
        self.check("allowed", "ec2:TerminateInstances", shared, owned(**{"aws:CurrentTime": "2026-12-01T00:00:00Z"}))
        self.check("explicitDeny", "ec2:StartInstances", INSTANCE,
                   member_context(**{"ec2:ResourceTag/Project": "personal", "ec2:InstanceType": "g6.xlarge"}), broad=True)

    def test_configuration_fails_closed_for_wildcards_and_unsafe_exceptions(self):
        for changes in ({"account_id": "*"}, {"regions": ()}, {"instance_types": ("g6.*",)},
                        {"approved_image_arns": (IMAGE.replace("ami-11111111111111111", "*"),)},
                        {"approved_snapshot_arns": ()}, {"approved_subnet_arns": (SUBNET.replace(ACCOUNT, "999999999999"),)},
                        {"approved_security_group_arns": (SG, SG)}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                build_policy_bundle(replace(config(), **changes))
        grant = SharedGrant(INSTANCE, (ALICE,), ("ec2:StartInstances",), "2026-11-01T00:00:00Z", "approved")
        for changes in ({"actions": ("ec2:TerminateInstances",)}, {"expires_at": "2026-11-01"},
                        {"principal_arns": (ALICE.replace("Alice", "*"),)}, {"reason": ""},
                        {"resource_arn": VOLUME}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                build_policy_bundle(replace(config(), shared_grants=(replace(grant, **changes),)))
        with self.assertRaises(ValueError):
            build_policy_bundle(replace(config(), shared_grants=(grant, grant)))

    def test_json_configuration_is_strict_and_does_not_guess_omitted_inputs(self):
        import json
        data = json.loads(json.dumps(asdict(config())))
        self.assertEqual(config_from_mapping(data), config())
        for key in data:
            if key == "shared_grants":
                continue
            missing = dict(data)
            missing.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):
                config_from_mapping(missing)
        for changes in ({"guess_image_owner": "amazon"}, {"regions": "us-east-1"},
                        {"shared_grants": {"resource_arn": INSTANCE}},
                        {"shared_grants": [{"resource_arn": INSTANCE, "actions": ["ec2:StartInstances"]}]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                config_from_mapping({**data, **changes})

    def test_managed_policy_and_group_attachment_limits_fail_closed(self):
        snapshots = tuple(SNAPSHOT.replace("11111111111111111", "%017x" % item) for item in range(100))
        with self.assertRaisesRegex(ValueError, "statement exceeds"):
            build_policy_bundle(replace(config(), approved_snapshot_arns=snapshots))
        with self.assertRaisesRegex(ValueError, "six group attachments"):
            build_policy_bundle(config(), max_policy_size=1500)


if __name__ == "__main__":
    unittest.main()
