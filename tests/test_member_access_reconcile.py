"""Injected metadata clients verify provisioning, revocation, and race guards offline."""

import copy
import json
import re
import sys
import unittest
from dataclasses import asdict, replace
from unittest.mock import patch

from aws_audit.ec2_access.policy import MemberEc2Config
from aws_audit.member_access.models import (COMPONENT, FLAVOR_TAG_KEYS, MANAGED_BY, ROLE_PATH,
    STATE_POLICY_NAME, USER_TAG_KEYS, LaunchFlavor, MemberLaunchConfig, config_from_mapping,
    managed_tags, profile_arn, role_arn, template_name)
from aws_audit.member_access.policies import attached_policy_arns, role_state, trust_policy
from aws_audit.member_access.reconcile import apply_plan, plan, reconcile, snapshot


ACCOUNT, REGION = "123456789012", "us-east-1"
BOUNDARY = "arn:aws:iam::" + ACCOUNT + ":policy/MemberDataBoundary"


class ApiError(Exception):
    def __init__(self, code="NoSuchEntity", operation="TestOperation"):
        super().__init__("private SDK details must not be published")
        self.response = {"Error": {"Code": code, "Message": "private SDK details"}}
        self.operation_name = operation


def arn(kind, identifier, account=ACCOUNT):
    return "arn:aws:ec2:%s:%s:%s/%s" % (REGION, account, kind, identifier)


def config(names=("Alice", "Bob")):
    flavors = tuple(LaunchFlavor(name, REGION, "ami-" + str(index) * 17,
                                 "g6.xlarge" if name.startswith("DL") else "t3.micro",
                                 "subnet-" + "1" * 17, "sg-" + "1" * 17)
                    for index, name in enumerate(FLAVOR_TAG_KEYS, start=1))
    ec2 = MemberEc2Config(ACCOUNT, (REGION,), ("t3.micro", "g6.xlarge"),
                          tuple(arn("image", flavor.image_id, "") for flavor in flavors),
                          (arn("snapshot", "snap-" + "1" * 17, ""),),
                          (arn("subnet", "subnet-" + "1" * 17),),
                          (arn("security-group", "sg-" + "1" * 17),))
    manifest = {"account_id": ACCOUNT, "groups": {"admin": "admin", "current_member": "lab_members", "alumni": "alumni"},
                "users": [{"user_name": name, "role": "CurrentMember", "home_bucket": name.lower() + "-home"} for name in names],
                "buckets": [{"name": name.lower() + "-home", "scope": "User", "owner": name} for name in names]}
    return MemberLaunchConfig(manifest, ec2, flavors, permissions_boundary_arn=BOUNDARY)


def tags(mapping):
    return [{"Key": key, "Value": value} for key, value in mapping.items()]


class Iam:
    def __init__(self, cfg, timeline):
        self.cfg, self.timeline = cfg, timeline
        self.group = {row["user_name"] for row in cfg.s3_manifest["users"]}
        self.users = {name: {"HomeBucket": name.lower() + "-home", "AccessRole": "CurrentMember"} for name in self.group}
        self.roles, self.profiles = {}, {}
        self.fail_user_tags = set()
        self.group_error = None
        self.after_tag_user = None

    def get_group(self, **kw):
        if self.group_error:
            raise self.group_error
        return {"Users": [{"UserName": name} for name in sorted(self.group)]}

    def get_user(self, UserName):
        if UserName not in self.users:
            raise ApiError()
        return {"User": {"UserName": UserName, "Arn": "arn:aws:iam::" + ACCOUNT + ":user/" + UserName}}

    def list_user_tags(self, UserName):
        self.get_user(UserName)
        if UserName in self.fail_user_tags:
            raise ApiError("AccessDenied", "ListUserTags")
        return {"Tags": tags(self.users[UserName])}

    def list_roles(self, **kw):
        return {"Roles": [{"RoleName": name} for name in self.roles]}

    def get_role(self, RoleName):
        if RoleName not in self.roles:
            raise ApiError()
        row = self.roles[RoleName]
        return {"Role": {"RoleName": RoleName, "Arn": row["arn"], "Path": row["path"],
                          "AssumeRolePolicyDocument": copy.deepcopy(row["trust"]),
                          "PermissionsBoundary": {"PermissionsBoundaryArn": row.get("boundary")}}}

    def list_role_tags(self, RoleName):
        return {"Tags": tags(self.roles[RoleName]["tags"])}

    def list_attached_role_policies(self, RoleName):
        return {"AttachedPolicies": [{"PolicyArn": value} for value in sorted(self.roles[RoleName]["attached"])]}

    def list_role_policies(self, RoleName):
        return {"PolicyNames": sorted(self.roles[RoleName]["inline"])}

    def get_role_policy(self, RoleName, PolicyName):
        return {"PolicyDocument": copy.deepcopy(self.roles[RoleName]["inline"][PolicyName])}

    def list_instance_profiles(self, **kw):
        return {"InstanceProfiles": [{"InstanceProfileName": name} for name in self.profiles]}

    def get_instance_profile(self, InstanceProfileName):
        if InstanceProfileName not in self.profiles:
            raise ApiError()
        row = self.profiles[InstanceProfileName]
        return {"InstanceProfile": {"Arn": row["arn"], "Path": row["path"], "Roles": [{"RoleName": name} for name in sorted(row["roles"])]}}

    def list_instance_profile_tags(self, InstanceProfileName):
        return {"Tags": tags(self.profiles[InstanceProfileName]["tags"])}

    def create_role(self, **kw):
        self.timeline.append(("create_role", kw["RoleName"], copy.deepcopy(kw)))
        name = kw["RoleName"]
        self.roles[name] = {"arn": role_arn(self.cfg, name), "path": kw["Path"], "tags": {x["Key"]: x["Value"] for x in kw["Tags"]},
                            "trust": json.loads(kw["AssumeRolePolicyDocument"]), "attached": set(), "inline": {},
                            "boundary": kw.get("PermissionsBoundary")}

    def put_role_policy(self, **kw):
        self.timeline.append(("put_role_policy", kw["RoleName"], json.loads(kw["PolicyDocument"])))
        self.roles[kw["RoleName"]]["inline"][kw["PolicyName"]] = json.loads(kw["PolicyDocument"])

    def update_assume_role_policy(self, **kw):
        self.timeline.append(("update_assume_role_policy", kw["RoleName"], json.loads(kw["PolicyDocument"])))
        self.roles[kw["RoleName"]]["trust"] = json.loads(kw["PolicyDocument"])

    def tag_role(self, RoleName, Tags):
        self.timeline.append(("tag_role", RoleName, copy.deepcopy(Tags)))
        self.roles[RoleName]["tags"].update({x["Key"]: x["Value"] for x in Tags})

    def put_role_permissions_boundary(self, RoleName, PermissionsBoundary):
        self.timeline.append(("boundary", RoleName, PermissionsBoundary))
        self.roles[RoleName]["boundary"] = PermissionsBoundary

    def attach_role_policy(self, RoleName, PolicyArn):
        self.timeline.append(("attach_policy", RoleName, PolicyArn))
        self.roles[RoleName]["attached"].add(PolicyArn)

    def create_instance_profile(self, InstanceProfileName, Path, Tags):
        self.timeline.append(("create_profile", InstanceProfileName, None))
        self.profiles[InstanceProfileName] = {"arn": profile_arn(self.cfg, InstanceProfileName), "path": Path,
            "tags": {x["Key"]: x["Value"] for x in Tags}, "roles": set()}

    def add_role_to_instance_profile(self, InstanceProfileName, RoleName):
        self.timeline.append(("add_role_to_profile", RoleName, None))
        self.profiles[InstanceProfileName]["roles"].add(RoleName)

    def tag_instance_profile(self, InstanceProfileName, Tags):
        self.timeline.append(("tag_profile", InstanceProfileName, None))
        self.profiles[InstanceProfileName]["tags"].update({x["Key"]: x["Value"] for x in Tags})

    def tag_user(self, UserName, Tags):
        self.timeline.append(("tag_user", UserName, copy.deepcopy(Tags)))
        self.users[UserName].update({x["Key"]: x["Value"] for x in Tags})
        if self.after_tag_user:
            self.after_tag_user(UserName)

    def untag_user(self, UserName, TagKeys):
        self.timeline.append(("untag_user", UserName, list(TagKeys)))
        for key in TagKeys:
            self.users[UserName].pop(key, None)


class Ec2:
    def __init__(self, cfg, timeline):
        self.timeline, self.templates = timeline, {}
        self.keys = [{"KeyName": name.lower() + "_key", "KeyPairId": "key-" + str(index) * 17,
                      "Tags": tags({"Owner": name})} for index, name in enumerate(sorted(row["user_name"] for row in cfg.s3_manifest["users"]), start=1)]

    def describe_key_pairs(self):
        return {"KeyPairs": copy.deepcopy(self.keys)}

    def describe_launch_templates(self, **kw):
        if "LaunchTemplateNames" in kw:
            names = kw["LaunchTemplateNames"]
            if any(name not in self.templates for name in names):
                raise ApiError("InvalidLaunchTemplateName.NotFoundException")
        else:
            names = self.templates
        return {"LaunchTemplates": [copy.deepcopy(self.templates[name]["metadata"]) for name in sorted(names)]}

    def describe_launch_template_versions(self, LaunchTemplateId, Versions):
        row = next(row for row in self.templates.values() if row["metadata"]["LaunchTemplateId"] == LaunchTemplateId)
        return {"LaunchTemplateVersions": [{"LaunchTemplateData": copy.deepcopy(row["versions"][int(Versions[0])])}]}

    def create_launch_template(self, **kw):
        self.timeline.append(("create_template", kw["LaunchTemplateName"], copy.deepcopy(kw)))
        self.templates[kw["LaunchTemplateName"]] = {"metadata": {"LaunchTemplateName": kw["LaunchTemplateName"],
            "LaunchTemplateId": "lt-%017d" % (len(self.templates) + 1), "DefaultVersionNumber": 1,
            "LatestVersionNumber": 1, "Tags": copy.deepcopy(kw["TagSpecifications"][0]["Tags"])},
            "versions": {1: copy.deepcopy(kw["LaunchTemplateData"])}}

    def create_launch_template_version(self, **kw):
        self.timeline.append(("create_version", kw["LaunchTemplateId"], copy.deepcopy(kw)))
        row = next(row for row in self.templates.values() if row["metadata"]["LaunchTemplateId"] == kw["LaunchTemplateId"])
        number = row["metadata"]["LatestVersionNumber"] + 1
        row["metadata"]["LatestVersionNumber"] = number
        row["versions"][number] = copy.deepcopy(kw["LaunchTemplateData"])
        return {"LaunchTemplateVersion": {"VersionNumber": number}}

    def modify_launch_template(self, LaunchTemplateId, DefaultVersion):
        self.timeline.append(("set_default", LaunchTemplateId, DefaultVersion))
        row = next(row for row in self.templates.values() if row["metadata"]["LaunchTemplateId"] == LaunchTemplateId)
        row["metadata"]["DefaultVersionNumber"] = int(DefaultVersion)


class S3:
    def __init__(self, cfg):
        self.tags = {row["name"]: {"BucketScope": "User", "BucketOwner": row["owner"], "OwnerAccessRole": "CurrentMember"}
                     for row in cfg.s3_manifest["buckets"]}
        self.errors, self.calls = {}, []

    def get_bucket_tagging(self, Bucket, ExpectedBucketOwner):
        self.calls.append((Bucket, ExpectedBucketOwner))
        if ExpectedBucketOwner != ACCOUNT:
            raise AssertionError("wrong expected owner")
        if Bucket in self.errors:
            raise self.errors[Bucket]
        return {"TagSet": tags(self.tags[Bucket])}


class MemberAccessReconcileTest(unittest.TestCase):
    def setUp(self):
        self.cfg, self.timeline = config(), []
        self.iam, self.ec2, self.s3 = Iam(self.cfg, self.timeline), Ec2(self.cfg, self.timeline), S3(self.cfg)

    def reconcile(self, execute=True):
        return reconcile(self.iam, {REGION: self.ec2}, self.cfg, s3=self.s3, execute=execute)

    def test_template_names_normalize_only_unsafe_iam_chars_without_collisions(self):
        self.assertEqual(template_name("AliceUser", "Ubuntu2404"), "wanglab-member-AliceUser-Ubuntu2404")
        names = [template_name(username, "Ubuntu2404") for username in
                 ("Alice@User", "Alice+User", "Alice=User", "Alice,User", "Alice-User", "@" * 64)]
        self.assertEqual(len(set(names)), len(names))
        self.assertTrue(all(re.fullmatch(r"[a-zA-Z0-9().\-/_]{3,128}", name) for name in names))
        self.assertEqual(names[0], template_name("Alice@User", "Ubuntu2404"))

    def test_four_flavor_preview_is_pure_and_config_round_trips(self):
        mapping = asdict(self.cfg)
        self.assertEqual(config_from_mapping(json.loads(json.dumps(mapping))), self.cfg)
        preview = self.reconcile(False)
        self.assertEqual(self.timeline, [])
        self.assertEqual(preview["counts"]["active"], 2)
        for username, member in preview["desired"].items():
            self.assertEqual({t["user_tag_key"] for t in member["templates"]}, set(USER_TAG_KEYS))
            for template in member["templates"]:
                data = template["data"]
                self.assertEqual(data["IamInstanceProfile"], {"Arn": profile_arn(self.cfg, username)})
                self.assertEqual(data["MetadataOptions"], {"HttpTokens": "required", "HttpEndpoint": "enabled"})
                self.assertNotIn("MinCount", data)
                self.assertNotIn("UserData", data)
                self.assertEqual([x["ResourceType"] for x in data["TagSpecifications"]], ["instance", "volume", "network-interface"])
                self.assertTrue(all({tag["Key"]: tag["Value"] for tag in row["Tags"]}["Owner"] == username for row in data["TagSpecifications"]))

    def test_new_role_denied_until_ready_then_four_tags_and_true_idempotence(self):
        result = self.reconcile()
        self.assertEqual(result["errors"], {})
        self.assertEqual(len(self.ec2.templates), 8)
        for name in ("Alice", "Bob"):
            role = self.iam.roles[name]
            self.assertEqual(role["boundary"], BOUNDARY)
            self.assertEqual(role["trust"], trust_policy(True))
            self.assertEqual(role["attached"], set(attached_policy_arns(ACCOUNT)))
            self.assertEqual(role["inline"][STATE_POLICY_NAME], role_state(True, name.lower() + "-home"))
            self.assertEqual(set(self.iam.users[name]) & set(USER_TAG_KEYS), set(USER_TAG_KEYS))
            tag_index = next(index for index, call in enumerate(self.timeline) if call[:2] == ("tag_user", name))
            template_indices = [index for index, call in enumerate(self.timeline) if call[0] == "create_template" and ("-" + name + "-") in call[1]]
            self.assertLess(max(template_indices), tag_index)
            initial = next(call for call in self.timeline if call[:2] == ("create_role", name))
            self.assertEqual(json.loads(initial[2]["AssumeRolePolicyDocument"]), trust_policy(False))
            self.assertEqual(initial[2]["PermissionsBoundary"], BOUNDARY)
        self.timeline.clear()
        with patch.object(sys.modules[snapshot.__module__], "snapshot", wraps=snapshot) as capture:
            self.assertEqual(self.reconcile()["applied"], [])
            self.assertEqual(capture.call_count, 1)
        self.assertEqual(self.timeline, [])

    def test_missing_owned_key_stays_inactive_without_guessing_name(self):
        self.ec2.keys[0]["Tags"] = []
        preview = self.reconcile(False)
        self.assertEqual(preview["desired"]["Alice"]["status"], "pending_key")
        self.reconcile()
        self.assertEqual(self.iam.roles["Alice"]["inline"][STATE_POLICY_NAME], role_state(False))
        self.assertFalse(set(self.iam.users["Alice"]) & set(USER_TAG_KEYS))
        for name, template in self.ec2.templates.items():
            if "-Alice-" in name:
                self.assertNotIn("KeyName", template["versions"][1])
        self.ec2.keys[0]["Tags"] = tags({"Owner": "Alice"})
        self.assertEqual(self.reconcile()["errors"], {})
        self.assertEqual(len(set(self.iam.users["Alice"]) & set(USER_TAG_KEYS)), 4)

    def test_multiple_owned_keys_are_active_with_deterministic_personal_default(self):
        extra = copy.deepcopy(self.ec2.keys[0])
        extra.update({"KeyName": "aaa_alice_key", "KeyPairId": "key-" + "3" * 17})
        self.ec2.keys.append(extra)
        other = copy.deepcopy(extra)
        other.update({"KeyName": "000_foreign_key", "KeyPairId": "key-" + "4" * 17, "Tags": tags({"Owner": "Bob"})})
        self.ec2.keys.append(other)
        preview = self.reconcile(False)
        self.assertEqual(preview["desired"]["Alice"]["status"], "active")
        self.assertTrue(all(row["data"]["KeyName"] == "aaa_alice_key" for row in preview["desired"]["Alice"]["templates"]))
        self.assertEqual(self.reconcile()["errors"], {})
        self.assertEqual(self.iam.roles["Alice"]["inline"][STATE_POLICY_NAME], role_state(True, "alice-home"))

    def test_adding_second_owned_key_keeps_working_default_and_does_not_revoke(self):
        self.reconcile(); self.timeline.clear()
        extra = copy.deepcopy(self.ec2.keys[0])
        extra.update({"KeyName": "aaa_alice_key", "KeyPairId": "key-" + "3" * 17})
        self.ec2.keys.append(extra)
        result = self.reconcile()
        self.assertEqual(result["applied"], [])
        self.assertEqual(result["plan"]["desired"]["Alice"]["status"], "active")
        self.assertTrue(all(row["data"]["KeyName"] == "alice_key" for row in result["plan"]["desired"]["Alice"]["templates"]))
        self.assertEqual(self.timeline, [])

    def test_offboard_all_revokes_precede_other_member_grants_preserves_instances(self):
        self.reconcile()
        self.iam.group.remove("Alice")
        self.iam.users["Alice"]["AccessRole"] = "Alumni"
        self.iam.users["Bob"].pop(USER_TAG_KEYS[0])
        self.timeline.clear()
        result = self.reconcile()
        self.assertEqual(result["errors"], {})
        self.assertEqual(self.iam.roles["Alice"]["inline"][STATE_POLICY_NAME], role_state(False))
        self.assertEqual(self.iam.roles["Alice"]["trust"], trust_policy(False))
        self.assertFalse(set(self.iam.users["Alice"]) & set(USER_TAG_KEYS))
        grants = [index for index, call in enumerate(self.timeline) if call[0] == "tag_user"]
        deny_index = next(index for index, call in enumerate(self.timeline) if call[:2] == ("put_role_policy", "Alice"))
        self.assertLess(deny_index, min(grants))
        self.assertEqual(len(self.iam.profiles), 2)
        self.assertEqual(len(self.ec2.templates), 8)

    def test_deleted_user_role_discovered_even_when_missing_from_dynamic_manifest(self):
        self.reconcile()
        self.iam.group.remove("Alice"); self.iam.users.pop("Alice")
        self.cfg = config(("Bob",))
        result = self.reconcile()
        self.assertEqual(result["errors"], {})
        self.assertEqual(self.iam.roles["Alice"]["inline"][STATE_POLICY_NAME], role_state(False))

    def test_one_unreadable_bucket_or_user_does_not_block_unrelated_offboarding(self):
        for failure in ("bucket", "user"):
            with self.subTest(failure=failure):
                self.setUp(); self.reconcile(); self.iam.group.remove("Alice")
                if failure == "bucket":
                    self.s3.errors["bob-home"] = ApiError("AccessDenied", "GetBucketTagging")
                else:
                    self.iam.fail_user_tags.add("Bob")
                self.timeline.clear()
                result = self.reconcile()
                self.assertIn("Bob", result["plan"]["blocked"])
                self.assertEqual(self.iam.roles["Alice"]["inline"][STATE_POLICY_NAME], role_state(False))
                self.assertEqual(self.iam.roles["Bob"]["inline"][STATE_POLICY_NAME], role_state(False))
                self.assertFalse(set(self.iam.users["Bob"]) & set(USER_TAG_KEYS))

    def test_global_membership_failure_is_not_empty_membership(self):
        self.reconcile(); self.timeline.clear()
        self.iam.group_error = ApiError("Throttling", "GetGroup")
        with self.assertRaises(ApiError):
            self.reconcile()
        self.assertEqual(self.timeline, [])
        self.iam.group_error = ApiError("NoSuchEntity", "GetGroup")
        self.assertEqual(self.reconcile()["errors"], {})
        self.assertTrue(all(row["inline"][STATE_POLICY_NAME] == role_state(False) for row in self.iam.roles.values()))

    def test_bucket_owner_account_and_all_three_tags_checked_before_grants(self):
        self.s3.tags["alice-home"]["OwnerAccessRole"] = "Alumni"
        result = self.reconcile()
        self.assertIn("Alice", result["plan"]["blocked"])
        self.assertNotIn("Alice", self.iam.roles)
        self.assertTrue(all(account == ACCOUNT for _, account in self.s3.calls))

    def test_foreign_role_and_template_collisions_never_mutated(self):
        self.iam.roles["Alice"] = {"arn": role_arn(self.cfg, "Alice"), "path": ROLE_PATH, "tags": {}, "trust": trust_policy(True)}
        result = self.reconcile()
        self.assertIn("foreign", result["plan"]["blocked"]["Alice"])
        self.assertFalse(any(call[1] == "Alice" for call in self.timeline))
        self.setUp(); self.reconcile()
        row = self.ec2.templates[template_name("Alice", "Ubuntu2404")]
        row["metadata"]["Tags"] = tags({"Owner": "Alice"})
        self.timeline.clear(); result = self.reconcile()
        self.assertIn("Alice", result["plan"]["blocked"])
        self.assertFalse(any(call[0] in {"create_version", "set_default"} for call in self.timeline))
        self.assertEqual(self.iam.roles["Alice"]["inline"][STATE_POLICY_NAME], role_state(False))

    def test_managed_home_mismatch_and_extra_role_policy_deactivate_without_reassign(self):
        self.reconcile()
        self.iam.roles["Alice"]["tags"]["HomeBucket"] = "another-home"
        self.iam.roles["Bob"]["attached"].add("arn:aws:iam::aws:policy/AdministratorAccess")
        result = self.reconcile()
        self.assertEqual(set(result["plan"]["blocked"]), {"Alice", "Bob"})
        self.assertEqual(self.iam.roles["Alice"]["tags"]["HomeBucket"], "another-home")
        self.assertTrue(all(row["inline"][STATE_POLICY_NAME] == role_state(False) for row in self.iam.roles.values()))

    def test_changed_preview_or_live_metadata_rejected_before_writes(self):
        preview = self.reconcile(False)
        changed = copy.deepcopy(preview); changed["desired"]["Alice"]["home_bucket"] = "foreign-home"
        with self.assertRaisesRegex(RuntimeError, "stale or modified"):
            apply_plan(self.iam, {REGION: self.ec2}, self.cfg, changed, s3=self.s3)
        self.iam.group.remove("Alice")
        with self.assertRaisesRegex(RuntimeError, "stale or modified"):
            apply_plan(self.iam, {REGION: self.ec2}, self.cfg, preview, s3=self.s3)
        self.assertEqual(self.timeline, [])

    def test_concurrent_offboard_after_tag_publication_revokes_only_that_member(self):
        self.iam.after_tag_user = lambda name: self.iam.group.discard("Alice") if name == "Alice" else None
        result = self.reconcile()
        self.assertEqual(result["errors"], {"Alice": {"operation": "Reconcile", "code": "RuntimeError"}})
        self.assertFalse(set(self.iam.users["Alice"]) & set(USER_TAG_KEYS))
        self.assertEqual(self.iam.roles["Alice"]["inline"][STATE_POLICY_NAME], role_state(False))
        self.assertEqual(self.iam.roles["Bob"]["inline"][STATE_POLICY_NAME], role_state(True, "bob-home"))

    def test_template_repair_never_inherits_or_exposes_legacy_user_data(self):
        self.reconcile()
        row = self.ec2.templates[template_name("Alice", "Ubuntu2404")]
        row["versions"][1]["UserData"] = "private legacy script bytes"
        preview = self.reconcile(False)
        self.assertNotIn("private legacy", json.dumps(preview))
        observed = snapshot(self.iam, {REGION: self.ec2}, self.cfg, s3=self.s3)
        self.assertNotIn("private legacy", json.dumps(observed))
        self.timeline.clear(); self.reconcile()
        version = next(call for call in self.timeline if call[0] == "create_version")
        self.assertNotIn("SourceVersion", version[2])
        self.assertNotIn("UserData", version[2]["LaunchTemplateData"])

    def test_boundary_drift_is_repaired_before_activation(self):
        self.reconcile(); self.timeline.clear()
        self.iam.roles["Alice"]["boundary"] = None
        self.reconcile()
        self.assertEqual(self.iam.roles["Alice"]["boundary"], BOUNDARY)
        self.assertIn(("boundary", "Alice", BOUNDARY), self.timeline)

    def test_aws_tag_and_policy_array_order_does_not_create_versions_or_self_trigger(self):
        self.reconcile(); self.timeline.clear()
        for row in self.ec2.templates.values():
            data = row["versions"][1]
            data["TagSpecifications"].reverse()
            for spec in data["TagSpecifications"]:
                spec["Tags"].reverse()
        for role in self.iam.roles.values():
            role["inline"][STATE_POLICY_NAME]["Statement"].reverse()
            for statement in role["inline"][STATE_POLICY_NAME]["Statement"]:
                for key in ("Action", "NotAction"):
                    if isinstance(statement.get(key), list):
                        statement[key].reverse()
        self.assertEqual(self.reconcile()["applied"], [])
        self.assertEqual(self.timeline, [])

    def test_marker_on_other_path_is_a_collision_not_permission_to_mutate(self):
        self.reconcile()
        self.iam.roles["Alice"]["path"] = "/unrelated/"
        self.iam.roles["Alice"]["arn"] = "arn:aws:iam::" + ACCOUNT + ":role/unrelated/Alice"
        self.timeline.clear()
        result = self.reconcile()
        self.assertIn("path mismatch", result["plan"]["blocked"]["Alice"])
        self.assertFalse(any(call[0] in {"put_role_policy", "tag_role", "update_assume_role_policy"}
                             and call[1] == "Alice" for call in self.timeline))
        self.assertFalse(set(self.iam.users["Alice"]) & set(USER_TAG_KEYS))

    def test_unreadable_role_or_failed_revoke_does_not_prevent_other_revokes(self):
        for failure in ("read", "write"):
            with self.subTest(failure=failure):
                self.setUp(); self.reconcile(); self.iam.group.clear()
                original_read, original_write = self.iam.list_role_tags, self.iam.put_role_policy
                def read(RoleName):
                    if RoleName == "Alice" and failure == "read":
                        raise ApiError("AccessDenied", "ListRoleTags")
                    return original_read(RoleName)
                def write(**kwargs):
                    if kwargs["RoleName"] == "Alice" and failure == "write":
                        raise ApiError("AccessDenied", "PutRolePolicy")
                    return original_write(**kwargs)
                with patch.object(self.iam, "list_role_tags", side_effect=read), patch.object(self.iam, "put_role_policy", side_effect=write):
                    result = self.reconcile()
                self.assertEqual(result["errors"]["Alice"], {"operation": "ListRoleTags" if failure == "read" else "PutRolePolicy", "code": "AccessDenied"})
                self.assertEqual(self.iam.roles["Bob"]["inline"][STATE_POLICY_NAME], role_state(False))
                self.assertNotIn("private SDK", json.dumps(result))

    def test_ec2_metadata_outage_cannot_prevent_known_iam_offboard(self):
        self.reconcile(); self.iam.group.remove("Alice")
        with patch.object(self.ec2, "describe_key_pairs", side_effect=ApiError("RequestLimitExceeded", "DescribeKeyPairs")):
            result = self.reconcile()
        self.assertIn("Bob", result["plan"]["blocked"])
        self.assertEqual(self.iam.roles["Alice"]["inline"][STATE_POLICY_NAME], role_state(False))

    def test_wrong_account_client_is_rejected_before_any_mutation(self):
        with patch.object(self.iam, "get_group", return_value={"Group": {"Arn": "arn:aws:iam::999999999999:group/lab_members"}, "Users": []}):
            with self.assertRaisesRegex(RuntimeError, "different account"):
                self.reconcile()
        self.assertEqual(self.timeline, [])

    def test_missing_state_policy_after_listing_never_hides_role_or_skips_offboarding(self):
        self.reconcile(); self.iam.group.remove("Alice")
        original = self.iam.get_role_policy
        def policy(RoleName, PolicyName):
            if RoleName == "Alice":
                raise ApiError("NoSuchEntity", "GetRolePolicy")
            return original(RoleName, PolicyName)
        with patch.object(self.iam, "get_role_policy", side_effect=policy):
            observed = snapshot(self.iam, {REGION: self.ec2}, self.cfg, s3=self.s3)
            self.assertIsNotNone(observed["roles"]["Alice"])
            self.assertIsNone(observed["roles"]["Alice"]["state"])
            result = self.reconcile()
        self.assertEqual(result["errors"], {})
        self.assertEqual(self.iam.roles["Alice"]["inline"][STATE_POLICY_NAME], role_state(False))
        self.assertEqual(self.iam.roles["Alice"]["trust"], trust_policy(False))
        self.assertFalse(set(self.iam.users["Alice"]) & set(USER_TAG_KEYS))

    def test_known_role_policy_metadata_error_retains_ownership_and_retries_revocation(self):
        self.reconcile(); self.iam.group.remove("Alice")
        original = self.iam.get_role_policy
        def policy(RoleName, PolicyName):
            if RoleName == "Alice":
                raise ApiError("AccessDenied", "GetRolePolicy")
            return original(RoleName, PolicyName)
        with patch.object(self.iam, "get_role_policy", side_effect=policy):
            observed = snapshot(self.iam, {REGION: self.ec2}, self.cfg, s3=self.s3)
            self.assertEqual(observed["roles"]["Alice"]["tags"]["ManagedBy"], MANAGED_BY)
            self.assertEqual(observed["roles"]["Alice"]["read_error"]["code"], "AccessDenied")
            result = self.reconcile()
        self.assertEqual(result["errors"]["Alice"], {"operation": "GetRolePolicy", "code": "AccessDenied"})
        self.assertEqual(self.iam.roles["Alice"]["inline"][STATE_POLICY_NAME], role_state(False))
        self.assertFalse(set(self.iam.users["Alice"]) & set(USER_TAG_KEYS))

    def test_invalid_member_metadata_and_missing_s3_client_cannot_grant(self):
        cfg = copy.deepcopy(self.cfg)
        cfg.s3_manifest["users"][0].pop("home_bucket")
        result = reconcile(self.iam, {REGION: self.ec2}, cfg, s3=self.s3, execute=True)
        self.assertIn("Alice", result["plan"]["blocked"])
        self.assertNotIn("Alice", self.iam.roles)
        self.setUp()
        preview = reconcile(self.iam, {REGION: self.ec2}, self.cfg)
        self.assertEqual(set(preview["blocked"]), {"Alice", "Bob"})
        self.assertEqual(self.timeline, [])

    def test_empty_dynamic_manifest_is_valid_but_bad_flavors_and_cross_account_boundary_fail(self):
        cfg = config(())
        mapping = json.loads(json.dumps(asdict(cfg)))
        self.assertEqual(config_from_mapping(mapping), cfg)
        for changed in (replace(cfg, flavors=cfg.flavors[:-1]),
                        replace(cfg, member_group="other_members"),
                        replace(cfg, permissions_boundary_arn=BOUNDARY.replace(ACCOUNT, "999999999999"))):
            with self.assertRaises(ValueError):
                plan(changed, {})


if __name__ == "__main__":
    unittest.main()
