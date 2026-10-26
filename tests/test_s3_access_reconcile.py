import unittest
from copy import deepcopy
from unittest import mock

from aws_audit.s3_access import reconcile
from test_ec2_access import decision


class S3AccessReconcileTest(unittest.TestCase):
    """Tests for the S3 access reconciliation policy model."""

    def setUp(self) -> None:
        self.manifest = {
            "account_id": "123456789012",
            "groups": {"admin": "admin", "current_member": "members", "alumni": "alumni"},
            "users": [
                {"user_name": "Member", "role": "CurrentMember", "home_bucket": "member"},
                {"user_name": "Former", "role": "Alumni", "home_bucket": "former"},
                {"user_name": "Admin", "role": "Admin"},
            ],
            "buckets": [
                {"name": "member", "scope": "User", "owner": "Member"},
                {"name": "former", "scope": "User", "owner": "Former"},
                {"name": "ops", "scope": "SharedOps"},
                {"name": "service", "scope": "ServiceManaged"},
            ],
        }

    def test_policy_names_match_live_account_prefix(self) -> None:
        """Managed policy names use the live WangLab prefix."""
        self.assertEqual(reconcile.READ_POLICY_NAME, "WangLabS3AccessReadApproved")
        self.assertEqual(
            reconcile.MEMBER_WRITE_POLICY_NAME,
            "WangLabS3AccessCurrentMemberWriteOwn",
        )
        self.assertEqual(
            reconcile.ADMIN_POLICY_NAME,
            "WangLabS3AccessAdminWriteSharedOpsAndReadService",
        )
        self.assertEqual(reconcile.ALUMNI_BASE_POLICY_NAME, "WangLabS3AccessAlumniBase")

    def test_bucket_creation_prohibition_survives_broad_grants_and_preserves_admins(self) -> None:
        bundle = {"member": reconcile.member_write_policy()}
        for action in ("s3:CreateBucket", "s3express:CreateBucket",
                       "s3tables:CreateTableBucket", "s3vectors:CreateVectorBucket"):
            for role in (None, "CurrentMember", "Alumni"):
                context = {} if role is None else {"aws:PrincipalTag/AccessRole": role}
                self.assertEqual(decision(bundle, action, context=context, competing_allow=True), "explicitDeny")
            self.assertEqual(decision(bundle, action, context={"aws:PrincipalTag/AccessRole": "Admin"},
                                      competing_allow=True), "allowed")

    def test_bucket_creation_guard_preserves_existing_home_object_access(self) -> None:
        bundle = {"member": reconcile.member_write_policy()}
        context = {"aws:PrincipalTag/AccessRole": "CurrentMember", "aws:PrincipalTag/HomeBucket": "member-home"}
        for action in ("s3:PutObject", "s3:DeleteObject"):
            self.assertEqual(decision(bundle, action, "arn:aws:s3:::member-home/example", context), "allowed")
            self.assertEqual(decision(bundle, action, "arn:aws:s3:::other-home/example", context), "implicitDeny")

    def test_bucket_guardrails_use_live_account_sids(self) -> None:
        """Desired bucket guardrail statements use live WangLab SIDs."""
        user_sids = [item["Sid"] for item in reconcile.user_bucket_guardrails("example")]
        admin_sids = [item["Sid"] for item in reconcile.admin_only_guardrails("example")]
        self.assertEqual(
            user_sids,
            [
                "WangLabDenyWriteUnlessHomeBucketMatches",
                "WangLabDenyWriteUnlessCurrentMemberOrAdmin",
            ],
        )
        self.assertEqual(admin_sids, ["WangLabDenyWriteUnlessAdmin"])
        self.assertIn("AwsAuditDenyWriteUnlessHomeBucketMatches", reconcile.guardrail_sids())

    def test_alumni_describe_exception_preserves_s3_and_service_scope(self) -> None:
        """The deny excludes exactly approved describes and applies only to direct EC2."""
        before = deepcopy(self.manifest)
        policy = reconcile.alumni_base_policy(self.manifest)
        deny, allow = policy["Statement"][:2]
        self.assertEqual(deny["Effect"], "Deny")
        self.assertNotIn("Action", deny)
        self.assertEqual(deny["NotAction"], allow["Action"])
        self.assertEqual(len(allow["Action"]), 11)
        self.assertIn("ec2:DescribeInstances", allow["Action"])
        self.assertTrue(all(action.startswith("ec2:Describe") and "*" not in action for action in allow["Action"]))
        self.assertEqual(deny["Resource"], "*")
        self.assertEqual(deny["Condition"], {
            "Bool": {"aws:ViaAWSService": "false"},
            "Null": {"ec2:Region": "false"},
        })
        self.assertEqual(allow["Effect"], "Allow")
        self.assertEqual(policy["Statement"][2:], reconcile.read_policy(self.manifest)["Statement"])
        self.assertEqual(self.manifest, before)

    def test_policy_builds_do_not_share_mutable_action_lists(self) -> None:
        """A deployment caller editing a document cannot change later policy builds."""
        first = reconcile.alumni_ec2_statements()
        first[0]["NotAction"].append("ec2:RunInstances")
        first[1]["Action"].append("ec2:TerminateInstances")
        second = reconcile.alumni_ec2_statements()
        self.assertNotIn("ec2:RunInstances", second[0]["NotAction"])
        self.assertNotIn("ec2:TerminateInstances", second[1]["Action"])

    def test_manifest_accepts_explicit_roles_scopes_and_matching_ownership(self) -> None:
        reconcile.validate_manifest_structure(self.manifest)

    def test_manifest_rejects_invalid_role_or_scope(self) -> None:
        for collection, field, value in [
            ("users", "role", "currentmember"),
            ("users", "role", None),
            ("buckets", "scope", "Shared"),
            ("buckets", "scope", None),
        ]:
            with self.subTest(collection=collection, field=field, value=value):
                manifest = deepcopy(self.manifest)
                manifest[collection][-1][field] = value
                with self.assertRaisesRegex(RuntimeError, "invalid"):
                    reconcile.validate_manifest_structure(manifest)

    def test_manifest_rejects_duplicate_names_before_live_inventory_reads(self) -> None:
        for collection in ["users", "buckets"]:
            with self.subTest(collection=collection):
                manifest = deepcopy(self.manifest)
                manifest[collection].append(deepcopy(manifest[collection][0]))
                with mock.patch.object(reconcile, "current_iam_users") as live_users:
                    with self.assertRaisesRegex(RuntimeError, "Duplicate"):
                        reconcile.validate_manifest(manifest)
                    live_users.assert_not_called()

    def test_manifest_rejects_mismatched_or_shared_home_bucket(self) -> None:
        for home in ["former", "ops", "missing", "", None]:
            with self.subTest(home=home):
                manifest = deepcopy(self.manifest)
                manifest["users"][0]["home_bucket"] = home
                with self.assertRaises(RuntimeError):
                    reconcile.validate_manifest_structure(manifest)

    def test_manifest_rejects_user_bucket_without_matching_owner_home(self) -> None:
        for owner in ["Admin", "Former", "missing", None]:
            with self.subTest(owner=owner):
                manifest = deepcopy(self.manifest)
                # Make this an additional bucket so validation must check its owner,
                # even though no user's HomeBucket points to it.
                manifest["buckets"].append({"name": "orphan", "scope": "User", "owner": owner})
                with self.assertRaisesRegex(RuntimeError, "owner"):
                    reconcile.validate_manifest_structure(manifest)

    def test_manifest_rejects_missing_or_reused_role_group(self) -> None:
        for groups in [{"admin": "admin"}, {"admin": "same", "current_member": "same", "alumni": "alumni"}]:
            with self.subTest(groups=groups):
                manifest = deepcopy(self.manifest)
                manifest["groups"] = groups
                with self.assertRaisesRegex(RuntimeError, "groups"):
                    reconcile.validate_manifest_structure(manifest)

    def test_manifest_requires_complete_live_account_inventory(self) -> None:
        users = {user["user_name"] for user in self.manifest["users"]}
        buckets = {bucket["name"] for bucket in self.manifest["buckets"]}
        with mock.patch.object(reconcile, "current_iam_users", return_value=users), mock.patch.object(
            reconcile, "current_s3_buckets", return_value=buckets
        ):
            reconcile.validate_manifest(self.manifest)
        for extra_users, extra_buckets in [({"unlisted-user"}, set()), (set(), {"unlisted-bucket"})]:
            with self.subTest(extra_users=extra_users, extra_buckets=extra_buckets):
                with mock.patch.object(reconcile, "current_iam_users", return_value=users | extra_users), mock.patch.object(
                    reconcile, "current_s3_buckets", return_value=buckets | extra_buckets
                ):
                    with self.assertRaisesRegex(RuntimeError, "Manifest does not match live account"):
                        reconcile.validate_manifest(self.manifest)

    def test_reconciliation_preserves_hpc_uid_on_role_changes(self) -> None:
        """S3 reconciliation must not erase IAM's separately managed stable Linux UID."""
        manifest = {"users": [{"user_name": "Former", "role": "Alumni", "home_bucket": "former"}]}
        tags = {"AccessRole": "CurrentMember", "HomeBucket": "former", "HpcUid": "2001"}
        with mock.patch.object(reconcile, "get_user_tags", return_value=tags), mock.patch.object(
            reconcile, "run_aws"
        ) as run:
            reconcile.reconcile_user_tags(manifest, apply=True)
        run.assert_called_once_with([
            "iam", "tag-user", "--user-name", "Former", "--tags", "Key=AccessRole,Value=Alumni",
        ])
