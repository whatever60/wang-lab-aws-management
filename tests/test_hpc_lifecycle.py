"""Offline behavioral tests: no AWS, Linux account, or sshd changes are made."""
import base64
import copy
import json
import os
import struct
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from aws_audit.hpc import lifecycle, user_sync, workflow

KEY = "ssh-ed25519 " + base64.b64encode(struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(range(32))).decode()


def member(name="alice", uid=2012, active=True, adopt=False):
    return {"iam_user": name.title() + "_User", "linux_user": name, "uid": uid,
            "active": active, "public_keys": [KEY] if active else [], "adopt_existing": adopt}


def registry(users=None):
    return {"schema_version": 1, "cluster_name": "lab-hpc", "users": users if users is not None else [member()],
            "head_limits": {"cpu_quota": "200%", "memory_max": "16G", "max_logins": 4,
                            "max_processes": 512, "max_open_files": 8192, "cpu_time_seconds": 14400,
                            "max_file_size_kib": 40 * 1024 * 1024}}


def account(name="alice", uid=2012):
    return {"name": name, "uid": uid, "gid": 2000, "home": "/home/" + name}


class LifecycleTest(unittest.TestCase):
    def manifest(self):
        data = workflow.load_manifest(Path("config/hpc_workflow_manifest.json"))
        data["user_lifecycle"]["current_s3_uri"] = "s3://lab-assets/parallelcluster-assets/users/current.json"
        data["user_lifecycle"]["public_key_sources"] = {
            "Alice_User": {"ec2_key_name": "alice", "public_key_sha256": user_sync.digest(KEY.encode("utf-8"))}}
        return data

    def test_registry_rejects_reserved_duplicate_and_colliding_identities(self):
        cases = [[member(uid=0)], [member(uid=2000)], [member(uid=60001)],
                 [member(), member("bob", 2012)], [member(), dict(member("bob", 2013), linux_user="alice")]]
        for users in cases:
            with self.subTest(users=users), self.assertRaises(ValueError):
                user_sync.validate_registry(registry(users), "lab-hpc")

    def test_active_missing_key_and_key_options_are_rejected(self):
        for keys in [[], ["no-port-forwarding " + KEY], [KEY + "\n" + KEY], ["-----BEGIN PRIVATE KEY-----"]]:
            with self.subTest(keys=keys), self.assertRaises(ValueError):
                user_sync.validate_registry(registry([dict(member(), public_keys=keys)]), "lab-hpc")
        self.assertEqual(user_sync.public_key(KEY + " comment"), KEY)

    def test_iam_filters_alumni_without_requiring_a_uid_and_checks_active_uids(self):
        manifest = self.manifest()
        names = ["Alice_User", "Bob_User", "Former_User"]
        tags = {"Alice_User": {"AccessRole": "CurrentMember", "HpcUid": "2012"},
                "Bob_User": {"AccessRole": "Admin", "HpcUid": "2013"}, "Former_User": {"AccessRole": "Alumni"}}
        with mock.patch.object(workflow, "selected_iam_users", return_value=names), mock.patch.object(workflow, "iam_user_tags", side_effect=lambda name: tags[name]):
            self.assertEqual([row["uid"] for row in workflow.lab_users_from_iam(manifest)], [2012, 2013])
            for value in ["", "abc", "2000", "0", "-1", "60001"]:
                tags["Alice_User"]["HpcUid"] = value
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, "requires a unique"):
                    workflow.lab_users_from_iam(manifest)
            tags["Alice_User"]["HpcUid"] = "2013"
            with self.assertRaisesRegex(ValueError, "Duplicate uid"):
                workflow.lab_users_from_iam(manifest)

    def test_public_keys_use_only_explicit_pub_or_ec2_public_metadata(self):
        manifest = self.manifest()
        with mock.patch.object(lifecycle, "aws_json", return_value={"KeyPairs": [{"PublicKey": KEY}]} ) as aws:
            self.assertEqual(lifecycle.public_key_for_user(manifest, member()), KEY)
            self.assertIn("--include-public-key", aws.call_args[0][0])
            self.assertIn("alice", aws.call_args[0][0])
        manifest["user_lifecycle"]["public_key_sources"] = {"Alice_User": {
            "local_public_key_path": "/forbidden/private.pem", "public_key_sha256": user_sync.digest(KEY.encode("utf-8"))}}
        with mock.patch.object(lifecycle, "read_admin_file") as read, self.assertRaisesRegex(ValueError, ".pub"):
            lifecycle.public_key_for_user(manifest, member())
        read.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            public = Path(temporary).resolve() / "alice.pub"
            public.write_text(KEY + " Alice\n")
            manifest["user_lifecycle"]["public_key_sources"]["Alice_User"]["local_public_key_path"] = str(public)
            self.assertEqual(lifecycle.public_key_for_user(manifest, member()), KEY)

    def test_tombstones_preserve_identity_and_forbid_uid_reuse(self):
        manifest = self.manifest()
        previous = registry()
        retired = lifecycle.desired_registry(manifest, [], previous)
        self.assertEqual(retired["users"], [member(active=False)])
        with mock.patch.object(lifecycle, "public_key_for_user", return_value=KEY):
            with self.assertRaisesRegex(ValueError, "cannot be changed"):
                lifecycle.desired_registry(manifest, [dict(member(), uid=2013)], previous)
            with self.assertRaisesRegex(ValueError, "Duplicate uid"):
                lifecycle.desired_registry(manifest, [member("bob", 2012)], retired)
        with self.assertRaisesRegex(ValueError, "disappeared"):
            user_sync.validate_transition(previous, registry([]))

    def test_adoption_and_local_uid_conflicts_are_preflighted(self):
        for accounts in [[account()], [account("other", 2012)], [account("alice", 3000)], [account(), account("alias", 2012)]]:
            with self.subTest(accounts=accounts), self.assertRaises(ValueError):
                user_sync.account_plan([member()], {"users": []}, accounts)
        self.assertFalse(user_sync.account_plan([member(adopt=True)], {"users": []}, [account()])[0]["create"])
        self.assertTrue(user_sync.account_plan([member()], {"users": []}, [])[0]["create"])
        # A tombstone alone never authorizes adopting/revoking an unrelated local account.
        with self.assertRaisesRegex(ValueError, "unmanaged"):
            user_sync.account_plan([member(active=False)], {"users": []}, [account()])

    def fake_runner(self, calls, accounts):
        def run(command, **kwargs):
            calls.append(command)
            if command[0] == "useradd":
                accounts.append(account(command[-1], int(command[command.index("--uid") + 1])))
            output = "nfs4\n" if command[0] == "findmnt" else ""
            if command[:2] == ["/usr/sbin/sshd", "-T"]:
                output = ("authorizedkeysfile /etc/aws-audit/authorized_keys/%u\nauthorizedkeyscommand none\n"
                          "passwordauthentication no\nkbdinteractiveauthentication no\nauthenticationmethods publickey\n"
                          "pubkeyacceptedalgorithms ssh-ed25519,rsa-sha2-256\n")
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")
        return run

    def test_new_member_then_offboarding_preserves_home_and_revokes_sessions(self):
        calls, accounts = [], []
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(os, "chown"):
            root = Path(temporary)
            (root / "home").mkdir()
            reconciler = user_sync.Reconciler(root, self.fake_runner(calls, accounts), lambda: accounts, root_owner_uid=os.geteuid())
            reconciler.apply(registry(), "lab-hpc", "compute", accounts, None)
            key_file = root / "etc/aws-audit/authorized_keys/alice"
            self.assertEqual(key_file.read_text(), KEY + "\n")
            self.assertEqual(key_file.stat().st_mode & 0o777, 0o644)
            self.assertFalse((root / "home/alice/.ssh/authorized_keys").exists())
            home = root / "home/alice"
            (home / "important.txt").write_text("retain this")
            reconciler.apply(registry([member(active=False)]), "lab-hpc", "compute", accounts, 2000)
            self.assertEqual(key_file.read_bytes(), b"")
            self.assertEqual((home / "important.txt").read_text(), "retain this")
            self.assertIn(["usermod", "--lock", "--expiredate", "1", "--shell", "/usr/sbin/nologin", "alice"], calls)
            self.assertIn(["pkill", "-KILL", "-u", "2012"], calls)
            self.assertFalse(any(cmd[0] == "userdel" for cmd in calls))

    def test_new_node_tombstone_never_reactivates_shared_efs_ssh_files(self):
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authorized = root / "home/alice/.ssh/authorized_keys"
            authorized.parent.mkdir(parents=True)
            authorized.write_text(KEY)
            reconciler = user_sync.Reconciler(root, self.fake_runner(calls, []), lambda: [], root_owner_uid=os.geteuid())
            reconciler.apply(registry([member(active=False)]), "lab-hpc", "compute", [], 2000)
            self.assertEqual(authorized.read_text(), KEY)  # Data remains, but sshd never uses it.
            self.assertEqual((root / "etc/aws-audit/authorized_keys/alice").read_bytes(), b"")
            self.assertFalse(any(command[0] in {"useradd", "usermod"} for command in calls))

    def test_invalid_registry_preserves_existing_valid_access(self):
        calls, accounts = [], [account(), account("unrelated", 3030)]
        with tempfile.TemporaryDirectory() as temporary:
            reconciler = user_sync.Reconciler(Path(temporary), self.fake_runner(calls, accounts), lambda: accounts, root_owner_uid=os.geteuid())
            reconciler.atomic_file(reconciler.state_path, user_sync.canonical_bytes(registry()))
            reconciler.atomic_file(reconciler.key_dir / "alice", KEY.encode())
            with self.assertRaises(ValueError):
                reconciler.apply(registry([dict(member(), public_keys=[])]), "lab-hpc", "compute", accounts, 2000)
            self.assertEqual((reconciler.key_dir / "alice").read_bytes(), KEY.encode())
            self.assertFalse(any(command[0] in {"usermod", "pkill", "scancel"} for command in calls))
            self.assertFalse(any("unrelated" in command for command in calls))
            self.assertFalse(any(command[0] == "useradd" for command in calls))

    def test_first_migration_failure_does_not_revoke_unmanaged_account(self):
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            reconciler = user_sync.Reconciler(Path(temporary), self.fake_runner(calls, [account()]), lambda: [account()], root_owner_uid=os.geteuid())
            with self.assertRaisesRegex(ValueError, "unmanaged"):
                reconciler.apply(registry(), "lab-hpc", "compute", [account()], 2000)
            self.assertEqual(calls, [])
            self.assertFalse(reconciler.state_path.exists())

    def test_version_pinned_fetch_rejects_checksum_and_runtime_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            runtime = directory / "runtime.py"
            runtime.write_text("trusted runtime")
            content = user_sync.canonical_bytes(registry())
            pointer = {"schema_version": 1, "cluster_name": "lab-hpc", "runtime_sha256": user_sync.digest(runtime.read_bytes()),
                       "registry_key": "users/releases/one.json", "registry_version_id": "version-42", "registry_sha256": user_sync.digest(content)}
            def get(bucket, key, destination, version_id=""):
                destination.write_bytes(user_sync.canonical_bytes(pointer) if key == "users/current.json" else content)
                if key != "users/current.json":
                    self.assertEqual(version_id, "version-42")
                return {"VersionId": "v1"}
            with mock.patch.object(user_sync, "get_versioned_object", side_effect=get):
                self.assertEqual(user_sync.fetch_registry("s3://assets/users/current.json", "lab-hpc", runtime, directory), registry())
                pointer["registry_sha256"] = "0" * 64
                with self.assertRaisesRegex(ValueError, "checksum"):
                    user_sync.fetch_registry("s3://assets/users/current.json", "lab-hpc", runtime, directory)
                pointer["runtime_sha256"] = "0" * 64
                with self.assertRaisesRegex(ValueError, "Runtime release changed"):
                    user_sync.fetch_registry("s3://assets/users/current.json", "lab-hpc", runtime, directory)

    def test_s3_outage_preserves_last_valid_keys_accounts_and_jobs(self):
        calls, accounts = [], [account()]
        with tempfile.TemporaryDirectory() as temporary:
            reconciler = user_sync.Reconciler(Path(temporary), self.fake_runner(calls, accounts), lambda: accounts, root_owner_uid=os.geteuid())
            reconciler.atomic_file(reconciler.state_path, user_sync.canonical_bytes(registry()))
            reconciler.atomic_file(reconciler.key_dir / "alice", KEY.encode())
            fake_temporary = mock.MagicMock()
            fake_temporary.__enter__.return_value = temporary
            with mock.patch.object(user_sync.tempfile, "TemporaryDirectory", return_value=fake_temporary), \
                    mock.patch.object(user_sync, "fetch_registry", side_effect=TimeoutError("S3 unavailable")), \
                    mock.patch.object(user_sync, "Reconciler", return_value=reconciler), \
                    mock.patch.object(user_sync, "system_accounts", return_value=accounts), \
                    mock.patch.object(user_sync.os, "geteuid", return_value=0), \
                    mock.patch.object(user_sync.grp, "getgrnam", return_value=mock.Mock(gr_gid=2000)), \
                    mock.patch.object(Path, "open", return_value=mock.MagicMock()), \
                    mock.patch("fcntl.flock"), \
                    mock.patch.object(user_sync.sys, "argv", ["runtime", "--manifest-uri", "s3://assets/users/current.json", "--cluster-name", "lab-hpc", "--node-role", "compute"]):
                with self.assertRaisesRegex(TimeoutError, "S3 unavailable"):
                    user_sync.main()
            self.assertEqual((reconciler.key_dir / "alice").read_bytes(), KEY.encode())
            self.assertEqual(calls, [])

    def test_revoke_shared_uid_refuses_before_keys_accounts_jobs_or_processes(self):
        calls = []
        accounts = [account(), account("unrelated", 2012)]
        with tempfile.TemporaryDirectory() as temporary:
            reconciler = user_sync.Reconciler(Path(temporary), self.fake_runner(calls, accounts), lambda: accounts,
                                             root_owner_uid=os.geteuid())
            reconciler.atomic_file(reconciler.key_dir / "alice", KEY.encode())
            for role in ["head", "compute"]:
                with self.subTest(role=role), mock.patch.object(reconciler, "atomic_file") as write:
                    with self.assertRaisesRegex(ValueError, "shared UID"):
                        reconciler.revoke(member(), {row["name"]: row for row in accounts}, role)
                    write.assert_not_called()
            self.assertEqual((reconciler.key_dir / "alice").read_bytes(), KEY.encode())
            self.assertEqual(calls, [])

    def test_offboarding_shared_uid_does_not_revoke_or_kill_unrelated_identity(self):
        calls = []
        accounts = [account(), account("unrelated", 2012)]
        with tempfile.TemporaryDirectory() as temporary:
            reconciler = user_sync.Reconciler(Path(temporary), self.fake_runner(calls, accounts), lambda: accounts,
                                             root_owner_uid=os.geteuid())
            reconciler.atomic_file(reconciler.state_path, user_sync.canonical_bytes(registry()))
            reconciler.atomic_file(reconciler.key_dir / "alice", KEY.encode())
            with self.assertRaisesRegex(ValueError, "shared UID"):
                reconciler.apply(registry([member(active=False)]), "lab-hpc", "head", accounts, 2000)
            self.assertEqual((reconciler.key_dir / "alice").read_bytes(), KEY.encode())
            self.assertEqual(calls, [])
            # The explicit emergency path must use the same per-target identity guard.
            with self.assertRaisesRegex(RuntimeError, "shared UID"):
                reconciler.fail_closed(registry(), accounts, "head")
            self.assertEqual((reconciler.key_dir / "alice").read_bytes(), KEY.encode())
            self.assertEqual(calls, [])

    def test_valid_revocation_still_applies_when_another_enrollment_has_uid_conflict(self):
        calls, accounts = [], [account(), account("unrelated", 2013)]
        with tempfile.TemporaryDirectory() as temporary:
            reconciler = user_sync.Reconciler(Path(temporary), self.fake_runner(calls, accounts), lambda: accounts, root_owner_uid=os.geteuid())
            reconciler.atomic_file(reconciler.state_path, user_sync.canonical_bytes(registry()))
            reconciler.atomic_file(reconciler.key_dir / "alice", KEY.encode())
            with self.assertRaisesRegex(ValueError, "already belongs"):
                reconciler.apply(registry([member(active=False), member("bob", 2013)]), "lab-hpc", "compute", accounts, 2000)
            self.assertEqual((reconciler.key_dir / "alice").read_bytes(), b"")
            self.assertIn(["pkill", "-KILL", "-u", "2012"], calls)
            self.assertFalse(any("unrelated" in command for command in calls))

    def test_enrollment_failure_rolls_back_only_new_grants(self):
        calls, accounts = [], [account()]
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(os, "chown"):
            root = Path(temporary)
            (root / "home").mkdir()
            reconciler = user_sync.Reconciler(root, self.fake_runner(calls, accounts), lambda: accounts, root_owner_uid=os.geteuid())
            reconciler.atomic_file(reconciler.state_path, user_sync.canonical_bytes(registry()))
            reconciler.atomic_file(reconciler.key_dir / "alice", KEY.encode())
            # Existing data belongs to alice in a real EFS mount; skip creating her home
            # so this fixture can test provisioning failure without requiring root chown.
            desired = registry([member(), member("bob", 2013)])
            original_verify = reconciler.verify_ssh_policy
            def reject_bob(name):
                if name == "bob":
                    raise ValueError("bad effective sshd policy")
                original_verify(name)
            with mock.patch.object(reconciler, "verify_ssh_policy", side_effect=reject_bob), self.assertRaisesRegex(ValueError, "effective"):
                reconciler.apply(desired, "lab-hpc", "compute", accounts, 2000)
            self.assertEqual((reconciler.key_dir / "alice").read_bytes(), KEY.encode())
            self.assertFalse(any(command[0] == "pkill" and command[-1] == "2012" for command in calls))
            self.assertIn(["pkill", "-KILL", "-u", "2013"], calls)
            state = reconciler.previous()
            self.assertTrue(next(row for row in state["users"] if row["linux_user"] == "alice")["active"])
            self.assertFalse(next(row for row in state["users"] if row["linux_user"] == "bob")["active"])

    def test_deployed_config_requires_dynamic_hooks_for_every_queue(self):
        import io
        import yaml
        manifest = self.manifest()
        bucket, bootstrap_key = lifecycle.s3_location(lifecycle.release_asset(manifest, "bootstrap")[1])
        pointer = {"bootstrap_key": bootstrap_key}
        head = {"CustomActions": workflow.custom_action_config(manifest, [], True)}
        compute = {"CustomActions": workflow.custom_action_config(manifest, [], False)}
        config = {"HeadNode": head, "Scheduling": {"SlurmQueues": [compute]}}
        result = subprocess.CompletedProcess([], 0, stdout=json.dumps({"clusterConfiguration": {"url": "https://assets.s3.amazonaws.com/config.yaml?secret=not-logged"}}))
        class Response(io.BytesIO):
            def geturl(self):
                return "https://assets.s3.amazonaws.com/config.yaml"
        with mock.patch.object(lifecycle.subprocess, "run", return_value=result), \
                mock.patch.object(lifecycle.urllib.request, "urlopen", side_effect=lambda *args, **kwargs: Response(yaml.safe_dump(config).encode())):
            lifecycle.verify_cluster_hooks(manifest, pointer)
            compute["CustomActions"]["OnNodeConfigured"]["Args"] = ["alice:2012"]
            with self.assertRaisesRegex(ValueError, "stale"):
                lifecycle.verify_cluster_hooks(manifest, pointer)
        result.stdout = json.dumps({"clusterConfiguration": {"url": "file:///etc/shadow"}})
        with mock.patch.object(lifecycle.subprocess, "run", return_value=result), mock.patch.object(lifecycle.urllib.request, "urlopen") as urlopen:
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                lifecycle.verify_cluster_hooks(manifest, pointer)
            urlopen.assert_not_called()

    def test_publish_preview_never_puts_and_execute_uses_conditional_pointer(self):
        manifest = self.manifest()
        old = {"registry": registry(), "pointer": {"registry_sha256": "old"}}
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(lifecycle, "load_release", return_value=(old, {"ETag": '"etag-old"'})), \
                mock.patch.object(lifecycle, "aws_json", return_value={"Status": "Enabled"}), \
                mock.patch.object(lifecycle, "public_key_for_user", return_value=KEY), \
                mock.patch.object(lifecycle, "put_file", return_value={"VersionId": "v-new"}) as put:
            path = Path(temporary).resolve() / "preview.json"
            prepared = lifecycle.publish_users(manifest, [member()], path)
            put.assert_not_called()
            reviewed_bytes = path.read_bytes()
            self.assertEqual(user_sync.digest(user_sync.canonical_bytes(prepared["preview"])), prepared["preview_sha256"])
            lifecycle.publish_users(manifest, [member()], path, execute=True,
                                    approved_preview_sha256=prepared["preview_sha256"])
            self.assertEqual(path.read_bytes(), reviewed_bytes)
            self.assertEqual(put.call_args.kwargs, {"if_match": '"etag-old"'})
            self.assertEqual(put.call_args.args[1], "parallelcluster-assets/users/current.json")
            self.assertEqual(put.call_count, 4)

    def test_alumni_removal_reaches_head_and_future_compute_hooks(self):
        manifest = self.manifest()
        head = workflow.custom_action_config(manifest, [], True)["OnNodeConfigured"]
        compute = workflow.custom_action_config(manifest, [member()], False)["OnNodeConfigured"]
        self.assertEqual(head["Args"][-1], "head")
        self.assertEqual(compute["Args"][-1], "compute")
        self.assertEqual(head["Args"][1], manifest["user_lifecycle"]["current_s3_uri"])
        self.assertNotIn("alice", json.dumps(compute))
        self.assertIn("/releases/code/", head["Script"])

    def test_concurrent_efs_home_initialization_cannot_observe_mkdir_chown_gap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "home").mkdir(mode=0o755)
            home = root / "home/alice"
            first_in_gap, release_chown = threading.Event(), threading.Event()
            second_waiting, second_observed = threading.Event(), threading.Event()
            chown_done = threading.Event()
            ownership, errors = {}, []
            original_lstat = Path.lstat
            original_flock = user_sync.fcntl.flock
            first = user_sync.Reconciler(root, root_owner_uid=os.geteuid())
            second = user_sync.Reconciler(root, root_owner_uid=os.geteuid())
            def fake_chown(path, uid, gid):
                self.assertEqual(Path(path), home)
                first_in_gap.set()
                if not release_chown.wait(5):
                    raise TimeoutError("Test did not release chown")
                ownership[str(path)] = uid
                chown_done.set()
            def observed_lstat(path):
                result = original_lstat(path)
                if path == home:
                    if threading.current_thread().name == "second-node":
                        second_observed.set()
                        if not chown_done.is_set():
                            raise AssertionError("Second node inspected a half-initialized home")
                    fields = list(result)
                    fields[4] = ownership.get(str(path), result.st_uid)
                    return os.stat_result(fields)
                return result
            def observed_flock(fd, operation):
                try:
                    return original_flock(fd, operation)
                except BlockingIOError:
                    if threading.current_thread().name == "second-node":
                        second_waiting.set()
                    raise
            def initialize(reconciler):
                try:
                    reconciler.ensure_home(member(), create=True)
                except Exception as exc:
                    errors.append(exc)
            with mock.patch.object(os, "chown", side_effect=fake_chown), \
                    mock.patch.object(Path, "lstat", new=observed_lstat), \
                    mock.patch.object(user_sync.fcntl, "flock", side_effect=observed_flock):
                thread_one = threading.Thread(target=initialize, args=(first,), name="first-node")
                thread_two = threading.Thread(target=initialize, args=(second,), name="second-node")
                thread_one.start()
                try:
                    self.assertTrue(first_in_gap.wait(2))
                    original_inode = home.stat().st_ino
                    (home / "existing-data.txt").write_text("preserve me")
                    thread_two.start()
                    self.assertTrue(second_waiting.wait(2))
                    self.assertFalse(second_observed.is_set())
                finally:
                    release_chown.set()
                    thread_one.join(3)
                    if thread_two.ident is not None:
                        thread_two.join(3)
                self.assertFalse(thread_one.is_alive())
                self.assertFalse(thread_two.is_alive())
                self.assertEqual(errors, [])
                self.assertTrue(second_observed.is_set())
                self.assertEqual(home.lstat().st_uid, 2012)
                self.assertEqual(home.stat().st_ino, original_inode)
                self.assertEqual((home / "existing-data.txt").read_text(), "preserve me")

    def test_efs_home_lock_timeout_does_not_create_or_change_a_home(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "home").mkdir(mode=0o755)
            first = user_sync.Reconciler(root, root_owner_uid=os.geteuid())
            second = user_sync.Reconciler(root, root_owner_uid=os.geteuid())
            with first.shared_home_lock("alice"), mock.patch.object(user_sync, "HOME_LOCK_TIMEOUT_SECONDS", 0.02):
                with self.assertRaisesRegex(TimeoutError, "shared EFS home initialization lock"):
                    second.ensure_home(member(), create=True)
            self.assertFalse((root / "home/alice").exists())
            self.assertEqual((root / "home/.aws-audit-hpc-locks").stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / "home/.aws-audit-hpc-locks/alice.lock").stat().st_mode & 0o777, 0o600)

    def test_efs_home_locks_reject_symlinks_bad_ownership_and_existing_home_conflicts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "home").mkdir(mode=0o755)
            reconciler = user_sync.Reconciler(root, root_owner_uid=os.geteuid())
            home = root / "home/alice"
            home.mkdir()
            (home / "data").write_text("never overwrite")
            with self.assertRaisesRegex(ValueError, "ownership mismatch"):
                reconciler.ensure_home(member(uid=os.geteuid() + 1), create=True)
            self.assertEqual((home / "data").read_text(), "never overwrite")
            lock_file = root / "home/.aws-audit-hpc-locks/alice.lock"
            lock_file.unlink()
            lock_file.symlink_to(home / "data")
            with self.assertRaises(OSError):
                reconciler.ensure_home(member(), create=True)
            self.assertEqual((home / "data").read_text(), "never overwrite")
            lock_file.unlink()
            lock_dir = lock_file.parent
            lock_dir.rmdir()
            lock_dir.symlink_to(home, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "lock directory"):
                reconciler.ensure_home(member(), create=True)
            lock_dir.unlink()
            (root / "home").chmod(0o777)
            with self.assertRaisesRegex(ValueError, "root-owned"):
                reconciler.ensure_home(member(), create=True)
            (root / "home").chmod(0o755)
            untrusted = user_sync.Reconciler(root, root_owner_uid=os.geteuid() + 1)
            with self.assertRaisesRegex(ValueError, "root-owned"):
                untrusted.ensure_home(member(), create=True)

    def test_head_limits_use_pam_units_and_current_slice_limits(self):
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            reconciler = user_sync.Reconciler(Path(temporary), self.fake_runner(calls, []), lambda: [], root_owner_uid=os.geteuid())
            reconciler.head_limits([member()], registry()["head_limits"])
            pam = (Path(temporary) / "etc/security/limits.d/95-aws-audit-login-limits.conf").read_text()
            self.assertIn("alice hard cpu 240", pam)
            self.assertIn("alice hard fsize 41943040", pam)
            self.assertNotIn("@hpc-users", pam)  # Unadopted members are not changed.
            self.assertIn(["systemctl", "set-property", "user-2012.slice", "CPUQuota=200%", "MemoryMax=16G", "TasksMax=512"], calls)

    def test_ssm_rollout_refuses_stopped_or_offline_nodes_before_send(self):
        manifest = self.manifest()
        pointer = {"registry_sha256": "a" * 64}
        for kind in ["runtime", "bootstrap"]:
            path, uri = lifecycle.release_asset(manifest, kind)
            pointer[kind + "_sha256"] = user_sync.digest(path.read_bytes())
        old = {"pointer": pointer, "registry": registry()}
        target = {"instance_id": "i-exact", "node_role": "head", "state": "stopped"}
        with mock.patch.object(lifecycle, "load_release", return_value=(old, {})), \
                mock.patch.object(lifecycle, "sync_targets", return_value=[target]), \
                mock.patch.object(lifecycle, "verify_cluster_hooks"), \
                mock.patch.object(lifecycle, "aws_json", return_value={"InstanceInformationList": []}) as aws:
            with self.assertRaisesRegex(ValueError, "Stopped"):
                lifecycle.rollout_users(manifest, execute=True)
            aws.assert_not_called()
            target["state"] = "running"
            with self.assertRaisesRegex(ValueError, "SSM Online"):
                lifecycle.rollout_users(manifest, execute=True)
            self.assertFalse(any(call.args[0][:2] == ["ssm", "send-command"] for call in aws.call_args_list))

    def test_sync_discovery_uses_exact_cluster_tags_and_recognized_roles(self):
        manifest = self.manifest()
        head_id, compute_id = "i-00000000000000001", "i-00000000000000002"
        stack_arn = "arn:aws:cloudformation:us-east-1:123456789012:stack/lab-hpc/example-stack"
        profile_arn = "arn:aws:iam::123456789012:instance-profile/lab-hpc-compute-profile"
        template_id = "lt-00000000000000001"
        cluster = {"clusterName": "lab-hpc", "region": "us-east-1", "headNode": {"instanceId": head_id},
                   "cloudformationStackArn": stack_arn, "cloudFormationStackStatus": "CREATE_COMPLETE"}
        resources = [{"ResourceType": kind, "PhysicalResourceId": identity, "ResourceStatus": "CREATE_COMPLETE"}
                     for kind, identity in [("AWS::EC2::Instance", head_id),
                                            ("AWS::IAM::InstanceProfile", "lab-hpc-compute-profile"),
                                            ("AWS::EC2::LaunchTemplate", template_id)]]
        head = {"InstanceId": head_id, "State": {"Name": "running"}, "Tags": [
            {"Key": "parallelcluster:cluster-name", "Value": "lab-hpc"},
            {"Key": "parallelcluster:node-type", "Value": "HeadNode"}]}
        compute = {"InstanceId": compute_id, "State": {"Name": "running"},
                   "IamInstanceProfile": {"Arn": profile_arn, "Id": "example-profile-id"}, "Tags": [
            {"Key": "parallelcluster:cluster-name", "Value": "lab-hpc"},
            {"Key": "parallelcluster:node-type", "Value": "Compute"},
            {"Key": "aws:ec2launchtemplate:id", "Value": template_id},
            {"Key": "aws:ec2launchtemplate:version", "Value": "1"}]}
        def aws_response(command):
            if command[:2] == ["cloudformation", "list-stack-resources"]:
                self.assertIn(stack_arn, command)
                return {"StackResourceSummaries": resources}
            if command[:2] == ["ec2", "describe-instances"]:
                self.assertIn("Name=tag:parallelcluster:cluster-name,Values=lab-hpc", command)
                return {"Reservations": [{"Instances": [head, compute]}]}
            if command[:2] == ["iam", "get-instance-profile"]:
                self.assertIn("lab-hpc-compute-profile", command)
                return {"InstanceProfile": {"Arn": profile_arn, "InstanceProfileId": "example-profile-id"}}
            raise AssertionError(f"Unexpected AWS operation: {command[:2]}")
        with mock.patch.object(lifecycle, "describe_cluster", return_value=cluster), \
                mock.patch.object(lifecycle, "aws_json", side_effect=aws_response):
            self.assertEqual(lifecycle.sync_targets(manifest), [
                {"instance_id": head_id, "node_role": "head", "state": "running"},
                {"instance_id": compute_id, "node_role": "compute", "state": "running"}])
            next(tag for tag in compute["Tags"] if tag["Key"] == "parallelcluster:node-type")["Value"] = "unknown"
            with self.assertRaisesRegex(ValueError, "Unrecognized node role"):
                lifecycle.sync_targets(manifest)

    def test_generated_roles_and_asset_policy_grant_ssm_and_only_asset_reads(self):
        manifest = self.manifest()
        with mock.patch.object(workflow, "lab_users_from_iam", return_value=[]), mock.patch.object(workflow, "grouped_candidates", return_value={"cpu": [], "gpu": []}):
            config = workflow.generated_cluster_config(manifest)
        sections = [config["HeadNode"], *config["Scheduling"]["SlurmQueues"]]
        for section in sections:
            policies = section["Iam"]["AdditionalIamPolicies"]
            self.assertIn({"Policy": "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"}, policies)
        policy = json.loads(Path("config/parallelcluster_assets_read_policy.template.json").read_text())
        self.assertEqual(policy["Statement"][0]["Action"], ["s3:GetObject", "s3:GetObjectVersion"])
        resources = policy["Statement"][0]["Resource"]
        self.assertTrue(any(resource.endswith("/users/current.json") for resource in resources))
        self.assertFalse(any(resource.endswith("/parallelcluster-assets/*") for resource in resources))

    def test_storage_cleanup_default_refuses_before_any_aws_call(self):
        manifest = self.manifest()
        with mock.patch.object(workflow, "run_json") as read, mock.patch.object(workflow, "run_command") as mutation:
            with self.assertRaisesRegex(ValueError, "explicit test manifest"):
                workflow.cleanup_tagged_storage(manifest)
        read.assert_not_called()
        mutation.assert_not_called()
        manifest["storage_management"] = {"purpose": "test", "allow_cleanup": True}
        for item in manifest["storage"]:
            item["deletion_policy"] = "Delete"
        with mock.patch.object(workflow, "run_json", return_value=[]) as read:
            workflow.cleanup_tagged_storage(manifest)
        for args in read.call_args_list:
            query = args.args[0][args.args[0].index("--query") + 1]
            self.assertIn("aws-audit:storage-purpose", query)
            self.assertIn("aws-audit:storage-lifecycle", query)
            self.assertIn("parallelcluster:cluster-name", query)
        self.assertFalse(workflow.build_parser().parse_args(["delete-cluster"]).cleanup_storage)


if __name__ == "__main__":
    unittest.main()
