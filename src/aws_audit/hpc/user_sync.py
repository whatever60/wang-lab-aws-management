#!/usr/bin/env python3
"""Standalone root-side HPC account reconciler; also imported by the publisher.

Only public keys enter this module. No IAM access or private keys are required on nodes.
"""
import argparse
import base64
import copy
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import pwd
import grp
import re
import shutil
import struct
import stat
import subprocess
import tempfile
import time
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MIN_UID = 2001
MAX_UID = 60000
GROUP = "hpc-users"
GID = 2000
HOME_LOCK_TIMEOUT_SECONDS = 30
KEY_TYPES = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def public_key(value: str) -> str:
    """Accept one bare OpenSSH public key, never options or private-key material."""
    if not isinstance(value, str) or "\n" in value.strip() or "\r" in value.strip():
        raise ValueError("Expected one OpenSSH public key line")
    parts = value.strip().split()
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        raise ValueError("Unsupported public key type or authorized_keys options")
    try:
        blob = base64.b64decode(parts[1], validate=True)
        length = struct.unpack(">I", blob[:4])[0]
        algorithm = blob[4:4 + length].decode("ascii")
        if algorithm != parts[0] or len(blob) <= 4 + length + 4:
            raise ValueError("Invalid public key blob")
        # ssh-keygen verifies complete key structure at publication time as well.
        if algorithm == "ssh-ed25519" and (len(blob) != 51 or blob[15:19] != b"\x00\x00\x00\x20"):
            raise ValueError("Invalid Ed25519 key length")
    except (ValueError, UnicodeError, struct.error) as exc:
        raise ValueError("Invalid OpenSSH public key encoding") from exc
    return " ".join(parts[:2])


def validate_registry(data: dict[str, Any], cluster_name: str) -> list[dict[str, Any]]:
    if data.get("schema_version") != SCHEMA_VERSION or data.get("cluster_name") != cluster_name:
        raise ValueError("Unexpected user registry schema or cluster")
    users = data.get("users")
    if not isinstance(users, list):
        raise ValueError("User registry must contain users list")
    seen = {"uid": set(), "linux_user": set(), "iam_user": set()}
    for user in users:
        uid = user.get("uid")
        name = user.get("linux_user", "")
        iam_name = user.get("iam_user", "")
        if type(uid) is not int or not MIN_UID <= uid <= MAX_UID:
            raise ValueError(f"Invalid/reserved UID for {iam_name}")
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name):
            raise ValueError(f"Invalid Linux user {name!r}")
        if not isinstance(iam_name, str) or not re.fullmatch(r"[\w+=,.@-]{1,64}", iam_name, re.ASCII):
            raise ValueError("Invalid IAM user name")
        for field in seen:
            if user[field] in seen[field]:
                raise ValueError(f"Duplicate {field}: {user[field]}")
            seen[field].add(user[field])
        if type(user.get("active")) is not bool or type(user.get("adopt_existing", False)) is not bool:
            raise ValueError(f"Invalid active/adoption state for {name}")
        keys = user.get("public_keys")
        if not isinstance(keys, list) or (user["active"] and not keys):
            raise ValueError(f"Active user {name} requires a public key")
        if not user["active"] and keys:
            raise ValueError(f"Revoked user {name} must have no public keys")
        for key in keys:
            public_key(key)
    policy = data.get("staleness_policy", {"on_fetch_failure": "retain", "warn_after_seconds": 3600})
    if policy.get("on_fetch_failure") != "retain" or type(policy.get("warn_after_seconds")) is not int or policy["warn_after_seconds"] < 60:
        raise ValueError("Only explicit retain-last-valid staleness policy is supported")
    limits = data.get("head_limits", {})
    if limits:
        if not re.fullmatch(r"[1-9][0-9]*%", str(limits.get("cpu_quota", ""))):
            raise ValueError("Invalid CPUQuota")
        if not re.fullmatch(r"[1-9][0-9]*[MG]", str(limits.get("memory_max", ""))):
            raise ValueError("Invalid MemoryMax")
        for field in ["max_logins", "max_processes", "max_open_files", "cpu_time_seconds", "max_file_size_kib"]:
            if type(limits.get(field)) is not int or limits[field] < 1:
                raise ValueError(f"Invalid head limit {field}")
    return users


def validate_transition(previous: dict[str, Any], desired: dict[str, Any]) -> None:
    """Managed identities and tombstones cannot disappear, change UID, or be reused."""
    current = {user["iam_user"]: user for user in desired["users"]}
    for old in previous.get("users", []):
        new = current.get(old["iam_user"])
        if new is None or any(new[field] != old[field] for field in ["linux_user", "uid"]):
            raise ValueError(f"Managed identity changed/disappeared: {old['iam_user']}")


def account_plan(users: list[dict[str, Any]], previous: dict[str, Any], accounts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Preflight the entire batch before creating accounts or granting any keys."""
    by_name = {account["name"]: account for account in accounts}
    by_uid = {}
    for account in accounts:
        by_uid.setdefault(account["uid"], []).append(account)
    managed = {user["linux_user"]: user for user in previous.get("users", [])}
    plan = []
    for user in users:
        name, uid = user["linux_user"], user["uid"]
        account = by_name.get(name)
        for collision in by_uid.get(uid, []):
            if collision["name"] != name:
                raise ValueError(f"UID {uid} already belongs to {collision['name']}")
        if account:
            if account["uid"] != uid or account["gid"] != GID or account["home"] != f"/home/{name}":
                raise ValueError(f"Account identity mismatch for {name}; manual migration required")
            if name not in managed and not (user["active"] and user.get("adopt_existing", False)):
                raise ValueError(f"Refusing to adopt unmanaged account {name}")
            if name in managed and managed[name]["uid"] != uid:
                raise ValueError(f"Managed UID changed for {name}")
        plan.append({"user": user, "create": account is None and user["active"]})
    return plan


class Reconciler:
    def __init__(self, root: Path = Path("/"), runner=None, account_reader=None, root_owner_uid: int = 0):
        self.root = root
        self.runner = runner or subprocess.run
        self.account_reader = account_reader or system_accounts
        self.root_owner_uid = root_owner_uid
        self.state_path = root / "var/lib/aws-audit/hpc-users.json"
        self.key_dir = root / "etc/aws-audit/authorized_keys"

    def command(self, *args: str, optional: bool = False) -> str:
        result = self.runner(list(args), check=False, capture_output=True, text=True, timeout=30)
        if result.returncode and not optional:
            raise RuntimeError(f"Command failed: {args[0]} ({result.returncode})")
        return result.stdout

    def atomic_file(self, path: Path, content: bytes, mode: int = 0o600) -> None:
        parent_existed = path.parent.exists()
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError(f"Refusing symlink at managed path {path}")
        if not parent_existed or path.parent == self.key_dir:
            os.chmod(path.parent, 0o755 if path.parent == self.key_dir or mode == 0o644 else 0o700)
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".hpc-")
        try:
            with os.fdopen(fd, "wb") as handle:
                os.fchmod(handle.fileno(), mode)
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def previous(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {"users": []}
        return json.loads(self.state_path.read_text())

    def revoke(self, user: dict[str, Any], accounts: dict[str, dict[str, Any]], node_role: str) -> None:
        """Only touch a locally recorded/adopted identity with the exact expected UID."""
        name = user["linux_user"]
        account = accounts.get(name)
        uid_owners = [row for row in accounts.values() if row["uid"] == user["uid"]]
        # Process and Slurm cancellation operate on the numeric identity. A shared UID
        # would also terminate an unrelated account, even when this name/UID matches.
        # Validate before touching keys, account attributes, sessions or jobs.
        if account is None:
            if uid_owners:
                raise ValueError(f"Refusing to revoke {name}: UID {user['uid']} belongs to another local account")
        elif (account["uid"] != user["uid"] or account["name"] != name
              or len(uid_owners) != 1 or uid_owners[0]["name"] != name):
            raise ValueError(f"Refusing to revoke {name}: name/UID mismatch or shared UID {user['uid']}")
        self.atomic_file(self.key_dir / name, b"")
        if account is None:
            return
        failures = []
        operations = [("usermod", "--lock", "--expiredate", "1", "--shell", "/usr/sbin/nologin", name)]
        if node_role == "head":
            scancel = shutil.which("scancel") or ("/opt/slurm/bin/scancel" if Path("/opt/slurm/bin/scancel").exists() else None)
            if scancel:
                operations.append((scancel, "--user", name))
            else:
                failures.append("Cannot revoke queued Slurm jobs: scancel is unavailable")
        for operation in operations:
            try:
                self.command(*operation)
            except Exception as exc:
                failures.append(str(exc))
        if shutil.which("loginctl"):
            self.command("loginctl", "terminate-user", name, optional=True)
        self.command("pkill", "-KILL", "-u", str(user["uid"]), optional=True)
        if failures:
            raise RuntimeError("; ".join(failures))

    def fail_closed(self, previous: dict[str, Any], accounts: list[dict[str, Any]], node_role: str) -> None:
        by_name = {account["name"]: account for account in accounts}
        failures = []
        for user in previous.get("users", []):
            try:
                self.revoke(user, by_name, node_role)
            except Exception as exc:
                failures.append(str(exc))
        if failures:
            raise RuntimeError("Failed to revoke some managed accounts: " + "; ".join(failures))

    def install_ssh_policy(self, names: list[str]) -> None:
        path = self.root / "etc/ssh/sshd_config.d/00-aws-audit-hpc-users.conf"
        # Reset Match at the end: the main sshd_config may continue after Include.
        selected = ",".join(sorted(names)) if names else "__aws_audit_no_managed_users__"
        config = (f"Match Group {GROUP} User {selected}\n"
                  f"    AuthorizedKeysFile /etc/aws-audit/authorized_keys/%u\n"
                  "    AuthorizedKeysCommand none\n"
                  "    PasswordAuthentication no\n"
                  "    KbdInteractiveAuthentication no\n"
                  "    AuthenticationMethods publickey\n"
                  "    PubkeyAcceptedAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256\n"
                  "Match all\n")
        original = path.read_bytes() if path.exists() else None
        self.atomic_file(path, config.encode(), 0o644)
        try:
            self.command("/usr/sbin/sshd", "-t")
            self.command("systemctl", "reload", "ssh")
        except Exception:
            if original is None:
                path.unlink(missing_ok=True)
            else:
                self.atomic_file(path, original, 0o644)
            raise

    def verify_ssh_policy(self, name: str) -> None:
        effective = self.command("/usr/sbin/sshd", "-T", "-C", f"user={name},host=localhost,addr=127.0.0.1")
        values = dict(line.split(None, 1) for line in effective.splitlines() if " " in line)
        expected = {"authorizedkeysfile": "/etc/aws-audit/authorized_keys/%u", "authorizedkeyscommand": "none",
                    "passwordauthentication": "no", "kbdinteractiveauthentication": "no", "authenticationmethods": "publickey"}
        if any(values.get(key) != value for key, value in expected.items()):
            raise ValueError(f"Effective sshd policy does not enforce managed-key-only login for {name}")
        if "-cert-" in values.get("pubkeyacceptedalgorithms", ""):
            raise ValueError("Managed users must not bypass their root-owned key file with a global SSH CA")

    def head_limits(self, users: list[dict[str, Any]], limits: dict[str, Any]) -> None:
        if not limits:
            raise ValueError("Head/login limits are required")
        pam = []
        for kind, key in [("nproc", "max_processes"), ("nofile", "max_open_files"), ("maxlogins", "max_logins"),
                          ("cpu", "cpu_time_seconds"), ("fsize", "max_file_size_kib")]:
            # PAM cpu is minutes; fsize is KiB (never a suffix such as 40G).
            value = max(1, (limits[key] + 59) // 60) if kind == "cpu" else limits[key]
            for user in users:
                name = user["linux_user"]
                pam.append(f"{name} hard {kind} {value}\n{name} soft {kind} {value}\n")
        self.atomic_file(self.root / "etc/security/limits.d/95-aws-audit-login-limits.conf", "".join(pam).encode(), 0o644)
        for user in users:
            content = ("[Slice]\nCPUAccounting=yes\nMemoryAccounting=yes\nTasksAccounting=yes\n"
                       f"CPUQuota={limits['cpu_quota']}\nMemoryMax={limits['memory_max']}\nTasksMax={limits['max_processes']}\n")
            self.atomic_file(self.root / f"etc/systemd/system/user-{user['uid']}.slice.d/95-aws-audit-login-limits.conf", content.encode(), 0o644)
        self.command("systemctl", "daemon-reload")
        for user in users:
            unit = f"user-{user['uid']}.slice"
            result = self.runner(["systemctl", "is-active", "--quiet", unit], check=False, capture_output=True, text=True)
            if result.returncode == 0:
                self.command("systemctl", "set-property", unit, f"CPUQuota={limits['cpu_quota']}",
                             f"MemoryMax={limits['memory_max']}", f"TasksMax={limits['max_processes']}")

    @contextmanager
    def shared_home_lock(self, name: str):
        """Serialize each EFS home across nodes using Linux NFSv4 advisory locking."""
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name):
            raise ValueError("Invalid home lock identity")
        home_root = self.root / "home"
        metadata = home_root.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != self.root_owner_uid
                or metadata.st_mode & 0o022):
            raise ValueError("/home must be a root-owned, non-symlink directory without group/other write access")
        lock_dir = home_root / ".aws-audit-hpc-locks"
        try:
            lock_dir.mkdir(mode=0o700)
        except FileExistsError:
            pass
        metadata = lock_dir.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != self.root_owner_uid
                or stat.S_IMODE(metadata.st_mode) != 0o700):
            raise ValueError("EFS home lock directory must be root-owned, non-symlink and mode 0700")
        lock_path = lock_dir / (name + ".lock")
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != self.root_owner_uid
                    or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1):
                raise ValueError("EFS home lock file must be root-owned, regular, not hardlinked and mode 0600")
            deadline = time.monotonic() + HOME_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"Timed out waiting for shared EFS home initialization lock: {name}")
                    time.sleep(0.05)
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def ensure_home(self, user: dict[str, Any], create: bool) -> None:
        """Check/create under the same shared lock; never replace or recursively chown data."""
        name, uid = user["linux_user"], user["uid"]
        with self.shared_home_lock(name):
            home = self.root / "home" / name
            try:
                metadata = home.lstat()
            except FileNotFoundError:
                if not create:
                    return
                home.mkdir(mode=0o700)
                # Other participating nodes cannot inspect this transient root-owned
                # directory until chown completes and the shared lock is released.
                os.chown(home, uid, GID)
                return
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != uid:
                raise ValueError(f"Existing home ownership mismatch for {name}")

    def report_fetch_failure(self) -> None:
        """A control-plane outage never revokes valid access or kills research jobs."""
        success_path = self.root / "var/lib/aws-audit/hpc-last-success.json"
        age = "unknown"
        threshold = 3600
        if success_path.exists():
            last = json.loads(success_path.read_text())
            age = max(0, int(time.time()) - last["completed_epoch"])
            threshold = last.get("staleness_policy", {}).get("warn_after_seconds", 3600)
        state = "STALE" if age == "unknown" or age >= threshold else "FETCH_FAILED"
        print(f"HPC_USERS_{state}: keeping last valid access; last successful sync age={age}s, warning threshold={threshold}s", file=sys.stderr)

    def apply(self, data: dict[str, Any], cluster_name: str, node_role: str,
              accounts: list[dict[str, Any]], group_gid: Any) -> None:
        previous = self.previous()
        users = validate_registry(data, cluster_name)
        if previous.get("cluster_name", cluster_name) != cluster_name:
            raise ValueError("Node is already managed for another cluster")
        validate_transition(previous, data)
        before = {user["linux_user"]: user for user in previous.get("users", [])}
        desired = {user["linux_user"]: user for user in users}
        by_name = {account["name"]: account for account in accounts}
        working = copy.deepcopy(data)
        working["users"] = copy.deepcopy(previous.get("users", []))
        # A verified revocation is independent of enrolling another member. Persist it
        # first, so a later enrollment conflict cannot restore a departed member.
        for index, old in enumerate(working["users"]):
            if not desired[old["linux_user"]]["active"]:
                working["users"][index] = copy.deepcopy(desired[old["linux_user"]])
        if working["users"]:
            self.atomic_file(self.state_path, canonical_bytes(working))
        for old in previous.get("users", []):
            if not desired[old["linux_user"]]["active"]:
                self.revoke(old, by_name, node_role)
        # Invalid identities/new keys never change other members' valid access.
        plan = account_plan(users, previous, accounts)
        if group_gid is not None and group_gid != GID:
            raise ValueError("hpc-users group has unexpected GID")
        if self.command("findmnt", "--noheadings", "--output", "FSTYPE", "--mountpoint", "/home").strip() != "nfs4":
            raise ValueError("Shared EFS /home must be mounted before user reconciliation")
        for item in plan:
            if item["user"]["active"]:
                self.ensure_home(item["user"], create=False)
        if group_gid is None:
            self.command("groupadd", "--gid", str(GID), GROUP)
        created = []
        adopted = []
        reactivated = []
        saved_keys = {}
        ssh_path = self.root / "etc/ssh/sshd_config.d/00-aws-audit-hpc-users.conf"
        original_ssh = ssh_path.read_bytes() if ssh_path.exists() else None
        try:
            for item in plan:
                user = item["user"]
                name = user["linux_user"]
                if not user["active"]:
                    # A fresh node must not recreate an alumni account from shared EFS.
                    self.atomic_file(self.key_dir / name, b"")
                    continue
                if item["create"]:
                    self.command("useradd", "--uid", str(user["uid"]), "--gid", GROUP, "--no-create-home",
                                 "--home-dir", f"/home/{name}", "--shell", "/usr/sbin/nologin", "--password", "*", name)
                    created.append(user)
                elif name not in before:
                    adopted.append(user)
                if name not in before:
                    working["users"].append(dict(user, active=False, public_keys=[]))
                    self.atomic_file(self.state_path, canonical_bytes(working))
                self.ensure_home(user, create=True)
            names = [user["linux_user"] for user in working["users"]]
            self.install_ssh_policy(names)
            for user in users:
                if user["active"]:
                    self.verify_ssh_policy(user["linux_user"])
            if node_role == "head":
                self.head_limits(users, data.get("head_limits", {}))
            # Grant only after every identity, home, SSH policy and head limit passes.
            for user in users:
                if not user["active"]:
                    continue
                name = user["linux_user"]
                key_path = self.key_dir / name
                saved_keys[name] = key_path.read_bytes() if key_path.exists() else None
                if name in before or user in created:
                    if not before.get(name, {}).get("active", False):
                        reactivated.append(user)
                    self.command("usermod", "--expiredate", "", "--shell", "/bin/bash", name)
                # Explicit legacy adoption does not change passwords/expiry/shell.
                self.atomic_file(key_path, ("\n".join(public_key(key) for key in user["public_keys"]) + "\n").encode(), 0o644)
            # Only records actually owned on this host enter local management provenance.
            managed_names = set(names)
            final = dict(data, users=[user for user in users if user["linux_user"] in managed_names])
            self.atomic_file(self.state_path, canonical_bytes(final))
            self.atomic_file(self.root / "var/lib/aws-audit/hpc-last-success.json", canonical_bytes({
                "completed_epoch": int(time.time()), "registry_sha256": digest(canonical_bytes(data)),
                "staleness_policy": data.get("staleness_policy", {"on_fetch_failure": "retain", "warn_after_seconds": 3600})}))
        except Exception:
            # Roll back grants from this attempt; never terminate existing valid users.
            current_accounts = {account["name"]: account for account in self.account_reader()}
            errors = []
            for name, content in saved_keys.items():
                try:
                    if content is None:
                        (self.key_dir / name).unlink(missing_ok=True)
                    else:
                        self.atomic_file(self.key_dir / name, content, 0o644)
                except Exception as exc:
                    errors.append(str(exc))
            for user in {user["linux_user"]: user for user in created + reactivated}.values():
                try:
                    self.revoke(user, current_accounts, node_role)
                except Exception as exc:
                    errors.append(str(exc))
            # Restore legacy adoption to its original SSH behavior; no account lock or kill.
            if original_ssh is None:
                ssh_path.unlink(missing_ok=True)
            else:
                self.atomic_file(ssh_path, original_ssh, 0o644)
            self.command("/usr/sbin/sshd", "-t")
            self.command("systemctl", "reload", "ssh")
            failed = copy.deepcopy(working)
            adopted_names = {user["linux_user"] for user in adopted}
            failed["users"] = [user for user in failed["users"] if user["linux_user"] not in adopted_names]
            for index, user in enumerate(failed["users"]):
                if user["linux_user"] in {row["linux_user"] for row in created + reactivated}:
                    failed["users"][index] = dict(user, active=False, public_keys=[])
            self.atomic_file(self.state_path, canonical_bytes(failed))
            if errors:
                raise RuntimeError("Enrollment rollback requires administrator attention: " + "; ".join(errors))
            raise


def system_accounts() -> list[dict[str, Any]]:
    return [{"name": entry.pw_name, "uid": entry.pw_uid, "gid": entry.pw_gid, "home": entry.pw_dir}
            for entry in pwd.getpwall()]


def get_versioned_object(bucket: str, key: str, destination: Path, version_id: str = "") -> dict[str, Any]:
    command = ["aws", "--cli-connect-timeout", "5", "--cli-read-timeout", "15", "s3api", "get-object", "--bucket", bucket, "--key", key]
    if version_id:
        command += ["--version-id", version_id]
    command.append(str(destination))
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
    metadata = json.loads(result.stdout)
    if not metadata.get("VersionId") or metadata["VersionId"] == "null":
        raise ValueError("HPC registry requires S3 versioning")
    if version_id and metadata["VersionId"] != version_id:
        raise ValueError("S3 returned an unexpected object version")
    return metadata


def fetch_registry(uri: str, cluster_name: str, runtime_path: Path, temporary: Path,
                   expected_revision: str = "") -> dict[str, Any]:
    match = re.fullmatch(r"s3://([^/]+)/(.+)", uri)
    if not match or "${" in uri:
        raise ValueError("Expected a configured S3 current.json URI")
    bucket, key = match.groups()
    get_versioned_object(bucket, key, temporary / "current.json")
    pointer = json.loads((temporary / "current.json").read_text())
    if pointer.get("schema_version") != SCHEMA_VERSION or pointer.get("cluster_name") != cluster_name:
        raise ValueError("Unexpected release pointer")
    if pointer.get("runtime_sha256") != digest(runtime_path.read_bytes()):
        raise ValueError("Runtime release changed; reinstall with hpc sync-users --execute")
    if expected_revision and pointer.get("registry_sha256") != expected_revision:
        raise ValueError("User revision changed while sync was being dispatched")
    manifest_key = pointer.get("registry_key", "")
    prefix = key.rsplit("/", 1)[0] + "/releases/"
    if not manifest_key.startswith(prefix) or not pointer.get("registry_version_id"):
        raise ValueError("Registry must be a version-pinned release in the lifecycle prefix")
    get_versioned_object(bucket, manifest_key, temporary / "users.json", pointer["registry_version_id"])
    content = (temporary / "users.json").read_bytes()
    if digest(content) != pointer.get("registry_sha256"):
        raise ValueError("User registry checksum mismatch")
    data = json.loads(content)
    validate_registry(data, cluster_name)
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-uri", required=True)
    parser.add_argument("--cluster-name", required=True)
    parser.add_argument("--node-role", choices=["head", "compute"], required=True)
    parser.add_argument("--expected-revision", default="")
    parser.add_argument("--revoke-managed", action="store_true", help="Emergency fail-closed path; never reads desired state")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run as root")
    reconciler = Reconciler()
    import signal
    def interrupted(signum, frame):
        raise RuntimeError("HPC user synchronization interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    # A node-local lock prevents a timer and SSM rollout changing account state concurrently.
    lock_path = Path("/run/lock/aws-audit-hpc-users.lock")
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        accounts = system_accounts()
        if args.revoke_managed:
            reconciler.fail_closed(reconciler.previous(), accounts, args.node_role)
            return
        try:
            group_gid = grp.getgrnam(GROUP).gr_gid
        except KeyError:
            group_gid = None
        try:
            with tempfile.TemporaryDirectory(prefix="hpc-users-", dir="/run") as directory:
                data = fetch_registry(args.manifest_uri, args.cluster_name, Path(__file__), Path(directory), args.expected_revision)
            reconciler.apply(data, args.cluster_name, args.node_role, accounts, group_gid)
        except Exception:
            reconciler.report_fetch_failure()
            raise


if __name__ == "__main__":
    main()
