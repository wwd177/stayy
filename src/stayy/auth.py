"""Unified authentication, epoch revocation, pairing codes, media tickets, and admin ACL helpers for Stayy."""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import logging
import os
import secrets
import subprocess
import sys
import threading
import time
import uuid
from collections import OrderedDict
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


def atomic_update_env_vars(env_path: Path, updates: dict[str, str]) -> None:
    """Atomically upsert key=value entries in `env_path` using temp-file + `os.replace`."""
    env_path.parent.mkdir(parents=True, exist_ok=True)
    raw = env_path.read_text(encoding="utf-8") if env_path.is_file() else ""
    lines = raw.splitlines()
    remaining = dict(updates)

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in remaining:
            lines[idx] = f"{key}={remaining.pop(key)}"

    for key, val in remaining.items():
        lines.append(f"{key}={val}")

    content = "\n".join(lines) + "\n"
    tmp_path = env_path.with_name(f".{env_path.name}.{secrets.token_hex(6)}.tmp")
    try:
        with tmp_path.open("w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp_path, env_path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def atomic_write_env_token(env_path: Path, new_token: str) -> None:
    """Atomically persist `WEB_ACCESS_TOKEN=<new_token>` to `env_path` using temp-file + `os.replace`."""
    atomic_update_env_vars(env_path, {"WEB_ACCESS_TOKEN": new_token})


def load_or_create_host_id(runtime_dir: Path) -> str:
    """Persist and return a unique random `host_id` identifying this Stayy host."""
    runtime_dir.mkdir(parents=True, exist_ok=True)
    host_file = runtime_dir / "host_id"
    if host_file.is_file():
        existing = host_file.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    new_id = str(uuid.uuid4())
    tmp = host_file.with_name(f".host_id.{secrets.token_hex(4)}.tmp")
    try:
        tmp.write_text(new_id + "\n", encoding="utf-8")
        os.replace(tmp, host_file)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
    return new_id


def restrict_file_to_current_user(path: Path) -> tuple[bool, str]:
    """Restrict `path` ACL to the current Windows user only (`icacls`), or `0o600` on POSIX."""
    if sys.platform != "win32":
        try:
            path.chmod(0o600)
            return True, "chmod 0600"
        except OSError as exc:
            return False, str(exc)

    user_name = getpass.getuser()
    domain = os.environ.get("USERDOMAIN", "")
    principal = f"{domain}\\{user_name}" if domain else user_name
    try:
        res = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{principal}:F"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            creationflags=CREATE_NO_WINDOW,
        )
        if res.returncode == 0:
            return True, principal
        # Retry with bare username if domain prefix failed on local account
        res2 = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user_name}:F"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            creationflags=CREATE_NO_WINDOW,
        )
        if res2.returncode == 0:
            return True, user_name
        return False, (res2.stderr or res.stderr or res2.stdout).strip()
    except Exception as exc:
        return False, str(exc)


def restrict_directory_to_current_user(path: Path) -> tuple[bool, str]:
    """Restrict directory `path` ACL to the current Windows user only (or `0o700` on POSIX)."""
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        try:
            path.chmod(0o700)
            return True, "chmod 0700"
        except OSError as exc:
            return False, str(exc)

    user_name = getpass.getuser()
    domain = os.environ.get("USERDOMAIN", "")
    principal = f"{domain}\\{user_name}" if domain else user_name
    for cand in ([principal, user_name] if domain else [user_name]):
        try:
            res = subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{cand}:(OI)(CI)F"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=8,
                creationflags=CREATE_NO_WINDOW,
            )
            if res.returncode == 0:
                return True, cand
        except Exception:
            pass
    return False, "directory icacls failed"


def write_admin_state(runtime_dir: Path, port: int, admin_token: str, pid: int) -> Path:
    """Persist loopback-only admin API coordinates with strict pre-write ACL restriction."""
    restrict_directory_to_current_user(runtime_dir)
    admin_file = runtime_dir / "admin.json"
    if admin_file.exists():
        try:
            admin_file.unlink()
        except OSError:
            pass
    payload = json.dumps(
        {"port": int(port), "admin_token": admin_token, "pid": int(pid), "service": "stayy"},
        ensure_ascii=False,
        indent=2,
    )
    tmp = admin_file.with_name(f".admin.{secrets.token_hex(4)}.tmp")
    # Create empty file inside ACL-locked runtime_dir and restrict its ACL BEFORE writing secret!
    tmp.write_text("", encoding="utf-8")
    restrict_file_to_current_user(tmp)
    tmp.write_text(payload + "\n", encoding="utf-8")
    os.replace(tmp, admin_file)
    ok_acl, info = restrict_file_to_current_user(admin_file)
    if not ok_acl:
        logger.warning("Failed to restrict ACL on admin.json (%s): %s", admin_file, info)
    return admin_file


def cleanup_admin_state(admin_file: Path | None) -> None:
    if admin_file is None:
        return
    try:
        admin_file.unlink(missing_ok=True)
    except OSError:
        pass


class AuthManager:
    """Centralized thread-safe authentication, epoch revocation, pairing codes, and media tickets."""

    def __init__(
        self,
        access_token: str,
        *,
        runtime_dir: Path | None = None,
        host_id: str | None = None,
        env_path: Path | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self.access_token = (access_token or "").strip()
        self.auth_epoch: int = 1
        self.env_path = env_path
        self.runtime_dir = runtime_dir
        self.host_id = host_id or (
            load_or_create_host_id(runtime_dir) if runtime_dir is not None else str(uuid.uuid4())
        )
        self._failed_auth: dict[str, list[float]] = {}
        self._pairing_codes: OrderedDict[str, float] = OrderedDict()

    def _signing_key(self, epoch: int) -> bytes:
        material = f"{self.host_id}|{epoch}|{self.access_token}".encode("utf-8")
        return hashlib.sha256(material).digest()

    def is_ip_locked(self, ip: str) -> bool:
        with self._lock:
            now = time.monotonic()
            attempts = [t for t in self._failed_auth.get(ip, []) if now - t < 60.0]
            if attempts:
                self._failed_auth[ip] = attempts
            else:
                self._failed_auth.pop(ip, None)
            return len(attempts) >= 8

    def record_auth_failure(self, ip: str) -> None:
        with self._lock:
            now = time.monotonic()
            if len(self._failed_auth) >= 512 and ip not in self._failed_auth:
                stale_keys = [
                    k
                    for k, ts_list in list(self._failed_auth.items())
                    if not ts_list or now - ts_list[-1] >= 60.0
                ]
                for k in stale_keys:
                    self._failed_auth.pop(k, None)
                if len(self._failed_auth) >= 512:
                    oldest_key = next(iter(self._failed_auth))
                    self._failed_auth.pop(oldest_key, None)
            arr = [t for t in self._failed_auth.get(ip, []) if now - t < 60.0]
            arr.append(now)
            self._failed_auth[ip] = arr

    def current_epoch(self) -> int:
        with self._lock:
            return self.auth_epoch

    def is_epoch_active(self, epoch: int) -> bool:
        with self._lock:
            return epoch > 0 and epoch == self.auth_epoch

    def issue_pairing_code(self, ttl_sec: float = 300.0) -> str:
        """Issue a short-lived single-use pairing code for QR/onboarding exchange."""
        code = secrets.token_urlsafe(12)
        now = time.monotonic()
        with self._lock:
            expired = [k for k, exp in self._pairing_codes.items() if exp <= now]
            for k in expired:
                self._pairing_codes.pop(k, None)
            while len(self._pairing_codes) >= 16:
                self._pairing_codes.popitem(last=False)
            self._pairing_codes[code] = now + max(15.0, float(ttl_sec))
        return code

    def _sign_token(self, prefix: str, subject: str, epoch: int, ttl_sec: float) -> str:
        exp = int(time.time()) + max(15, int(ttl_sec))
        nonce = secrets.token_urlsafe(10)
        body = f"{prefix}.{epoch}.{exp}.{subject}.{nonce}"
        mac = hmac.new(self._signing_key(epoch), body.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
        return f"{body}.{mac}"

    def _verify_signed_token(self, raw: str, expected_prefix: str, expected_subject: str) -> tuple[bool, int]:
        parts = (raw or "").strip().split(".")
        if len(parts) != 6:
            return False, 0
        prefix, epoch_s, exp_s, subject, nonce, mac_hex = parts
        if prefix != expected_prefix or not nonce:
            return False, 0
        if expected_subject and not hmac.compare_digest(subject, expected_subject):
            return False, 0
        try:
            epoch = int(epoch_s)
            exp = int(exp_s)
        except ValueError:
            return False, 0
        if epoch != self.auth_epoch or epoch <= 0:
            return False, 0
        if exp < int(time.time()):
            return False, 0
        body = f"{prefix}.{epoch}.{exp}.{subject}.{nonce}"
        expected_mac = hmac.new(
            self._signing_key(epoch), body.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:32]
        if not hmac.compare_digest(mac_hex, expected_mac):
            return False, 0
        return True, epoch

    def issue_session_token(self, ttl_sec: float = 86400.0 * 30) -> str:
        with self._lock:
            return self._sign_token("s1", "sess", self.auth_epoch, ttl_sec)

    def issue_media_ticket(self, media_id: str, ttl_sec: float = 120.0) -> str:
        with self._lock:
            return self._sign_token("m1", (media_id or "").strip(), self.auth_epoch, ttl_sec)

    def verify_media_ticket(self, ticket: str, media_id: str) -> bool:
        clean_id = (media_id or "").strip()
        if not clean_id:
            return False
        with self._lock:
            ok, _ = self._verify_signed_token(ticket, "m1", clean_id)
            return ok

    def exchange_pairing_code(
        self, code: str, ip: str, *, session_ttl_sec: float = 86400.0 * 30
    ) -> tuple[bool, str, int]:
        if self.is_ip_locked(ip):
            return False, "", 0
        cand = (code or "").strip()
        if not cand:
            self.record_auth_failure(ip)
            return False, "", 0

        now = time.monotonic()
        matched_key: str | None = None
        with self._lock:
            for k, exp in list(self._pairing_codes.items()):
                if exp <= now:
                    self._pairing_codes.pop(k, None)
                    continue
                if hmac.compare_digest(cand, k):
                    matched_key = k
            if matched_key is None:
                self.record_auth_failure(ip)
                return False, "", 0
            self._pairing_codes.pop(matched_key, None)
            sess_tok = self.issue_session_token(ttl_sec=session_ttl_sec)
            return True, sess_tok, self.auth_epoch

    def verify_credential(
        self,
        raw_credential: str,
        ip: str,
        *,
        allow_master: bool = True,
        record_failure: bool = True,
    ) -> tuple[bool, int]:
        if self.is_ip_locked(ip):
            return False, 0
        cand = (raw_credential or "").strip()
        if not cand:
            if record_failure:
                self.record_auth_failure(ip)
            return False, 0

        with self._lock:
            ok_sess, ep = self._verify_signed_token(cand, "s1", "sess")
            if ok_sess:
                return True, ep
            if allow_master and self.access_token and hmac.compare_digest(cand, self.access_token):
                return True, self.auth_epoch

        if record_failure:
            self.record_auth_failure(ip)
        return False, 0

    def revoke_and_rotate(self, env_path: Path | None = None) -> tuple[bool, str, int]:
        """Atomically persist a newly rotated `WEB_ACCESS_TOKEN` and increment `auth_epoch`.

        If persisting to `.env` fails, abort WITHOUT incrementing `auth_epoch` so a process
        restart can never silently resurrect the revoked token.
        """
        new_token = secrets.token_urlsafe(24)
        target_env = env_path if env_path is not None else self.env_path
        with self._lock:
            if target_env is not None:
                try:
                    atomic_write_env_token(target_env, new_token)
                except Exception as exc:
                    return False, f"原子写入新密钥失败，已保留原状态：{exc}", self.auth_epoch
            self.access_token = new_token
            self.auth_epoch += 1
            self._pairing_codes.clear()
            return True, new_token, self.auth_epoch
