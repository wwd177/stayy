"""Opt-in zero-trust encrypted tunnel beacon & static iOS Standalone PWA publisher for Stayy.

Multi-user safety guarantees:
- Disabled by default (`BEACON_ENABLED=false`) and NEVER blindly infers `origin` to push to upstream author repos.
- Requires explicit `BEACON_GIT_REMOTE` (a git remote name or HTTPS remote URL owned by the user).
- Embeds `host_id` and `nonce` inside the encrypted envelope and reads back the published HTTPS `beacon.json`
  after pushing so "git push succeeded / GitHub Pages published / branch not hijacked by another host" are strictly
  verified before presenting a permanent beacon QR code.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
PBKDF2_ITERATIONS = 100_000
BEACON_DOMAIN_TAG = b"STAYY-BEACON-V1"
_BEACON_PUBLISH_LOCK = threading.Lock()

# Protect upstream project repositories against accidental force-push from cloned forks without explicit configuration
PROTECTED_UPSTREAM_REPOS = frozenset(
    {"wwd177/antigravity-remote-assistant", "wwd177/stayy"}
)

GITHUB_REMOTE_RE = re.compile(
    r"^(?:https?://(?:www\.)?github\.com/|ssh://git@github\.com/|git@github\.com:)"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _derive_keys(access_token: str, salt: bytes) -> tuple[bytes, bytes]:
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        access_token.strip().encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=64,
    )
    return dk[:32], dk[32:]


def _xor_keystream(enc_key: bytes, nonce: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    blocks = (len(data) + 31) // 32
    for idx in range(blocks):
        ks = hmac.new(enc_key, nonce + idx.to_bytes(4, "big"), hashlib.sha256).digest()
        start = idx * 32
        end = min(start + 32, len(data))
        for j in range(start, end):
            out[j] = data[j] ^ ks[j - start]
    return bytes(out)


def encrypt_beacon_payload(payload: dict[str, Any], access_token: str) -> dict[str, Any]:
    """Encrypt connection endpoints so public `beacon.json` leaks zero IP, URL, or host_id metadata."""
    if not access_token or not access_token.strip():
        raise ValueError("access_token must not be empty")
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    enc_key, mac_key = _derive_keys(access_token, salt)

    pt = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ct = _xor_keystream(enc_key, nonce, pt)
    mac = hmac.new(mac_key, BEACON_DOMAIN_TAG + salt + nonce + ct, hashlib.sha256).digest()

    return {
        "v": 1,
        "updated_ms": int(time.time() * 1000),
        "iter": PBKDF2_ITERATIONS,
        "salt": _b64u_encode(salt),
        "nonce": _b64u_encode(nonce),
        "ct": _b64u_encode(ct),
        "mac": _b64u_encode(mac),
    }


def decrypt_beacon_payload(
    envelope: dict[str, Any],
    access_token: str,
    *,
    max_age_sec: float | None = None,
) -> dict[str, Any]:
    """Verify MAC, decrypt `beacon.json` envelope, and optionally enforce inner timestamp freshness."""
    if int(envelope.get("v") or 0) != 1:
        raise ValueError("Unsupported beacon version")
    salt = _b64u_decode(str(envelope["salt"]))
    nonce = _b64u_decode(str(envelope["nonce"]))
    ct = _b64u_decode(str(envelope["ct"]))
    expected_mac = _b64u_decode(str(envelope["mac"]))

    enc_key, mac_key = _derive_keys(access_token, salt)
    actual_mac = hmac.new(mac_key, BEACON_DOMAIN_TAG + salt + nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(actual_mac, expected_mac):
        raise ValueError("Beacon MAC verification failed (invalid token)")

    pt = _xor_keystream(enc_key, nonce, ct)
    parsed = json.loads(pt.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("Decrypted beacon payload is not an object")
    if max_age_sec is not None:
        inner_ts = int(parsed.get("ts") or 0)
        now_ms = int(time.time() * 1000)
        if inner_ts <= 0 or (now_ms - inner_ts) > int(max_age_sec * 1000) or (inner_ts - now_ms) > 300_000:
            raise ValueError("Beacon payload timestamp expired or invalid")
    return parsed


_FORBIDDEN_BEACON_BRANCHES = frozenset(
    {"main", "master", "trunk", "develop", "dev", "head", "prod", "production", "release"}
)


def _normalize_safe_beacon_branch(branch: str) -> str | None:
    cand = (branch or "").strip()
    if not cand or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in cand):
        return None
    if cand.lower().startswith("refs/heads/"):
        cand = cand[len("refs/heads/"):]
    elif cand.lower().startswith("refs/"):
        return None
    if not cand or cand.startswith(("-", "/")) or cand.endswith(("/", ".", ".lock")):
        return None
    if ".." in cand or "@{" in cand or "\\" in cand or "//" in cand:
        return None
    for bad in ("~", "^", ":", "?", "*", "["):
        if bad in cand:
            return None
    if cand.lower() in _FORBIDDEN_BEACON_BRANCHES:
        return None
    return cand


def _apply_git_push_rewrites(project_dir: Path, raw_url: str) -> str:
    extra = {"creationflags": CREATE_NO_WINDOW} if sys.platform == "win32" else {}
    cwd_target = str(project_dir) if project_dir.is_dir() else None
    try:
        res = subprocess.run(
            ["git", "config", "--get-regexp", r"^url\..*\.(pushinsteadof|insteadof)$"],
            cwd=cwd_target,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=4,
            **extra,
        )
        if res.returncode != 0 or not res.stdout:
            return raw_url
    except Exception:
        return raw_url

    best_push: tuple[int, str, str] | None = None
    best_any: tuple[int, str, str] | None = None
    for raw_ln in res.stdout.splitlines():
        ln = raw_ln.strip()
        if not ln or " " not in ln:
            continue
        key, _, prefix = ln.partition(" ")
        prefix = prefix.strip()
        if not prefix or not raw_url.startswith(prefix):
            continue
        k_low = key.lower()
        if k_low.startswith("url.") and k_low.endswith(".pushinsteadof"):
            repl = key[4 : -len(".pushinsteadof")]
            if repl and (best_push is None or len(prefix) > best_push[0]):
                best_push = (len(prefix), prefix, repl)
        elif k_low.startswith("url.") and k_low.endswith(".insteadof"):
            repl = key[4 : -len(".insteadof")]
            if repl and (best_any is None or len(prefix) > best_any[0]):
                best_any = (len(prefix), prefix, repl)
    chosen = best_push or best_any
    if chosen is not None:
        _, pref, repl = chosen
        return repl + raw_url[len(pref):]
    return raw_url


def resolve_explicit_beacon_target(
    project_dir: Path,
    *,
    beacon_enabled: bool,
    explicit_remote: str,
    allow_upstream_protected: bool = False,
) -> tuple[str, str, str, str] | None:
    """Resolve explicit user-owned GitHub Pages beacon target.

    NEVER infers `origin` implicitly when `beacon_enabled` is False or `explicit_remote` is blank.
    Always inspects git push URL (`--push`), rejects inline credentials and protected upstream repos.
    Returns `(remote_url, owner, repo, pages_url)` or None.
    """
    if not beacon_enabled:
        return None
    clean_remote = (explicit_remote or "").strip()
    if not clean_remote:
        return None

    remote_url = ""
    is_literal_url = False
    if clean_remote.startswith(("https://", "http://", "git@", "ssh://", "file://")) or Path(clean_remote).exists():
        remote_url = clean_remote
        is_literal_url = True
    else:
        extra = {"creationflags": CREATE_NO_WINDOW} if sys.platform == "win32" else {}
        try:
            res = subprocess.run(
                ["git", "remote", "get-url", "--push", "--all", clean_remote],
                cwd=str(project_dir),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=4,
                **extra,
            )
            if res.returncode != 0 or not (res.stdout or "").strip():
                logger.warning("Refusing beacon remote without verifiable push URL: %s", clean_remote)
                return None
            lines_out = [ln.strip() for ln in (res.stdout or "").splitlines() if ln.strip()]
            if len(lines_out) == 1:
                remote_url = lines_out[0]
            elif len(lines_out) > 1:
                logger.warning("Refusing ambiguous multi-pushurl git remote %s", clean_remote)
                return None
        except Exception:
            return None

    if not remote_url:
        return None
    if is_literal_url:
        remote_url = _apply_git_push_rewrites(project_dir, remote_url)

    try:
        if remote_url.startswith(("http://", "https://")):
            parsed = urlsplit(remote_url)
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                logger.warning("Refusing beacon URL containing inline credentials or query/fragment")
                return None
        elif remote_url.startswith("ssh://"):
            parsed = urlsplit(remote_url)
            if parsed.password or (parsed.username and parsed.username != "git"):
                logger.warning("Refusing ssh beacon URL with non-standard credentials")
                return None
    except ValueError:
        logger.warning("Refusing malformed beacon URL")
        return None

    m = GITHUB_REMOTE_RE.match(remote_url)
    if not m:
        return None
    owner = m.group("owner")
    repo = m.group("repo")
    slug = f"{owner}/{repo}".lower()
    if slug in PROTECTED_UPSTREAM_REPOS and not allow_upstream_protected:
        logger.warning("Refusing to publish beacon onto protected upstream repo %s", slug)
        return None
    pages_url = f"https://{owner.lower()}.github.io/{repo}/"
    return (remote_url, owner, repo, pages_url)


def detect_candidate_beacon_remote(project_dir: Path) -> tuple[str, str, str, str] | None:
    """Inspect git `origin` as a *candidate* beacon target for UI preview ONLY.

    Always refuses `PROTECTED_UPSTREAM_REPOS`; NEVER enables `BEACON_ENABLED` implicitly.
    """
    return resolve_explicit_beacon_target(
        project_dir,
        beacon_enabled=True,
        explicit_remote="origin",
        allow_upstream_protected=False,
    )


def save_beacon_state(runtime_dir: Path, state: dict[str, Any]) -> Path:
    """Persist beacon publish/verification progress into `.runtime/beacon_state.json`."""
    from .auth import restrict_directory_to_current_user, restrict_file_to_current_user

    restrict_directory_to_current_user(runtime_dir)
    state_file = runtime_dir / "beacon_state.json"
    tmp = state_file.with_name(f".beacon_state.{secrets.token_hex(4)}.tmp")
    tmp.write_text("", encoding="utf-8")
    restrict_file_to_current_user(tmp)
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, state_file)
    restrict_file_to_current_user(state_file)
    return state_file


def load_beacon_state(runtime_dir: Path) -> dict[str, Any]:
    """Load persisted `.runtime/beacon_state.json` if present, returning empty dict otherwise."""
    state_file = runtime_dir / "beacon_state.json"
    if not state_file.is_file():
        return {}
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


STATIC_PWA_SW_JS = """\
const SCOPE_SLUG = new URL(self.registration.scope).pathname.replace(/[^a-zA-Z0-9_-]/g, '_');
const CACHE_PREFIX = 'stayy-ios-shell-' + SCOPE_SLUG + '-';
const CACHE_NAME = CACHE_PREFIX + 'v3';
const REQUIRED_SHELL = ['./', './index.html'];
const OPTIONAL_ASSETS = ['./apple-touch-icon.png', './icon-192.png', './icon-512.png', './manifest.json'];

async function cacheUrlStrict(cache, assetUrl) {
  const res = await fetch(assetUrl, { cache: 'no-cache' });
  if (!res || !res.ok) throw new Error('SHELL_PRECACHE_FAILED:' + assetUrl);
  await cache.put(assetUrl, res);
}

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      await Promise.all(REQUIRED_SHELL.map((u) => cacheUrlStrict(cache, u)));
      await Promise.allSettled(OPTIONAL_ASSETS.map((u) => cacheUrlStrict(cache, u)));
      await self.skipWaiting();
    })
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => k.startsWith(CACHE_PREFIX) && k !== CACHE_NAME)
          .map((k) => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

function fetchWithTimeout(req, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  return fetch(req, { cache: 'no-store', signal: ctrl.signal }).finally(() => clearTimeout(timer));
}

self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin || url.pathname.endsWith('/beacon.json')) {
    return;
  }
  const isNavShell = e.request.mode === 'navigate'
    || url.pathname.endsWith('/')
    || url.pathname.endsWith('/index.html');

  if (isNavShell) {
    e.respondWith(
      fetchWithTimeout(e.request, 3200)
        .then((res) => {
          if (!res || !res.ok) throw new Error('HTTP_' + (res ? res.status : 0));
          const clone = res.clone();
          e.waitUntil(caches.open(CACHE_NAME).then((c) => c.put(e.request, clone)).catch(() => {}));
          return res;
        })
        .catch(() =>
          caches.open(CACHE_NAME)
            .then((c) => c.match(e.request).then((m) => m || c.match('./index.html')))
            .then((m) => m || caches.match('./index.html'))
        )
    );
    return;
  }

  e.respondWith(
    caches.open(CACHE_NAME).then((cache) =>
      cache.match(e.request).then((cached) => {
        const netUpdate = fetchWithTimeout(e.request, 3500)
          .then((res) => {
            if (res && res.ok) {
              return cache.put(e.request, res.clone()).catch(() => {}).then(() => res);
            }
            return cached || res;
          })
          .catch(() => cached);
        if (cached) {
          e.waitUntil(netUpdate);
          return cached;
        }
        return netUpdate;
      })
    )
  );
});
"""


def build_static_pwa_bundle(
    project_dir: Path,
    stage_dir: Path,
    *,
    owner: str,
    repo: str,
    access_token: str,
    tunnel_url: str,
    lan_url: str,
    host_id: str,
    nonce: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Assemble the static iOS Standalone PWA shell + encrypted `beacon.json` into `stage_dir`."""
    stage_dir.mkdir(parents=True, exist_ok=True)
    src_html = project_dir / "src" / "stayy" / "static" / "index.html"
    assets_dir = project_dir / "assets"

    html_text = src_html.read_text(encoding="utf-8")
    repo_slug = f"{owner}/{repo}"
    html_text = html_text.replace(
        '<html lang="zh-CN">',
        f'<html lang="zh-CN" data-beacon-repo="{repo_slug}">',
        1,
    )
    (stage_dir / "index.html").write_text(html_text, encoding="utf-8")
    (stage_dir / ".nojekyll").write_text("", encoding="utf-8")
    (stage_dir / "sw.js").write_text(STATIC_PWA_SW_JS, encoding="utf-8")

    # Never put credentials into manifest start_url
    manifest = {
        "id": "./",
        "name": "Stayy",
        "short_name": "Stayy",
        "description": "Local-first AI Coding & Precision PC Remote Hub",
        "start_url": "./",
        "scope": "./",
        "display": "standalone",
        "background_color": "#000000",
        "theme_color": "#000000",
        "orientation": "portrait-primary",
        "icons": [
            {"src": "./apple-touch-icon.png", "sizes": "180x180", "type": "image/png", "purpose": "any maskable"},
            {"src": "./icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
            {"src": "./icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
        ],
    }
    (stage_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    for icon_name in ("apple-touch-icon.png", "icon-192.png", "icon-512.png"):
        src_icon = assets_dir / icon_name
        if not src_icon.is_file() and icon_name == "apple-touch-icon.png":
            src_icon = assets_dir / "icon-192.png"
        if src_icon.is_file():
            shutil.copy2(src_icon, stage_dir / icon_name)

    pub_nonce = nonce or secrets.token_urlsafe(12)
    beacon_env = encrypt_beacon_payload(
        {
            "host_id": host_id,
            "nonce": pub_nonce,
            "tunnel_url": tunnel_url.rstrip("/"),
            "lan_url": lan_url.rstrip("/"),
            "ts": int(time.time() * 1000),
        },
        access_token,
    )
    (stage_dir / "beacon.json").write_text(
        json.dumps(beacon_env, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return beacon_env, pub_nonce


def verify_published_beacon(
    pages_url: str,
    access_token: str,
    expected_host_id: str,
    expected_nonce: str,
    *,
    timeout: float = 10.0,
    ignore_nonce: bool = False,
) -> tuple[bool, str, str]:
    """Read back deployed `beacon.json` over HTTP(S) to verify live publish & host identity.

    Returns `(ok, state_code, human_detail)` where `state_code` is one of:
    - `'verified'`
    - `'pages_not_ready'`
    - `'host_conflict'`
    - `'decrypt_failed'`
    """
    url = pages_url.rstrip("/") + "/beacon.json?_t=" + str(int(time.time()))
    try:
        req = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return False, "pages_not_ready", f"Pages 返回状态 {resp.status}"
            env_data = json.loads(resp.read(65536).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 403}:
            return False, "auth_denied", f"GitHub Pages 访问受限（HTTP {exc.code}，请确认仓库公开且 Pages 已启用）"
        return False, "pages_not_ready", f"GitHub Pages 尚未生效（HTTP {exc.code}）"
    except Exception as exc:
        return False, "pages_not_ready", f"无法读回在线信标：{exc}"

    try:
        parsed = decrypt_beacon_payload(
            env_data,
            access_token,
            max_age_sec=(None if ignore_nonce else 600),
        )
    except Exception as exc:
        # Either CDN still serves an older key version or another host pushed with a different secret
        return False, "decrypt_failed", f"目标信标无法使用当前密钥解密（可能为旧密钥缓存或另一主机）：{exc}"

    if parsed.get("host_id") != expected_host_id:
        return False, "host_conflict", "目标分支当前绑定着另一台主机的 host_id，已拒绝复用"
    if not ignore_nonce and parsed.get("nonce") != expected_nonce:
        return False, "pages_not_ready", "GitHub Pages CDN 仍在返回旧版信标，等待生效中"
    return True, "verified", "已核验 GitHub Pages 在线信标归属本机"


def publish_ios_pwa_and_beacon(
    project_dir: Path,
    *,
    access_token: str,
    tunnel_url: str,
    lan_url: str,
    host_id: str,
    beacon_enabled: bool,
    explicit_remote: str,
    beacon_branch: str = "gh-pages",
    verify_live: bool = True,
    runtime_dir: Path | None = None,
    out_meta: dict[str, Any] | None = None,
) -> tuple[bool, str, str]:
    """Build and push static PWA + encrypted `beacon.json` ONLY when explicitly enabled for a user-owned remote.

    Returns `(ok, state_code, info_or_url)`.
    """
    clean_branch = _normalize_safe_beacon_branch(beacon_branch)
    if not clean_branch:
        return (False, "invalid_branch", "拒绝将信标强推至受保护源码分支、标签或非法分支名")
    gh_info = resolve_explicit_beacon_target(
        project_dir,
        beacon_enabled=beacon_enabled,
        explicit_remote=explicit_remote,
    )
    if gh_info is None:
        return (False, "disabled", "未显式启用用户自建 GitHub Pages 信标（BEACON_ENABLED=false）")
    remote_url, owner, repo, pages_url = gh_info

    stage_dir = project_dir / ".gh_pages_stage"
    extra = {"creationflags": CREATE_NO_WINDOW} if sys.platform == "win32" else {}

    def _record_state(state_code: str, nonce_val: str = "", pushed: bool = False) -> None:
        snap = {
            "state": state_code,
            "target_remote": remote_url,
            "owner": owner,
            "repo": repo,
            "branch": clean_branch,
            "pages_url": pages_url,
            "host_id": host_id,
            "pending_nonce": nonce_val,
            "pushed": pushed,
            "updated_ms": int(time.time() * 1000),
        }
        if out_meta is not None:
            out_meta.update(snap)
        if runtime_dir is not None:
            try:
                save_beacon_state(runtime_dir, snap)
            except Exception as exc:
                logger.debug("save_beacon_state warning: %s", exc)

    with _BEACON_PUBLISH_LOCK:
        if verify_live:
            pre_ok, pre_state, pre_detail = verify_published_beacon(
                pages_url, access_token, host_id, expected_nonce="__precheck__", timeout=4.0
            )
            if not pre_ok and pre_state == "host_conflict":
                _record_state("host_conflict")
                return (False, "host_conflict", pre_detail)
        try:
            if stage_dir.exists():
                shutil.rmtree(stage_dir, ignore_errors=True)
            stage_dir.mkdir(parents=True, exist_ok=True)

            _, pub_nonce = build_static_pwa_bundle(
                project_dir,
                stage_dir,
                owner=owner,
                repo=repo,
                access_token=access_token,
                tunnel_url=tunnel_url,
                lan_url=lan_url,
                host_id=host_id,
            )

            def _git(*args: str, timeout: int = 25) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["git", *args],
                    cwd=str(stage_dir),
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    **extra,
                )

            init_res = _git("init", "-b", clean_branch)
            if init_res.returncode != 0:
                _record_state("push_failed")
                return (
                    False,
                    "push_failed",
                    f"初始化信标仓库失败：{(init_res.stderr or init_res.stdout).strip()[:120]}",
                )
            _git("config", "user.name", "Stayy Beacon")
            _git("config", "user.email", "beacon@stayy.local")
            _git("remote", "add", "_beacon_target", remote_url)
            re_checked = resolve_explicit_beacon_target(
                stage_dir,
                beacon_enabled=True,
                explicit_remote="_beacon_target",
            )
            if (
                re_checked is None
                or (re_checked[1].lower(), re_checked[2].lower()) != (owner.lower(), repo.lower())
            ):
                _record_state("invalid_remote")
                return (False, "invalid_remote", "最终 Git push 目标校验未通过（已拦截受保护上游或 rewrite 规则）")
            add_res = _git(
                "add",
                "--",
                "index.html",
                ".nojekyll",
                "sw.js",
                "manifest.json",
                "beacon.json",
                "apple-touch-icon.png",
                "icon-192.png",
                "icon-512.png",
            )
            if add_res.returncode != 0:
                _record_state("push_failed")
                return (
                    False,
                    "push_failed",
                    f"暂存信标文件失败：{(add_res.stderr or add_res.stdout).strip()[:120]}",
                )

            c_res = _git("commit", "-m", "chore(pwa): sync encrypted Stayy beacon")
            if c_res.returncode != 0:
                _record_state("push_failed")
                return (
                    False,
                    "push_failed",
                    f"生成信标提交失败：{(c_res.stderr or c_res.stdout).strip()[:120]}",
                )

            _record_state("pushing", pub_nonce, pushed=False)
            p_res = _git("push", "-f", "_beacon_target", f"HEAD:refs/heads/{clean_branch}", timeout=30)
            if p_res.returncode != 0 and sys.platform == "win32":
                # Transient Windows schannel retry
                p_res = _git("-c", "http.sslBackend=openssl", "push", "-f", "_beacon_target", f"HEAD:refs/heads/{clean_branch}", timeout=30)
            if p_res.returncode != 0:
                _record_state("push_failed", pub_nonce, pushed=False)
                return (
                    False,
                    "push_failed",
                    f"推送 {clean_branch} 失败：{(p_res.stderr or p_res.stdout).strip()[:140]}",
                )

            if verify_live:
                ok_live, state_code, detail = verify_published_beacon(
                    pages_url, access_token, host_id, pub_nonce
                )
                if not ok_live:
                    _record_state(state_code, pub_nonce, pushed=True)
                    return (False, state_code, detail)

            _record_state("verified", pub_nonce, pushed=True)
            return (True, "verified", pages_url)
        except Exception as exc:
            _record_state("push_failed")
            return (False, "push_failed", f"同步永久入口异常：{exc}")
