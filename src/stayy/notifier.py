"""Privacy-preserving Bark push notifier with SSRF guards, no-redirect transport, and bounded dedup."""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Fixed sanitized notification copy (zero commands, paths, secrets, screenshots, or approval actions)
SAFE_NOTIFY_TITLE = "Stayy 提醒"
SAFE_NOTIFY_BODY = "电脑端有待查看的确认请求，请打开 Stayy 查看。"


def redact_url(raw_url: str) -> str:
    """Mask device token / path / query segments so URLs never leak to logs or --doctor output."""
    s = (raw_url or "").strip()
    if not s:
        return ""
    try:
        p = urlparse(s)
        host = p.hostname or "unknown"
        port_part = f":{p.port}" if p.port else ""
        return f"{p.scheme or 'https'}://{host}{port_part}/***"
    except Exception:
        return "https://***/***"


def _is_disallowed_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private_host: bool) -> bool:
    # Always block link-local (169.254.0.0/16 cloud metadata), multicast, and unspecified
    if ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
        return True
    if not allow_private_host:
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            return True
    return False


def validate_bark_url(raw_url: str, *, allow_private_host: bool = False) -> tuple[bool, str]:
    """Validate `BARK_PUSH_URL` strictly against HTTPS, non-empty key path, and SSRF IP rules."""
    s = (raw_url or "").strip()
    if not s:
        return False, "未配置 BARK_PUSH_URL"
    try:
        parsed = urlparse(s)
    except Exception:
        return False, "BARK_PUSH_URL 格式无效"

    if parsed.scheme.lower() != "https":
        return False, "BARK_PUSH_URL 必须使用 HTTPS 协议"
    host = (parsed.hostname or "").strip()
    if not host:
        return False, "BARK_PUSH_URL 缺少有效主机名"
    if host.lower() in {"localhost", "metadata.google.internal"} and not allow_private_host:
        return False, "BARK_PUSH_URL 禁止指向本机或元数据域名"

    port = parsed.port or 443
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return False, f"Bark 主机解析失败 ({redact_url(s)}): {exc}"

    if not infos:
        return False, f"Bark 主机无可用地址 ({redact_url(s)})"

    for _, _, _, _, sockaddr in infos:
        ip_str = str(sockaddr[0]).split("%")[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, "Bark 解析地址无效"
        if _is_disallowed_ip(ip_obj, allow_private_host=allow_private_host):
            return False, f"Bark 目标地址被安全策略拦截 ({redact_url(s)})"

    return True, "ok"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "HTTP redirects are disabled for Bark SSRF protection",
            headers,
            fp,
        )


def post_sanitized_bark_push(
    push_url: str,
    *,
    allow_private_host: bool = False,
    timeout: float = 6.0,
    opener_factory=None,
) -> tuple[bool, str]:
    """Send fixed sanitized notification payload over HTTPS without following HTTP redirects."""
    ok_url, reason = validate_bark_url(push_url, allow_private_host=allow_private_host)
    if not ok_url:
        return False, reason

    payload = {
        "title": SAFE_NOTIFY_TITLE,
        "body": SAFE_NOTIFY_BODY,
        "group": "stayy",
    }
    raw_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        push_url.strip(),
        data=raw_body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "Stayy-Notifier/0.1",
        },
    )
    opener = opener_factory() if opener_factory is not None else urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(req, timeout=timeout) as resp:
            code = getattr(resp, "status", 200)
            if 200 <= int(code) < 300:
                return True, f"已通过 {redact_url(push_url)} 发送提醒"
            return False, f"Bark 返回非成功状态 HTTP {code}"
    except Exception as exc:
        # Scrub original push_url from any exception text before logging/returning!
        err_str = str(exc).replace(push_url.strip(), redact_url(push_url))
        return False, f"Bark 推送失败 ({redact_url(push_url)}): {err_str}"


class BarkNotifier:
    """Rate-limited, bounded-TTL event-instance notifier with cooldown coalescing."""

    def __init__(
        self,
        push_url: str = "",
        *,
        allow_private_host: bool = False,
        cooldown_seconds: float = 30.0,
        event_ttl_seconds: float = 6 * 3600.0,
        sender_fn=post_sanitized_bark_push,
    ) -> None:
        self.push_url = (push_url or "").strip()
        self.allow_private_host = bool(allow_private_host)
        self.cooldown_seconds = max(1.0, float(cooldown_seconds))
        self.event_ttl_seconds = max(60.0, float(event_ttl_seconds))
        self._sender_fn = sender_fn
        self._lock = threading.Lock()
        self._seen_events: OrderedDict[str, float] = OrderedDict()
        self._last_sent_mono: float = 0.0
        self._pending_coalesced: bool = False

    @property
    def enabled(self) -> bool:
        return bool(self.push_url)

    def _prune_locked(self, now: float) -> None:
        cutoff = now - self.event_ttl_seconds
        expired = [k for k, ts in self._seen_events.items() if ts < cutoff]
        for k in expired:
            self._seen_events.pop(k, None)
        while len(self._seen_events) > 512:
            self._seen_events.popitem(last=False)

    def notify_for_events(self, event_keys: list[str], *, now_mono: float | None = None) -> tuple[bool, str]:
        """Notify if any unseen event_key is present, coalescing bursts inside cooldown."""
        if not self.enabled:
            return False, "disabled"

        now = time.monotonic() if now_mono is None else float(now_mono)
        with self._lock:
            self._prune_locked(now)
            has_new = False
            for k in event_keys:
                clean_k = (k or "").strip()
                if clean_k and clean_k not in self._seen_events:
                    self._seen_events[clean_k] = now
                    has_new = True

            if has_new:
                self._pending_coalesced = True

            if not self._pending_coalesced:
                return False, "no_new_event"

            if self._last_sent_mono > 0.0 and (now - self._last_sent_mono) < self.cooldown_seconds:
                return False, "coalesced_in_cooldown"

            self._pending_coalesced = False
            self._last_sent_mono = now

        ok, detail = self._sender_fn(self.push_url, allow_private_host=self.allow_private_host)
        if not ok:
            logger.warning("%s", detail)
        return ok, detail
