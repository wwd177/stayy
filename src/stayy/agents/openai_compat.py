"""Endpoint-pinned OpenAI-compatible SSE client & ACL-protected session persistence (Doubao Ark / DeepSeek / Ollama)."""

from __future__ import annotations

import asyncio
import http.client
import ipaddress
import json
import logging
import re
import socket
import ssl
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..auth import restrict_directory_to_current_user, restrict_file_to_current_user
from .base import AgentRunResult, AgentTurnCallbacks

logger = logging.getLogger(__name__)


def _is_loopback_host(host: str) -> bool:
    h = (host or "").strip().lower()
    if h in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def validate_llm_endpoint_url(
    raw_url: str,
    *,
    allow_local_ports: tuple[int, ...] = (11434, 1234),
) -> tuple[bool, str, list[str], bool]:
    """Resolve and validate an OpenAI-compatible base URL strictly against SSRF rules.

    - Non-loopback endpoints MUST use HTTPS and resolve solely to public non-private/non-link-local IPs.
    - Loopback endpoints (`127.0.0.1`, `localhost`, `::1`) are allowed ONLY when their explicit port
      is in `allow_local_ports` (e.g. Ollama `11434` / LM Studio `1234`), preventing probing Stayy
      admin/gateway ports.
    Returns `(ok, detail, pinned_ips, is_loopback)`.
    """
    s = (raw_url or "").strip().rstrip("/")
    if not s:
        return False, "未配置 API 接口地址", [], False
    try:
        parsed = urlparse(s)
    except Exception:
        return False, "API 接口地址格式无效", [], False

    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").strip()
    if not host:
        return False, "API 接口缺少主机名", [], False

    is_lb = _is_loopback_host(host)
    if is_lb:
        if scheme not in {"http", "https"}:
            return False, "本机模型端口仅支持 http/https", [], True
        port = parsed.port or (443 if scheme == "https" else 80)
        if port not in set(allow_local_ports):
            return False, f"本机端口 {port} 不在本地 LLM 白名单 {list(allow_local_ports)} 内", [], True
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            return False, f"本机端口解析失败：{exc}", [], True
        ips: list[str] = []
        for _, _, _, _, sockaddr in infos:
            ip_s = str(sockaddr[0]).split("%")[0]
            try:
                if ipaddress.ip_address(ip_s).is_loopback and ip_s not in ips:
                    ips.append(ip_s)
            except ValueError:
                pass
        if not ips:
            return False, "本机回环地址解析失败", [], True
        return True, "ok", ips, True

    if scheme != "https":
        return False, "公网 OpenAI 兼容端点必须使用 HTTPS 协议", [], False
    if host.lower() in {"metadata.google.internal"}:
        return False, "禁止指向元数据主机名", [], False

    port = parsed.port or 443
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return False, f"API 主机解析失败：{exc}", [], False
    if not infos:
        return False, "API 主机无可用 IP", [], False

    pinned: list[str] = []
    for _, _, _, _, sockaddr in infos:
        ip_s = str(sockaddr[0]).split("%")[0]
        try:
            ip_obj = ipaddress.ip_address(ip_s)
        except ValueError:
            return False, "API 解析地址无效", [], False
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return False, f"API 地址 {ip_s} 被 SSRF 安全策略拦截", [], False
        if ip_s not in pinned:
            pinned.append(ip_s)

    return True, "ok", pinned, False


class _PinnedHttpConn(http.client.HTTPConnection):
    def __init__(self, host: str, *, pinned_ips: list[str], port: int, timeout: float = 30.0) -> None:
        self._pinned_ips = pinned_ips
        super().__init__(host, port=port, timeout=timeout)

    def connect(self) -> None:
        last_exc: Exception | None = None
        for ip_addr in self._pinned_ips:
            try:
                self.sock = socket.create_connection((ip_addr, self.port), self.timeout, self.source_address)
                return
            except Exception as exc:
                last_exc = exc
        if last_exc is not None:
            raise last_exc
        raise OSError("No pinned loopback IPs available")


class _PinnedHttpsConn(http.client.HTTPSConnection):
    def __init__(self, host: str, *, pinned_ips: list[str], port: int, timeout: float = 30.0) -> None:
        self._pinned_ips = pinned_ips
        ctx = ssl.create_default_context()
        super().__init__(host, port=port, timeout=timeout, context=ctx)

    def connect(self) -> None:
        last_exc: Exception | None = None
        for ip_addr in self._pinned_ips:
            raw = None
            try:
                raw = socket.create_connection((ip_addr, self.port), self.timeout, self.source_address)
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                return
            except Exception as exc:
                last_exc = exc
                if raw is not None:
                    try:
                        raw.close()
                    except OSError:
                        pass
        if last_exc is not None:
            raise last_exc
        raise OSError("No pinned HTTPS IPs available")


def _safe_session_id(raw: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "_", (raw or "").strip()).strip("_")
    if len(cleaned) < 6:
        prefix = cleaned or "api"
        cleaned = f"{prefix}-{uuid.uuid4().hex[:8]}"
    return cleaned[:80]


def api_sessions_dir(runtime_dir: Path, store: str) -> Path:
    safe_store = re.sub(r"[^A-Za-z0-9_.-]", "_", store or "api")
    d = runtime_dir / "api_sessions" / safe_store
    restrict_directory_to_current_user(d)
    return d


def load_api_session_history(runtime_dir: Path, store: str, session_id: str) -> list[dict[str, Any]]:
    safe_store = re.sub(r"[^A-Za-z0-9_.-]", "_", store or "api")
    fp = runtime_dir / "api_sessions" / safe_store / f"{_safe_session_id(session_id)}.json"
    if not fp.is_file():
        return []
    try:
        data = json.loads(fp.read_text(encoding="utf-8"))
        msgs = data.get("messages") if isinstance(data, dict) else []
        return list(msgs) if isinstance(msgs, list) else []
    except Exception:
        return []


def save_api_session_record(
    runtime_dir: Path,
    store: str,
    session_id: str,
    *,
    title: str,
    workspace: str,
    messages: list[dict[str, Any]],
) -> None:
    sid = _safe_session_id(session_id)
    fp = api_sessions_dir(runtime_dir, store) / f"{sid}.json"
    tmp = fp.with_name(f".{sid}.{uuid.uuid4().hex[:6]}.tmp")
    payload = {
        "session_id": sid,
        "store": store,
        "title": title,
        "workspace": workspace,
        "updated_ms": int(time.time() * 1000),
        "messages": messages[-80:],
    }
    tmp.write_text("", encoding="utf-8")
    restrict_file_to_current_user(tmp)
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(fp)
    restrict_file_to_current_user(fp)


MAX_SSE_LINE_BYTES = 2 * 1024 * 1024
MAX_HTTP_ERROR_BODY_BYTES = 65536


def _extract_non_sse_json_response(
    raw_json_str: str,
    *,
    api_key: str,
    loop: asyncio.AbstractEventLoop,
    out_q: asyncio.Queue[tuple[str, str]],
) -> bool:
    """Handle HTTP 200 JSON responses (error envelope or non-streaming completion)."""
    try:
        obj = json.loads(raw_json_str)
    except json.JSONDecodeError:
        return False
    if not isinstance(obj, dict):
        return False
    if obj.get("error"):
        err_obj = obj["error"]
        msg = (
            err_obj.get("message")
            if isinstance(err_obj, dict)
            else str(err_obj)
        ) or str(obj)
        if api_key:
            msg = str(msg).replace(api_key, "***")
        loop.call_soon_threadsafe(out_q.put_nowait, ("error", f"API 返回错误：{msg}"))
        return True
    choices = obj.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0] if isinstance(choices[0], dict) else {}
        msg_obj = first.get("message") if isinstance(first.get("message"), dict) else {}
        thought = str(msg_obj.get("reasoning_content") or msg_obj.get("reasoning") or "")
        content = str(msg_obj.get("content") or first.get("text") or "")
        if thought:
            loop.call_soon_threadsafe(out_q.put_nowait, ("thought", thought))
        if content:
            loop.call_soon_threadsafe(out_q.put_nowait, ("delta", content))
        loop.call_soon_threadsafe(out_q.put_nowait, ("done", ""))
        return True
    return False


async def run_openai_compat_turn(
    *,
    store: str,
    base_url: str,
    api_key: str,
    model: str,
    prompt: str,
    workspace: str,
    session_id: str = "",
    system_prompt: str = "",
    runtime_dir: Path | None = None,
    allow_local_ports: tuple[int, ...] = (11434, 1234),
    chunk_timeout_sec: float = 30.0,
    total_timeout_sec: float = 180.0,
    cancel_event: asyncio.Event | None = None,
    callbacks: AgentTurnCallbacks | None = None,
) -> AgentRunResult:
    """Stream an OpenAI-compatible SSE completion turn cleanly via endpoint-pinned HTTP(S) transport."""
    cb = callbacks or AgentTurnCallbacks()
    ok_url, reason, pinned_ips, is_lb = await asyncio.to_thread(
        validate_llm_endpoint_url, base_url, allow_local_ports=allow_local_ports
    )
    if not ok_url:
        return AgentRunResult(ok=False, error=reason)
    if not api_key and not is_lb:
        return AgentRunResult(ok=False, error="尚未配置该云端模型的 API Key，请在主机 `.env` 或 `agents.local.json` 中填写")

    sid = _safe_session_id(session_id)
    if sid != session_id and cb.on_session:
        await cb.on_session(sid)

    history: list[dict[str, Any]] = []
    if runtime_dir is not None and session_id:
        history = load_api_session_history(runtime_dir, store, sid)

    api_messages: list[dict[str, str]] = []
    if system_prompt.strip():
        api_messages.append({"role": "system", "content": system_prompt.strip()})
    for m in history[-20:]:
        r = str(m.get("role") or "")
        t = str(m.get("text") or "")
        if r in {"user", "assistant"} and t:
            api_messages.append({"role": r, "content": t})
    api_messages.append({"role": "user", "content": prompt})

    parsed = urlparse(base_url.rstrip("/"))
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    base_path = parsed.path.rstrip("/")
    req_path = f"{base_path}/chat/completions"

    req_body = json.dumps(
        {
            "model": model,
            "messages": api_messages,
            "stream": True,
        },
        ensure_ascii=False,
    ).encode("utf-8")

    headers = {
        "Host": parsed.netloc,
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "text/event-stream",
        "User-Agent": "Stayy-Agent/0.2",
        "Connection": "close",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    loop = asyncio.get_running_loop()
    out_q: asyncio.Queue[tuple[str, str]] = asyncio.Queue()
    conn_lock = threading.Lock()
    active_conn: list[http.client.HTTPConnection | None] = [None]

    def _close_active_conn() -> None:
        with conn_lock:
            c = active_conn[0]
            active_conn[0] = None
        if c is not None:
            try:
                sock = getattr(c, "sock", None)
                if sock is not None:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    sock.close()
            except Exception:
                pass
            try:
                c.close()
            except Exception:
                pass

    def _worker() -> None:
        conn: http.client.HTTPConnection | None = None
        deadline = time.monotonic() + total_timeout_sec
        try:
            conn = (
                _PinnedHttpsConn(host, pinned_ips=pinned_ips, port=port, timeout=chunk_timeout_sec)
                if scheme == "https"
                else _PinnedHttpConn(host, pinned_ips=pinned_ips, port=port, timeout=chunk_timeout_sec)
            )
            with conn_lock:
                if cancel_event is not None and cancel_event.is_set():
                    try:
                        conn.close()
                    except Exception:
                        pass
                    loop.call_soon_threadsafe(out_q.put_nowait, ("aborted", ""))
                    return
                active_conn[0] = conn
            conn.request("POST", req_path, body=req_body, headers=headers)
            resp = conn.getresponse()
            if 300 <= resp.status < 400:
                loop.call_soon_threadsafe(out_q.put_nowait, ("error", f"出于 SSRF 安全限制已禁止 {resp.status} 重定向"))
                return
            if resp.status < 200 or resp.status >= 300:
                err_snippet = resp.read(MAX_HTTP_ERROR_BODY_BYTES).decode("utf-8", errors="replace").strip()
                if len(err_snippet) > 512:
                    err_snippet = err_snippet[:512] + "…"
                if api_key:
                    err_snippet = err_snippet.replace(api_key, "***")
                loop.call_soon_threadsafe(
                    out_q.put_nowait,
                    ("error", f"API 请求失败 (HTTP {resp.status}): {err_snippet or resp.reason}"),
                )
                return

            ctype = (resp.getheader("Content-Type") or "").lower()
            if "application/json" in ctype and "text/event-stream" not in ctype:
                raw_json = resp.read(MAX_HTTP_ERROR_BODY_BYTES).decode("utf-8", errors="replace").strip()
                if _extract_non_sse_json_response(raw_json, api_key=api_key, loop=loop, out_q=out_q):
                    return
                masked = raw_json.replace(api_key, "***") if api_key else raw_json
                loop.call_soon_threadsafe(
                    out_q.put_nowait,
                    ("error", f"API 返回无法解析的 JSON 响应：{masked[:300]}"),
                )
                return

            def _emit_sse_chunk(chunk: dict[str, Any]) -> str:
                if chunk.get("error"):
                    err_obj = chunk["error"]
                    msg = (err_obj.get("message") if isinstance(err_obj, dict) else str(err_obj)) or str(chunk)
                    if api_key:
                        msg = str(msg).replace(api_key, "***")
                    loop.call_soon_threadsafe(out_q.put_nowait, ("error", f"API 流返回错误：{msg}"))
                    return "error"
                choices = chunk.get("choices") or []
                if not choices:
                    return "emitted"
                delta = choices[0].get("delta")
                if not isinstance(delta, dict):
                    msg_obj = choices[0].get("message")
                    delta = msg_obj if isinstance(msg_obj, dict) else {}
                if delta.get("reasoning_content"):
                    loop.call_soon_threadsafe(out_q.put_nowait, ("thought", str(delta["reasoning_content"])))
                if delta.get("content"):
                    loop.call_soon_threadsafe(out_q.put_nowait, ("delta", str(delta["content"])))
                return "emitted"

            def _flush_sse_data(buf: list[str]) -> str:
                if not buf:
                    return "continue"
                payload_s = "\n".join(buf).strip()
                buf.clear()
                if not payload_s:
                    return "continue"
                if payload_s == "[DONE]":
                    return "done"
                try:
                    chunk = json.loads(payload_s)
                except json.JSONDecodeError:
                    return "continue"
                if not isinstance(chunk, dict):
                    return "continue"
                return _emit_sse_chunk(chunk)

            data_buf: list[str] = []
            saw_sse_frame = False
            raw_fallback = bytearray()

            while True:
                if cancel_event is not None and cancel_event.is_set():
                    loop.call_soon_threadsafe(out_q.put_nowait, ("aborted", ""))
                    return
                if time.monotonic() > deadline:
                    loop.call_soon_threadsafe(
                        out_q.put_nowait, ("error", f"API 流式响应超过 {int(total_timeout_sec)}s 总时限，已断开")
                    )
                    return
                raw_line = resp.readline(MAX_SSE_LINE_BYTES)
                if not raw_line:
                    break
                if len(raw_line) >= MAX_SSE_LINE_BYTES and not raw_line.endswith((b"\n", b"\r")):
                    loop.call_soon_threadsafe(
                        out_q.put_nowait,
                        ("error", f"API SSE 单行超过 {MAX_SSE_LINE_BYTES // 1024}KB 安全上限，已断开"),
                    )
                    return

                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                if not line:
                    res_state = _flush_sse_data(data_buf)
                    if res_state == "done":
                        break
                    if res_state == "error":
                        return
                    continue

                if line.startswith(":"):
                    saw_sse_frame = True
                    continue

                if line.startswith("data:"):
                    saw_sse_frame = True
                    part = line[5:]
                    item = part[1:] if part.startswith(" ") else part
                    if not data_buf:
                        stripped_item = item.strip()
                        if stripped_item == "[DONE]":
                            break
                        if stripped_item.startswith("{"):
                            try:
                                chunk = json.loads(stripped_item)
                            except json.JSONDecodeError:
                                chunk = None
                            if isinstance(chunk, dict):
                                if _emit_sse_chunk(chunk) == "error":
                                    return
                                continue
                        data_buf.append(item)
                    else:
                        data_buf.append(item)
                        joined = "\n".join(data_buf).strip()
                        if joined == "[DONE]":
                            data_buf.clear()
                            break
                        if joined.startswith("{") and joined.endswith("}"):
                            try:
                                chunk = json.loads(joined)
                            except json.JSONDecodeError:
                                chunk = None
                            if isinstance(chunk, dict):
                                data_buf.clear()
                                if _emit_sse_chunk(chunk) == "error":
                                    return
                    continue

                if line.startswith(("event:", "id:", "retry:")):
                    saw_sse_frame = True
                    continue

                if not saw_sse_frame and len(raw_fallback) < MAX_HTTP_ERROR_BODY_BYTES:
                    take = min(len(raw_line), MAX_HTTP_ERROR_BODY_BYTES - len(raw_fallback))
                    raw_fallback.extend(raw_line[:take])

            if data_buf:
                if _flush_sse_data(data_buf) == "error":
                    return

            if not saw_sse_frame and raw_fallback:
                fallback_txt = bytes(raw_fallback).decode("utf-8", errors="replace").strip()
                if fallback_txt:
                    if _extract_non_sse_json_response(fallback_txt, api_key=api_key, loop=loop, out_q=out_q):
                        return
                    masked = fallback_txt.replace(api_key, "***") if api_key else fallback_txt
                    loop.call_soon_threadsafe(
                        out_q.put_nowait,
                        ("error", f"API 返回非 SSE 响应：{masked[:300]}"),
                    )
                    return

            loop.call_soon_threadsafe(out_q.put_nowait, ("done", ""))
        except Exception as exc:
            err_txt = str(exc)
            if api_key:
                err_txt = err_txt.replace(api_key, "***")
            loop.call_soon_threadsafe(out_q.put_nowait, ("error", f"API 连接异常：{err_txt}"))
        finally:
            with conn_lock:
                if active_conn[0] is conn:
                    active_conn[0] = None
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    worker_fut = asyncio.to_thread(_worker)
    worker_task = asyncio.create_task(worker_fut)

    collected_text: list[str] = []
    collected_thought: list[str] = []
    final_err = ""
    was_aborted = False

    while True:
        if cancel_event is not None and cancel_event.is_set():
            was_aborted = True
            _close_active_conn()
            break
        try:
            kind, val = await asyncio.wait_for(out_q.get(), timeout=0.25)
        except asyncio.TimeoutError:
            if cancel_event is not None and cancel_event.is_set():
                was_aborted = True
                _close_active_conn()
                break
            if worker_task.done():
                break
            continue
        if kind == "delta":
            collected_text.append(val)
            if cb.on_delta:
                await cb.on_delta(val)
        elif kind == "thought":
            collected_thought.append(val)
            if cb.on_thought:
                await cb.on_thought(val)
        elif kind == "error":
            final_err = val
            break
        elif kind == "aborted":
            was_aborted = True
            break
        elif kind == "done":
            break

    if cancel_event is not None and cancel_event.is_set():
        was_aborted = True
        _close_active_conn()
    if was_aborted:
        try:
            await asyncio.wait_for(asyncio.shield(worker_task), timeout=0.6)
        except Exception:
            pass
    else:
        await asyncio.gather(worker_task, return_exceptions=True)

    if was_aborted:
        return AgentRunResult(ok=False, session_id=sid, aborted=True, error="已中断当前请求")
    if final_err:
        return AgentRunResult(
            ok=False,
            session_id=sid,
            text="".join(collected_text).strip(),
            thought="".join(collected_thought).strip(),
            error=final_err,
        )

    full_text = "".join(collected_text).strip() or "(无文本返回)"
    full_thought = "".join(collected_thought).strip()

    if runtime_dir is not None:
        now_ms = int(time.time() * 1000)
        new_hist = list(history)
        new_hist.append({"role": "user", "text": prompt, "ts": now_ms})
        new_hist.append({"role": "assistant", "text": full_text, "thought": full_thought, "ts": now_ms})
        try:
            title = str(new_hist[0]["text"]).splitlines()[0][:40] if new_hist else model
            save_api_session_record(
                runtime_dir, store, sid, title=title, workspace=workspace, messages=new_hist
            )
        except Exception as exc:
            logger.debug("save_api_session_record failed: %s", exc)

    return AgentRunResult(ok=True, session_id=sid, text=full_text, thought=full_thought)
