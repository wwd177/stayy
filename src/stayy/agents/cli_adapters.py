"""Read-only-default headless CLI adapters for DeepSeek Harness, WorkBuddy, and GitHub Copilot CLI."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from .base import (
    CREATE_NO_WINDOW,
    AgentRunResult,
    AgentTurnCallbacks,
    is_path_safe_no_reparse,
    kill_pid_tree_sync,
)

logger = logging.getLogger(__name__)
STREAM_LIMIT = 4 * 1024 * 1024


def discover_node_executable(local_app_data: Path | None = None) -> Path | None:
    """Locate a safe Node.js runtime bundled with local AI apps or on PATH."""
    la = local_app_data or Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    candidates = [
        la / "Programs" / "DeepSeek Harness" / "resources" / "runtime" / "primary-runtime" / "dependencies" / "node" / "bin" / "node.exe",
        Path.home() / ".workbuddy" / "binaries" / "node" / "versions" / "22.22.2-6" / "node.exe",
        Path(os.getenv("ProgramFiles") or r"C:\Program Files") / "nodejs" / "node.exe",
    ]
    # Also scan ~/.workbuddy/binaries/node/versions/*/node.exe dynamically
    wb_node_root = Path.home() / ".workbuddy" / "binaries" / "node" / "versions"
    if wb_node_root.is_dir():
        for exe in sorted(wb_node_root.glob("*/node.exe"), reverse=True):
            candidates.insert(1, exe)
    which_node = shutil.which("node")
    if which_node:
        candidates.append(Path(which_node))

    for cand in candidates:
        if cand.is_file() and is_path_safe_no_reparse(cand):
            return cand.resolve()
    return None


def discover_dsh_installation(local_app_data: Path | None = None) -> dict[str, str]:
    """Detect DeepSeek Harness direct Electron Node entrypoint cleanly."""
    la = local_app_data or Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    base_dir = la / "Programs" / "DeepSeek Harness"
    exe = base_dir / "DeepSeek Harness.exe"
    asar = base_dir / "resources" / "app.asar"
    if exe.is_file() and asar.is_file() and is_path_safe_no_reparse(exe) and is_path_safe_no_reparse(asar):
        cli_js = asar / "dsh" / "node_modules" / "@deepseek-ai" / "dsh-desktop-host" / "lib" / "cli.js"
        return {
            "mode": "electron_node",
            "exe": str(exe.resolve()),
            "cli_js": str(cli_js),
        }
    return {}


def discover_workbuddy_installation(local_app_data: Path | None = None) -> dict[str, str]:
    """Detect WorkBuddy CLI script (`codebuddy-lite-wb.mjs`) and Node runtime cleanly."""
    la = local_app_data or Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    node_exe = discover_node_executable(la)
    cli_mjs = la / "Programs" / "WorkBuddy" / "resources" / "app.asar.unpacked" / "cli" / "dist" / "codebuddy-lite-wb.mjs"
    if node_exe and cli_mjs.is_file() and is_path_safe_no_reparse(cli_mjs):
        product_json = cli_mjs.parent.parent / "product.json"
        return {
            "node_exe": str(node_exe),
            "cli_mjs": str(cli_mjs.resolve()),
            "product_json": str(product_json.resolve()) if product_json.is_file() and is_path_safe_no_reparse(product_json) else "",
        }
    return {}


def discover_copilot_installation(local_app_data: Path | None = None) -> dict[str, str]:
    """Detect GitHub Copilot CLI executable cleanly."""
    la = local_app_data or Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    sdk_root = la / "copilot-sdk" / "cli"
    candidates: list[Path] = []
    if sdk_root.is_dir():
        candidates.extend(sorted(sdk_root.glob("*/copilot.exe"), reverse=True))
    which_cop = shutil.which("copilot")
    if which_cop:
        candidates.append(Path(which_cop))
    for cand in candidates:
        if cand.is_file() and cand.suffix.lower() in {".exe", ""} and is_path_safe_no_reparse(cand):
            return {"exe": str(cand.resolve())}
    return {}


def build_dsh_command(
    install_info: dict[str, str],
    *,
    session_id: str = "",
    allow_write: bool = False,
) -> tuple[list[str], dict[str, str]]:
    """Build safe argument list & env for DeepSeek Harness headless CLI (default read-only, approval never)."""
    perm_mode = "workspace-write" if allow_write else "read-only"
    cli_args = [
        "--profile",
        "headless",
        "--json",
        "--permission-mode",
        perm_mode,
        "--approval-policy",
        "never",
    ]
    if session_id:
        cli_args.extend(["--session-id", session_id])
    cli_args.append("-")

    extra_env: dict[str, str] = {}
    if install_info.get("mode") == "electron_node":
        cmd = [install_info["exe"], "--expose-internals", install_info["cli_js"], *cli_args]
        extra_env["ELECTRON_RUN_AS_NODE"] = "1"
    else:
        cmd = [install_info["exe"], *cli_args]
    return cmd, extra_env


def build_workbuddy_command(
    install_info: dict[str, str],
    *,
    session_id: str = "",
    model: str = "",
    allow_write: bool = False,
) -> tuple[list[str], dict[str, str]]:
    """Build safe argument list & env for WorkBuddy headless CLI (strictly read-only & no `-y` by default)."""
    tools_arg = "default" if allow_write else "Read,Glob,Grep,LS"
    perm_mode = "acceptEdits" if allow_write else "dontAsk"
    cmd = [
        install_info["node_exe"],
        install_info["cli_mjs"],
        "-p",
        "--output-format",
        "stream-json",
        "--include-partial-messages",
        "--permission-mode",
        perm_mode,
        "--tools",
        tools_arg,
    ]
    if session_id:
        cmd.extend(["--resume", session_id])
    if model:
        cmd.extend(["--model", model])

    extra_env: dict[str, str] = {"CODEBUDDY_SKIP_GIT_BASH_CHECK": "1"}
    if install_info.get("product_json"):
        extra_env["ACC_PRODUCT_CONFIG_PATH"] = install_info["product_json"]
    return cmd, extra_env


def build_copilot_command(
    install_info: dict[str, str],
    *,
    prompt: str,
    session_id: str = "",
    model: str = "",
    allow_write: bool = False,
) -> tuple[list[str], dict[str, str]]:
    """Build safe argument list for GitHub Copilot CLI (non-interactive, read-only tool denials by default)."""
    safe_prompt = f" {prompt}" if prompt.lstrip().startswith("-") else prompt
    cmd = [
        install_info["exe"],
        "-p",
        safe_prompt,
        "--output-format",
        "json",
        "--no-ask-user",
    ]
    if not allow_write:
        cmd.extend(["--deny-tool", "write", "--deny-tool", "shell"])
    if session_id:
        cmd.append(f"--resume={session_id}")
    if model:
        cmd.extend(["--model", model])
    return cmd, {}


def _resolve_cwd(workspace: str | Path) -> Path:
    try:
        p = Path(workspace).expanduser()
        if p.is_dir():
            return p.resolve()
    except Exception:
        pass
    return Path.home()


async def run_cli_agent_turn(
    *,
    store: str,
    install_info: dict[str, str],
    prompt: str,
    workspace: str | Path,
    session_id: str = "",
    model: str = "",
    allow_write: bool = False,
    extra_env: dict[str, str] | None = None,
    timeout_sec: float = 180.0,
    cancel_event: asyncio.Event | None = None,
    callbacks: AgentTurnCallbacks | None = None,
) -> AgentRunResult:
    """Execute a single streaming headless CLI turn safely via `create_subprocess_exec`."""
    cb = callbacks or AgentTurnCallbacks()
    cwd = _resolve_cwd(workspace)

    if store == "dsh":
        cmd, base_env = build_dsh_command(install_info, session_id=session_id, allow_write=allow_write)
        stdin_payload = prompt.encode("utf-8")
    elif store == "workbuddy":
        cmd, base_env = build_workbuddy_command(
            install_info, session_id=session_id, model=model, allow_write=allow_write
        )
        stdin_payload = prompt.encode("utf-8")
    elif store == "copilot":
        if len(prompt or "") > 24000:
            return AgentRunResult(ok=False, error="Copilot CLI 单次指令超过 24000 字命令行安全上限，请精简后再试")
        cmd, base_env = build_copilot_command(
            install_info, prompt=prompt, session_id=session_id, model=model, allow_write=allow_write
        )
        stdin_payload = None
    else:
        return AgentRunResult(ok=False, error=f"不支持的原生 CLI 类型：{store}")

    if cancel_event is not None and cancel_event.is_set():
        return AgentRunResult(ok=False, aborted=True, error="任务已取消")

    env = os.environ.copy()
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.update(base_env)
    if extra_env:
        env.update(extra_env)

    extra_kwargs: dict[str, Any] = {}
    if sys.platform == "win32":
        extra_kwargs["creationflags"] = CREATE_NO_WINDOW

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_payload is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd),
            env=env,
            limit=STREAM_LIMIT,
            **extra_kwargs,
        )
    except OSError as exc:
        return AgentRunResult(ok=False, error=f"启动 {store} 失败：{exc}")
    if cb.on_proc_started:
        await cb.on_proc_started(proc)

    if stdin_payload is not None and proc.stdin is not None:
        try:
            proc.stdin.write(stdin_payload)
            await proc.stdin.drain()
            proc.stdin.close()
        except Exception:
            pass

    collected_text: list[str] = []
    collected_thought: list[str] = []
    final_sid = session_id
    fatal_err = ""
    plain_lines: list[str] = []
    stderr_lines: list[str] = []

    async def _drain_stderr() -> None:
        assert proc.stderr is not None
        while True:
            try:
                raw = await proc.stderr.readline()
            except ValueError:
                break
            if not raw:
                break
            s = raw.decode("utf-8", errors="replace").rstrip()
            if s:
                stderr_lines.append(s)
                if len(stderr_lines) > 40:
                    stderr_lines.pop(0)

    async def _watch_cancel() -> None:
        if cancel_event is None:
            return
        await cancel_event.wait()
        if proc.returncode is None and proc.pid:
            await asyncio.to_thread(kill_pid_tree_sync, proc.pid)

    async def _read_stdout() -> None:
        nonlocal final_sid, fatal_err
        assert proc.stdout is not None
        wb_snapshot = ""
        while True:
            try:
                raw = await proc.stdout.readline()
            except ValueError:
                fatal_err = f"{store} 单行输出超过 4MB 安全上限，已终止"
                if proc.returncode is None and proc.pid:
                    await asyncio.to_thread(kill_pid_tree_sync, proc.pid)
                break
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                plain_lines.append(line)
                continue
            if not isinstance(evt, dict):
                continue

            if store == "dsh":
                sid = str(evt.get("sessionId") or "")
                if sid and sid != final_sid:
                    final_sid = sid
                    if cb.on_session:
                        await cb.on_session(sid)
                et = str(evt.get("type") or "")
                if et in {"text", "text_delta", "delta"}:
                    txt = str(evt.get("delta") or evt.get("text") or "")
                    if txt:
                        collected_text.append(txt)
                        if cb.on_delta:
                            await cb.on_delta(txt)
                elif et in {"thinking", "reasoning_delta", "thought"}:
                    th = str(evt.get("delta") or evt.get("text") or "")
                    if th:
                        collected_thought.append(th)
                        if cb.on_thought:
                            await cb.on_thought(th)
                elif et in {"tool_call", "tool_start"} or evt.get("phase") == "tool_start":
                    if collected_text and cb.on_demote_to_thought:
                        await cb.on_demote_to_thought()
                        collected_thought.extend(collected_text)
                        collected_text.clear()
                    if cb.on_tool:
                        await cb.on_tool(str(evt.get("toolName") or evt.get("name") or "dsh_tool"), "")
                elif et == "final":
                    reason = evt.get("reason") or {}
                    if isinstance(reason, dict) and reason.get("kind") == "error":
                        err_obj = reason.get("error") or {}
                        fatal_err = str((err_obj.get("message") if isinstance(err_obj, dict) else err_obj) or "DeepSeek Harness 执行失败")
                    elif evt.get("text") and not collected_text:
                        t_final = str(evt["text"])
                        collected_text.append(t_final)
                        if cb.on_delta:
                            await cb.on_delta(t_final)
                elif et == "status":
                    reason = evt.get("reason") or {}
                    if isinstance(reason, dict) and reason.get("kind") == "error":
                        err_obj = reason.get("error") or {}
                        fatal_err = str((err_obj.get("message") if isinstance(err_obj, dict) else err_obj) or fatal_err)

            elif store == "workbuddy":
                sid = str(evt.get("session_id") or evt.get("sessionId") or "")
                if sid and sid != final_sid:
                    final_sid = sid
                    if cb.on_session:
                        await cb.on_session(sid)
                et = str(evt.get("type") or "")
                if et == "stream_event" and isinstance(evt.get("event"), dict):
                    inner = evt["event"]
                    it = inner.get("type")
                    if it == "content_block_delta" and isinstance(inner.get("delta"), dict):
                        dl = inner["delta"]
                        if dl.get("type") == "text_delta" and dl.get("text"):
                            txt = str(dl["text"])
                            collected_text.append(txt)
                            if cb.on_delta:
                                await cb.on_delta(txt)
                        elif dl.get("type") == "thinking_delta" and dl.get("thinking"):
                            th = str(dl["thinking"])
                            collected_thought.append(th)
                            if cb.on_thought:
                                await cb.on_thought(th)
                    elif it == "content_block_start" and isinstance(inner.get("content_block"), dict):
                        if inner["content_block"].get("type") == "tool_use":
                            if collected_text and cb.on_demote_to_thought:
                                await cb.on_demote_to_thought()
                                collected_thought.extend(collected_text)
                                collected_text.clear()
                            if cb.on_tool:
                                await cb.on_tool(str(inner["content_block"].get("name") or "tool"), "")
                elif et == "assistant" and isinstance(evt.get("message"), dict):
                    blocks = evt["message"].get("content") or []
                    snap_parts: list[str] = []
                    for b in blocks:
                        if isinstance(b, dict) and b.get("type") == "text" and b.get("text"):
                            snap_parts.append(str(b["text"]))
                    snap_str = "".join(snap_parts)
                    if snap_str:
                        wb_snapshot = snap_str
                elif et == "result":
                    if evt.get("is_error"):
                        errs = evt.get("errors") or []
                        fatal_err = "; ".join(str(x) for x in errs) if errs else str(evt.get("result") or "WorkBuddy 返回错误")
                    elif not collected_text:
                        fin = str(evt.get("result") or wb_snapshot or "")
                        if fin:
                            collected_text.append(fin)
                            if cb.on_delta:
                                await cb.on_delta(fin)

            elif store == "copilot":
                sid = str(evt.get("sessionId") or evt.get("session_id") or "")
                if sid and sid != final_sid:
                    final_sid = sid
                    if cb.on_session:
                        await cb.on_session(sid)
                txt = str(evt.get("response") or evt.get("content") or evt.get("text") or evt.get("delta") or "")
                if txt:
                    collected_text.append(txt)
                    if cb.on_delta:
                        await cb.on_delta(txt)
                if evt.get("error"):
                    fatal_err = str(evt["error"])

        if store == "workbuddy" and not collected_text and wb_snapshot and not fatal_err:
            collected_text.append(wb_snapshot)
            if cb.on_delta:
                await cb.on_delta(wb_snapshot)

    stderr_task = asyncio.create_task(_drain_stderr())
    cancel_task = asyncio.create_task(_watch_cancel()) if cancel_event is not None else None
    rc: int | None = None
    timed_out = False
    try:
        await asyncio.wait_for(asyncio.gather(_read_stdout(), proc.wait()), timeout=timeout_sec)
        rc = proc.returncode
    except asyncio.TimeoutError:
        timed_out = True
        if proc.pid:
            await asyncio.to_thread(kill_pid_tree_sync, proc.pid)
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except Exception:
            pass
    finally:
        if cancel_task is not None:
            cancel_task.cancel()
        stderr_task.cancel()
        await asyncio.gather(
            *[t for t in (cancel_task, stderr_task) if t is not None],
            return_exceptions=True,
        )
        if proc.returncode is None:
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except Exception:
                pass
        tr = getattr(proc, "_transport", None)
        if tr is not None:
            try:
                if hasattr(tr, "is_closing") and not tr.is_closing():
                    tr.close()
            except Exception:
                pass
        await asyncio.sleep(0)
        if cb.on_proc_finished:
            await cb.on_proc_finished(proc)

    if cancel_event is not None and cancel_event.is_set():
        return AgentRunResult(ok=False, session_id=final_sid, aborted=True, error="已中断当前任务")

    if timed_out:
        return AgentRunResult(ok=False, session_id=final_sid, error=f"{store} 执行超过 {int(timeout_sec)}s 已安全终止")

    if plain_lines and not collected_text and not fatal_err and rc == 0:
        joined = "\n".join(plain_lines)
        collected_text.append(joined)
        if cb.on_delta:
            await cb.on_delta(joined)

    text_out = "".join(collected_text).strip()
    thought_out = "".join(collected_thought).strip()
    if fatal_err and not text_out:
        return AgentRunResult(ok=False, session_id=final_sid, error=fatal_err)
    if rc not in (0, None) and not text_out:
        err_detail = (
            "\n".join(stderr_lines).strip()
            or "\n".join(plain_lines[-8:]).strip()
            or f"{store} CLI 退出码: {rc}"
        )
        return AgentRunResult(ok=False, session_id=final_sid, error=err_detail)

    return AgentRunResult(
        ok=True,
        session_id=final_sid,
        text=text_out or "(已完成，无文本输出)",
        thought=thought_out,
    )
