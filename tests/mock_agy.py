"""Mock `agy --input-format stream-json --output-format stream-json` process for testing."""

from __future__ import annotations

import json
import os
import sys
import time
import uuid


def main() -> None:
    conversation_id = ""
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg == "--conversation" and i + 1 < len(args):
            conversation_id = args[i + 1]
    if not conversation_id:
        conversation_id = f"mock-conv-{uuid.uuid4().hex[:8]}"

    init_event = {
        "event": "init",
        "conversation_id": conversation_id,
        "init": {
            "cwd": os.getcwd(),
            "tools": ["run_command", "read_file", "write_to_file"],
            "permission_mode": "always-proceed",
        },
    }
    sys.stdout.write(json.dumps(init_event, ensure_ascii=False) + "\n")
    sys.stdout.flush()

    history: list[str] = []
    num_turns = 0

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        content = msg.get("message", {}).get("content", "")
        num_turns += 1
        history.append(content)

        active_model = os.environ.get("AGY_ACTIVE_MODEL", "")
        if active_model.startswith("exhausted-"):
            res = {
                "event": "result",
                "result": {
                    "conversation_id": conversation_id,
                    "status": "ERROR",
                    "response": "",
                    "error": f"429 RESOURCE_EXHAUSTED: quota exceeded for {active_model}",
                    "duration_seconds": 0.02,
                    "num_turns": num_turns,
                },
            }
        elif content == "__TRIGGER_ERROR__":
            res = {
                "event": "result",
                "result": {
                    "conversation_id": conversation_id,
                    "status": "ERROR",
                    "response": "",
                    "error": "simulated failure",
                    "duration_seconds": 0.05,
                    "num_turns": num_turns,
                },
            }
        elif content == "__LONG_REPLY__":
            long_text = "\n\n".join(f"段落 {i}: " + ("测试内容" * 20) for i in range(1, 8))
            res = {
                "event": "result",
                "result": {
                    "conversation_id": conversation_id,
                    "status": "SUCCESS",
                    "response": long_text,
                    "duration_seconds": 0.1,
                    "num_turns": num_turns,
                },
            }
        elif "__SLOW_STREAM__" in content:
            sys.stdout.write(
                json.dumps(
                    {
                        "event": "step_update",
                        "step_update": {
                            "conversation_id": conversation_id,
                            "step_type": "agent_response",
                            "state": "ACTIVE",
                            "text_delta": "前半段流式输出...",
                        },
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            sys.stdout.flush()
            time.sleep(0.65)
            sys.stdout.write(
                json.dumps(
                    {
                        "event": "step_update",
                        "step_update": {
                            "conversation_id": conversation_id,
                            "step_type": "agent_response",
                            "state": "ACTIVE",
                            "text_delta": "后半段圆满结束！",
                        },
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            sys.stdout.flush()
            res = {
                "event": "result",
                "result": {
                    "conversation_id": conversation_id,
                    "status": "SUCCESS",
                    "response": "前半段流式输出...后半段圆满结束！",
                    "duration_seconds": 0.7,
                    "num_turns": num_turns,
                },
            }
        elif "__TOOL_STEP__" in content:
            sys.stdout.write(
                json.dumps(
                    {
                        "event": "step_update",
                        "step_update": {
                            "conversation_id": conversation_id,
                            "step_type": "tool",
                            "state": "ACTIVE",
                            "tool_name": "edit_file",
                        },
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            sys.stdout.flush()
            html_out = "```html\n<h1>Hello Canvas</h1>\n```"
            sys.stdout.write(
                json.dumps(
                    {
                        "event": "step_update",
                        "step_update": {
                            "conversation_id": conversation_id,
                            "step_type": "agent_response",
                            "state": "ACTIVE",
                            "text_delta": html_out,
                        },
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            sys.stdout.flush()
            res = {
                "event": "result",
                "result": {
                    "conversation_id": conversation_id,
                    "status": "SUCCESS",
                    "response": html_out,
                    "duration_seconds": 0.2,
                    "num_turns": num_turns,
                },
            }
        else:
            reply = f"[turn={num_turns} cwd={os.path.basename(os.getcwd())}] 收到: {content} | 历史条数={len(history)}"
            mid = max(1, len(reply) // 2)
            for delta_part in (reply[:mid], reply[mid:]):
                delta_ev = {
                    "event": "step_update",
                    "step_update": {
                        "conversation_id": conversation_id,
                        "step_type": "agent_response",
                        "state": "ACTIVE",
                        "text_delta": delta_part,
                    },
                }
                sys.stdout.write(json.dumps(delta_ev, ensure_ascii=False) + "\n")
                sys.stdout.flush()
            res = {
                "event": "result",
                "result": {
                    "conversation_id": conversation_id,
                    "status": "SUCCESS",
                    "response": reply,
                    "duration_seconds": 0.05,
                    "num_turns": num_turns,
                },
            }

        sys.stdout.write(json.dumps(res, ensure_ascii=False) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
