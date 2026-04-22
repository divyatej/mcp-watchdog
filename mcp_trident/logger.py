"""
Structured JSONL audit logger for mcp-trident.

Each line is a self-contained JSON event.  This makes the log trivially
queryable with jq, importable into any SIEM, and parseable by the report
generator.
"""

import json
import time
from pathlib import Path

from .rules import Verdict


class AuditLogger:
    def __init__(self, log_path: str = "mcp_trident.jsonl"):
        self._path = Path(log_path)
        self._buffer: list[dict] = []

    # ------------------------------------------------------------------

    def log_message(self, session_id: str, direction: str, msg: dict):
        method = msg.get("method", "")
        if not method:
            return  # skip responses / acks

        event = {
            "ts": self._ts(),
            "session": session_id,
            "type": "message",
            "direction": direction,
            "method": method,
        }

        # Capture tool name + truncated arguments for tool calls
        if method == "tools/call":
            params = msg.get("params", {})
            event["tool"] = params.get("name", "")
            event["args"] = self._truncate_args(params.get("arguments", {}))

        self._buffer.append(event)

    def log_verdict(self, session_id: str, tool_name: str, arguments: dict, verdict: Verdict):
        if verdict.action == "allow":
            return  # don't clutter the log with every allowed call

        event = {
            "ts": self._ts(),
            "session": session_id,
            "type": "verdict",
            "tool": tool_name,
            "action": verdict.action,
            "rule": verdict.rule_name,
            "reason": verdict.reason,
            "args": self._truncate_args(arguments),
        }
        self._buffer.append(event)
        self._write(event)

    def flush(self):
        with self._path.open("a") as f:
            for event in self._buffer:
                if event.get("type") != "verdict":
                    f.write(json.dumps(event) + "\n")
        self._buffer.clear()

    # ------------------------------------------------------------------

    def _write(self, event: dict):
        with self._path.open("a") as f:
            f.write(json.dumps(event) + "\n")

    def _ts(self) -> str:
        t = time.time()
        ms = int((t % 1) * 1000)
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{ms:03d}Z"

    def _truncate_args(self, args: dict, max_len: int = 500) -> dict:
        out = {}
        for k, v in args.items():
            if isinstance(v, (dict, list)):
                s = json.dumps(v, ensure_ascii=False)
            else:
                s = str(v)
            out[k] = s[:max_len] + "…" if len(s) > max_len else s
        return out


# ---------------------------------------------------------------------------
# Log reader (used by report generator)
# ---------------------------------------------------------------------------

def load_log(log_path: str) -> list[dict]:
    path = Path(log_path)
    if not path.exists():
        return []
    events = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events