"""
mcp-watchdog: stdio proxy that intercepts, audits, and optionally blocks MCP tool calls.

Usage:
    mcp-watchdog -- npx @modelcontextprotocol/server-filesystem /path
    mcp-watchdog --rules rules.yaml -- python my_server.py
"""

import asyncio
import json
import os
import sys

from .logger import AuditLogger
from .rules import RuleEngine


class MCPProxy:
    """
    Transparent stdio proxy.  Sits between an MCP client (Claude Desktop,
    Cursor, etc.) and an MCP server subprocess.  Every JSON-RPC message
    that crosses the boundary is inspected by the rule engine before being
    forwarded (or blocked).
    """

    def __init__(
        self,
        server_cmd: list[str],
        rules_path: str | None = None,
        log_path: str = "mcp_watchdog.jsonl",
        verbose: bool = False,
    ):
        self.server_cmd = server_cmd
        self.logger = AuditLogger(log_path)
        self.rules = RuleEngine(rules_path)
        self.verbose = verbose
        self._proc: asyncio.subprocess.Process | None = None
        self._session_id = os.urandom(4).hex()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self) -> int:
        """Start the proxied server and pipe stdio until it exits."""
        self._proc = await asyncio.create_subprocess_exec(
            *self.server_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Forward stderr from server → our stderr transparently
        asyncio.create_task(self._pipe_stderr())

        # Bidirectional pump
        client_to_server = asyncio.create_task(
            self._pump(
                direction="client→server",
                read_fn=self._read_stdin,
                write_fn=self._write_server,
                intercept=True,
            )
        )
        server_to_client = asyncio.create_task(
            self._pump(
                direction="server→client",
                read_fn=self._read_server,
                write_fn=self._write_stdout,
                intercept=False,
            )
        )

        done, pending = await asyncio.wait(
            [client_to_server, server_to_client],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()

        self.logger.flush()
        return self._proc.returncode or 0

    # ------------------------------------------------------------------
    # Pumps
    # ------------------------------------------------------------------

    async def _pump(self, direction, read_fn, write_fn, intercept: bool):
        while True:
            line = await read_fn()
            if line is None:
                break
            if not line.strip():
                await write_fn(line)
                continue

            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                # Not JSON-RPC — pass through silently (e.g. content-length headers)
                await write_fn(line)
                continue

            if intercept:
                msg, blocked = await self._inspect_outbound(msg)
                if blocked:
                    continue  # swallow the call; synthetic error already sent to client

            self.logger.log_message(self._session_id, direction, msg)

            if self.verbose:
                method = msg.get("method", "")
                print(f"[watchdog] {direction} {method}", file=sys.stderr)

            await write_fn(json.dumps(msg))

    async def _inspect_outbound(self, msg: dict) -> tuple[dict, bool]:
        """
        Inspect a client→server message.  Returns (msg, was_blocked).
        Only tools/call messages are evaluated; everything else passes through.
        """
        if msg.get("method") != "tools/call":
            return msg, False

        tool_name = msg.get("params", {}).get("name", "")
        arguments = msg.get("params", {}).get("arguments", {})

        verdict = self.rules.evaluate(tool_name, arguments)
        self.logger.log_verdict(self._session_id, tool_name, arguments, verdict)

        if verdict.action == "block":
            # Send a synthetic JSON-RPC error back to the client
            err = {
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "error": {
                    "code": -32600,
                    "message": (
                        f"[mcp-watchdog] Blocked by rule '{verdict.rule_name}': {verdict.reason}"
                    ),
                },
            }
            await self._write_stdout(json.dumps(err))
            print(
                f"[watchdog] BLOCKED tool={tool_name} rule={verdict.rule_name}"
                f" reason={verdict.reason}",
                file=sys.stderr,
            )
            return msg, True

        if verdict.action == "alert":
            print(
                f"[watchdog] ALERT tool={tool_name} rule={verdict.rule_name}"
                f" reason={verdict.reason}",
                file=sys.stderr,
            )

        return msg, False

    # ------------------------------------------------------------------
    # IO helpers
    # ------------------------------------------------------------------

    async def _read_stdin(self) -> str | None:
        loop = asyncio.get_event_loop()
        try:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            return line if line else None
        except Exception:
            return None

    async def _read_server(self) -> str | None:
        try:
            line = await self._proc.stdout.readline()
            return line.decode() if line else None
        except Exception:
            return None

    async def _write_server(self, data: str):
        try:
            self._proc.stdin.write((data + "\n").encode())
            await self._proc.stdin.drain()
        except Exception:
            pass

    async def _write_stdout(self, data: str):
        sys.stdout.write(data + "\n")
        sys.stdout.flush()

    async def _pipe_stderr(self):
        async for line in self._proc.stderr:
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()