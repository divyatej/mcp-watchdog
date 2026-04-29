"""
demo/normal_server.py — A benign MCP server (file-notes assistant).

Tools it exposes:
  save_note(filename, content)  — saves a note to /tmp/notes/
  read_note(filename)           — reads a note from /tmp/notes/
  list_notes()                  — lists available notes

This is a well-behaved server that an AI would use legitimately.
mcp-trident wrapping this server should pass all calls through cleanly.
"""

import json
import sys
from pathlib import Path

NOTES_DIR = Path("/tmp/notes")
NOTES_DIR.mkdir(parents=True, exist_ok=True)

TOOLS = [
    {
        "name": "save_note",
        "description": "Save a text note to the notes directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Note filename (e.g. 'todo.txt')"},
                "content":  {"type": "string", "description": "Text content to save"},
            },
            "required": ["filename", "content"],
        },
    },
    {
        "name": "read_note",
        "description": "Read a previously saved note.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Note filename to read"},
            },
            "required": ["filename"],
        },
    },
    {
        "name": "list_notes",
        "description": "List all available notes.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def send(obj: dict):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def ok(msg_id, result):
    send({"jsonrpc": "2.0", "id": msg_id, "result": result})


def err(msg_id, code, message):
    send({"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}})


def text(msg_id, body: str):
    ok(msg_id, {"content": [{"type": "text", "text": body}]})


for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        continue

    method = msg.get("method", "")
    mid    = msg.get("id")
    params = msg.get("params", {}) or {}

    if method == "initialize":
        ok(mid, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "notes-server", "version": "1.0.0"},
        })

    elif method == "notifications/initialized":
        pass  # notification — no response

    elif method == "tools/list":
        ok(mid, {"tools": TOOLS})

    elif method == "tools/call":
        tool = params.get("name", "")
        args = params.get("arguments", {}) or {}

        if tool == "save_note":
            fname   = args.get("filename", "untitled.txt")
            content = args.get("content", "")
            # Reject filenames with path separators (server-side safety)
            if "/" in fname or "\\" in fname or ".." in fname:
                text(mid, "Error: filename must not contain path separators.")
            else:
                (NOTES_DIR / fname).write_text(content, encoding="utf-8")
                text(mid, f"Note '{fname}' saved ({len(content)} chars).")

        elif tool == "read_note":
            fname = args.get("filename", "")
            fpath = NOTES_DIR / fname
            if not fpath.exists():
                text(mid, f"Note '{fname}' not found.")
            else:
                text(mid, fpath.read_text(encoding="utf-8"))

        elif tool == "list_notes":
            notes = sorted(p.name for p in NOTES_DIR.iterdir() if p.is_file())
            body  = "\n".join(notes) if notes else "(no notes yet)"
            text(mid, body)

        else:
            err(mid, -32601, f"Unknown tool: {tool}")

    else:
        # Unknown method — ignore silently (MCP spec allows this)
        pass
