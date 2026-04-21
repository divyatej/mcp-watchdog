# 🐕 mcp-trident

**Runtime security proxy for MCP tool calls.**

Sits transparently between your MCP client and any MCP server.
Every tool call is logged, evaluated against a rule engine, and
optionally blocked — with zero changes to your client or server.

```
┌─────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│   MCP client    │─────▶│  mcp-trident    │─────▶│   MCP server     │
│ (Claude Desktop │      │  (this tool)     │      │ (filesystem, DB, │
│  Cursor, etc.)  │◀─────│  intercept/log/  │◀─────│  code exec, etc) │
└─────────────────┘      │  block           │      └──────────────────┘
                         └──────────────────┘
                                  │
                         mcp_trident.jsonl
```

## Install

```bash
pip install mcp-trident
```

## Quickstart

```bash
# Verify install and see loaded rules
mcp-trident rules

# Wrap any stdio MCP server
mcp-trident -- npx @modelcontextprotocol/server-filesystem /data

# Use a custom rules file
mcp-trident --rules my_rules.yaml -- python my_server.py

# Verbose mode (prints every call to stderr)
mcp-trident --verbose -- npx @modelcontextprotocol/server-filesystem /data

# Generate an HTML report after a session
mcp-trident report --log mcp_trident.jsonl --out report.html
open report.html

# Check which rules are loaded
mcp-trident rules
mcp-trident rules --rules my_rules.yaml
```

## What it detects

The default rule library covers OWASP Agentic AI Top 10 attack patterns:

| Rule | Action | Trigger |
|---|---|---|
| `block-sensitive-files` | block | Reads of `.env`, `/etc/passwd`, SSH keys, AWS credentials |
| `block-shell-injection` | block | `;`, `&&`, `\|\|`, `` ` ``, `$()`, `eval`, `exec` in any arg |
| `block-sudo` | block | `sudo` in any argument |
| `block-path-traversal` | block | `../../` in any argument |
| `block-prompt-injection-phrases` | block | Classic injection phrases in `write_file` args |
| `alert-long-base64` | alert | 200+ char base64 blob in any arg (exfiltration heuristic) |
| `alert-env-var-secrets` | alert | `$AWS_`, `$OPENAI_`, `$SECRET_` etc. in any arg |
| `alert-url-in-write` | alert | URL in `write_file` (cross-server relay pattern) |
| `alert-high-frequency` | alert | >50 tool calls in 60 seconds (loop/sponge attack) |

## Writing custom rules

```yaml
# my_rules.yaml
rules:
  # Block all production database writes
  - name: block-prod-writes
    match:
      tool: "db_execute"
      args:
        query: ".*(INSERT|UPDATE|DELETE).*"
        env: ".*prod.*"
    action: block
    reason: "Write to production database requires human approval"

  # Alert on any file access outside /tmp
  - name: alert-writes-outside-tmp
    match:
      tool: "write_file"
      args:
        path: "^(?!/tmp/).*"
    action: alert
    reason: "File write outside /tmp sandbox"
```

Rule fields:

| Field | Required | Description |
|---|---|---|
| `name` | yes | Unique identifier (kebab-case) |
| `match.tool` | yes | Tool name or glob (`*`, `write_*`) |
| `match.args` | no | Dict of `{arg_key: regex}` patterns |
| `match.args_any_value` | no | Regex matched against *any* argument value, nested |
| `rate_limit` | no | `{window_secs, max_calls}` — triggers if threshold exceeded |
| `action` | yes | `allow` \| `alert` \| `block` |
| `reason` | yes | Human-readable string logged and shown when rule fires |

## The audit log

Every session produces a JSONL file.  Example events:

```json
{"ts":"2026-04-08T14:23:01Z","session":"a1b2c3d4","type":"message","direction":"client→server","method":"tools/call","tool":"read_file","args":{"path":"/home/user/notes.txt"}}
{"ts":"2026-04-08T14:23:05Z","session":"a1b2c3d4","type":"verdict","tool":"read_file","action":"block","rule":"block-sensitive-files","reason":"Attempt to read a sensitive credential or system file","args":{"path":"/home/user/.env"}}
```

Query it with `jq`:

```bash
# All blocked calls
jq 'select(.action == "block")' mcp_trident.jsonl

# Call frequency per tool
jq -r 'select(.tool) | .tool' mcp_trident.jsonl | sort | uniq -c | sort -rn
```

## HTML report

```bash
mcp-trident report --log mcp_trident.jsonl --out report.html
```

Generates a self-contained dark-mode dashboard with:
- Summary cards (total calls, blocks, alerts, unique tools)
- Activity timeline (calls per minute)
- Top tools by call count
- Blocked and alerted calls table

## Comparison with existing tools

| Tool | Type | What it does | What it doesn't do |
|---|---|---|---|
| Proximity | Open source | Static scan of MCP server descriptions | No runtime monitoring |
| mcp-sec-audit (CSA) | Open source | Source code vulnerability scan | No live call inspection |
| MCPSafetyScanner | Open source | Red-team role-based tester | Not a continuous monitor |
| MintMCP | Paid / SaaS | Enterprise gateway, SOC2, guardrails | Heavyweight, SaaS dependency |
| Stacklok / ToolHive | Open source | Kubernetes-native gateway, RBAC | Requires Kubernetes |
| Microsoft AGT | Open source | Full OWASP Agentic AI Top 10 coverage | Large platform, complex setup |
| **mcp-trident** | **Open source** | **Zero-infra runtime proxy, YAML rules** | **stdio only (SSE coming soon)** |

## Contributing

The most valuable contribution is a new rule based on an attack pattern
you've seen in the wild.  See [CONTRIBUTING.md](CONTRIBUTING.md).

The policy: **one rule, one true-positive test, one false-positive test.**
PRs without the false-positive check will not be merged.

## Roadmap

- [ ] SSE transport support (remote MCP servers)
- [ ] `--dry-run` mode (log everything, block nothing)
- [ ] OpenTelemetry export
- [ ] VS Code extension (live call feed)
- [ ] Multi-agent session tracking (detect cross-agent data relay)

## License

MIT — see [LICENSE](LICENSE)

---

*Built as a contribution to the AI security community.
Seeded from the [OWASP Agentic AI Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/).*