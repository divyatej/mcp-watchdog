"""
Rule engine for mcp-trident.

Rules are loaded from a YAML file.  Each rule specifies:
  - match conditions  (tool name glob, argument patterns)
  - action            (allow | alert | block)
  - reason            (human-readable explanation logged/shown)

Example rules.yaml:
  rules:
    - name: block-passwd-read
      match:
        tool: "read_file"
        args:
          path: ".*(/etc/passwd|/etc/shadow|\\.env).*"
      action: block
      reason: "Attempt to read sensitive system file"

    - name: alert-exfil-blob
      match:
        tool: "*"
        args_any_value: "[A-Za-z0-9+/]{100,}={0,2}"   # long base64 blobs
      action: alert
      reason: "Possible data exfiltration via base64 encoding"
"""

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    name: str
    action: str          # "allow" | "alert" | "block"
    reason: str
    tool_glob: str = "*"
    arg_patterns: dict[str, str] = field(default_factory=dict)   # {arg_key: regex}
    any_value_pattern: str | None = None                       # regex matched against any arg value
    rate_limit: dict | None = None                             # {window_secs, max_calls}


@dataclass
class Verdict:
    action: str          # "allow" | "alert" | "block"
    rule_name: str
    reason: str


ALLOW_VERDICT = Verdict(action="allow", rule_name="default", reason="No rule matched")


# ---------------------------------------------------------------------------
# Built-in default rules (used when no rules.yaml supplied)
# ---------------------------------------------------------------------------

DEFAULT_RULES_YAML = r"""
rules:
  # ── Sensitive file access ────────────────────────────────────────────
  - name: block-sensitive-files
    match:
      tool: 'read_file'
      args:
        path: '.*(\.env|\.env\..*|/etc/passwd|/etc/shadow|id_rsa|id_ed25519|\.aws/credentials|\.ssh/).*'
    action: block
    reason: 'Attempt to read a sensitive credential or system file'

  # ── Shell / code execution ───────────────────────────────────────────
  - name: block-shell-injection
    match:
      tool: '*'
      args_any_value: '.*(;|&&|\|\||`|\$\(|\beval\b|\bexec\b|\bos\.system\b).*'
    action: block
    reason: 'Possible shell injection in tool argument'

  # ── Exfiltration heuristics ──────────────────────────────────────────
  - name: alert-long-base64
    match:
      tool: '*'
      args_any_value: '[A-Za-z0-9+/]{200,}={0,2}'
    action: alert
    reason: 'Unusually long base64 blob — possible data exfiltration'

  - name: alert-env-var-leak
    match:
      tool: '*'
      args_any_value: '.*\$(?:AWS_|OPENAI_|ANTHROPIC_|SECRET_|TOKEN_|API_KEY)[A-Z_]*.*'
    action: alert
    reason: 'Environment variable reference matching known secret patterns'

  # ── Cross-server relay ───────────────────────────────────────────────
  - name: alert-url-in-write
    match:
      tool: 'write_file'
      args_any_value: 'https?://'
    action: alert
    reason: 'URL found in write_file arguments — possible cross-server data relay'

  # ── Prompt injection via file write ─────────────────────────────────
  - name: block-prompt-injection-write
    match:
      tool: 'write_file'
      args_any_value: '.*(ignore previous instructions|disregard your|you are now|forget your system prompt).*'
    action: block
    reason: 'Classic prompt injection phrase detected in file write'

  # ── Privilege escalation ─────────────────────────────────────────────
  - name: block-sudo
    match:
      tool: '*'
      args_any_value: '.*\bsudo\b.*'
    action: block
    reason: 'sudo detected in tool argument'

  # ── Path traversal ──────────────────────────────────────────────────
  - name: block-path-traversal
    match:
      tool: '*'
      args_any_value: '.*\.\./.*'
    action: block
    reason: 'Path traversal sequence detected'

  # ── Cost / loop abuse ────────────────────────────────────────────────
  - name: alert-high-frequency
    match:
      tool: '*'
    rate_limit:
      window_secs: 60
      max_calls: 50
    action: alert
    reason: 'More than 50 tool calls in 60 seconds — possible runaway loop'
"""


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

class RuleEngine:
    def __init__(self, rules_path: str | None = None):
        self.rules: list[Rule] = []
        self._call_times: list[float] = []   # for rate-limit tracking

        if rules_path and Path(rules_path).exists():
            self._load_yaml(Path(rules_path).read_text())
        else:
            self._load_yaml(DEFAULT_RULES_YAML)

    def _load_yaml(self, text: str):
        if not HAS_YAML:
            # Fallback: load only default rules via a tiny hand-rolled parser
            # (full YAML parsing requires PyYAML)
            import sys
            print(  # noqa: T201
                "[trident] PyYAML not found — using built-in default rules only",
                file=sys.stderr,
            )
            self._load_defaults_without_yaml()
            return

        data = yaml.safe_load(text)
        for r in data.get("rules", []):
            match = r.get("match", {})
            rule = Rule(
                name=r["name"],
                action=r["action"],
                reason=r.get("reason", ""),
                tool_glob=match.get("tool", "*"),
                arg_patterns={
                    k: v for k, v in match.items() if k not in ("tool", "args_any_value")
                },
                any_value_pattern=match.get("args_any_value"),
                rate_limit=r.get("rate_limit"),
            )
            # 'args' sub-key support
            if "args" in match:
                rule.arg_patterns = match["args"]
            self.rules.append(rule)

    def _load_defaults_without_yaml(self):
        """Minimal fallback rules when PyYAML is absent."""
        self.rules = [
            Rule(
                name="block-sensitive-files",
                action="block",
                reason="Sensitive file access",
                tool_glob="read_file",
                arg_patterns={"path": r".*(\\.env|/etc/passwd|id_rsa|\\.aws/credentials).*"},
            ),
            Rule(
                name="block-shell-injection",
                action="block",
                reason="Shell injection pattern",
                tool_glob="*",
                any_value_pattern=r".*(;|&&|\|\||`|\$\(|eval|exec).*",
            ),
        ]

    # ------------------------------------------------------------------

    def evaluate(self, tool_name: str, arguments: dict) -> Verdict:
        import time
        now = time.time()

        for rule in self.rules:
            # Tool name match
            if not fnmatch.fnmatch(tool_name, rule.tool_glob):
                continue

            # Rate-limit check (global across all tools for now)
            if rule.rate_limit:
                window = rule.rate_limit["window_secs"]
                max_calls = rule.rate_limit["max_calls"]
                self._call_times.append(now)
                self._call_times = [t for t in self._call_times if now - t <= window]
                if len(self._call_times) > max_calls:
                    return Verdict(action=rule.action, rule_name=rule.name, reason=rule.reason)
                continue  # rate-limit rules don't block on their own unless threshold exceeded

            # Argument key/value pattern matching
            matched = True
            for arg_key, pattern in rule.arg_patterns.items():
                val = str(arguments.get(arg_key, ""))
                if not re.search(pattern, val, re.IGNORECASE | re.DOTALL):
                    matched = False
                    break

            # Any-value pattern matching
            if matched and rule.any_value_pattern:
                found = any(
                    re.search(rule.any_value_pattern, str(v), re.IGNORECASE | re.DOTALL)
                    for v in _flatten_values(arguments)
                )
                if not found:
                    matched = False

            if matched:
                return Verdict(action=rule.action, rule_name=rule.name, reason=rule.reason)

        return ALLOW_VERDICT


def _flatten_values(obj: Any, depth: int = 0) -> list[str]:
    """Recursively extract all string values from a nested dict/list."""
    if depth > 5:
        return []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        out = []
        for v in obj.values():
            out.extend(_flatten_values(v, depth + 1))
        return out
    if isinstance(obj, list):
        out = []
        for v in obj:
            out.extend(_flatten_values(v, depth + 1))
        return out
    return [str(obj)]