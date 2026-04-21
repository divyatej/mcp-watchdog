# Contributing to mcp-trident

Thanks for helping make AI agents safer.

## The most valuable contribution: new rules

The `rules.yaml` file is the community rulebook.  If you've encountered
an MCP attack pattern in the wild, seen a new technique in research, or
spotted a gap in the defaults — open a PR with a new rule.

Each rule needs:
1. A descriptive `name` (kebab-case, e.g. `block-github-token-leak`)
2. A precise `match` block (avoid over-broad patterns that cause false positives)
3. A clear `reason` string that will make sense to a developer reading the log
4. A reference comment linking to the source (CVE, blog post, paper)

## Running tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Adding a new rule + test

1. Add the rule to the `DEFAULT_RULES_YAML` constant in `mcp_trident/rules.py` (that is the active default ruleset). The `rules.yaml` in the repo root is a reference copy for users who supply `--rules`.
2. Add a test in `tests/test_rules.py` that:
   - verifies the rule fires on a known-bad input
   - verifies it does NOT fire on a known-good input (false-positive check)

PRs without the false-positive test will not be merged.

## Code changes

- Keep `proxy.py` dependency-free except for stdlib
- `rules.py` depends only on `pyyaml` (already required)
- All new features need tests

## Reporting a false positive

Open an issue with the `false-positive` label.  Include the tool name
and argument that was incorrectly flagged.

## Code of conduct

Be respectful.  Security research is collaborative.