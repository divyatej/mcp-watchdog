"""
mcp-trident CLI entry point.

Subcommands:
  run      (default) — start the proxy
  report   — generate HTML report from a .jsonl log
  rules    — validate and print loaded rules
"""

import argparse
import asyncio
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="mcp-trident",
        description="Runtime security proxy for MCP tool calls",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Wrap a stdio MCP server
  mcp-trident -- npx @modelcontextprotocol/server-filesystem /data

  # Use a custom rules file
  mcp-trident --rules my_rules.yaml -- python my_server.py

  # Generate an HTML report from a previous session log
  mcp-trident report --log mcp_trident.jsonl --out report.html

  # Check which rules are loaded
  mcp-trident rules --rules my_rules.yaml
""",
    )

    parser.add_argument("--rules", metavar="FILE", help="Path to rules YAML (default: built-in)")
    parser.add_argument(
        "--log", metavar="FILE", default="mcp_trident.jsonl", help="Audit log path"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print every intercepted call to stderr"
    )
    parser.add_argument("--version", action="version", version="mcp-trident 0.1.0")

    subparsers = parser.add_subparsers(dest="subcommand")

    # report subcommand
    rep = subparsers.add_parser("report", help="Generate HTML report from audit log")
    rep.add_argument("--log", metavar="FILE", default="mcp_trident.jsonl")
    rep.add_argument("--out", metavar="FILE", default="mcp_trident_report.html")

    # rules subcommand
    rul = subparsers.add_parser("rules", help="Print loaded rules and exit")
    rul.add_argument("--rules", metavar="FILE")

    # Split on '--' before argparse sees it so it isn't mistaken for a subcommand
    argv = sys.argv[1:]
    if "--" in argv:
        split = argv.index("--")
        remainder = argv[split + 1 :]
        argv = argv[:split]
    else:
        remainder = []

    args = parser.parse_args(argv)

    # ----------------------------------------------------------------
    if args.subcommand == "report":
        from .report import generate_report
        generate_report(args.log, args.out)
        return

    if args.subcommand == "rules":
        rules_path = getattr(args, "rules", None)
        from .rules import RuleEngine
        engine = RuleEngine(rules_path)
        print(f"Loaded {len(engine.rules)} rules:")
        for r in engine.rules:
            print(f"  [{r.action.upper():5}] {r.name}  —  {r.reason}")
        return

    # Default: run proxy
    if not remainder:
        parser.print_help()
        print("\nError: provide a server command after '--'", file=sys.stderr)
        sys.exit(1)

    from .proxy import MCPProxy

    proxy = MCPProxy(
        server_cmd=remainder,
        rules_path=args.rules,
        log_path=args.log,
        verbose=args.verbose,
    )

    try:
        exit_code = asyncio.run(proxy.run())
    except KeyboardInterrupt:
        exit_code = 0

    sys.exit(exit_code)


if __name__ == "__main__":
    main()