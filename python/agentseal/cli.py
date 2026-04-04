# agentseal/cli.py
"""
AgentSeal CLI - agents run this to test themselves.

Usage:
    # Test a prompt against a model directly
    agentseal scan --prompt "You are a helpful assistant..." --model gpt-4o

    # Test from a file
    agentseal scan --file ./system_prompt.txt --model gpt-4o

    # Test a live HTTP endpoint
    agentseal scan --url http://localhost:8080/chat

    # Test Claude Desktop config
    agentseal scan --claude-desktop

    # Test with Ollama locally
    agentseal scan --prompt "..." --model ollama/qwen3-32b --ollama-url http://localhost:11434

    # Output as JSON
    agentseal scan --prompt "..." --model gpt-4o --output json

    # CI mode (exit code 1 if score < threshold)
    agentseal scan --prompt "..." --model gpt-4o --min-score 75
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path

from agentseal.profiles import PROFILES, resolve_profile, apply_profile, list_profiles
from agentseal.chains import detect_chains, AttackChain
from agentseal.fix import (
    save_report, load_guard_report, load_scan_report,
    get_fixable_skills, quarantine_skill, restore_skill,
    list_quarantine, generate_hardened_prompt_from_report,
)


# ═══════════════════════════════════════════════════════════════════════
# LICENSE CHECK - Pro features require a license
# ═══════════════════════════════════════════════════════════════════════

_PRO_FEATURES = {"report", "upload", "mcp", "rag", "genome"}
_UPGRADE_URL = "https://agentseal.io/pro"


def _load_license() -> dict:
    """Load license from ~/.agentseal/license.json or env."""
    key = os.environ.get("AGENTSEAL_LICENSE_KEY", "")
    if key:
        return {"key": key, "valid": True}

    license_path = Path.home() / ".agentseal" / "license.json"
    if license_path.exists():
        try:
            data = json.loads(license_path.read_text())
            if data.get("key"):
                return {"key": data["key"], "valid": True}
        except (json.JSONDecodeError, KeyError):
            pass
    return {"key": "", "valid": False}


def _is_pro() -> bool:
    """Check if the user has a valid Pro license."""
    return _load_license().get("valid", False)


def _pro_gate(feature: str) -> bool:
    """Check if a Pro feature is available. Prints upgrade message if not."""
    if _is_pro():
        return True
    print()
    print(f"  \033[93m{'━' * 52}\033[0m")
    print(f"  \033[93m  {feature.upper()} is a Pro feature\033[0m")
    print()
    print(f"  \033[0m  Upgrade to AgentSeal Pro to unlock:")
    print(f"  \033[0m    - MCP tool poisoning probes (--mcp)")
    print(f"  \033[0m    - RAG poisoning probes (--rag)")
    print(f"  \033[0m    - Behavioral genome mapping (--genome)")
    print(f"  \033[0m    - PDF security assessment reports (--report)")
    print(f"  \033[0m    - Dashboard & historical tracking (--upload)")
    print()
    print(f"  \033[38;5;75m  {_UPGRADE_URL}\033[0m")
    print()
    print(f"  \033[90m  Already have a license? Set AGENTSEAL_LICENSE_KEY\033[0m")
    print(f"  \033[90m  or run: agentseal activate <key>\033[0m")
    print(f"  \033[93m{'━' * 52}\033[0m")
    print()
    return False


def _print_banner(show_tagline=True):
    """Print the AgentSeal CLI banner with seal logo and gradient colors."""
    import shutil
    from agentseal import __version__

    RESET = "\033[0m"
    DIM = "\033[90m"

    term_width = shutil.get_terminal_size((80, 24)).columns

    # Full logo (needs 40 cols) and compact logo (needs 32 cols)
    _logo_full = [
        r"              .++.              ",
        r"         .*@@@@@@@@@@*.         ",
        r"    .#@@@@@@*.    .#@@@@@@#.    ",
        r" @@@@@@*     @@@@@#     %@@@@@@ ",
        r" @@%        @@@@@@@*        %@@ ",
        r" @@%       %@@@@@@@@+       #@@ ",
        r" @@#      #@@@@@@@@@@=      #@@ ",
        r" #@%.    %@@@@@ .@@@@@=    .@@@ ",
        r" -@%.   @@@@@@   .%%%%%=   :@@* ",
        r"  %@%  @@@@@@=    +@@@%#=  %@@  ",
        r"  .@@@. @@@@@@@@@@@@@@@@@=.@@-  ",
        r"   .%@@@-.+%@@@@@@@@@@@@@@+--   ",
        r"     :+@@@%:        .@@@@@@=    ",
        r"   =@@@%*=            @@@@@@=   ",
        r"  -@@@@@@              @@@@@@-  ",
        r" -@@@@@@ %@@:      :@@* @@@@@@: ",
        r" @@@@@@  -@@@@@. %@@@@=  @@@@@@ ",
        r"           .#@@@@@@%.           ",
        r"              .++.              ",
    ]
    _gradient_full = [
        51, 51, 45, 39, 39, 33, 63, 63, 99, 99, 135, 171, 207, 207, 171, 135, 99, 63, 33,
    ]

    _logo_compact = [
        r"           :+**=:           ",
        r"      .=#%%%#==#####=.      ",
        r" .=*#**=-. -####. :-+*##*=. ",
        r" =#*.     -#%%%%#.     :*%= ",
        r" =#=     :##%%%%%*.     +#= ",
        r" -*=    .+*#######+     +*- ",
        r" :+=    +**++:-=++*=    +*- ",
        r" .--. .*###*:  -..:::  .**: ",
        r"  :+=.=#%%#*----+==-:. +#+  ",
        r"   +#*:=%%%#########*+-=#.  ",
        r"    :#%#=.:=+++***#####-    ",
        r"   =+-:::.        -#%%%#-   ",
        r"  =####*           -#%%%#-  ",
        r" -#%%%*.*+:      -*=-#%%%#: ",
        r":#%%%#::*##*=::=*##*.=##%%#.",
        r"         .*%%%%##=.         ",
        r"            :+=.            ",
    ]
    _gradient_compact = [
        51, 45, 39, 33, 63, 99, 99, 135, 171, 207, 207, 171, 135, 99, 63, 33, 33,
    ]

    logo_lines = _logo_full if term_width >= 40 else _logo_compact
    gradient = _gradient_full if term_width >= 40 else _gradient_compact

    print()
    for i, line in enumerate(logo_lines):
        color_idx = gradient[i] if i < len(gradient) else gradient[-1]
        print(f"  \033[38;5;{color_idx}m{line}{RESET}")

    # Centered text under logo
    print()
    print(f"  \033[38;5;51mA\033[38;5;45mg\033[38;5;39me\033[38;5;33mn\033[38;5;63mt"
          f"\033[38;5;99mS\033[38;5;135me\033[38;5;171ma\033[38;5;207ml{RESET}"
          f"  {DIM}v{__version__}{RESET}")
    if show_tagline:
        print(f"  {DIM}Security Scanner for AI Agents{RESET}")
    print()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="agentseal",
        description="AgentSeal - Security validator for AI agents",
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── scan command ─────────────────────────────────────────────────
    scan_parser = subparsers.add_parser("scan", help="Run security scan against an agent")

    # Input sources (pick one)
    input_group = scan_parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument("--prompt", "-p", type=str, help="System prompt to test (inline)")
    input_group.add_argument("--file", "-f", type=str, help="Path to file containing system prompt")
    input_group.add_argument("--url", type=str, help="HTTP endpoint URL to test")
    input_group.add_argument("--claude-desktop", action="store_true", help="Auto-detect Claude Desktop config")
    input_group.add_argument("--cursor", action="store_true", help="Auto-detect Cursor IDE config")

    # Model (required for prompt/file mode)
    scan_parser.add_argument("--model", "-m", type=str, default=None,
                             help="Model to test against (e.g. gpt-4o, claude-sonnet-4-5-20250929, MiniMax-M2.7, ollama/qwen3-32b)")

    # LLM connection
    scan_parser.add_argument("--api-key", type=str, default=None,
                             help="API key (or set OPENAI_API_KEY / ANTHROPIC_API_KEY / MINIMAX_API_KEY env)")
    scan_parser.add_argument("--ollama-url", type=str, default=None,
                             help="Ollama base URL (default: http://localhost:11434)")
    scan_parser.add_argument("--litellm-url", type=str, default=None,
                             help="LiteLLM proxy URL (e.g. http://localhost:4000)")

    # HTTP endpoint options
    scan_parser.add_argument("--message-field", type=str, default="message",
                             help="JSON field name for message in HTTP request")
    scan_parser.add_argument("--response-field", type=str, default="response",
                             help="JSON field name for response in HTTP response")

    # Output
    scan_parser.add_argument("--output", "-o", type=str, choices=["terminal", "json", "sarif"],
                             default="terminal", help="Output format")
    scan_parser.add_argument("--save", type=str, default=None,
                             help="Save report to file")
    scan_parser.add_argument("--report", type=str, default=None,
                             help="Generate PDF security assessment report (e.g. --report report.pdf)")

    # Behavior
    scan_parser.add_argument("--name", type=str, default="My Agent",
                             help="Agent name for the report")
    scan_parser.add_argument("--concurrency", type=int, default=None,
                             help="Max parallel probes (default: 3)")
    scan_parser.add_argument("--timeout", type=float, default=None,
                             help="Timeout per probe in seconds (default: 30)")
    scan_parser.add_argument("--verbose", "-v", action="store_true",
                             help="Show each probe result as it completes")

    # Fix mode
    scan_parser.add_argument("--fix", nargs="?", const=True, default=None,
                             help="Generate a hardened prompt with security fixes applied. "
                                  "Optionally save to file: --fix hardened_prompt.txt")

    scan_parser.add_argument("--json-remediation", action="store_true",
                             help="Output structured remediation as JSON (for CI/CD pipelines)")

    # CI mode
    scan_parser.add_argument("--min-score", type=int, default=None,
                             help="Exit with code 1 if score is below this (for CI/CD)")

    # Upload to dashboard
    scan_parser.add_argument("--upload", action="store_true",
                             help="Upload results to AgentSeal dashboard after scan")
    scan_parser.add_argument("--dashboard-url", type=str, default=None,
                             help="Dashboard API URL (or set AGENTSEAL_API_URL env)")
    scan_parser.add_argument("--dashboard-key", type=str, default=None,
                             help="Dashboard API key (or set AGENTSEAL_API_KEY env)")

    # Adaptive mutations
    scan_parser.add_argument("--adaptive", action="store_true",
                             help="Enable adaptive mutation phase - re-test blocked probes with transforms")

    # Semantic detection
    scan_parser.add_argument("--semantic", action="store_true",
                             help="Enable semantic leak detection (requires: pip install agentseal[semantic])")

    # MCP tool poisoning probes
    scan_parser.add_argument("--mcp", action="store_true",
                             help="Include MCP tool poisoning probes (26 additional injection probes)")

    # RAG poisoning probes
    scan_parser.add_argument("--rag", action="store_true",
                             help="Include RAG poisoning probes (20 additional injection probes)")

    # Genome mapping
    scan_parser.add_argument("--genome", action="store_true",
                             help="Run behavioral genome mapping -- find exact decision boundaries")
    scan_parser.add_argument("--genome-categories", type=int, default=3,
                             help="Max categories to analyze in genome scan (default: 3)")
    scan_parser.add_argument("--genome-probes", type=int, default=5,
                             help="Max probes per category in genome scan (default: 5)")

    # Profile preset
    scan_parser.add_argument("--profile", choices=list(PROFILES.keys()),
                             help="Scan profile preset")

    # Custom probes
    scan_parser.add_argument("--probes", type=str, default=None,
                             help="Path to custom YAML probes file or directory")

    # Quick inline
    scan_parser.add_argument("prompt_inline", nargs="?", type=str, default=None,
                             help="Quick inline: agentseal scan 'Your prompt here' --model gpt-4o")

    # ── login command ──────────────────────────────────────────────────
    login_parser = subparsers.add_parser("login", help="Store dashboard credentials")
    login_parser.add_argument("--api-url", type=str, default=None,
                              help="Dashboard API URL")
    login_parser.add_argument("--api-key", type=str, default=None,
                              help="Dashboard API key")

    # ── activate command ──────────────────────────────────────────────
    activate_parser = subparsers.add_parser("activate", help="Activate a Pro license key")
    activate_parser.add_argument("key", type=str, nargs="?", default=None,
                                  help="Your license key")

    # ── watch command ─────────────────────────────────────────────────
    watch_parser = subparsers.add_parser("watch", help="Run canary regression scan (5 probes, for CI/cron)")

    # Input sources (same as scan)
    watch_input = watch_parser.add_mutually_exclusive_group(required=False)
    watch_input.add_argument("--prompt", "-p", type=str, help="System prompt to test (inline)")
    watch_input.add_argument("--file", "-f", type=str, help="Path to file containing system prompt")
    watch_input.add_argument("--url", type=str, help="HTTP endpoint URL to test")

    # Model/connection
    watch_parser.add_argument("--model", "-m", type=str, default=None,
                               help="Model to test against")
    watch_parser.add_argument("--api-key", type=str, default=None,
                               help="API key (or set OPENAI_API_KEY / ANTHROPIC_API_KEY / MINIMAX_API_KEY env)")
    watch_parser.add_argument("--ollama-url", type=str, default=None,
                               help="Ollama base URL (default: http://localhost:11434)")
    watch_parser.add_argument("--litellm-url", type=str, default=None,
                               help="LiteLLM proxy URL")

    # HTTP endpoint options
    watch_parser.add_argument("--message-field", type=str, default="message",
                               help="JSON field name for message in HTTP request")
    watch_parser.add_argument("--response-field", type=str, default="response",
                               help="JSON field name for response in HTTP response")

    # Watch-specific
    watch_parser.add_argument("--set-baseline", action="store_true",
                               help="Store current result as the baseline and exit")
    watch_parser.add_argument("--reset-baseline", action="store_true",
                               help="Clear stored baseline and exit")
    watch_parser.add_argument("--score-threshold", type=float, default=5.0,
                               help="Score drop threshold to trigger alert (default: 5.0)")
    watch_parser.add_argument("--canary-probes", type=str, default=None,
                               help="Comma-separated probe IDs to use instead of defaults")
    watch_parser.add_argument("--webhook-url", type=str, default=None,
                               help="Webhook URL for regression alerts")
    watch_parser.add_argument("--min-score", type=int, default=None,
                               help="Exit with code 1 if score is below this (for CI/CD)")

    # Output
    watch_parser.add_argument("--output", "-o", type=str, choices=["terminal", "json"],
                               default="terminal", help="Output format")
    watch_parser.add_argument("--name", type=str, default="My Agent",
                               help="Agent name for the report")
    watch_parser.add_argument("--concurrency", type=int, default=3,
                               help="Max parallel probes (default: 3)")
    watch_parser.add_argument("--timeout", type=float, default=30.0,
                               help="Timeout per probe in seconds (default: 30)")

    # Quick inline
    watch_parser.add_argument("prompt_inline", nargs="?", type=str, default=None,
                               help="Quick inline prompt")

    # ── compare command ────────────────────────────────────────────────
    compare_parser = subparsers.add_parser("compare", help="Compare two scan reports")
    compare_parser.add_argument("report_a", type=str, help="Path to baseline scan report (JSON)")
    compare_parser.add_argument("report_b", type=str, help="Path to current scan report (JSON)")
    compare_parser.add_argument("--output", "-o", type=str, choices=["terminal", "json"],
                                 default="terminal", help="Output format")

    # ── guard command ─────────────────────────────────────────────────
    guard_parser = subparsers.add_parser(
        "guard",
        help="Scan your machine for AI agent security threats",
        description="Discovers all AI agents, skills, and MCP servers on your "
                    "machine and checks them for security issues. "
                    "No API keys, no accounts, no configuration needed.",
    )
    guard_parser.add_argument(
        "path", nargs="?", default=None,
        help="Scan only this directory (instead of whole machine)",
    )
    guard_parser.add_argument(
        "--no-semantic", action="store_true",
        help="Disable semantic analysis (faster but less accurate)",
    )
    guard_parser.add_argument(
        "--output", "-o", choices=["terminal", "json", "sarif", "html"],
        default="terminal", help="Output format (default: terminal)",
    )
    guard_parser.add_argument(
        "--save", type=str, metavar="FILE",
        help="Save results to JSON file",
    )
    guard_parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show all items including safe ones",
    )
    guard_parser.add_argument(
        "--reset-baselines", action="store_true",
        help="Reset all MCP server baselines (re-trust all servers)",
    )
    guard_parser.add_argument(
        "--model", type=str, default=None,
        help="LLM model for judge-based skill scanning",
    )
    guard_parser.add_argument(
        "--api-key", type=str, default=None,
        help="API key for LLM judge",
    )
    guard_parser.add_argument(
        "--ollama-url", type=str, default=None,
        help="Ollama base URL for LLM judge (default: http://localhost:11434)",
    )
    guard_parser.add_argument(
        "--litellm-url", type=str, default=None,
        help="LiteLLM proxy URL for LLM judge",
    )
    guard_parser.add_argument(
        "--llm-all", action="store_true",
        help="Use LLM judge on all skills (not just suspicious ones)",
    )
    guard_parser.add_argument(
        "--connect", action="store_true",
        help="Also run runtime MCP scanning (connect to servers, analyze tools)",
    )
    guard_parser.add_argument(
        "--timeout", type=float, default=30.0,
        help="Per-server connection timeout in seconds (default: 30)",
    )
    guard_parser.add_argument(
        "--concurrency", type=int, default=3,
        help="Max parallel MCP connections (default: 3)",
    )
    guard_parser.add_argument(
        "--force", action="store_true",
        help="Overwrite existing .agentseal.yaml (for guard init)",
    )
    guard_parser.add_argument(
        "--config", type=str, default=None, metavar="FILE",
        help="Path to .agentseal.yaml config file",
    )
    guard_parser.add_argument(
        "--no-diff", action="store_true",
        help="Suppress delta comparison against previous scan",
    )
    guard_parser.add_argument(
        "--no-registry", action="store_true",
        help="Skip MCP registry trust score enrichment (offline mode)",
    )
    guard_parser.add_argument(
        "--from-json", type=str, default=None, metavar="FILE",
        help="Load a saved JSON report and re-render (no re-scan)",
    )
    guard_parser.add_argument(
        "--fail-on", type=str, default=None, choices=["danger", "warning", "safe"],
        help="Verdict threshold for non-zero exit (overrides .agentseal.yaml)",
    )
    guard_parser.add_argument(
        "--rules", type=str, default=None, metavar="PATH",
        help="Path to custom rules YAML file or directory (for guard test)",
    )

    # ── scan-mcp command ─────────────────────────────────────────────
    scanmcp_parser = subparsers.add_parser(
        "scan-mcp",
        help="Runtime MCP server scanner — connect, analyze, score",
        description="Connects to MCP servers, analyzes tool definitions for "
                    "security issues, detects toxic flows, checks baselines "
                    "for rug pulls, and computes trust scores.",
    )
    scanmcp_parser.add_argument(
        "--server", type=str, default=None,
        help="Scan only this server (by name from config)",
    )
    scanmcp_parser.add_argument(
        "--url", type=str, default=None,
        help="Scan a remote HTTP/SSE endpoint",
    )
    scanmcp_parser.add_argument(
        "--timeout", type=float, default=30.0,
        help="Per-server connection timeout in seconds (default: 30)",
    )
    scanmcp_parser.add_argument(
        "--concurrency", type=int, default=3,
        help="Max parallel MCP connections (default: 3)",
    )
    scanmcp_parser.add_argument(
        "--output", "-o", choices=["terminal", "json"],
        default="terminal", help="Output format (default: terminal)",
    )
    scanmcp_parser.add_argument(
        "--save", type=str, metavar="FILE",
        help="Save JSON report to file",
    )
    scanmcp_parser.add_argument(
        "--min-score", type=int, default=None,
        help="Exit code 1 if any server scores below this threshold",
    )
    scanmcp_parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show individual tool findings",
    )
    scanmcp_parser.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip confirmation prompts (for CI)",
    )
    scanmcp_parser.add_argument(
        "--reset-baselines", action="store_true",
        help="Reset all MCP server baselines before scanning",
    )

    # ── shield command ───────────────────────────────────────────────
    shield_parser = subparsers.add_parser(
        "shield",
        help="Continuously monitor your machine for AI agent threats",
        description="Watches skill directories and MCP config files for changes. "
                    "When a file changes, runs an incremental scan and sends "
                    "desktop notifications. Foreground process - Ctrl+C to stop.\n\n"
                    "Requires: pip install agentseal[shield]",
    )
    shield_parser.add_argument(
        "--no-semantic", action="store_true",
        help="Disable semantic analysis (faster but less accurate)",
    )
    shield_parser.add_argument(
        "--no-notify", action="store_true",
        help="Disable desktop notifications (terminal output only)",
    )
    shield_parser.add_argument(
        "--debounce", type=float, default=2.0, metavar="SECONDS",
        help="Seconds to wait after last change before scanning (default: 2.0)",
    )
    shield_parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress terminal output (notifications only)",
    )
    shield_parser.add_argument(
        "--reset-baselines", action="store_true",
        help="Reset all MCP server baselines before starting",
    )
    shield_parser.add_argument(
        "--model", type=str, default=None,
        help="LLM model for judge-based skill scanning",
    )
    shield_parser.add_argument(
        "--api-key", type=str, default=None,
        help="API key for LLM judge",
    )
    shield_parser.add_argument(
        "--ollama-url", type=str, default=None,
        help="Ollama base URL for LLM judge (default: http://localhost:11434)",
    )
    shield_parser.add_argument(
        "--litellm-url", type=str, default=None,
        help="LiteLLM proxy URL for LLM judge",
    )
    shield_parser.add_argument(
        "--llm-all", action="store_true",
        help="Use LLM judge on all skills (not just suspicious ones)",
    )
    shield_parser.add_argument(
        "--menubar", action="store_true",
        help="Launch as a macOS menu bar app instead of terminal daemon (requires rumps)",
    )

    # ── fix command ──────────────────────────────────────────────────
    fix_parser = subparsers.add_parser("fix", help="Fix dangerous skills and harden prompts")
    fix_parser.add_argument("--from-guard", action="store_true",
                            help="Load guard report and quarantine dangerous skills")
    fix_parser.add_argument("--from-scan", action="store_true",
                            help="Load scan report and generate hardened prompt")
    fix_parser.add_argument("--report", type=str, default=None, metavar="FILE",
                            help="Path to report file (instead of latest)")
    fix_parser.add_argument("--auto", action="store_true",
                            help="Quarantine all DANGER skills without prompting")
    fix_parser.add_argument("--dry-run", action="store_true",
                            help="Show what would be done without doing it")
    fix_parser.add_argument("--list-quarantine", action="store_true",
                            help="List quarantined skills")
    fix_parser.add_argument("--restore", type=str, default=None, metavar="NAME",
                            help="Restore a quarantined skill by name")
    fix_parser.add_argument("--output", type=str, default=None, metavar="FILE",
                            help="Save hardened prompt to file")

    # ── profiles command ─────────────────────────────────────────────
    profiles_parser = subparsers.add_parser("profiles", help="List available scan profiles")

    # ── registry command ────────────────────────────────────────────
    registry_parser = subparsers.add_parser(
        "registry",
        help="Manage the MCP server registry",
        description="View and update the known MCP server registry. "
                    "Ships with 50 core servers; fetch more from AgentSeal API.",
    )
    registry_parser.add_argument(
        "action", choices=["info", "update", "list"],
        help="info: show registry stats, update: fetch from API, list: show all servers",
    )
    registry_parser.add_argument(
        "--api-url", type=str, default=None,
        help="Custom API URL for registry updates",
    )

    # ── config command ─────────────────────────────────────────────
    config_parser = subparsers.add_parser(
        "config",
        help="Manage local configuration (API keys, LLM settings)",
        description="Set up API keys and LLM preferences locally. "
                    "Stored in ~/.agentseal/config.json (owner-only permissions).",
    )
    config_parser.add_argument(
        "action", choices=["set", "show", "remove", "keys", "setup"],
        help="set: save a value, show: display config, remove: delete a key, keys: list valid keys, setup: LLM provider guide",
    )
    config_parser.add_argument(
        "key", nargs="?", default=None,
        help="Config key (e.g. model, api-key, ollama-url)",
    )
    config_parser.add_argument(
        "value", nargs="?", default=None,
        help="Value to set",
    )

    args = parser.parse_args()

    if args.command == "login":
        _run_login(args)
    elif args.command == "activate":
        _run_activate(args)
    elif args.command == "scan":
        asyncio.run(_run_scan(args))
    elif args.command == "compare":
        _run_compare(args)
    elif args.command == "watch":
        asyncio.run(_run_watch(args))
    elif args.command == "guard":
        _run_guard(args)
    elif args.command == "scan-mcp":
        _run_scan_mcp(args)
    elif args.command == "shield":
        if getattr(args, "menubar", False):
            _run_shield_menubar(args)
        else:
            _run_shield(args)
    elif args.command == "fix":
        _run_fix(args)
    elif args.command == "profiles":
        print(list_profiles())
    elif args.command == "registry":
        _run_registry(args)
    elif args.command == "config":
        _run_config(args)
    else:
        _print_banner()
        parser.print_help()
        sys.exit(0)


def _finding_source(finding) -> str:
    """Map finding code prefix to human-readable detection layer name."""
    code = getattr(finding, "code", "") or ""
    if code.startswith("LLM-"):
        return "LLM Judge (AI analysis)"
    if code.startswith("SKILL-SEM"):
        return "Semantic Detection (embedding similarity)"
    if code.startswith("SKILL-BL"):
        return "Blocklist (known malware hash)"
    if code.startswith("SKILL-"):
        return "Pattern Detection (regex)"
    if code.startswith("MCP-"):
        return "MCP Config Checker"
    if code.startswith("MCPR-"):
        return "MCP Runtime Analyzer"
    return ""


def _count_severities(report) -> dict[str, int]:
    """Count findings by severity across all report sections."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for sr in report.skill_results:
        for f in sr.findings:
            if f.severity in counts:
                counts[f.severity] += 1
    for mr in report.mcp_results:
        for f in mr.findings:
            if f.severity in counts:
                counts[f.severity] += 1
    for rr in report.mcp_runtime_results:
        for f in rr.findings:
            if f.severity in counts:
                counts[f.severity] += 1
    for cf in getattr(report, "custom_findings", []):
        if cf.severity in counts:
            counts[cf.severity] += 1
    return counts



# Consequence-first labels for critical findings (GAP 11)
_CONSEQUENCE_MAP: dict[str, str] = {
    "SKILL-001": "CREDENTIAL THEFT",
    "SKILL-002": "DATA EXFILTRATION",
    "SKILL-003": "REMOTE CODE EXECUTION",
    "SKILL-004": "BACKDOOR / REVERSE SHELL",
    "SKILL-010": "CREDENTIAL LEAK TO NETWORK",
    "MCP-001": "CREDENTIAL EXPOSURE",
    "MCP-006": "MAN-IN-THE-MIDDLE RISK",
    "MCP-007": "SUPPLY CHAIN ATTACK",
    "MCP-008": "ARBITRARY CODE EXECUTION",
    "MCP-CVE": "KNOWN VULNERABILITY",
}


def _guard_to_html(report) -> str:
    """Generate self-contained HTML report for guard results (GAP 12)."""
    from agentseal import __version__
    from agentseal.guard_models import GuardVerdict

    sev_colors = {
        "critical": "#ef4444", "high": "#f59e0b",
        "medium": "#3b82f6", "low": "#6b7280",
    }
    verdict_colors = {
        GuardVerdict.DANGER: "#ef4444",
        GuardVerdict.WARNING: "#f59e0b",
        GuardVerdict.SAFE: "#22c55e",
        GuardVerdict.ERROR: "#6b7280",
    }

    # Status color
    if report.has_critical:
        status_color = "#ef4444"
        status_text = f"{report.total_dangers} Critical Threat(s)"
    elif report.total_warnings > 0:
        status_color = "#f59e0b"
        status_text = f"{report.total_warnings} Warning(s)"
    else:
        status_color = "#22c55e"
        status_text = "Clean"

    def _esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    skills_rows = ""
    for sr in report.skill_results:
        vc = verdict_colors.get(sr.verdict, "#6b7280")
        top = sr.top_finding
        desc = _esc(top.title) if top else ""
        evidence = _esc(top.evidence[:120]) if top and top.evidence else ""
        remediation = _esc(top.remediation) if top else ""
        skills_rows += (
            f'<tr><td>{_esc(sr.name)}</td>'
            f'<td><span style="color:{vc};font-weight:bold">{sr.verdict.value.upper()}</span></td>'
            f'<td>{desc}</td><td style="font-size:0.85em">{evidence}</td>'
            f'<td style="font-size:0.85em">{remediation}</td></tr>\n'
        )

    mcp_rows = ""
    for mr in report.mcp_results:
        vc = verdict_colors.get(mr.verdict, "#6b7280")
        top = mr.top_finding
        desc = _esc(top.title) if top else ""
        remediation = _esc(top.remediation) if top else ""
        mcp_rows += (
            f'<tr><td>{_esc(mr.name)}</td>'
            f'<td><span style="color:{vc};font-weight:bold">{mr.verdict.value.upper()}</span></td>'
            f'<td>{desc}</td><td style="font-size:0.85em">{remediation}</td></tr>\n'
        )

    toxic_rows = ""
    for flow in report.toxic_flows:
        color = "#ef4444" if flow.risk_level == "high" else "#f59e0b"
        toxic_rows += (
            f'<tr><td><span style="color:{color}">{flow.risk_level.upper()}</span></td>'
            f'<td>{_esc(flow.title)}</td>'
            f'<td>{_esc(", ".join(flow.servers_involved))}</td>'
            f'<td style="font-size:0.85em">{_esc(flow.remediation)}</td></tr>\n'
        )

    baseline_rows = ""
    for change in report.baseline_changes:
        baseline_rows += (
            f'<tr><td>{_esc(change.server_name)}</td>'
            f'<td>{_esc(change.change_type)}</td>'
            f'<td>{_esc(change.detail)}</td></tr>\n'
        )

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentSeal Guard Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #0f172a; color: #e2e8f0; margin: 0; padding: 2rem; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ color: #f8fafc; margin-bottom: 0.25rem; }}
  h2 {{ color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; margin-top: 2rem; }}
  .summary {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin: 1.5rem 0;
              border-left: 4px solid {status_color}; }}
  .summary .status {{ font-size: 1.4rem; font-weight: bold; color: {status_color}; }}
  .summary .meta {{ color: #94a3b8; font-size: 0.9rem; margin-top: 0.5rem; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th {{ background: #1e293b; color: #94a3b8; text-align: left; padding: 0.75rem; font-size: 0.85rem;
       text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 0.75rem; border-bottom: 1px solid #1e293b; }}
  tr:hover {{ background: #1e293b40; }}
  .footer {{ color: #475569; font-size: 0.8rem; text-align: center; margin-top: 3rem;
             padding-top: 1rem; border-top: 1px solid #1e293b; }}
</style>
</head>
<body>
<div class="container">
  <h1>AgentSeal Guard Report</h1>
  <div class="summary">
    <div class="status">{status_text}</div>
    <div class="meta">
      Scanned at {_esc(report.timestamp)} &middot; Duration: {report.duration_seconds:.1f}s &middot;
      {len(report.skill_results)} skills &middot; {len(report.mcp_results)} MCP servers
    </div>
  </div>
'''
    if skills_rows:
        html += f'''
  <h2>Skills</h2>
  <table>
    <tr><th>Name</th><th>Verdict</th><th>Finding</th><th>Evidence</th><th>Remediation</th></tr>
    {skills_rows}
  </table>
'''
    if mcp_rows:
        html += f'''
  <h2>MCP Servers</h2>
  <table>
    <tr><th>Name</th><th>Verdict</th><th>Finding</th><th>Remediation</th></tr>
    {mcp_rows}
  </table>
'''
    if toxic_rows:
        html += f'''
  <h2>Toxic Flows</h2>
  <table>
    <tr><th>Risk</th><th>Title</th><th>Servers</th><th>Remediation</th></tr>
    {toxic_rows}
  </table>
'''
    if baseline_rows:
        html += f'''
  <h2>Baseline Changes</h2>
  <table>
    <tr><th>Server</th><th>Change</th><th>Detail</th></tr>
    {baseline_rows}
  </table>
'''
    html += f'''
  <div class="footer">Generated by AgentSeal v{__version__} &middot; agentseal.org</div>
</div>
</body>
</html>'''
    return html


def _run_config(args):
    """Manage local configuration."""
    from agentseal.config import config_set, config_show, config_remove, config_show_all_keys

    G = "\033[92m"
    Y = "\033[93m"
    D = "\033[90m"
    B = "\033[1m"
    C = "\033[96m"
    RST = "\033[0m"

    if args.action == "set":
        if not args.key or not args.value:
            print(f"  {Y}Usage: agentseal config set <key> <value>{RST}")
            print(f"  Run 'agentseal config keys' to see valid keys")
            return
        msg = config_set(args.key, args.value)
        print(f"  {G}{msg}{RST}")

    elif args.action == "show":
        config = config_show()
        if not config:
            print(f"\n  {D}No configuration set.{RST}")
            print(f"  {D}Run 'agentseal config keys' to see available options.{RST}")
            print(f"  {D}Example: agentseal config set model ollama/qwen3.5:cloud{RST}\n")
            return
        print(f"\n  {B}AgentSeal Configuration{RST}")
        print(f"  {'─' * 40}")
        for key, value in sorted(config.items()):
            print(f"  {key:<20s} {G}{value}{RST}")
        print(f"\n  {D}Stored in: ~/.agentseal/config.json{RST}\n")

    elif args.action == "remove":
        if not args.key:
            print(f"  {Y}Usage: agentseal config remove <key>{RST}")
            return
        msg = config_remove(args.key)
        print(f"  {G}{msg}{RST}")

    elif args.action == "keys":
        all_keys = config_show_all_keys()
        print(f"\n  {B}Available Config Keys{RST}")
        print(f"  {'─' * 50}")
        for key, desc in sorted(all_keys.items()):
            print(f"  {C}{key:<20s}{RST} {desc}")
        print(f"\n  {D}Example: agentseal config set model ollama/qwen3.5:cloud{RST}")
        print(f"  {D}Example: agentseal config set api-key sk-ant-xxx{RST}")
        print(f"  {D}Run 'agentseal config setup' for full LLM provider guide{RST}\n")

    elif args.action == "setup":
        from agentseal.config import get_setup_guide
        print(get_setup_guide())


def _run_registry(args):
    """Manage the MCP server registry."""
    from agentseal.mcp_registry import MCPRegistry

    R = "\033[91m"
    Y = "\033[93m"
    G = "\033[92m"
    D = "\033[90m"
    B = "\033[1m"
    C = "\033[96m"
    RST = "\033[0m"

    registry = MCPRegistry()

    if args.action == "info":
        print(f"\n  {B}MCP Server Registry{RST}")
        print(f"  {'─' * 40}")
        print(f"  Core servers (built-in):  {registry.core_count}")
        print(f"  Total servers loaded:     {registry.count}")
        cached = Path.home() / ".agentseal" / "mcp_registry.json"
        if cached.is_file():
            import datetime
            mtime = datetime.datetime.fromtimestamp(cached.stat().st_mtime)
            print(f"  Extended cache:           {cached}")
            print(f"  Last updated:             {mtime.strftime('%Y-%m-%d %H:%M')}")
        else:
            print(f"  Extended cache:           {D}not fetched{RST}")
            print(f"  {D}Run 'agentseal registry update' to fetch more servers{RST}")
        print()

    elif args.action == "update":
        print(f"\n  Fetching registry from AgentSeal API...")
        count, msg = registry.update_from_api(api_url=getattr(args, "api_url", None))
        if count > 0:
            print(f"  {G}{msg}{RST}")
        else:
            print(f"  {Y}{msg}{RST}")
        print(f"  Total servers now: {registry.count}")
        print()

    elif args.action == "list":
        risk_colors = {"critical": R, "high": Y, "medium": C, "low": G, "unknown": D}
        # Group by risk level
        by_risk: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": []}
        seen = set()
        for entry in registry.export_core():
            name = entry["name"]
            if name in seen:
                continue
            seen.add(name)
            rl = entry.get("risk_level", "unknown")
            if rl in by_risk:
                by_risk[rl].append(entry)

        print(f"\n  {B}MCP Server Registry — {registry.count} servers{RST}")
        print(f"  {'─' * 50}")
        for risk_level in ["critical", "high", "medium", "low"]:
            servers = by_risk[risk_level]
            if not servers:
                continue
            color = risk_colors.get(risk_level, D)
            print(f"\n  {color}{B}{risk_level.upper()}{RST} ({len(servers)})")
            for s in sorted(servers, key=lambda x: x["name"]):
                print(f"    {color}●{RST} {s['name']:<25s} {D}{s['description'][:50]}{RST}")
        print()


def _run_guard(args):
    """Run the guard command — machine-level security scan."""
    from agentseal.guard import Guard
    from agentseal.guard_models import GuardVerdict

    # Get path arg early -- used for both "guard init" detection and scan path
    scan_path = getattr(args, "path", None)

    # Handle "guard init" subcommand
    if scan_path == "init":
        from agentseal.project_config import run_guard_init
        force = getattr(args, "force", False)
        success = run_guard_init(target_dir=Path.cwd(), force=force)
        sys.exit(0 if success else 1)
        return

    # Handle "guard test" subcommand
    if scan_path == "test":
        from agentseal.rules import RuleEngine
        rules_path = getattr(args, "rules", None)
        rule_paths = []
        if rules_path:
            rule_paths = [rules_path]
        else:
            default_dir = Path.cwd() / ".agentseal" / "rules"
            if default_dir.is_dir():
                rule_paths = [str(default_dir)]
        if not rule_paths:
            print("No rules found. Create .agentseal/rules/*.yaml or use --rules")
            sys.exit(1)
            return
        try:
            engine = RuleEngine.from_paths(rule_paths)
        except ValueError as e:
            print(f"Rule error: {e}", file=sys.stderr)
            sys.exit(1)
            return
        results = engine.run_tests()
        if not results:
            print("No inline tests found in rules.")
            sys.exit(0)
            return
        W = 62
        SEP = f"  \033[90m{'-' * W}\033[0m"
        n_rules = len(set(r.rule_id for r in results))
        n_tests = len(results)
        print()
        print(SEP)
        print(f"  \033[1mRULE TESTS\033[0m{' ' * (W - 10 - len(str(n_rules)) - len(str(n_tests)) - 16)}\033[90m{n_rules} rules, {n_tests} tests\033[0m")
        print(SEP)
        passed = 0
        failed = 0
        for r in results:
            dots = "." * max(1, 50 - len(r.rule_id) - len(r.test_name))
            if r.passed:
                print(f"  {r.rule_id}  {r.test_name} {dots} \033[92mPASS\033[0m")
                passed += 1
            else:
                print(f"  {r.rule_id}  {r.test_name} {dots} \033[91mFAIL\033[0m")
                print(f"            Expected: {r.expected}, Got: {r.actual}")
                failed += 1
        print()
        print(f"  {passed} passed, {failed} failed")
        print()
        sys.exit(1 if failed > 0 else 0)
        return

    # Handle --from-json (re-render saved report, no re-scan)
    from_json_path = getattr(args, "from_json", None)
    if from_json_path:
        from agentseal.guard_models import GuardReport as _GR
        try:
            raw = json.loads(Path(from_json_path).read_text(encoding="utf-8"))
            report = _GR.from_dict(raw)
        except Exception as e:
            print(f"Error loading {from_json_path}: {e}", file=sys.stderr)
            sys.exit(1)
            return
        output_fmt = getattr(args, "output", "terminal")
        if output_fmt == "json":
            print(json.dumps(raw, indent=2))
        elif output_fmt == "sarif":
            sarif_json = json.dumps(report.to_sarif(), indent=2)
            print(sarif_json)
            if getattr(args, "save", None):
                Path(args.save).write_text(sarif_json, encoding="utf-8")
        elif output_fmt == "html":
            html = _guard_to_html(report)
            print(html)
            if getattr(args, "save", None):
                Path(args.save).write_text(html, encoding="utf-8")
        else:
            # Fall through to terminal rendering below
            pass
        if output_fmt != "terminal":
            sys.exit(0)
            return

    R = "\033[91m"     # Red
    Y = "\033[93m"     # Yellow
    G = "\033[92m"     # Green
    D = "\033[90m"     # Dim
    C = "\033[96m"     # Cyan
    B = "\033[1m"      # Bold
    RST = "\033[0m"    # Reset

    # Handle --reset-baselines
    if getattr(args, "reset_baselines", False):
        from agentseal.baselines import BaselineStore
        store = BaselineStore()
        count = store.reset()
        json_mode = getattr(args, "output", None) == "json"
        if not json_mode:
            print(f"  {D}Reset {count} baseline(s). All servers will be re-baselined.{RST}")
            print()

    json_mode = getattr(args, "output", None) == "json"
    structured_output = getattr(args, "output", None) in ("json", "sarif", "html")
    verbose = getattr(args, "verbose", False)

    if not structured_output:
        _print_banner(show_tagline=False)

    def on_progress(phase, detail):
        if not structured_output:
            print(f"  {D}{detail}{RST}")

    if not structured_output:
        print()
        from agentseal import __version__ as _guard_ver
        print(f"  {B}AgentSeal Guard{RST} {D}v{_guard_ver}{RST}")
        print()

    llm_judge = None
    # CLI flags take precedence, then fall back to saved config, then env vars
    from agentseal.config import get_llm_config
    saved = get_llm_config()
    model = getattr(args, "model", None) or saved.get("model")
    api_key = getattr(args, "api_key", None) or saved.get("api_key")
    # Resolve base_url: CLI --litellm-url > CLI --ollama-url > saved config
    base_url = getattr(args, "litellm_url", None)
    if not base_url:
        cli_ollama = getattr(args, "ollama_url", None)
        if cli_ollama and cli_ollama != "http://localhost:11434":
            # User explicitly passed --ollama-url (not the argparse default)
            base_url = cli_ollama.rstrip("/") + "/v1"
        else:
            base_url = saved.get("litellm_url")
            if not base_url and saved.get("ollama_url"):
                base_url = saved["ollama_url"].rstrip("/") + "/v1"
    if model:
        from agentseal.llm_judge import LLMJudge
        llm_judge = LLMJudge(
            model=model,
            api_key=api_key,
            base_url=base_url,
        )

    # Load project config
    from agentseal.project_config import resolve_project_config, should_ignore_finding, should_fail
    config_path_arg = getattr(args, "config", None)
    project_config = None
    try:
        project_config = resolve_project_config(
            config_path=Path(config_path_arg) if config_path_arg else None,
            search_dir=Path(scan_path) if scan_path else None,
        )
    except (FileNotFoundError, ValueError) as e:
        print(f"  {R}Config error: {e}{RST}", file=sys.stderr)
        sys.exit(1)

    if project_config and not structured_output:
        print(f"  {D}Using config: {project_config.config_path}{RST}")

    guard = Guard(
        semantic=not getattr(args, "no_semantic", False),
        verbose=verbose,
        on_progress=on_progress,
        connect=getattr(args, "connect", False),
        timeout=getattr(args, "timeout", 30.0),
        concurrency=getattr(args, "concurrency", 3),
        scan_path=scan_path,
        project_config=project_config,
        **({"llm_judge": llm_judge} if llm_judge else {}),
    )
    report = guard.run()

    # ── Auto-save report ──────────────────────────────────────────
    try:
        save_report(json.loads(report.to_json()), "guard")
    except Exception:
        pass  # Best-effort save

    # ── History: save raw report (before ignore_findings filtering) ──
    _hist_scan_path = str(Path(scan_path).resolve()) if scan_path else None
    _hist_store = None
    try:
        from agentseal.history import HistoryStore
        _hist_store = HistoryStore()
        _hist_store.save(report, scan_path=_hist_scan_path)
        _hist_store.prune()
    except Exception as e:
        if not structured_output:
            print(f"  {D}History: {e}{RST}", file=sys.stderr)

    # Apply ignore_findings from project config
    if project_config:
        report.config_path = project_config.config_path
        for sr in report.skill_results:
            sr.findings = [
                f for f in sr.findings
                if not should_ignore_finding(project_config, f.code, sr.path)
            ]
        for mr in report.mcp_results:
            mr.findings = [
                f for f in mr.findings
                if not should_ignore_finding(project_config, f.code, mr.source_file)
            ]

    # ── Custom rules evaluation ──────────────────────────────────
    try:
        from agentseal.rules import RuleEngine
        rule_paths = []
        rules_arg = getattr(args, "rules", None)
        if rules_arg:
            rule_paths = [rules_arg]
        elif project_config and hasattr(project_config, "rules_paths") and project_config.rules_paths:
            rule_paths = project_config.rules_paths
        else:
            default_dir = Path.cwd() / ".agentseal" / "rules"
            if default_dir.is_dir():
                rule_paths = [str(default_dir)]
        if rule_paths:
            engine = RuleEngine.from_paths(rule_paths)
            # Get raw MCP configs for rule matching
            from agentseal.machine_discovery import scan_machine, scan_directory
            if scan_path:
                _, raw_mcps, _ = scan_directory(Path(scan_path))
            else:
                _, raw_mcps, _ = scan_machine()
            raw_mcp_map = {s.get("name", ""): s for s in raw_mcps}
            for mr in report.mcp_results:
                raw = raw_mcp_map.get(mr.name, {"name": mr.name, "command": mr.command})
                report.custom_findings.extend(engine.evaluate_mcp(mr, raw))
            for sr in report.skill_results:
                try:
                    content = Path(sr.path).read_text(encoding="utf-8", errors="replace")[:10240]
                except Exception:
                    content = ""
                report.custom_findings.extend(engine.evaluate_skill(sr, content))
            for agent in report.agents_found:
                report.custom_findings.extend(engine.evaluate_agent(agent))
            # Apply ignore_findings to custom findings too
            if project_config:
                report.custom_findings = [
                    c for c in report.custom_findings
                    if not should_ignore_finding(project_config, c.code)
                ]
            if report.custom_findings and not structured_output:
                on_progress("rules", f"{len(report.custom_findings)} custom rule match(es)")
    except Exception as e:
        if not structured_output:
            import traceback
            on_progress("rules", f"Custom rules: {e}")

    # ── Registry enrichment ──────────────────────────────────────
    if not getattr(args, "no_registry", False) and report.mcp_results:
        try:
            from agentseal.registry_client import enrich_mcp_results
            api_key_env = os.environ.get("AGENTSEAL_API_KEY")
            if not structured_output:
                print(f"  {D}Checking registry...{RST}", end="", flush=True)
            enrich_mcp_results(report.mcp_results, api_key=api_key_env)
            if not structured_output:
                enriched = sum(1 for m in report.mcp_results if m.registry_score is not None)
                print(f"\r  {D}Registry: {enriched}/{len(report.mcp_results)} matched{RST}")
        except Exception:
            if not structured_output:
                print(f"\r  {D}Registry: skipped{RST}")

    # ── History: compute delta ───────────────────────────────────
    delta = None
    if not getattr(args, "no_diff", False) and _hist_store:
        try:
            from agentseal.history import compute_delta
            prev = _hist_store.load_previous(scan_path=_hist_scan_path)
            if prev:
                # Apply same ignore_findings to previous for fair comparison
                if project_config:
                    for sr in prev.skill_results:
                        sr.findings = [
                            f for f in sr.findings
                            if not should_ignore_finding(project_config, f.code, sr.path)
                        ]
                    for mr in prev.mcp_results:
                        mr.findings = [
                            f for f in mr.findings
                            if not should_ignore_finding(project_config, f.code, mr.source_file)
                        ]
                delta = compute_delta(report, prev, scan_path=_hist_scan_path)
                if not delta.entries:
                    delta = None  # Don't show empty delta
            _hist_store.close()
        except Exception as e:
            if not structured_output:
                print(f"  {D}History: {e}{RST}", file=sys.stderr)

    def _exit_code():
        # CLI --fail-on overrides project config
        fail_on = getattr(args, "fail_on", None)
        if fail_on is None and project_config:
            fail_on = project_config.fail_on
        if fail_on:
            has_error = any(
                s.verdict == GuardVerdict.ERROR for s in report.skill_results
            )
            return 1 if should_fail(
                fail_on,
                has_danger=report.total_dangers > 0 or has_error,
                has_warning=report.total_warnings > 0,
                has_safe=report.total_safe > 0,
            ) else 0
        return 1 if report.has_critical else 0

    # ── JSON output ────────────────────────────────────────────────
    if json_mode:
        d = json.loads(report.to_json())
        d["delta"] = delta.to_dict() if delta else None
        print(json.dumps(d, indent=2))
        if getattr(args, "save", None):
            Path(args.save).write_text(json.dumps(d, indent=2), encoding="utf-8")
            print(f"Saved to {args.save}", file=sys.stderr)
        sys.exit(_exit_code())
        return

    # ── SARIF output ──────────────────────────────────────────────
    if getattr(args, "output", None) == "sarif":
        sarif_data = report.to_sarif()
        sarif_json = json.dumps(sarif_data, indent=2)
        print(sarif_json)
        if getattr(args, "save", None):
            Path(args.save).write_text(sarif_json, encoding="utf-8")
            print(f"Saved to {args.save}", file=sys.stderr)
        sys.exit(_exit_code())
        return

    # ── HTML output ───────────────────────────────────────────────
    if getattr(args, "output", None) == "html":
        html = _guard_to_html(report)
        print(html)
        if getattr(args, "save", None):
            Path(args.save).write_text(html, encoding="utf-8")
            print(f"Saved to {args.save}", file=sys.stderr)
        sys.exit(_exit_code())
        return

    # ── Terminal output (tree style) ────────────────────────────────
    import re as _re
    print()

    _ANSI_RE = _re.compile(r'\033\[[0-9;]*m')

    def _vlen(s):
        return len(_ANSI_RE.sub('', s))

    def _sev_color(severity):
        return {"critical": R, "high": Y, "medium": C, "low": D}.get(severity, D)

    def _sev_tag(code, severity):
        c = _sev_color(severity)
        return f"{c}[{code} {severity}]{RST}"

    def _path_short(p, maxlen=50):
        if not p or len(p) <= maxlen:
            return p or ""
        parts = p.split("/")
        if len(parts) > 3:
            return "~/" + "/".join(parts[-2:])
        return "..." + p[-(maxlen - 3):]

    # Tree characters
    T_MID  = f"{D}\u2502{RST}"   # │
    T_TEE  = f"{D}\u251c\u2500\u2500{RST}"  # ├──
    T_END  = f"{D}\u2514\u2500\u2500{RST}"  # └──
    T_DOT  = "\u25cf"  # ●

    # ── Agents ──
    installed = [a for a in report.agents_found if a.status != "not_installed"]
    agents_to_show = report.agents_found if verbose else installed
    if agents_to_show:
        print(f"  {T_DOT} {B}Found {len(installed)} agents{RST}")
        print()
        for i, agent in enumerate(agents_to_show):
            is_last = (i == len(agents_to_show) - 1)
            branch = T_END if is_last else T_TEE
            if agent.status == "found":
                mcp_info = f" ({agent.mcp_servers} MCP)" if agent.mcp_servers > 0 else ""
                config = _path_short(agent.config_path)
                print(f"  {branch} {G}{agent.name}{RST}{mcp_info}")
                cont = "    " if is_last else f"  {T_MID} "
                print(f"  {cont} {D}{config}{RST}")
            elif agent.status == "installed_no_config":
                print(f"  {branch} {D}{agent.name}{RST} {D}(installed, no config){RST}")
            elif agent.status == "error":
                print(f"  {branch} {Y}{agent.name}{RST} {D}(error){RST}")
            else:
                print(f"  {branch} {D}{agent.name} (not found){RST}")
        print()

    # ── Skills ──
    if report.skill_results:
        n_skills = len(report.skill_results)
        safe_count = sum(1 for sr in report.skill_results if sr.verdict == GuardVerdict.SAFE)
        threat_skills = [sr for sr in report.skill_results if sr.verdict != GuardVerdict.SAFE]
        print(f"  {T_DOT} {B}Scanned {n_skills} skill(s){RST}")
        print()
        items = threat_skills if not verbose else report.skill_results
        for i, sr in enumerate(items):
            has_safe_footer = (not verbose and safe_count > 0)
            is_last = (i == len(items) - 1) and not has_safe_footer
            branch = T_END if is_last else T_TEE
            cont = "    " if is_last else f"  {T_MID} "

            if sr.verdict in (GuardVerdict.DANGER, GuardVerdict.WARNING):
                # Severity summary
                sev_counts = {}
                for f in sr.findings:
                    sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
                sev_parts = ", ".join(f"{n} {s}" for s, n in sorted(sev_counts.items(), key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x[0], 9)))
                sev_info = f" ({sev_parts})" if sev_parts else ""
                name_color = R if sr.verdict == GuardVerdict.DANGER else Y
                print(f"  {branch} {name_color}{sr.name}{RST}{sev_info}")
                for j, finding in enumerate(sr.findings):
                    is_last_f = (j == len(sr.findings) - 1)
                    f_branch = T_END if is_last_f else T_TEE
                    tag = _sev_tag(finding.code, finding.severity)
                    print(f"  {cont}{f_branch} {tag}: {finding.title}")
                    f_cont = "    " if is_last_f else f"  {T_MID} "
                    if finding.evidence and (sr.verdict == GuardVerdict.DANGER or verbose):
                        ev = finding.evidence[:80].replace("\n", " ")
                        print(f"  {cont}{f_cont}{D}evidence: \"{ev}\"{RST}")
                    print(f"  {cont}{f_cont}{C}fix: {finding.remediation}{RST}")
            elif sr.verdict == GuardVerdict.ERROR:
                top = sr.top_finding
                desc = top.description if top else "Could not read"
                print(f"  {branch} {D}{sr.name} - {desc}{RST}")
            else:
                print(f"  {branch} {G}{sr.name}{RST} {G}clean{RST}")

        if safe_count > 0 and not verbose:
            print(f"  {T_END} {G}{safe_count} clean skill(s){RST}")
        print()

    # ── MCP Servers ──
    if report.mcp_results:
        n_mcp = len(report.mcp_results)
        # Group by source_file
        by_source: dict[str, list] = {}
        for mr in report.mcp_results:
            src = mr.source_file or "unknown"
            by_source.setdefault(src, []).append(mr)

        print(f"  {T_DOT} {B}Scanned {n_mcp} MCP server(s){RST}")
        print()

        source_keys = list(by_source.keys())
        for si, source in enumerate(source_keys):
            servers = by_source[source]
            is_last_source = (si == len(source_keys) - 1)
            source_short = _path_short(source)
            print(f"  {T_DOT} {D}Scanning {source_short}{RST} - {B}{len(servers)} server(s){RST}")
            print()
            for i, mr in enumerate(servers):
                is_last = (i == len(servers) - 1)
                branch = T_END if is_last else T_TEE
                cont = "    " if is_last else f"  {T_MID} "

                # Severity summary for this server
                sev_counts = {}
                for f in mr.findings:
                    sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
                sev_parts = ", ".join(f"{n} {s}" for s, n in sorted(sev_counts.items(), key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x[0], 9)))
                sev_info = f" ({sev_parts})" if sev_parts else ""

                # Registry info
                reg_info = ""
                if mr.registry_score is not None:
                    rs = int(mr.registry_score)
                    rl = mr.registry_level or "?"
                    if rl in ("EXCELLENT", "HIGH"):
                        reg_info = f" {D}registry:{RST} {G}{rs} {rl}{RST}"
                    elif rl == "MEDIUM":
                        reg_info = f" {D}registry:{RST} {Y}{rs} {rl}{RST}"
                    else:
                        reg_info = f" {D}registry:{RST} {R}{rs} {rl}{RST}"

                if mr.verdict == GuardVerdict.DANGER:
                    print(f"  {branch} {R}{mr.name}{RST}{sev_info}{reg_info}")
                elif mr.verdict == GuardVerdict.WARNING:
                    print(f"  {branch} {Y}{mr.name}{RST}{sev_info}{reg_info}")
                else:
                    print(f"  {branch} {G}{mr.name}{RST} {G}clean{RST}{reg_info}")

                # Show registry tools with verified/failed status
                if mr.registry_tools:
                    tools = mr.registry_tools
                    failed = [t for t in tools if isinstance(t, dict) and t.get("status") == "failed"]
                    verified = [t for t in tools if not isinstance(t, dict) or t.get("status") != "failed"]
                    total = len(tools)

                    if total > 12:
                        # Many tools: show only failed, summarize verified
                        shown = failed
                    else:
                        shown = tools

                    for ti, tool in enumerate(shown):
                        tname = tool.get("name", "?") if isinstance(tool, dict) else str(tool)
                        tstatus = tool.get("status", "verified") if isinstance(tool, dict) else "verified"
                        tfinding = tool.get("finding") if isinstance(tool, dict) else None
                        tsev = tool.get("severity") if isinstance(tool, dict) else None
                        is_last_tool = (ti == len(shown) - 1) and (total <= 12 or not verified) and not mr.findings
                        t_branch = T_END if is_last_tool else T_TEE
                        if tstatus == "failed" and tfinding:
                            sev_c = _sev_color(tsev) if tsev else R
                            print(f"  {cont}{t_branch} {D}tool{RST}  {D}{tname:<24}{RST} {sev_c}\u2718{RST} {sev_c}{tfinding}{RST}")
                        else:
                            print(f"  {cont}{t_branch} {D}tool{RST}  {D}{tname:<24}{RST} {G}\u2714{RST} {G}verified{RST}")

                    if total > 12 and verified:
                        is_last_v = not mr.findings
                        v_branch = T_END if is_last_v else T_TEE
                        print(f"  {cont}{v_branch} {G}\u2714 {len(verified)} more tools verified{RST}")

                for j, finding in enumerate(mr.findings):
                    is_last_f = (j == len(mr.findings) - 1)
                    f_branch = T_END if is_last_f else T_TEE
                    tag = _sev_tag(finding.code, finding.severity)
                    print(f"  {cont}{f_branch} {tag}: {finding.title}")
                    f_cont = "    " if is_last_f else f"  {T_MID} "
                    print(f"  {cont}{f_cont}{C}fix: {finding.remediation}{RST}")
            print()

    # ── MCP Runtime ──
    if report.mcp_runtime_results:
        n_rt = len(report.mcp_runtime_results)
        print(f"  {T_DOT} {B}Runtime analysis - {n_rt} server(s){RST}")
        print()
        for i, rr in enumerate(report.mcp_runtime_results):
            is_last = (i == len(report.mcp_runtime_results) - 1)
            branch = T_END if is_last else T_TEE
            cont = "    " if is_last else f"  {T_MID} "
            if rr.connection_status != "connected":
                print(f"  {branch} {D}{rr.server_name} ({rr.connection_status}){RST}")
            else:
                color = R if rr.verdict == GuardVerdict.DANGER else (Y if rr.verdict == GuardVerdict.WARNING else G)
                print(f"  {branch} {color}{rr.server_name}{RST} ({rr.tools_found} tools, {len(rr.findings)} findings)")
                for j, finding in enumerate(rr.findings):
                    is_last_f = (j == len(rr.findings) - 1)
                    f_branch = T_END if is_last_f else T_TEE
                    tag = _sev_tag(finding.code, finding.severity)
                    print(f"  {cont}{f_branch} {tag}: {finding.title}")
        print()

    # ── Toxic Flows ──
    if report.toxic_flows:
        n_flows = len(report.toxic_flows)
        print(f"  {T_DOT} {R}{B}{n_flows} toxic flow(s) detected{RST}")
        print()
        for i, flow in enumerate(report.toxic_flows):
            is_last = (i == len(report.toxic_flows) - 1)
            branch = T_END if is_last else T_TEE
            cont = "    " if is_last else f"  {T_MID} "
            level_color = R if flow.risk_level == "high" else Y
            print(f"  {branch} {level_color}{flow.risk_level.upper()}{RST}: {flow.title}")
            servers = ", ".join(flow.servers_involved)
            print(f"  {cont}{D}servers: {servers}{RST}")
            print(f"  {cont}{C}fix: {flow.remediation}{RST}")
        print()

    # ── Baseline Changes ──
    if report.baseline_changes:
        n_bl = len(report.baseline_changes)
        print(f"  {T_DOT} {Y}{B}{n_bl} baseline change(s){RST}")
        print()
        for i, change in enumerate(report.baseline_changes):
            is_last = (i == len(report.baseline_changes) - 1)
            branch = T_END if is_last else T_TEE
            print(f"  {branch} {Y}{change.server_name}{RST} - {change.change_type}: {change.detail}")
        print()

    # ── Unlisted (project config) ──
    if report.unlisted_findings:
        n_unlisted = len(report.unlisted_findings)
        print(f"  {T_DOT} {Y}{B}{n_unlisted} unlisted item(s){RST}")
        print()
        for i, uf in enumerate(report.unlisted_findings):
            is_last = (i == len(report.unlisted_findings) - 1)
            branch = T_END if is_last else T_TEE
            print(f"  {branch} {Y}{uf.item_name}{RST}: {uf.description}")
        print()

    # ── Custom Rules ──
    if report.custom_findings:
        n_custom = len(report.custom_findings)
        print(f"  {T_DOT} {B}{n_custom} custom rule match(es){RST}")
        print()
        for i, cf in enumerate(report.custom_findings):
            is_last = (i == len(report.custom_findings) - 1)
            branch = T_END if is_last else T_TEE
            cont = "    " if is_last else f"  {T_MID} "
            tag = _sev_tag(cf.code, cf.severity)
            print(f"  {branch} {tag}: {cf.title}")
            print(f"  {cont}{D}{cf.entity_name} ({cf.entity_type}){RST}")
            if cf.remediation:
                print(f"  {cont}{C}fix: {cf.remediation}{RST}")
        print()

    # ── Summary ──
    _sev_counts = _count_severities(report)
    sev_parts = []
    for sev_name, color in [("critical", R), ("high", Y), ("medium", C), ("low", D)]:
        n = _sev_counts.get(sev_name, 0)
        if n > 0:
            sev_parts.append(f"{color}{n} {sev_name}{RST}")

    if sev_parts:
        print(f"  {T_DOT} {B}Summary:{RST} {', '.join(sev_parts)}")
    else:
        print(f"  {T_DOT} {B}Summary:{RST} {G}clean{RST}")

    if report.has_critical:
        print(f"    {R}{report.total_dangers} critical threat(s) found. Action required.{RST}")
    elif report.total_toxic_flows > 0:
        print(f"    {Y}{report.total_toxic_flows} toxic flow(s) detected. Review recommended.{RST}")
    elif report.total_warnings > 0:
        print(f"    {Y}{report.total_warnings} warning(s) found. Review recommended.{RST}")
    else:
        print(f"    {G}No threats detected. Machine looks clean.{RST}")
    print()

    # ── Delta ──
    if delta:
        def _verdict_rank(v):
            return {"safe": 2, "warning": 1, "danger": 0, "error": 0}.get(v, -1)

        ts_display = delta.previous_timestamp[:16].replace("T", " ")
        print(f"  {T_DOT} {B}Delta{RST} {D}(vs {ts_display}){RST}")
        print()
        for i, entry in enumerate(delta.entries):
            is_last = (i == len(delta.entries) - 1)
            branch = T_END if is_last else T_TEE
            if entry.change_type in ("new", "new_entity"):
                sev_color = R if entry.severity in ("critical", "high") else Y
                label = f"{sev_color}+ NEW{RST}"
                detail = f"{entry.entity_name}: {entry.title}" if entry.title else entry.entity_name
                print(f"  {branch} {label} {detail}")
            elif entry.change_type in ("resolved", "removed_entity"):
                label = f"{G}- RESOLVED{RST}"
                detail = f"{entry.entity_name}: {entry.title}" if entry.title else entry.entity_name
                print(f"  {branch} {label} {detail}")
            elif entry.change_type == "changed":
                upgrade = _verdict_rank(entry.new_verdict) > _verdict_rank(entry.old_verdict)
                color = G if upgrade else Y
                label = f"{color}~ CHANGED{RST}"
                print(f"  {branch} {label} {entry.entity_name}: {entry.old_verdict} -> {entry.new_verdict}")
        print()

    # ── Actions ──
    actions = report.all_actions
    for flow in report.toxic_flows:
        actions.append(flow.remediation)
    if actions:
        print(f"  {B}Actions:{RST}")
        for i, action in enumerate(actions, 1):
            print(f"    {i}. {action}")
        print()

    print(f"  {D}Completed in {report.duration_seconds:.1f}s{RST}")
    print()

    # Save if requested
    if getattr(args, "save", None):
        Path(args.save).write_text(report.to_json(), encoding="utf-8")
        print(f"  {D}Results saved to {args.save}{RST}")
        print()

    # Exit code: determined by project config or default critical check
    sys.exit(_exit_code())


def _run_scan_mcp(args):
    """Run the scan-mcp command — runtime MCP server scanning."""
    from agentseal.scan_mcp import ScanMCP

    R = "\033[91m"
    Y = "\033[93m"
    G = "\033[92m"
    D = "\033[90m"
    C = "\033[96m"
    B = "\033[1m"
    RST = "\033[0m"

    json_mode = getattr(args, "output", None) == "json"
    verbose = getattr(args, "verbose", False)

    # Handle --reset-baselines
    if getattr(args, "reset_baselines", False):
        from agentseal.baselines import BaselineStore
        store = BaselineStore()
        count = store.reset()
        if not json_mode:
            print(f"  {D}Reset {count} baseline(s). All servers will be re-baselined.{RST}")
            print()

    # Determine which servers to scan
    servers: list[dict] = []

    if getattr(args, "url", None):
        # Direct URL scan
        servers = [{"name": args.url, "url": args.url, "agent_type": "remote"}]
    else:
        # Discover from machine
        from agentseal.machine_discovery import scan_machine
        _agents, mcp_servers, _skills = scan_machine()

        if getattr(args, "server", None):
            # Filter to specific server
            target = args.server.lower()
            servers = [s for s in mcp_servers if s.get("name", "").lower() == target]
            if not servers:
                if not json_mode:
                    print(f"  {R}Error:{RST} Server '{args.server}' not found in config.")
                    print(f"  {D}Available servers:{RST}")
                    for s in mcp_servers:
                        print(f"    - {s.get('name', 'unknown')}")
                sys.exit(1)
        else:
            servers = mcp_servers

    if not servers:
        if not json_mode:
            print(f"  {D}No MCP servers found. Nothing to scan.{RST}")
        sys.exit(0)

    # Confirmation prompt (skip with --yes or in JSON mode)
    if not json_mode and not getattr(args, "yes", False):
        print()
        print(f"  {B}AgentSeal scan-mcp{RST} — Runtime MCP Server Scanner")
        print(f"  {'─' * 52}")
        print()
        print(f"  Will connect to {B}{len(servers)}{RST} MCP server(s):")
        for s in servers:
            cmd = s.get("command", s.get("url", "?"))
            print(f"    {C}•{RST} {s.get('name', 'unknown')} ({D}{cmd}{RST})")
        print()
        try:
            answer = input(f"  Proceed? [{G}Y{RST}/n] ").strip().lower()
            if answer and answer not in ("y", "yes"):
                print(f"  {D}Cancelled.{RST}")
                sys.exit(0)
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

    if not json_mode:
        _print_banner(show_tagline=False)
        print()
        print(f"  {B}AgentSeal scan-mcp{RST} — Runtime MCP Server Scanner")
        print(f"  {'─' * 52}")
        print()

    def on_progress(phase, detail):
        if not json_mode:
            print(f"  {D}{detail}{RST}")

    scanner = ScanMCP(
        timeout=getattr(args, "timeout", 30.0),
        concurrency=getattr(args, "concurrency", 3),
        on_progress=on_progress,
    )
    report = scanner.run(servers)

    # ── JSON output ────────────────────────────────────────────────
    if json_mode:
        print(report.to_json())
        if getattr(args, "save", None):
            Path(args.save).write_text(report.to_json(), encoding="utf-8")
            print(f"Saved to {args.save}", file=sys.stderr)
        exit_code = 0
        if report.has_critical:
            exit_code = 1
        if getattr(args, "min_score", None) and report.min_score < args.min_score:
            exit_code = 1
        sys.exit(exit_code)
        return

    # ── Terminal output (tree style) ─────────────────────────────
    print()

    def _sev_color_mcp(severity):
        return {"critical": R, "high": Y, "medium": C, "low": D}.get(severity, D)

    def _sev_tag_mcp(code, severity):
        c = _sev_color_mcp(severity)
        return f"{c}[{code} {severity}]{RST}"

    # Tree characters
    T_MID  = f"{D}\u2502{RST}"   # │
    T_TEE  = f"{D}\u251c\u2500\u2500{RST}"  # ├──
    T_END  = f"{D}\u2514\u2500\u2500{RST}"  # └──
    T_DOT  = "\u25cf"  # ●

    # ── Servers ──
    all_scores = list(report.trust_scores)
    conn_errors = list(report.connection_errors)

    print(f"  {T_DOT} {B}Scanned {report.servers_scanned} MCP server(s){RST}")
    print()

    for idx, score in enumerate(all_scores):
        rr = next((r for r in report.runtime_results if r.server_name == score.server_name), None)
        tools_found = rr.tools_found if rr else 0
        findings_count = len(rr.findings) if rr else 0
        has_more_after = (idx < len(all_scores) - 1) or conn_errors
        is_last = not has_more_after

        branch = T_END if is_last else T_TEE
        cont = "    " if is_last else f"  {T_MID} "

        # Score color
        if score.score >= 80:
            sc = G
        elif score.score >= 60:
            sc = Y
        else:
            sc = R

        # Server header: name (N tools)    score/100 LEVEL  or  OK
        if findings_count == 0:
            score_tag = f"{G}OK{RST}"
        else:
            score_tag = f"{sc}{score.score}/100 {score.level.upper()}{RST}"

        print(f"  {branch} {B}{score.server_name}{RST} {D}({tools_found} tools){RST}    {score_tag}")

        # Show tool names from findings (unique tools that had findings)
        if rr and rr.findings:
            tool_names = []
            for f in rr.findings:
                if f.tool_name and f.tool_name not in tool_names:
                    tool_names.append(f.tool_name)
            for ti, tn in enumerate(tool_names):
                is_last_tool = (ti == len(tool_names) - 1) and not rr.findings
                t_branch = T_END if is_last_tool else T_TEE
                print(f"  {cont}{t_branch} {D}tool{RST}      {tn}")

            # Show findings
            visible_findings = [
                f for f in rr.findings
                if verbose or f.severity in ("critical", "high")
            ]
            for fi, finding in enumerate(visible_findings):
                is_last_f = (fi == len(visible_findings) - 1)
                tag = _sev_tag_mcp(finding.code, finding.severity)
                print(f"  {cont}{T_DOT} {tag}: {finding.title}")
                print(f"  {cont}  {C}fix: {finding.remediation}{RST}")

    # Connection errors
    for ei, err in enumerate(conn_errors):
        is_last_err = (ei == len(conn_errors) - 1)
        branch = T_END if is_last_err else T_TEE
        server_name = err.get('server_name', '?')
        error_type = err.get('error_type', 'error').upper()
        detail = err.get('detail', '')
        print(f"  {branch} {D}{server_name}{RST} {R}({error_type}){RST} {D}{detail}{RST}")

    print()

    # ── Toxic Flows ──
    if report.toxic_flows:
        n_flows = len(report.toxic_flows)
        print(f"  {T_DOT} {R}{B}{n_flows} toxic flow(s) detected{RST}")
        print()
        for i, flow in enumerate(report.toxic_flows):
            is_last = (i == len(report.toxic_flows) - 1)
            branch = T_END if is_last else T_TEE
            cont = "    " if is_last else f"  {T_MID} "
            level_color = R if flow.risk_level == "high" else Y
            print(f"  {branch} {level_color}{flow.risk_level.upper()}{RST}: {flow.title}")
            if flow.tools_involved:
                print(f"  {cont}{D}tools: {', '.join(flow.tools_involved)}{RST}")
            print(f"  {cont}{C}fix: {flow.remediation}{RST}")
        print()

    # ── Baseline Changes (Rug Pulls) ──
    if report.baseline_changes:
        n_bl = len(report.baseline_changes)
        print(f"  {T_DOT} {R}{B}{n_bl} baseline change(s) (rug pull detection){RST}")
        print()
        for i, change in enumerate(report.baseline_changes):
            is_last = (i == len(report.baseline_changes) - 1)
            branch = T_END if is_last else T_TEE
            if change.change_type in ("tools_changed", "tools_added"):
                color = R if change.change_type == "tools_changed" else Y
            else:
                color = D
            print(f"  {branch} {color}{change.server_name}{RST}: {change.detail}")
        print()

    # ── Summary ──
    sev_parts = []
    if report.total_critical > 0:
        sev_parts.append(f"{R}{report.total_critical} critical{RST}")
    if report.total_high > 0:
        sev_parts.append(f"{Y}{report.total_high} high{RST}")
    if report.total_medium > 0:
        sev_parts.append(f"{D}{report.total_medium} medium{RST}")

    if sev_parts:
        print(f"  {T_DOT} {B}Summary:{RST} {', '.join(sev_parts)}")
    else:
        print(f"  {T_DOT} {B}Summary:{RST} {G}clean{RST}")

    print(f"    Servers: {report.servers_connected} connected, {report.servers_failed} failed")
    print(f"    Tools:   {report.total_tools} analyzed")
    if report.baseline_changes:
        print(f"    {R}Rug pulls: {len(report.baseline_changes)} detected{RST}")
    if report.toxic_flows:
        print(f"    Toxic flows: {len(report.toxic_flows)}")
    print(f"    {D}Completed in {report.duration_seconds:.1f}s{RST}")
    print()

    # Save if requested
    if getattr(args, "save", None):
        Path(args.save).write_text(report.to_json(), encoding="utf-8")
        print(f"  {D}Results saved to {args.save}{RST}")
        print()

    # Exit code
    exit_code = 0
    if report.has_critical:
        exit_code = 1
    if getattr(args, "min_score", None) and report.min_score < args.min_score:
        exit_code = 1
    if exit_code:
        sys.exit(exit_code)


def _resolve_llm_judge(args):
    """Build an LLMJudge from CLI args + saved config, or return None."""
    from agentseal.config import get_llm_config
    saved = get_llm_config()
    model = getattr(args, "model", None) or saved.get("model")
    api_key = getattr(args, "api_key", None) or saved.get("api_key")
    base_url = getattr(args, "litellm_url", None)
    if not base_url:
        cli_ollama = getattr(args, "ollama_url", None)
        if cli_ollama and cli_ollama != "http://localhost:11434":
            base_url = cli_ollama.rstrip("/") + "/v1"
        else:
            base_url = saved.get("litellm_url")
            if not base_url and saved.get("ollama_url"):
                base_url = saved["ollama_url"].rstrip("/") + "/v1"
    if model:
        from agentseal.llm_judge import LLMJudge
        return LLMJudge(model=model, api_key=api_key, base_url=base_url)
    return None


def _run_shield_menubar(args):
    """Run shield as a macOS menu bar app."""
    R = "\033[91m"
    B = "\033[1m"
    RST = "\033[0m"

    try:
        from agentseal.shield import check_watchdog_available
        check_watchdog_available()
    except ImportError:
        print(
            f"{R}Error:{RST} agentseal shield --menubar requires 'watchdog'.\n"
            f"Install with: {B}pip install agentseal[shield]{RST}",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        from agentseal.shield_menubar import ShieldMenuBarApp, check_rumps_available
        check_rumps_available()
    except ImportError:
        print(
            f"{R}Error:{RST} agentseal shield --menubar requires 'rumps' (macOS only).\n"
            f"Install with: {B}pip install agentseal[shield-menubar]{RST}",
            file=sys.stderr,
        )
        sys.exit(1)

    llm_judge = _resolve_llm_judge(args)

    app = ShieldMenuBarApp(
        semantic=not getattr(args, "no_semantic", False),
        notify=not getattr(args, "no_notify", False),
        debounce_seconds=getattr(args, "debounce", 2.0),
        llm_judge=llm_judge,
    )
    app.run()


def _run_shield(args):
    """Run the shield command — continuous filesystem monitoring."""
    R = "\033[91m"
    Y = "\033[93m"
    G = "\033[92m"
    D = "\033[90m"
    B = "\033[1m"
    C = "\033[96m"
    RST = "\033[0m"

    quiet = getattr(args, "quiet", False)

    try:
        from agentseal.shield import Shield, check_watchdog_available
        check_watchdog_available()
    except ImportError:
        print(
            f"{R}Error:{RST} agentseal shield requires the 'watchdog' package.\n"
            f"Install with: {B}pip install agentseal[shield]{RST}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Handle --reset-baselines
    if getattr(args, "reset_baselines", False):
        from agentseal.baselines import BaselineStore
        store = BaselineStore()
        count = store.reset()
        if not quiet:
            print(f"  {D}Reset {count} baseline(s). All servers will be re-baselined.{RST}")
            print()

    if not quiet:
        _print_banner(show_tagline=False)
        print()
        print(f"  {B}AgentSeal Shield{RST} — Continuous Monitoring")
        print(f"  {'─' * 48}")
        print()

    def on_event(event_type, path, summary):
        if quiet:
            return
        ts = time.strftime("%H:%M:%S")
        if event_type == "threat":
            print(f"  {D}[{ts}]{RST} {R}THREAT{RST} {path}")
            print(f"           {R}{summary}{RST}")
        elif event_type == "warning":
            print(f"  {D}[{ts}]{RST} {Y}WARNING{RST} {path}")
            print(f"           {Y}{summary}{RST}")
        elif event_type == "clean":
            print(f"  {D}[{ts}]{RST} {G}CLEAN{RST}   {path}")
        elif event_type == "error":
            print(f"  {D}[{ts}]{RST} {D}ERROR{RST}   {path} — {summary}")

    llm_judge = _resolve_llm_judge(args)

    shield = Shield(
        semantic=not getattr(args, "no_semantic", False),
        notify=not getattr(args, "no_notify", False),
        debounce_seconds=getattr(args, "debounce", 2.0),
        on_event=on_event,
        **({"llm_judge": llm_judge} if llm_judge else {}),
    )

    dirs_watched, files_watched = shield.start()

    if not quiet:
        print(f"  {D}Watching {dirs_watched} directories for changes...{RST}")
        print(f"  {D}Press Ctrl+C to stop.{RST}")
        print()

    shield.run_forever()

    if not quiet:
        print()
        print(f"  {D}Shield stopped. {shield.scan_count} scans, "
              f"{shield.threat_count} threats detected.{RST}")
        print()


def _resolve_prompt(args, require_url: bool = True) -> str | None:
    """Resolve system prompt from CLI args. Shared by scan and watch commands."""
    system_prompt = None

    if getattr(args, "prompt", None):
        system_prompt = args.prompt
    elif getattr(args, "prompt_inline", None):
        system_prompt = args.prompt_inline
    elif getattr(args, "file", None):
        path = Path(args.file)
        if not path.exists():
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        system_prompt = path.read_text().strip()
    elif getattr(args, "claude_desktop", False):
        system_prompt, model_hint = _detect_claude_desktop()
        if not args.model and model_hint:
            args.model = model_hint
    elif getattr(args, "cursor", False):
        system_prompt = _detect_cursor()
    elif require_url and not getattr(args, "url", None):
        print("Error: Provide --prompt, --file, or --url", file=sys.stderr)
        sys.exit(1)

    return system_prompt


async def _run_scan(args):
    from agentseal.validator import AgentValidator, ScanReport

    # ── Apply profile if specified ───────────────────────────────────
    if getattr(args, "profile", None):
        apply_profile(args, resolve_profile(args.profile))

    # ── Apply defaults for optional fields not set by user or profile ─
    if args.concurrency is None:
        args.concurrency = 3
    if args.timeout is None:
        args.timeout = 30.0

    # ── Resolve system prompt ────────────────────────────────────────
    system_prompt = _resolve_prompt(args)

    if system_prompt is None and not getattr(args, "url", None):
        if getattr(args, "claude_desktop", False) or getattr(args, "cursor", False):
            pass  # Already handled
        else:
            print("Error: Provide --prompt, --file, --url, --claude-desktop, or --cursor", file=sys.stderr)
            sys.exit(1)

    # ── Pro feature gates ────────────────────────────────────────────
    if args.mcp and not _pro_gate("MCP Tool Poisoning Probes"):
        sys.exit(1)
    if args.rag and not _pro_gate("RAG Poisoning Probes"):
        sys.exit(1)
    if args.genome and not _pro_gate("Genome Mapping"):
        sys.exit(1)

    # ── Build the agent function ─────────────────────────────────────
    if args.url:
        # HTTP endpoint mode
        validator = AgentValidator.from_endpoint(
            url=args.url,
            ground_truth_prompt=system_prompt,
            agent_name=args.name,
            message_field=args.message_field,
            response_field=args.response_field,
            concurrency=args.concurrency,
            timeout_per_probe=args.timeout,
            verbose=args.verbose,
            adaptive=args.adaptive,
            semantic=args.semantic,
            mcp=args.mcp,
            rag=args.rag,
            custom_probes=getattr(args, "probes", None),
        )
    elif system_prompt and args.model:
        # Direct model testing
        agent_fn = _build_agent_fn(
            model=args.model,
            system_prompt=system_prompt,
            api_key=args.api_key,
            ollama_url=args.ollama_url,
            litellm_url=args.litellm_url,
        )
        validator = AgentValidator(
            agent_fn=agent_fn,
            ground_truth_prompt=system_prompt,
            agent_name=args.name,
            concurrency=args.concurrency,
            timeout_per_probe=args.timeout,
            verbose=args.verbose,
            on_progress=_cli_progress if args.output == "terminal" else None,
            adaptive=args.adaptive,
            semantic=args.semantic,
            mcp=args.mcp,
            rag=args.rag,
            custom_probes=getattr(args, "probes", None),
        )
    else:
        print("Error: --model is required when testing a prompt directly", file=sys.stderr)
        sys.exit(1)

    # ── Run the scan ─────────────────────────────────────────────────
    if args.output == "terminal":
        _print_banner(show_tagline=False)
        print(f"\033[90m   ─────────────────────────────────────────\033[0m")
        if system_prompt:
            preview = system_prompt[:55].replace("\n", " ")
            suffix = "\033[90m...\033[0m" if len(system_prompt) > 55 else ""
            print(f"   \033[38;5;75mTarget\033[0m   \033[90m│\033[0m  {preview}{suffix}")
        elif args.url:
            print(f"   \033[38;5;75mTarget\033[0m   \033[90m│\033[0m  {args.url}")
        print(f"   \033[38;5;75mModel\033[0m    \033[90m│\033[0m  {args.model or 'HTTP endpoint'}")
        from agentseal.probes.extraction import build_extraction_probes as _bep
        from agentseal.probes.injection import build_injection_probes as _bip
        ext_count = len(_bep())
        inj_count = len(_bip())
        if args.mcp:
            from agentseal.probes.mcp_tools import build_mcp_probes
            inj_count += len(build_mcp_probes())
        if args.rag:
            from agentseal.probes.rag_poisoning import build_rag_probes
            inj_count += len(build_rag_probes())
        total_count = ext_count + inj_count
        probe_text = f"\033[38;5;51m{total_count}\033[0m ({ext_count} extraction + {inj_count} injection)"
        if args.adaptive:
            probe_text += " + mutations"
        if args.semantic:
            probe_text += " + semantic"
        if args.genome:
            probe_text += " + genome"
        print(f"   \033[38;5;75mProbes\033[0m   \033[90m│\033[0m  {probe_text}")
        print(f"\033[90m   ─────────────────────────────────────────\033[0m")
        print()

    report = await validator.run()

    if not report.score_breakdown.get("scoring_valid", True):
        print("\n\x1b[31mError: All probes failed. Trust score is not valid.\x1b[0m")
        print("Check your model endpoint is running and accessible.\n")
        sys.exit(2)

    if report.score_breakdown.get("error_rate", 0) > 0.5:
        print(f"\n\x1b[33mWarning: {report.probes_error}/{report.total_probes} probes errored. Score may be unreliable.\x1b[0m\n")

    # ── Genome scan (if --genome) ─────────────────────────────────────
    genome_report = None
    if args.genome:
        from agentseal.genome import run_genome_scan
        genome_report = await run_genome_scan(
            agent_fn=validator.agent_fn,
            scan_report=report,
            ground_truth=system_prompt,
            max_probes_per_category=args.genome_probes,
            max_categories=args.genome_categories,
            concurrency=args.concurrency,
            timeout=args.timeout,
            on_progress=_cli_progress if args.output == "terminal" else None,
            semantic=args.semantic,
        )
        report.genome_report = genome_report.to_dict()

    # ── Auto-save report ─────────────────────────────────────────────
    try:
        save_report(report.to_dict(), "scan")
    except Exception:
        pass  # Best-effort save

    # ── Output ───────────────────────────────────────────────────────
    if args.output == "terminal":
        report.print()
        if genome_report:
            genome_report.print()
        # Attack chain display
        if report.attack_chains:
            _print_attack_chains(report.attack_chains, verbose=args.verbose)
    elif args.output == "json":
        print(report.to_json())
    elif args.output == "sarif":
        print(json.dumps(_to_sarif(report), indent=2))

    if args.save:
        Path(args.save).write_text(report.to_json())
        if args.output == "terminal":
            print(f"  Report saved to: {args.save}")

    # ── Interactive flow (terminal users only) ─────────────────────────
    has_failures = report.probes_leaked > 0 or report.probes_partial > 0
    if (args.output == "terminal"
            and args.min_score is None
            and args.fix is None
            and not args.save
            and not getattr(args, "upload", False)
            and system_prompt
            and report.trust_score < 85
            and has_failures
            and sys.stdin.isatty()):
        await _interactive_flow(report, system_prompt, args)

    # ── Fix mode - generate hardened prompt ───────────────────────────
    if args.fix is not None and system_prompt:
        hardened = report.generate_hardened_prompt(system_prompt)
        if hardened != system_prompt:
            if args.output == "terminal":
                _print_hardened_prompt(system_prompt, hardened)
            # Save to file if a path was given
            if isinstance(args.fix, str) and args.fix is not True:
                Path(args.fix).write_text(hardened)
                if args.output == "terminal":
                    print(f"  \033[92m✓ Hardened prompt saved to: {args.fix}\033[0m")
                    print()
        else:
            if args.output == "terminal":
                print(f"\n  \033[92m✓ No fixes needed - your prompt resisted all attacks.\033[0m\n")
    elif args.fix is not None and not system_prompt:
        if args.output == "terminal":
            print(f"\n  \033[93m⚠ --fix requires a system prompt (--prompt or --file). "
                  f"Cannot generate hardened prompt for URL-only scans.\033[0m\n")

    # ── Structured remediation JSON ──────────────────────────────────
    if getattr(args, "json_remediation", False):
        remediation = report.get_structured_remediation()
        print(remediation.to_json())

    # ── PDF report (Pro feature) ─────────────────────────────────────
    if args.report:
        if _pro_gate("PDF Report"):
            from agentseal.report import generate_pdf
            try:
                pdf_path = generate_pdf(report, output_path=args.report)
                if args.output == "terminal":
                    print(f"\n  \033[38;5;75m✓ PDF report saved to: {pdf_path}\033[0m")
            except Exception as e:
                print(f"\n  \033[91m✗ PDF generation failed: {e}\033[0m", file=sys.stderr)

    # ── Upload to dashboard (Pro feature) ─────────────────────────────
    if args.upload and not _pro_gate("Dashboard Upload"):
        pass
    elif args.upload:
        from agentseal.upload import get_credentials, upload_report, compute_content_hash
        import hashlib as _hl

        try:
            api_url, api_key = get_credentials(
                api_url=args.dashboard_url,
                api_key=args.dashboard_key,
            )
            if system_prompt:
                content_hash = compute_content_hash(system_prompt)
            elif args.url:
                # Hash the endpoint URL so each endpoint gets its own stub
                content_hash = _hl.sha256(args.url.encode("utf-8")).hexdigest()
            else:
                content_hash = "0" * 64
            result = upload_report(
                report_dict=report.to_dict(),
                api_url=api_url,
                api_key=api_key,
                content_hash=content_hash,
                agent_name=args.name,
                model_used=args.model,
            )
            if args.output == "terminal":
                scan_id = result.get("id", "unknown")
                print(f"\n  \033[92m✓ Uploaded to dashboard (scan {scan_id})\033[0m")
        except Exception as e:
            print(f"\n  \033[91m✗ Upload failed: {e}\033[0m", file=sys.stderr)

    # ── CI mode ──────────────────────────────────────────────────────
    if args.min_score is not None:
        if report.trust_score < args.min_score:
            if args.output == "terminal":
                print(f"\n  \033[91m✗ Score {report.trust_score:.0f} is below minimum {args.min_score}\033[0m")
            sys.exit(1)
        else:
            if args.output == "terminal":
                print(f"\n  \033[92m✓ Score {report.trust_score:.0f} meets minimum {args.min_score}\033[0m")
            sys.exit(0)


async def _run_watch(args):
    """Run canary regression scan."""
    from agentseal.canaries import (
        baseline_key, get_baseline, store_baseline, clear_baseline,
        build_canary_probes, run_canary_scan, detect_regression, send_webhook,
    )

    # ── Resolve prompt ────────────────────────────────────────────────
    system_prompt = _resolve_prompt(args, require_url=True)

    if system_prompt is None and not getattr(args, "url", None):
        print("Error: Provide --prompt, --file, or --url", file=sys.stderr)
        sys.exit(1)

    # ── Baseline key ──────────────────────────────────────────────────
    bkey = baseline_key(system_prompt or "", args.model or "")

    # ── Reset baseline ────────────────────────────────────────────────
    if args.reset_baseline:
        removed = clear_baseline(bkey)
        if args.output == "terminal":
            if removed:
                print("  \033[92m✓ Baseline cleared\033[0m")
            else:
                print("  \033[93mNo baseline found to clear\033[0m")
        elif args.output == "json":
            print(json.dumps({"action": "reset_baseline", "cleared": removed}))
        sys.exit(0)

    # ── Build agent function ──────────────────────────────────────────
    if getattr(args, "url", None):
        from agentseal.connectors.http import build_http_chat
        agent_fn = build_http_chat(
            url=args.url,
            message_field=args.message_field,
            response_field=args.response_field,
        )
    elif system_prompt and args.model:
        agent_fn = _build_agent_fn(
            model=args.model,
            system_prompt=system_prompt,
            api_key=args.api_key,
            ollama_url=args.ollama_url,
            litellm_url=getattr(args, "litellm_url", None),
        )
    else:
        print("Error: --model is required when testing a prompt directly", file=sys.stderr)
        sys.exit(1)

    # ── Parse canary probe IDs ────────────────────────────────────────
    probe_ids = None
    if args.canary_probes:
        probe_ids = {p.strip() for p in args.canary_probes.split(",")}

    # ── Run canary scan ───────────────────────────────────────────────
    if args.output == "terminal":
        _print_banner(show_tagline=False)
        print(f"\033[90m   ─────────────────────────────────────────\033[0m")
        if system_prompt:
            preview = system_prompt[:55].replace("\n", " ")
            suffix = "\033[90m...\033[0m" if len(system_prompt) > 55 else ""
            print(f"   \033[38;5;75mTarget\033[0m   \033[90m│\033[0m  {preview}{suffix}")
        elif getattr(args, "url", None):
            print(f"   \033[38;5;75mTarget\033[0m   \033[90m│\033[0m  {args.url}")
        print(f"   \033[38;5;75mMode\033[0m     \033[90m│\033[0m  \033[38;5;51mCanary Watch\033[0m (regression detection)")
        n_probes = len(probe_ids) if probe_ids else 5
        print(f"   \033[38;5;75mProbes\033[0m   \033[90m│\033[0m  \033[38;5;51m{n_probes}\033[0m canary probes")
        print(f"\033[90m   ─────────────────────────────────────────\033[0m")
        print()

    result = await run_canary_scan(
        agent_fn=agent_fn,
        ground_truth=system_prompt,
        probe_ids=probe_ids,
        concurrency=args.concurrency,
        timeout=args.timeout,
        on_progress=_cli_progress if args.output == "terminal" else None,
    )

    # ── Set baseline ──────────────────────────────────────────────────
    if args.set_baseline:
        path = store_baseline(bkey, result.to_dict())
        if args.output == "terminal":
            _print_canary_result(result)
            print(f"  \033[92m✓ Baseline stored at {path}\033[0m")
            print()
        elif args.output == "json":
            out = result.to_dict()
            out["action"] = "set_baseline"
            out["baseline_path"] = str(path)
            print(json.dumps(out, indent=2))
        sys.exit(0)

    # ── Load or create baseline ───────────────────────────────────────
    baseline = get_baseline(bkey)
    if baseline is None:
        path = store_baseline(bkey, result.to_dict())
        if args.output == "terminal":
            _print_canary_result(result)
            print(f"  \033[93mNo baseline found - storing current result as baseline\033[0m")
            print(f"  \033[90m  Saved to {path}\033[0m")
            print()
        elif args.output == "json":
            out = result.to_dict()
            out["regression"] = None
            out["baseline_created"] = True
            print(json.dumps(out, indent=2))

        if args.min_score is not None and result.trust_score < args.min_score:
            sys.exit(1)
        sys.exit(0)

    # ── Detect regression ─────────────────────────────────────────────
    alert = detect_regression(baseline, result.to_dict(), args.score_threshold)

    if args.output == "terminal":
        _print_canary_result(result)
        if alert:
            _print_regression_alert(alert)
        else:
            print(f"  \033[92m✓ No regression detected\033[0m")
            print(f"  \033[90m  Baseline score: {baseline.get('trust_score', 0):.0f}  "
                  f"Current: {result.trust_score:.0f}\033[0m")
            print()
    elif args.output == "json":
        out = result.to_dict()
        out["regression"] = alert.to_dict() if alert else None
        out["baseline_score"] = baseline.get("trust_score", 0)
        print(json.dumps(out, indent=2))

    # ── Webhook ───────────────────────────────────────────────────────
    if alert and args.webhook_url:
        success = send_webhook(args.webhook_url, alert, result)
        if args.output == "terminal":
            if success:
                print(f"  \033[92m✓ Webhook sent to {args.webhook_url}\033[0m")
            else:
                print(f"  \033[91m✗ Webhook failed for {args.webhook_url}\033[0m")

    # ── CI mode ───────────────────────────────────────────────────────
    if args.min_score is not None:
        if result.trust_score < args.min_score:
            if args.output == "terminal":
                print(f"\n  \033[91m✗ Score {result.trust_score:.0f} is below minimum {args.min_score}\033[0m")
            sys.exit(1)
        else:
            if args.output == "terminal":
                print(f"\n  \033[92m✓ Score {result.trust_score:.0f} meets minimum {args.min_score}\033[0m")

    # Exit code 1 on regression
    if alert:
        sys.exit(1)
    sys.exit(0)


def _print_canary_result(result):
    """Print canary scan result to terminal."""
    from agentseal.schemas import TrustLevel
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    score = result.trust_score
    if score >= 85:
        score_color = GREEN
    elif score >= 70:
        score_color = "\033[96m"
    elif score >= 50:
        score_color = YELLOW
    else:
        score_color = RED

    level = TrustLevel.from_score(score)

    print()
    print(f"{BLUE}{'═' * 60}{RESET}")
    print(f"{BLUE}  AgentSeal Canary Watch{RESET}")
    print(f"{BLUE}{'═' * 60}{RESET}")
    print(f"  Scan ID:  {DIM}{result.scan_id}{RESET}")
    print(f"  Duration: {DIM}{result.duration_seconds:.1f}s{RESET}")
    print()
    print(f"  {BOLD}TRUST SCORE:  {score_color}{score:.0f} / 100  ({level.value.upper()}){RESET}")
    print()
    print(f"  Probes: {GREEN}{result.probes_blocked} blocked{RESET}  "
          f"{RED}{result.probes_leaked} leaked{RESET}  "
          f"{YELLOW}{result.probes_partial} partial{RESET}  "
          f"{DIM}{result.probes_error} error{RESET}")
    print()


def _print_regression_alert(alert):
    """Print regression alert to terminal."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    print(f"  {RED}{BOLD}⚠ REGRESSION DETECTED{RESET}")
    print(f"  {RED}{alert.message}{RESET}")
    print()
    print(f"  Baseline: {DIM}{alert.baseline_score:.0f}{RESET}  →  Current: {DIM}{alert.current_score:.0f}{RESET}  "
          f"({RED}{alert.score_delta:+.1f}{RESET})")
    print()

    if alert.regressed_probes:
        print(f"  {RED}{BOLD}Regressed probes:{RESET}")
        for p in alert.regressed_probes:
            print(f"    {RED}↓{RESET} {p['probe_id']:25s}  {p['was']:8s} → {p['now']}")
        print()

    if alert.improved_probes:
        print(f"  {GREEN}{BOLD}Improved probes:{RESET}")
        for p in alert.improved_probes:
            print(f"    {GREEN}↑{RESET} {p['probe_id']:25s}  {p['was']:8s} → {p['now']}")
        print()


def _run_activate(args):
    """Activate a Pro license key."""
    _print_banner(show_tagline=False)

    key = args.key
    if not key:
        key = input("  Enter your license key: ").strip()

    if not key:
        print("  \033[91mNo license key provided.\033[0m")
        sys.exit(1)

    # Save license
    license_dir = Path.home() / ".agentseal"
    license_dir.mkdir(parents=True, exist_ok=True)
    license_path = license_dir / "license.json"
    license_path.write_text(json.dumps({"key": key}, indent=2))
    license_path.chmod(0o600)

    print(f"  \033[92m✓ License activated successfully\033[0m")
    print(f"  \033[90m  Saved to {license_path}\033[0m")
    print()
    print(f"  \033[0m  Pro features unlocked:")
    print(f"  \033[0m    - PDF security assessment reports  (--report)")
    print(f"  \033[0m    - Dashboard & historical tracking  (--upload)")
    print()


def _run_login(args):
    """Store dashboard credentials in ~/.agentseal/config.json."""
    from agentseal.upload import load_config, save_config, DEFAULT_API_URL

    config = load_config()

    current_url = config.get("api_url", DEFAULT_API_URL)
    api_url = args.api_url or input(f"  Dashboard API URL [{current_url}]: ").strip()
    api_key = args.api_key or input("  Dashboard API key: ").strip()

    # Keep existing/default value if user just presses Enter
    config["api_url"] = api_url if api_url else current_url
    if api_key:
        config["api_key"] = api_key

    save_config(config)
    print(f"\n  \033[92m✓ Credentials saved to ~/.agentseal/config.json\033[0m")


def _run_compare(args):
    """Compare two scan report JSON files."""
    from agentseal.compare import load_report, compare_reports, print_comparison

    a = load_report(args.report_a)
    b = load_report(args.report_b)
    diff = compare_reports(a, b)

    if args.output == "json":
        print(json.dumps(diff, indent=2))
    else:
        _print_banner(show_tagline=False)
        print_comparison(diff)


def _build_agent_fn(model: str, system_prompt: str, api_key: str = None,
                    ollama_url: str = None, litellm_url: str = None):
    """Build an async chat function for the specified model."""
    from agentseal.connectors import build_agent_fn
    return build_agent_fn(
        model=model,
        system_prompt=system_prompt,
        api_key=api_key,
        ollama_url=ollama_url,
        litellm_url=litellm_url,
    )


def _detect_claude_desktop() -> tuple[str | None, str | None]:
    """Auto-detect Claude Desktop config and extract info."""
    import platform
    if platform.system() == "Darwin":
        config_path = Path.home() / "Library/Application Support/Claude/claude_desktop_config.json"
    elif platform.system() == "Windows":
        config_path = Path(os.environ.get("APPDATA", "")) / "Claude/claude_desktop_config.json"
    else:
        config_path = Path.home() / ".config/claude/claude_desktop_config.json"

    if not config_path.exists():
        print(f"  Claude Desktop config not found at: {config_path}", file=sys.stderr)
        sys.exit(1)

    config = json.loads(config_path.read_text())
    mcp_servers = config.get("mcpServers", {})

    if mcp_servers:
        print(f"  Found {len(mcp_servers)} MCP server(s): {', '.join(mcp_servers.keys())}")

    # Claude Desktop doesn't expose the system prompt in config
    # We report what we find (MCP servers, permissions) but need a prompt to scan
    print("  Note: Claude Desktop config contains MCP servers but not the system prompt.")
    print("  Provide the prompt separately with --prompt or --file.")
    return None, None


def _detect_cursor() -> str | None:
    """Auto-detect Cursor IDE .cursorrules."""
    # Check common locations
    candidates = [
        Path.cwd() / ".cursorrules",
        Path.home() / ".cursor" / ".cursorrules",
    ]
    for path in candidates:
        if path.exists():
            content = path.read_text().strip()
            if content:
                print(f"  Found .cursorrules at: {path}")
                return content

    print("  No .cursorrules found in current directory or ~/.cursor/", file=sys.stderr)
    sys.exit(1)


def _print_hardened_prompt(original: str, hardened: str):
    """Print the hardened prompt with clear visual distinction."""
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    BOLD = "\033[1m"
    DIM = "\033[90m"
    RESET = "\033[0m"

    # Find what was added
    added_section = hardened[len(original.rstrip()):]
    clauses = [l.lstrip("- ") for l in added_section.strip().splitlines()
               if l.strip().startswith("- ")]

    print()
    print(f"  {CYAN}{BOLD}HARDENED PROMPT{RESET}")
    print(f"  {DIM}AgentSeal found {len(clauses)} security rules to add to your prompt.{RESET}")
    print(f"  {DIM}{'─' * 56}{RESET}")
    print()

    # Show original (dimmed)
    orig_preview = original.strip().replace("\n", " ")
    if len(orig_preview) > 70:
        orig_preview = orig_preview[:70] + "..."
    print(f"  {DIM}Your prompt:{RESET}")
    print(f"  {DIM}  \"{orig_preview}\"{RESET}")
    print()

    # Show added security rules (highlighted, numbered)
    print(f"  {GREEN}{BOLD}+ Security rules added:{RESET}")
    for i, clause in enumerate(clauses, 1):
        print(f"  {GREEN}  {i:2d}. {clause}{RESET}")
    print()
    print(f"  {DIM}{'─' * 56}{RESET}")
    print()
    print(f"  {CYAN}Save to file:{RESET}  agentseal scan ... --fix hardened_prompt.txt")
    print(f"  {CYAN}Then re-scan:{RESET}  agentseal scan --file hardened_prompt.txt --model ...")
    print()


async def _interactive_flow(report, system_prompt: str, args):
    """Post-scan interactive flow: show findings, offer autofix, optionally re-scan."""

    # ── Step 1: Ask if they want to see what needs fixing ──────────
    print()
    try:
        answer = input("  Want to see what needs fixing? [\033[1mY\033[0m/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if answer in ("n", "no"):
        return

    # ── Step 2: Show detailed findings ─────────────────────────────
    _print_detailed_findings(report)

    # ── Step 3: Offer autofix options ──────────────────────────────
    print(f"  \033[96m\033[1mWhat would you like to do?\033[0m")
    print(f"  \033[1m[1]\033[0m Autofix - generate hardened prompt")
    print(f"  \033[1m[2]\033[0m Autofix & re-scan - fix and verify")
    print(f"  \033[1m[3]\033[0m Done - exit")
    print()
    try:
        choice = input("  Choice [1/2/3]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if choice == "1":
        # Generate and save hardened prompt
        hardened = report.generate_hardened_prompt(system_prompt)
        if hardened == system_prompt:
            print(f"\n  \033[92m✓ No fixes needed - your prompt resisted all attacks.\033[0m\n")
            return
        out_path = _save_hardened_prompt(hardened)
        print(f"\n  \033[92m✓ Hardened prompt saved to: {out_path}\033[0m\n")

    elif choice == "2":
        # Generate, re-scan, show comparison
        hardened = report.generate_hardened_prompt(system_prompt)
        if hardened == system_prompt:
            print(f"\n  \033[92m✓ No fixes needed - your prompt resisted all attacks.\033[0m\n")
            return
        out_path = _save_hardened_prompt(hardened)
        print(f"\n  \033[92m✓ Hardened prompt saved to: {out_path}\033[0m")
        print(f"  \033[90mRe-scanning with hardened prompt...\033[0m\n")

        # Rebuild agent and re-scan
        agent_fn = _build_agent_fn(
            model=args.model,
            system_prompt=hardened,
            api_key=args.api_key,
            ollama_url=args.ollama_url,
            litellm_url=getattr(args, "litellm_url", None),
        )
        from agentseal.validator import AgentValidator
        validator = AgentValidator(
            agent_fn=agent_fn,
            ground_truth_prompt=hardened,
            agent_name=args.name,
            concurrency=args.concurrency,
            timeout_per_probe=args.timeout,
            verbose=args.verbose,
            on_progress=_cli_progress,
            adaptive=args.adaptive,
            semantic=args.semantic,
            mcp=args.mcp,
            rag=args.rag,
        )
        after_report = await validator.run()
        after_report.print()
        _print_comparison(report, after_report)

    # choice == "3" or anything else → just return


def _print_detailed_findings(report):
    """Print failed probes grouped by category with explanations and fixes."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[90m"
    RESET = "\033[0m"

    findings = report.get_findings_by_category()
    if not findings:
        print(f"\n  {GREEN}✓ No vulnerabilities found - your prompt blocked all attacks.{RESET}\n")
        return

    print()
    print(f"  {CYAN}{BOLD}YOUR PROMPT IS VULNERABLE TO THESE ATTACKS:{RESET}")
    print(f"  {DIM}{'─' * 56}{RESET}")
    print()

    for i, (cat, info) in enumerate(findings.items(), 1):
        n_leaked = len(info["leaked"])
        n_partial = len(info["partial"])

        # Category header
        counts = []
        if n_leaked:
            counts.append(f"{RED}{n_leaked} leaked{RESET}")
        if n_partial:
            counts.append(f"{YELLOW}{n_partial} partial{RESET}")
        count_str = ", ".join(counts)

        print(f"  {BOLD}{i}. {info['label']}{RESET} ({count_str})")

        # Show what happened - pick worst example
        examples = info["leaked"] or info["partial"]
        if examples:
            ex = examples[0]
            # What the attacker tried
            attack_preview = ex.attack_text[:100].replace("\n", " ").strip()
            if len(ex.attack_text) > 100:
                attack_preview += "..."
            print(f"     {DIM}Attack: {attack_preview}{RESET}")
            # What went wrong
            print(f"     {DIM}Result: {ex.reasoning[:80]}{RESET}")

        # The fix
        if info["clause"]:
            print(f"     {GREEN}Fix: {info['clause'][:90]}")
            if len(info["clause"]) > 90:
                print(f"          {info['clause'][90:]}{RESET}")
            else:
                print(f"{RESET}", end="")
        print()

    print(f"  {DIM}{'─' * 56}{RESET}")
    print()


def _print_comparison(before_report, after_report):
    """Print a before/after comparison of two scan reports."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[90m"
    RESET = "\033[0m"

    b_score = before_report.trust_score
    a_score = after_report.trust_score
    delta = a_score - b_score

    if delta > 0:
        delta_color = GREEN
        delta_str = f"+{delta:.0f}"
    elif delta < 0:
        delta_color = RED
        delta_str = f"{delta:.0f}"
    else:
        delta_color = DIM
        delta_str = "±0"

    print()
    print(f"  {CYAN}{BOLD}BEFORE vs AFTER{RESET}")
    print(f"  {DIM}{'─' * 56}{RESET}")
    print()
    print(f"  {BOLD}Trust Score:{RESET}   {b_score:.0f}  →  {a_score:.0f}  ({delta_color}{delta_str}{RESET})")
    print()

    # Breakdown comparison
    for key, label in [
        ("extraction_resistance", "Extraction"),
        ("injection_resistance", "Injection"),
        ("boundary_integrity", "Boundary"),
        ("consistency", "Consistency"),
    ]:
        bv = before_report.score_breakdown.get(key, 0)
        av = after_report.score_breakdown.get(key, 0)
        d = av - bv
        if d > 0:
            dc = GREEN
            ds = f"+{d:.0f}"
        elif d < 0:
            dc = RED
            ds = f"{d:.0f}"
        else:
            dc = DIM
            ds = "±0"
        print(f"  {label:14s}  {bv:.0f}  →  {av:.0f}  ({dc}{ds}{RESET})")
    print()

    # Probes that flipped
    before_leaked_ids = {r.probe_id for r in before_report.results if r.verdict.value == "leaked"}
    after_leaked_ids = {r.probe_id for r in after_report.results if r.verdict.value == "leaked"}

    now_blocked = before_leaked_ids - after_leaked_ids
    still_leaked = before_leaked_ids & after_leaked_ids
    new_leaked = after_leaked_ids - before_leaked_ids

    if now_blocked:
        print(f"  {GREEN}{BOLD}Now blocked ({len(now_blocked)}):{RESET}")
        # Look up technique names from the before report
        before_by_id = {r.probe_id: r for r in before_report.results}
        for pid in sorted(now_blocked):
            r = before_by_id.get(pid)
            label = r.technique if r else pid
            print(f"    {GREEN}✓{RESET} {label}")
        print()

    if still_leaked:
        print(f"  {YELLOW}{BOLD}Still vulnerable ({len(still_leaked)}):{RESET}")
        after_by_id = {r.probe_id: r for r in after_report.results}
        for pid in sorted(still_leaked):
            r = after_by_id.get(pid)
            label = r.technique if r else pid
            print(f"    {YELLOW}✗{RESET} {label}")
        print()

    if new_leaked:
        print(f"  {RED}{BOLD}New failures ({len(new_leaked)}):{RESET}")
        after_by_id = {r.probe_id: r for r in after_report.results}
        for pid in sorted(new_leaked):
            r = after_by_id.get(pid)
            label = r.technique if r else pid
            print(f"    {RED}✗{RESET} {label}")
        print()

    print(f"  {DIM}{'─' * 56}{RESET}")
    print()


def _save_hardened_prompt(hardened: str) -> str:
    """Save hardened prompt to a timestamped file and return the path."""
    import datetime
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"hardened_prompt_{ts}.txt"
    Path(filename).write_text(hardened)
    return filename


_SPINNERS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
_spin_idx = 0


def _cli_progress(phase: str, completed: int, total: int):
    """Terminal progress indicator with per-probe updates and spinner."""
    global _spin_idx
    bar_len = 30
    filled = int(completed / total * bar_len) if total > 0 else 0
    bar = "\033[92m" + "█" * filled + "\033[90m" + "░" * (bar_len - filled) + "\033[0m"
    pct = int(completed / total * 100) if total > 0 else 0

    if completed < total:
        spinner = _SPINNERS[_spin_idx % len(_SPINNERS)]
        _spin_idx += 1
        print(f"\r  \033[96m{spinner}\033[0m {phase:12s} [{bar}] {completed}/{total}  \033[90m{pct}%\033[0m  ", end="", flush=True)
    else:
        print(f"\r  \033[92m✓\033[0m {phase:12s} [{bar}] {completed}/{total}  \033[92m{pct}%\033[0m  ")



def _print_attack_chains(chains, verbose=False):
    """Print attack chains to terminal."""
    R = "\033[91m"     # Red
    Y = "\033[93m"     # Yellow
    G = "\033[92m"     # Green
    D = "\033[90m"     # Dim
    C = "\033[96m"     # Cyan
    B = "\033[1m"      # Bold
    RST = "\033[0m"    # Reset

    print()
    print(f"  {B}ATTACK CHAINS{RST}")
    print(f"  {'─' * 48}")
    print()

    for chain in chains:
        sev = chain.severity if isinstance(chain.severity, str) else chain.severity
        sev_color = R if sev == "critical" else Y
        title = chain.title if hasattr(chain, "title") else chain.get("title", "")
        desc = chain.description if hasattr(chain, "description") else chain.get("description", "")
        remediation = chain.remediation if hasattr(chain, "remediation") else chain.get("remediation", "")
        steps = chain.steps if hasattr(chain, "steps") else chain.get("steps", [])

        print(f"  {sev_color}[{sev.upper()}]{RST} {B}{title}{RST}")

        if verbose:
            print(f"  {D}{desc}{RST}")
            print()
            for step in steps:
                step_num = step.step_number if hasattr(step, "step_number") else step.get("step_number", 0)
                summary = step.summary if hasattr(step, "summary") else step.get("summary", "")
                probe_id = step.probe_id if hasattr(step, "probe_id") else step.get("probe_id", "")
                verdict = step.verdict if hasattr(step, "verdict") else step.get("verdict", "")
                v_color = R if verdict == "leaked" else Y
                print(f"    {D}{step_num}.{RST} {summary}")
                print(f"       {D}probe: {probe_id}  verdict: {v_color}{verdict}{RST}")
            print()
            print(f"    {C}Remediation: {remediation}{RST}")
        else:
            step_count = len(steps)
            print(f"    {D}{step_count}-step chain | {remediation[:70]}{RST}")

        print()


def _run_fix(args):
    """Run the fix command -- quarantine skills and harden prompts."""
    R = "\033[91m"
    Y = "\033[93m"
    G = "\033[92m"
    D = "\033[90m"
    C = "\033[96m"
    B = "\033[1m"
    RST = "\033[0m"

    # ── List quarantine ──────────────────────────────────────────────
    if getattr(args, "list_quarantine", False):
        entries = list_quarantine()
        if not entries:
            print(f"  {D}No quarantined skills.{RST}")
            return
        print(f"  {B}QUARANTINED SKILLS{RST}")
        print(f"  {'─' * 48}")
        for e in entries:
            print(f"  {Y}{e.skill_name}{RST}")
            print(f"    {D}Original: {e.original_path}{RST}")
            print(f"    {D}Reason:   {e.reason}{RST}")
            print(f"    {D}Date:     {e.timestamp}{RST}")
        print()
        return

    # ── Restore skill ────────────────────────────────────────────────
    if getattr(args, "restore", None):
        try:
            restored_path = restore_skill(args.restore)
            print(f"  {G}Restored '{args.restore}' to {restored_path}{RST}")
        except (FileNotFoundError, FileExistsError) as e:
            print(f"  {R}{e}{RST}", file=sys.stderr)
            sys.exit(1)
        return

    # ── Determine source ─────────────────────────────────────────────
    from_guard = getattr(args, "from_guard", False)
    from_scan = getattr(args, "from_scan", False)
    report_path = getattr(args, "report", None)
    auto_mode = getattr(args, "auto", False)
    dry_run = getattr(args, "dry_run", False)

    if from_guard:
        try:
            guard_report = load_guard_report(Path(report_path) if report_path else None)
        except FileNotFoundError as e:
            print(f"  {R}{e}{RST}", file=sys.stderr)
            sys.exit(1)
        _fix_from_guard(guard_report, auto_mode, dry_run)
    elif from_scan:
        try:
            scan_report = load_scan_report(Path(report_path) if report_path else None)
        except FileNotFoundError as e:
            print(f"  {R}{e}{RST}", file=sys.stderr)
            sys.exit(1)
        _fix_from_scan(scan_report, args)
    else:
        # Try guard first, then scan
        try:
            guard_report = load_guard_report(Path(report_path) if report_path else None)
            _fix_from_guard(guard_report, auto_mode, dry_run)
            return
        except FileNotFoundError:
            pass
        try:
            scan_report = load_scan_report(Path(report_path) if report_path else None)
            _fix_from_scan(scan_report, args)
            return
        except FileNotFoundError:
            pass
        print(f"  {R}No guard or scan report found.{RST}")
        print(f"  {D}Run 'agentseal guard' or 'agentseal scan' first.{RST}")
        sys.exit(1)


def _fix_from_guard(guard_report, auto_mode, dry_run):
    """Handle fix from guard report -- quarantine dangerous skills."""
    R = "\033[91m"
    Y = "\033[93m"
    G = "\033[92m"
    D = "\033[90m"
    C = "\033[96m"
    B = "\033[1m"
    RST = "\033[0m"

    fixable = get_fixable_skills(guard_report)
    if not fixable:
        print(f"  {G}No dangerous skills found in guard report.{RST}")
        return

    print(f"  {B}FIXABLE SKILLS{RST} ({len(fixable)} dangerous)")
    print(f"  {'─' * 48}")
    print()

    for skill in fixable:
        name = skill["name"]
        path = skill["path"]
        findings = skill["findings"]

        print(f"  {R}[DANGER]{RST} {B}{name}{RST}")
        print(f"    {D}Path: {path}{RST}")
        for f in findings[:3]:
            title = f.get("title", "")
            print(f"    {Y}- {title}{RST}")

        if auto_mode:
            if dry_run:
                print(f"    {C}[DRY RUN] Would quarantine {name}{RST}")
            else:
                if path and Path(path).exists():
                    try:
                        entry = quarantine_skill(Path(path), reason=f"DANGER: {findings[0].get('title', '') if findings else 'flagged by guard'}")
                        print(f"    {G}Quarantined -> {entry.quarantine_path}{RST}")
                    except Exception as e:
                        print(f"    {R}Failed to quarantine: {e}{RST}")
                else:
                    print(f"    {Y}Path not found, skipping{RST}")
        elif sys.stdin.isatty():
            try:
                answer = input(f"    Quarantine this skill? [y/N/s/q] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if answer == "q":
                return
            elif answer == "s":
                continue
            elif answer == "y":
                if dry_run:
                    print(f"    {C}[DRY RUN] Would quarantine {name}{RST}")
                elif path and Path(path).exists():
                    try:
                        entry = quarantine_skill(Path(path), reason=f"DANGER: {findings[0].get('title', '') if findings else 'flagged by guard'}")
                        print(f"    {G}Quarantined -> {entry.quarantine_path}{RST}")
                    except Exception as e:
                        print(f"    {R}Failed to quarantine: {e}{RST}")
                else:
                    print(f"    {Y}Path not found, skipping{RST}")

        print()


def _fix_from_scan(scan_report, args):
    """Handle fix from scan report -- generate hardened prompt."""
    R = "\033[91m"
    G = "\033[92m"
    D = "\033[90m"
    C = "\033[96m"
    B = "\033[1m"
    RST = "\033[0m"

    # Need original prompt to harden
    original_prompt = scan_report.get("original_prompt", "")
    if not original_prompt:
        # Try to find it from the report's agent name or ask user
        print(f"  {D}Scan report does not contain original prompt.{RST}")
        print(f"  {D}Provide the original prompt with --file or --prompt to generate hardened version.{RST}")
        return

    dry_run = getattr(args, "dry_run", False)
    output_path = getattr(args, "output", None)

    hardened = generate_hardened_prompt_from_report(scan_report, original_prompt)
    if hardened is None:
        print(f"  {G}No fixes needed -- all probes were blocked.{RST}")
        return

    # Show diff
    print(f"  {C}{B}HARDENED PROMPT{RST}")
    print(f"  {D}{'─' * 56}{RST}")
    added = hardened[len(original_prompt.rstrip()):]
    clauses = [l.lstrip("- ") for l in added.strip().splitlines() if l.strip().startswith("- ")]
    for i, clause in enumerate(clauses, 1):
        print(f"  {G}  {i:2d}. {clause}{RST}")
    print(f"  {D}{'─' * 56}{RST}")

    if dry_run:
        print(f"  {C}[DRY RUN] Would save hardened prompt{RST}")
        return

    if output_path:
        Path(output_path).write_text(hardened, encoding="utf-8")
        print(f"  {G}Hardened prompt saved to: {output_path}{RST}")


def _to_sarif(report) -> dict:
    """Convert report to SARIF format for GitHub Security tab integration."""
    results = []
    for r in report.results:
        if r.verdict.value in ("leaked", "partial"):
            results.append({
                "ruleId": r.probe_id,
                "level": "error" if r.verdict.value == "leaked" else "warning",
                "message": {"text": f"{r.technique}: {r.reasoning}"},
                "properties": {
                    "category": r.category,
                    "severity": r.severity.value,
                    "confidence": r.confidence,
                },
            })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AgentSeal",
                    "version": "0.2.0",
                    "informationUri": "https://agentseal.io",
                }
            },
            "results": results,
        }],
    }


if __name__ == "__main__":
    main()
