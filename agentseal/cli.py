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
    """Print the AgentSeal CLI banner with gradient colors."""
    from agentseal import __version__

    # Gradient: cyan → blue → purple → pink
    c = [
        "\033[38;5;51m",   # A
        "\033[38;5;45m",   # G
        "\033[38;5;39m",   # E
        "\033[38;5;33m",   # N
        "\033[38;5;63m",   # T
        "\033[38;5;99m",   # S
        "\033[38;5;135m",  # E
        "\033[38;5;171m",  # A
        "\033[38;5;207m",  # L
    ]
    R = "\033[0m"
    D = "\033[90m"

    # Large 2x block letters
    rows = [
        f"   {c[0]}  ██████╗  {c[1]} ██████╗ {c[2]}███████╗{c[3]}███╗   ██╗{c[4]}████████╗{c[5]}███████╗{c[6]}███████╗{c[7]} █████╗ {c[8]}██╗     {R}",
        f"   {c[0]} ██╔══██╗ {c[1]}██╔════╝ {c[2]}██╔════╝{c[3]}████╗  ██║{c[4]}╚══██╔══╝{c[5]}██╔════╝{c[6]}██╔════╝{c[7]}██╔══██╗{c[8]}██║     {R}",
        f"   {c[0]} ███████║ {c[1]}██║  ███╗{c[2]}█████╗  {c[3]}██╔██╗ ██║{c[4]}   ██║   {c[5]}███████╗{c[6]}█████╗  {c[7]}███████║{c[8]}██║     {R}",
        f"   {c[0]} ██╔══██║ {c[1]}██║   ██║{c[2]}██╔══╝  {c[3]}██║╚██╗██║{c[4]}   ██║   {c[5]}╚════██║{c[6]}██╔══╝  {c[7]}██╔══██║{c[8]}██║     {R}",
        f"   {c[0]} ██║  ██║ {c[1]}╚██████╔╝{c[2]}███████╗{c[3]}██║ ╚████║{c[4]}   ██║   {c[5]}███████║{c[6]}███████╗{c[7]}██║  ██║{c[8]}███████╗{R}",
        f"   {c[0]} ╚═╝  ╚═╝ {c[1]} ╚═════╝ {c[2]}╚══════╝{c[3]}╚═╝  ╚═══╝{c[4]}   ╚═╝   {c[5]}╚══════╝{c[6]}╚══════╝{c[7]}╚═╝  ╚═╝{c[8]}╚══════╝{R}",
    ]

    print()
    for row in rows:
        print(row)
    print(f"   {D}v{__version__}{R}")
    if show_tagline:
        print(f"{D}                  Security Validator for AI Agents{R}")
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
                             help="Model to test against (e.g. gpt-4o, claude-sonnet-4-5-20250929, ollama/qwen3-32b)")

    # LLM connection
    scan_parser.add_argument("--api-key", type=str, default=None,
                             help="API key (or set OPENAI_API_KEY / ANTHROPIC_API_KEY env)")
    scan_parser.add_argument("--ollama-url", type=str, default="http://localhost:11434",
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
    scan_parser.add_argument("--concurrency", type=int, default=3,
                             help="Max parallel probes (default: 3)")
    scan_parser.add_argument("--timeout", type=float, default=30.0,
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
                               help="API key (or set OPENAI_API_KEY / ANTHROPIC_API_KEY env)")
    watch_parser.add_argument("--ollama-url", type=str, default="http://localhost:11434",
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
    else:
        _print_banner()
        parser.print_help()
        sys.exit(0)


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
        inj_count = 35
        if args.mcp:
            inj_count += 26
        if args.rag:
            inj_count += 20
        total_count = 37 + inj_count
        probe_text = f"\033[38;5;51m{total_count}\033[0m (37 extraction + {inj_count} injection)"
        if args.mcp:
            probe_text += " + 26 mcp"
        if args.rag:
            probe_text += " + 20 rag"
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

    # ── Output ───────────────────────────────────────────────────────
    if args.output == "terminal":
        report.print()
        if genome_report:
            genome_report.print()
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
