# agentseal/guard.py
"""
Guard — one-command machine security scan.

Chains machine discovery, skill scanning, and MCP config checking into
a single zero-config experience. The user types `agentseal guard` and
gets a complete security report of their machine.

All operations are synchronous and local — no network requests needed
(except optional blocklist update and optional LLM judge analysis).
"""

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from agentseal.baselines import BaselineStore
from agentseal.guard_models import (
    BaselineChangeResult,
    GuardReport,
    GuardVerdict,
    ToxicFlowResult,
)
from agentseal.machine_discovery import scan_directory, scan_machine
from agentseal.mcp_checker import MCPConfigChecker
from agentseal.project_config import (
    ProjectConfig, generate_unlisted_findings, should_ignore_path,
)
from agentseal.skill_scanner import SkillScanner
from agentseal.toxic_flows import analyze_toxic_flows


# Progress callback type: (phase: str, detail: str) -> None
ProgressFn = Callable[[str, str], None]


class Guard:
    """One-command machine security scan."""

    def __init__(
        self,
        semantic: bool = True,
        verbose: bool = False,
        on_progress: Optional[ProgressFn] = None,
        llm_judge=None,
        connect: bool = False,
        timeout: float = 30.0,
        concurrency: int = 3,
        scan_path: Optional[str] = None,
        project_config: Optional[ProjectConfig] = None,
    ):
        self.semantic = semantic
        self.verbose = verbose
        self._progress = on_progress or (lambda *a: None)
        self._llm_judge = llm_judge
        self._connect = connect
        self._timeout = timeout
        self._concurrency = concurrency
        self._scan_path = scan_path
        self._project_config = project_config

    def run(self) -> GuardReport:
        """Execute full guard scan. Returns a GuardReport with all findings."""
        start = time.monotonic()

        # Phase 1: Discover agents, MCP servers, and skills
        if self._scan_path:
            self._progress("discover", f"Scanning directory: {self._scan_path}")
            agents, mcp_servers, skill_paths = scan_directory(Path(self._scan_path))
        else:
            self._progress("discover", "Scanning for AI agents, skills, and MCP servers...")
            agents, mcp_servers, skill_paths = scan_machine()

        installed_count = sum(1 for a in agents if a.status in ("found", "installed_no_config"))
        self._progress(
            "discover",
            f"Found {installed_count} agents, {len(skill_paths)} skills, "
            f"{len(mcp_servers)} MCP servers",
        )

        # Apply ignore_paths from project config
        if self._project_config and self._project_config.ignore_paths:
            original = len(skill_paths)
            skill_paths = [
                p for p in skill_paths
                if not should_ignore_path(self._project_config, str(p))
            ]
            filtered = original - len(skill_paths)
            if filtered:
                self._progress("discover", f"Filtered {filtered} skill(s) via ignore_paths")

        # Phase 2: Scan skills
        self._progress("skills", f"Scanning {len(skill_paths)} skills for threats...")
        scanner = SkillScanner(semantic=self.semantic, llm_judge=self._llm_judge)
        skill_results = []
        for i, path in enumerate(skill_paths):
            self._progress("skills", f"[{i + 1}/{len(skill_paths)}] {path.name}")
            skill_results.append(scanner.scan_file(path))

        # Phase 2b: LLM judge analysis (async, only for SAFE/WARNING skills)
        llm_tokens_used = 0
        if self._llm_judge is not None:
            candidates = [
                (i, sr) for i, sr in enumerate(skill_results)
                if sr.verdict in (GuardVerdict.SAFE, GuardVerdict.WARNING)
            ]
            if candidates:
                self._progress("llm_judge", f"Running LLM analysis on {len(candidates)} skill(s)...")

                async def _run_llm():
                    tokens = 0
                    for idx, sr in candidates:
                        self._progress("llm_judge", f"Analyzing {sr.name}...")
                        content = Path(sr.path).read_text(encoding="utf-8", errors="replace")
                        llm_findings, used = await scanner.analyze_with_llm(content, Path(sr.path).name)
                        tokens += used
                        if llm_findings:
                            sr.findings.extend(llm_findings)
                            # Upgrade verdict if LLM found worse issues
                            worst = sr.verdict
                            for f in llm_findings:
                                if f.severity == "critical":
                                    worst = GuardVerdict.DANGER
                                elif f.severity in ("high", "medium") and worst == GuardVerdict.SAFE:
                                    worst = GuardVerdict.WARNING
                            # Never downgrade
                            _ORDER = {GuardVerdict.SAFE: 0, GuardVerdict.WARNING: 1, GuardVerdict.DANGER: 2}
                            if _ORDER.get(worst, 0) > _ORDER.get(sr.verdict, 0):
                                skill_results[idx] = type(sr)(
                                    name=sr.name,
                                    path=sr.path,
                                    verdict=worst,
                                    findings=sr.findings,
                                    blocklist_match=sr.blocklist_match,
                                    sha256=sr.sha256,
                                )
                    return tokens

                def _run_async(coro):
                    try:
                        return asyncio.run(coro)
                    except RuntimeError:
                        import warnings
                        warnings.warn("LLM judge skipped: cannot run async in existing event loop. "
                                      "Use 'pip install nest_asyncio' for Jupyter/async support.")
                        return 0

                llm_tokens_used = _run_async(_run_llm())
                self._progress("llm_judge", f"LLM analysis complete ({llm_tokens_used} tokens)")

        # Phase 3: Check MCP configs
        self._progress("mcp", f"Checking {len(mcp_servers)} MCP server configurations...")
        checker = MCPConfigChecker()
        mcp_results = checker.check_all(mcp_servers)

        # Phase 4: Toxic flow analysis
        toxic_flow_results: list[ToxicFlowResult] = []
        if len(mcp_servers) >= 2:
            self._progress("flows", "Analyzing MCP server capability combinations...")
            raw_flows = analyze_toxic_flows(mcp_servers)
            for flow in raw_flows:
                toxic_flow_results.append(ToxicFlowResult(
                    risk_level=flow.risk_level,
                    risk_type=flow.risk_type,
                    title=flow.title,
                    description=flow.description,
                    servers_involved=flow.servers_involved,
                    remediation=flow.remediation,
                ))
            if toxic_flow_results:
                self._progress("flows", f"Found {len(toxic_flow_results)} toxic flow(s)")
            else:
                self._progress("flows", "No dangerous capability combinations found")

        # Phase 5: Baseline check (rug pull detection)
        baseline_results: list[BaselineChangeResult] = []
        if mcp_servers:
            self._progress("baselines", "Checking MCP server baselines...")
            store = BaselineStore()
            changes = store.check_all(mcp_servers)
            for change in changes:
                baseline_results.append(BaselineChangeResult(
                    server_name=change.server_name,
                    agent_type=change.agent_type,
                    change_type=change.change_type,
                    detail=change.detail,
                ))
            if baseline_results:
                self._progress("baselines", f"{len(baseline_results)} baseline change(s) detected")
            else:
                self._progress("baselines", "All baselines verified")

        # Phase 6: Runtime MCP scanning (only with --connect)
        mcp_runtime_results = []
        if self._connect and mcp_servers:
            self._progress("runtime", "Connecting to MCP servers for runtime analysis...")
            from agentseal.scan_mcp import ScanMCP
            scan = ScanMCP(
                timeout=self._timeout,
                concurrency=self._concurrency,
                on_progress=self._progress,
            )
            scan_report = scan.run(mcp_servers)
            mcp_runtime_results = scan_report.runtime_results
            # Merge runtime toxic flows into guard toxic flows
            for flow in scan_report.toxic_flows:
                toxic_flow_results.append(flow)
            # Merge runtime baseline changes
            for change in scan_report.baseline_changes:
                baseline_results.append(change)

        duration = time.monotonic() - start

        # Generate UNLISTED findings from project config
        unlisted = []
        if self._project_config:
            unlisted = generate_unlisted_findings(
                self._project_config, agents, mcp_servers,
            )
            if unlisted:
                self._progress("config", f"{len(unlisted)} unlisted item(s) detected")

        return GuardReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration_seconds=round(duration, 2),
            agents_found=agents,
            skill_results=skill_results,
            mcp_results=mcp_results,
            mcp_runtime_results=mcp_runtime_results,
            toxic_flows=toxic_flow_results,
            baseline_changes=baseline_results,
            llm_tokens_used=llm_tokens_used,
            unlisted_findings=unlisted,
            config_path=self._project_config.config_path if self._project_config else "",
        )
