# agentseal/scan_mcp.py
"""
Runtime MCP Server Scanner — orchestration layer.

Connects to MCP servers, analyzes tool definitions for security issues,
detects toxic flows between servers, checks baselines for rug pulls,
and computes trust scores.

This module ties together:
  - mcp_runtime.py: MCP protocol connections (stdio/HTTP)
  - mcp_tool_analyzer.py: Tool description security analysis
  - toxic_flows.py: Cross/intra-server dangerous combos
  - baselines.py: Rug pull detection via tool signature hashing
  - mcp_trust_score.py: 0-100 trust scoring per server
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from agentseal.baselines import BaselineStore
from agentseal.guard_models import (
    BaselineChangeResult,
    GuardVerdict,
    MCPRuntimeFinding,
    MCPRuntimeResult,
    ToxicFlowResult,
)
from agentseal.mcp_runtime import (
    MCPConnectionError,
    MCPServerSnapshot,
    connect_http,
    connect_stdio,
)
from agentseal.mcp_tool_analyzer import MCPToolAnalyzer
from agentseal.mcp_trust_score import MCPTrustScore, compute_trust_score
from agentseal.toxic_flows import analyze_toxic_flows_runtime


# Progress callback: (phase: str, detail: str) -> None
ProgressFn = Callable[[str, str], None]


# ═══════════════════════════════════════════════════════════════════════
# RESULT MODEL
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ScanMCPReport:
    """Complete report from a scan-mcp run."""
    timestamp: str
    duration_seconds: float
    servers_scanned: int
    servers_connected: int
    servers_failed: int
    total_tools: int
    runtime_results: list[MCPRuntimeResult]
    trust_scores: list[MCPTrustScore]
    toxic_flows: list[ToxicFlowResult] = field(default_factory=list)
    baseline_changes: list[BaselineChangeResult] = field(default_factory=list)
    connection_errors: list[dict] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.runtime_results)

    @property
    def total_critical(self) -> int:
        return sum(
            1 for r in self.runtime_results
            for f in r.findings if f.severity == "critical"
        )

    @property
    def total_high(self) -> int:
        return sum(
            1 for r in self.runtime_results
            for f in r.findings if f.severity == "high"
        )

    @property
    def total_medium(self) -> int:
        return sum(
            1 for r in self.runtime_results
            for f in r.findings if f.severity == "medium"
        )

    @property
    def has_critical(self) -> bool:
        return self.total_critical > 0

    @property
    def min_score(self) -> int:
        if not self.trust_scores:
            return 100
        return min(s.score for s in self.trust_scores)

    def to_dict(self) -> dict:
        d = {
            "timestamp": self.timestamp,
            "duration_seconds": self.duration_seconds,
            "servers_scanned": self.servers_scanned,
            "servers_connected": self.servers_connected,
            "servers_failed": self.servers_failed,
            "total_tools": self.total_tools,
            "runtime_results": [r.to_dict() for r in self.runtime_results],
            "trust_scores": [s.to_dict() for s in self.trust_scores],
            "summary": {
                "total_findings": self.total_findings,
                "total_critical": self.total_critical,
                "total_high": self.total_high,
                "total_medium": self.total_medium,
            },
        }
        if self.toxic_flows:
            d["toxic_flows"] = [f.to_dict() for f in self.toxic_flows]
        if self.baseline_changes:
            d["baseline_changes"] = [c.to_dict() for c in self.baseline_changes]
        if self.connection_errors:
            d["connection_errors"] = self.connection_errors
        return d

    def to_json(self, indent: int = 2) -> str:
        import json
        return json.dumps(self.to_dict(), indent=indent)


# ═══════════════════════════════════════════════════════════════════════
# SCANNER ENGINE
# ═══════════════════════════════════════════════════════════════════════

class ScanMCP:
    """Runtime MCP Server Scanner — connects, analyzes, scores."""

    def __init__(
        self,
        *,
        timeout: float = 30.0,
        concurrency: int = 3,
        on_progress: Optional[ProgressFn] = None,
    ):
        self._timeout = timeout
        self._concurrency = concurrency
        self._progress = on_progress or (lambda *a: None)

    async def _connect_server(self, server: dict) -> MCPServerSnapshot | MCPConnectionError:
        """Connect to a single MCP server based on its config."""
        name = server.get("name", "unknown")
        raw_cmd = server.get("command", "")
        args = server.get("args", [])
        env = server.get("env")
        url = server.get("url", "")
        # command can be a list in some MCP configs (e.g. Opencode: ["npx", "-y", "@foo/bar"])
        if isinstance(raw_cmd, list):
            command = str(raw_cmd[0]) if raw_cmd else ""
            args = [str(a) for a in raw_cmd[1:]] + [str(a) for a in args]
        else:
            command = str(raw_cmd)

        # HTTP/SSE endpoint
        if url:
            headers = server.get("headers")
            return await connect_http(
                url=url,
                headers=headers,
                timeout=self._timeout,
                server_name=name,
            )

        # stdio server
        if command:
            return await connect_stdio(
                command=command,
                args=[str(a) for a in args],
                env=env,
                timeout=self._timeout,
                server_name=name,
            )

        return MCPConnectionError(
            server_name=name,
            error_type="invalid",
            detail="No command or url specified in server config",
        )

    async def _connect_all(
        self, servers: list[dict],
    ) -> tuple[list[MCPServerSnapshot], list[MCPConnectionError]]:
        """Connect to all servers with concurrency limit."""
        snapshots: list[MCPServerSnapshot] = []
        errors: list[MCPConnectionError] = []

        semaphore = asyncio.Semaphore(self._concurrency)

        async def _connect_one(server: dict):
            async with semaphore:
                name = server.get("name", "unknown")
                self._progress("connect", f"Connecting to '{name}'...")
                result = await self._connect_server(server)
                if isinstance(result, MCPConnectionError):
                    self._progress("connect", f"Failed to connect to '{name}': {result.error_type}")
                    errors.append(result)
                else:
                    self._progress("connect", f"Connected to '{name}' ({len(result.tools)} tools)")
                    snapshots.append(result)

        tasks = [_connect_one(s) for s in servers]
        await asyncio.gather(*tasks)

        return snapshots, errors

    def run(self, servers: list[dict]) -> ScanMCPReport:
        """Execute full scan-mcp pipeline.

        Args:
            servers: List of MCP server config dicts (from machine_discovery or manual).

        Returns:
            ScanMCPReport with all results.
        """
        start = time.monotonic()

        # Phase 1: Connect to all servers
        self._progress("connect", f"Connecting to {len(servers)} MCP server(s)...")
        snapshots, conn_errors = asyncio.run(self._connect_all(servers))

        self._progress(
            "connect",
            f"{len(snapshots)} connected, {len(conn_errors)} failed",
        )

        # Phase 2: Analyze tool definitions
        analyzer = MCPToolAnalyzer()
        runtime_results: list[MCPRuntimeResult] = []
        total_tools = 0

        for snapshot in snapshots:
            self._progress("analyze", f"Analyzing '{snapshot.server_name}' ({len(snapshot.tools)} tools)...")
            result = analyzer.analyze_server(snapshot)
            runtime_results.append(result)
            total_tools += len(snapshot.tools)

        # Cross-server analysis (name collisions, cross-references)
        if len(snapshots) >= 2:
            cross_findings = analyzer.analyze_cross_server(snapshots)
            # Attach cross-server findings to the relevant server's result
            for finding in cross_findings:
                for rr in runtime_results:
                    if rr.server_name == finding.server_name:
                        rr.findings.append(finding)
                        # Update verdict if needed
                        if finding.severity == "critical" and rr.verdict != GuardVerdict.DANGER:
                            rr.verdict = GuardVerdict.DANGER
                        elif finding.severity in ("high", "medium") and rr.verdict == GuardVerdict.SAFE:
                            rr.verdict = GuardVerdict.WARNING
                        break

        # Phase 3: Toxic flow analysis (runtime, tool-level)
        toxic_flow_results: list[ToxicFlowResult] = []
        if len(snapshots) >= 1:
            self._progress("flows", "Analyzing tool capability combinations...")
            raw_flows = analyze_toxic_flows_runtime(snapshots)
            for flow in raw_flows:
                toxic_flow_results.append(ToxicFlowResult(
                    risk_level=flow.risk_level,
                    risk_type=flow.risk_type,
                    title=flow.title,
                    description=flow.description,
                    servers_involved=flow.servers_involved,
                    remediation=flow.remediation,
                    tools_involved=getattr(flow, "tools_involved", []),
                    labels_involved=getattr(flow, "labels_involved", []),
                ))
            if toxic_flow_results:
                self._progress("flows", f"Found {len(toxic_flow_results)} toxic flow(s)")

        # Phase 4: Baseline check (rug pull detection)
        baseline_results: list[BaselineChangeResult] = []
        baseline_store = BaselineStore()
        server_baseline_changed: dict[str, bool] = {}

        for snapshot in snapshots:
            agent_type = _find_agent_type(snapshot.server_name, servers)
            changes = baseline_store.check_server_tools(
                snapshot.server_name, agent_type, snapshot,
            )
            for change in changes:
                baseline_results.append(BaselineChangeResult(
                    server_name=change.server_name,
                    agent_type=change.agent_type,
                    change_type=change.change_type,
                    detail=change.detail,
                ))
            server_baseline_changed[snapshot.server_name] = len(changes) > 0

        if baseline_results:
            self._progress("baselines", f"{len(baseline_results)} rug pull change(s) detected!")
        else:
            self._progress("baselines", "All baselines verified")

        # Phase 5: Trust scoring
        trust_scores: list[MCPTrustScore] = []
        for rr in runtime_results:
            snapshot_tools = None
            for s in snapshots:
                if s.server_name == rr.server_name:
                    snapshot_tools = s.tools
                    break
            score = compute_trust_score(
                rr,
                tools=snapshot_tools,
                baseline_changed=server_baseline_changed.get(rr.server_name, False),
            )
            trust_scores.append(score)

        duration = time.monotonic() - start

        return ScanMCPReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration_seconds=round(duration, 2),
            servers_scanned=len(servers),
            servers_connected=len(snapshots),
            servers_failed=len(conn_errors),
            total_tools=total_tools,
            runtime_results=runtime_results,
            trust_scores=trust_scores,
            toxic_flows=toxic_flow_results,
            baseline_changes=baseline_results,
            connection_errors=[e.to_dict() for e in conn_errors],
        )

    def run_single_url(self, url: str, *, headers: dict | None = None) -> ScanMCPReport:
        """Convenience: scan a single HTTP/SSE endpoint."""
        server = {"name": url, "url": url}
        if headers:
            server["headers"] = headers
        return self.run([server])


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _find_agent_type(server_name: str, servers: list[dict]) -> str:
    """Look up agent_type for a server name from the config list."""
    for s in servers:
        if s.get("name") == server_name:
            return s.get("agent_type", "unknown")
    return "unknown"
