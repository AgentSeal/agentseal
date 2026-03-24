# agentseal/guard_models.py
"""
Data models for the guard command — machine-level security scanning.

These are separate from schemas.py because guard operates at a different level:
schemas.py is about probe results (testing agent behavior via LLM),
guard_models.py is about static analysis of the local machine (skills, configs, MCP).
"""

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class GuardVerdict(str, Enum):
    """Verdict for a single scanned item (skill, MCP server, etc.)."""
    SAFE = "safe"
    WARNING = "warning"
    DANGER = "danger"
    ERROR = "error"


SEVERITY_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ═══════════════════════════════════════════════════════════════════════
# SKILL SCANNING MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class SkillFinding:
    """A single finding from skill analysis."""
    code: str               # e.g. "SKILL-001"
    title: str              # Human-readable: "Credential theft pattern"
    description: str        # Plain English: "This skill reads ~/.ssh/..."
    severity: str           # "critical", "high", "medium", "low"
    evidence: str           # The suspicious line or pattern found
    remediation: str        # "Remove this skill and rotate API keys"

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class SkillResult:
    """Result of scanning one skill."""
    name: str
    path: str
    verdict: GuardVerdict
    findings: list[SkillFinding] = field(default_factory=list)
    blocklist_match: bool = False
    sha256: str = ""

    @property
    def top_finding(self) -> Optional[SkillFinding]:
        """Return the highest-severity finding, or None."""
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "verdict": self.verdict.value,
            "findings": [f.to_dict() for f in self.findings],
            "blocklist_match": self.blocklist_match,
            "sha256": self.sha256,
        }


# ═══════════════════════════════════════════════════════════════════════
# MCP CONFIG SCANNING MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class MCPFinding:
    """A single finding from MCP config analysis."""
    code: str               # e.g. "MCP-001"
    title: str              # "Filesystem access to ~/.ssh"
    description: str        # Plain English explanation
    severity: str           # "critical", "high", "medium", "low"
    remediation: str        # "Remove ~/.ssh from allowed paths"

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "remediation": self.remediation,
        }


@dataclass
class MCPServerResult:
    """Result of checking one MCP server config."""
    name: str
    command: str
    source_file: str
    verdict: GuardVerdict
    findings: list[MCPFinding] = field(default_factory=list)

    @property
    def top_finding(self) -> Optional[MCPFinding]:
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "command": self.command,
            "source_file": self.source_file,
            "verdict": self.verdict.value,
            "findings": [f.to_dict() for f in self.findings],
        }


# ═══════════════════════════════════════════════════════════════════════
# AGENT DISCOVERY MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class AgentConfigResult:
    """Result of discovering one agent configuration on the machine."""
    name: str               # "Claude Desktop", "Cursor", etc.
    config_path: str        # Path to config file
    agent_type: str         # "claude-desktop", "cursor", "vscode", etc.
    mcp_servers: int        # Number of MCP servers configured
    skills_count: int       # Number of skills found
    status: str             # "found", "not_installed", "error"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "config_path": self.config_path,
            "agent_type": self.agent_type,
            "mcp_servers": self.mcp_servers,
            "skills_count": self.skills_count,
            "status": self.status,
        }


# ═══════════════════════════════════════════════════════════════════════
# MCP RUNTIME ANALYSIS MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class MCPRuntimeFinding:
    """A single finding from runtime MCP tool/server analysis."""
    code: str               # e.g. "MCPR-101"
    title: str              # "Tool Poisoning — Hidden Instructions"
    description: str        # Plain English explanation
    severity: str           # "critical", "high", "medium"
    evidence: str           # Exact quote from tool definition
    remediation: str        # How to fix
    tool_name: str          # Which tool has this issue ("" for server-level)
    server_name: str        # Which server

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "tool_name": self.tool_name,
            "server_name": self.server_name,
        }


@dataclass
class MCPRuntimeResult:
    """Result of runtime analysis for one MCP server."""
    server_name: str
    tools_found: int
    findings: list[MCPRuntimeFinding] = field(default_factory=list)
    verdict: GuardVerdict = GuardVerdict.SAFE
    connection_status: str = "connected"  # "connected", "timeout", "auth_failed", "error"

    @property
    def top_finding(self) -> Optional[MCPRuntimeFinding]:
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    def to_dict(self) -> dict:
        return {
            "server_name": self.server_name,
            "tools_found": self.tools_found,
            "findings": [f.to_dict() for f in self.findings],
            "verdict": self.verdict.value,
            "connection_status": self.connection_status,
        }


# ═══════════════════════════════════════════════════════════════════════
# TOXIC FLOW MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ToxicFlowResult:
    """A detected dangerous combination of server capabilities."""
    risk_level: str      # "high", "medium"
    risk_type: str       # "data_exfiltration", "remote_code_execution", etc.
    title: str
    description: str
    servers_involved: list[str]
    remediation: str
    tools_involved: list[str] = field(default_factory=list)    # e.g. ["server:read_file", "server:send_msg"]
    labels_involved: list[str] = field(default_factory=list)   # e.g. ["private_data", "public_sink"]

    def to_dict(self) -> dict:
        d = {
            "risk_level": self.risk_level,
            "risk_type": self.risk_type,
            "title": self.title,
            "description": self.description,
            "servers_involved": self.servers_involved,
            "remediation": self.remediation,
        }
        if self.tools_involved:
            d["tools_involved"] = self.tools_involved
        if self.labels_involved:
            d["labels_involved"] = self.labels_involved
        return d


# ═══════════════════════════════════════════════════════════════════════
# BASELINE CHANGE MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class BaselineChangeResult:
    """A detected change in an MCP server's baseline."""
    server_name: str
    agent_type: str
    change_type: str  # "config_changed", "binary_changed"
    detail: str

    def to_dict(self) -> dict:
        return {
            "server_name": self.server_name,
            "agent_type": self.agent_type,
            "change_type": self.change_type,
            "detail": self.detail,
        }


# ═══════════════════════════════════════════════════════════════════════
# UNLISTED (PROJECT CONFIG ALLOWLIST) MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class UnlistedFinding:
    """A finding for an agent or MCP server not in the project allowlist."""
    code: str               # "GUARD-001" (agent) or "GUARD-002" (server)
    title: str
    description: str
    severity: str = "medium"
    item_name: str = ""     # agent_type or server name
    item_type: str = ""     # "agent" or "mcp_server"

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "item_name": self.item_name,
            "item_type": self.item_type,
        }


# ═══════════════════════════════════════════════════════════════════════
# GUARD REPORT (top-level result)
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class GuardReport:
    """Complete guard scan report for a machine."""
    timestamp: str
    duration_seconds: float
    agents_found: list[AgentConfigResult]
    skill_results: list[SkillResult]
    mcp_results: list[MCPServerResult]
    mcp_runtime_results: list[MCPRuntimeResult] = field(default_factory=list)
    toxic_flows: list[ToxicFlowResult] = field(default_factory=list)
    baseline_changes: list[BaselineChangeResult] = field(default_factory=list)
    llm_tokens_used: int = 0
    unlisted_findings: list[UnlistedFinding] = field(default_factory=list)
    config_path: str = ""

    @property
    def total_dangers(self) -> int:
        skills = sum(1 for s in self.skill_results if s.verdict == GuardVerdict.DANGER)
        mcp = sum(1 for m in self.mcp_results if m.verdict == GuardVerdict.DANGER)
        runtime = sum(1 for r in self.mcp_runtime_results if r.verdict == GuardVerdict.DANGER)
        return skills + mcp + runtime

    @property
    def total_warnings(self) -> int:
        skills = sum(1 for s in self.skill_results if s.verdict == GuardVerdict.WARNING)
        mcp = sum(1 for m in self.mcp_results if m.verdict == GuardVerdict.WARNING)
        runtime = sum(1 for r in self.mcp_runtime_results if r.verdict == GuardVerdict.WARNING)
        return skills + mcp + runtime + len(self.unlisted_findings)

    @property
    def total_safe(self) -> int:
        skills = sum(1 for s in self.skill_results if s.verdict == GuardVerdict.SAFE)
        mcp = sum(1 for m in self.mcp_results if m.verdict == GuardVerdict.SAFE)
        runtime = sum(1 for r in self.mcp_runtime_results if r.verdict == GuardVerdict.SAFE)
        return skills + mcp + runtime

    @property
    def has_critical(self) -> bool:
        return self.total_dangers > 0

    @property
    def all_actions(self) -> list[str]:
        """Collect all remediation actions, sorted by severity."""
        all_findings: list[tuple[str, SkillFinding | MCPFinding | MCPRuntimeFinding]] = []
        for s in self.skill_results:
            for f in s.findings:
                all_findings.append((s.name, f))
        for m in self.mcp_results:
            for f in m.findings:
                all_findings.append((m.name, f))
        for r in self.mcp_runtime_results:
            for f in r.findings:
                all_findings.append((r.server_name, f))

        all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x[1].severity, 99))

        return [finding.remediation for _, finding in all_findings]

    @property
    def total_toxic_flows(self) -> int:
        return len(self.toxic_flows)

    @property
    def total_baseline_changes(self) -> int:
        return len(self.baseline_changes)

    def to_dict(self) -> dict:
        d = {
            "timestamp": self.timestamp,
            "duration_seconds": self.duration_seconds,
            "agents_found": [a.to_dict() for a in self.agents_found],
            "skill_results": [s.to_dict() for s in self.skill_results],
            "mcp_results": [m.to_dict() for m in self.mcp_results],
            "summary": {
                "total_dangers": self.total_dangers,
                "total_warnings": self.total_warnings,
                "total_safe": self.total_safe,
            },
        }
        if self.mcp_runtime_results:
            d["mcp_runtime_results"] = [r.to_dict() for r in self.mcp_runtime_results]
        if self.toxic_flows:
            d["toxic_flows"] = [f.to_dict() for f in self.toxic_flows]
        if self.baseline_changes:
            d["baseline_changes"] = [c.to_dict() for c in self.baseline_changes]
        if self.llm_tokens_used > 0:
            d["llm_tokens_used"] = self.llm_tokens_used
        if self.unlisted_findings:
            d["unlisted_findings"] = [f.to_dict() for f in self.unlisted_findings]
        d["config_path"] = self.config_path or None
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_sarif(self) -> dict:
        """Convert guard report to SARIF 2.1.0 format."""
        rules: list[dict] = []
        results: list[dict] = []
        rule_ids_seen: set[str] = set()

        def _severity_to_level(sev: str) -> str:
            if sev in ("critical", "high"):
                return "error"
            if sev == "medium":
                return "warning"
            return "note"

        def _ensure_rule(code: str, title: str) -> int:
            if code not in rule_ids_seen:
                rule_ids_seen.add(code)
                rules.append({"id": code, "shortDescription": {"text": title}})
            return next(i for i, r in enumerate(rules) if r["id"] == code)

        # Skill findings
        for sr in self.skill_results:
            for f in sr.findings:
                rule_idx = _ensure_rule(f.code, f.title)
                result: dict = {
                    "ruleId": f.code,
                    "ruleIndex": rule_idx,
                    "level": _severity_to_level(f.severity),
                    "message": {"text": f.description},
                }
                if sr.path:
                    result["locations"] = [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": sr.path},
                        }
                    }]
                if f.evidence:
                    result["fingerprints"] = {"evidence": f.evidence[:200]}
                results.append(result)

        # MCP findings
        for mr in self.mcp_results:
            for f in mr.findings:
                rule_idx = _ensure_rule(f.code, f.title)
                result = {
                    "ruleId": f.code,
                    "ruleIndex": rule_idx,
                    "level": _severity_to_level(f.severity),
                    "message": {"text": f.description},
                }
                if mr.source_file:
                    result["locations"] = [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": mr.source_file},
                        }
                    }]
                results.append(result)

        # MCP runtime findings
        for rr in self.mcp_runtime_results:
            for f in rr.findings:
                rule_idx = _ensure_rule(f.code, f.title)
                result = {
                    "ruleId": f.code,
                    "ruleIndex": rule_idx,
                    "level": _severity_to_level(f.severity),
                    "message": {"text": f.description},
                }
                if f.evidence:
                    result["fingerprints"] = {"evidence": f.evidence[:200]}
                results.append(result)

        # Unlisted findings
        for uf in self.unlisted_findings:
            rule_idx = _ensure_rule(uf.code, uf.title)
            result = {
                "ruleId": uf.code,
                "ruleIndex": rule_idx,
                "level": "warning",
                "message": {"text": uf.description},
            }
            results.append(result)

        from agentseal import __version__
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AgentSeal Guard",
                        "version": __version__,
                        "informationUri": "https://agentseal.org",
                        "rules": rules,
                    }
                },
                "results": results,
            }],
        }
