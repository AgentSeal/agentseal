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

    @classmethod
    def from_dict(cls, d: dict) -> "SkillFinding":
        return cls(
            code=d.get("code", ""),
            title=d.get("title", ""),
            description=d.get("description", ""),
            severity=d.get("severity", ""),
            evidence=d.get("evidence", ""),
            remediation=d.get("remediation", ""),
        )


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

    @classmethod
    def from_dict(cls, d: dict) -> "SkillResult":
        return cls(
            name=d.get("name", ""),
            path=d.get("path", ""),
            verdict=GuardVerdict(d.get("verdict", "safe")),
            findings=[SkillFinding.from_dict(f) for f in d.get("findings", [])],
            blocklist_match=d.get("blocklist_match", False),
            sha256=d.get("sha256", ""),
        )


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

    @classmethod
    def from_dict(cls, d: dict) -> "MCPFinding":
        return cls(
            code=d.get("code", ""),
            title=d.get("title", ""),
            description=d.get("description", ""),
            severity=d.get("severity", ""),
            remediation=d.get("remediation", ""),
        )


@dataclass
class MCPServerResult:
    """Result of checking one MCP server config."""
    name: str
    command: str
    source_file: str
    verdict: GuardVerdict
    findings: list[MCPFinding] = field(default_factory=list)
    registry_score: Optional[float] = None
    registry_level: Optional[str] = None          # EXCELLENT|HIGH|MEDIUM|LOW|CRITICAL
    registry_findings_count: Optional[int] = None
    registry_tools: list[dict] = field(default_factory=list)  # [{"name", "status", "finding", "severity"}]

    @property
    def top_finding(self) -> Optional[MCPFinding]:
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "command": self.command,
            "source_file": self.source_file,
            "verdict": self.verdict.value,
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.registry_score is not None:
            d["registry"] = {
                "score": self.registry_score,
                "level": self.registry_level,
                "findings_count": self.registry_findings_count,
                "tools": self.registry_tools,
            }
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "MCPServerResult":
        reg = d.get("registry") or {}
        return cls(
            name=d.get("name", ""),
            command=d.get("command", ""),
            source_file=d.get("source_file", ""),
            verdict=GuardVerdict(d.get("verdict", "safe")),
            findings=[MCPFinding.from_dict(f) for f in d.get("findings", [])],
            registry_score=reg.get("score"),
            registry_level=reg.get("level"),
            registry_findings_count=reg.get("findings_count"),
            registry_tools=reg.get("tools", []),
        )


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

    @classmethod
    def from_dict(cls, d: dict) -> "AgentConfigResult":
        return cls(
            name=d.get("name", ""),
            config_path=d.get("config_path", ""),
            agent_type=d.get("agent_type", ""),
            mcp_servers=d.get("mcp_servers", 0),
            skills_count=d.get("skills_count", 0),
            status=d.get("status", ""),
        )


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


@dataclass
class CustomFinding:
    """Finding from a user-defined YAML rule."""
    code: str              # CUSTOM-001
    title: str
    severity: str          # critical|high|medium|low
    verdict: str           # danger|warning
    remediation: str
    rule_file: str         # path to rule YAML that matched
    entity_type: str       # mcp|skill|agent
    entity_name: str       # name of matched entity

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "title": self.title,
            "severity": self.severity,
            "verdict": self.verdict,
            "remediation": self.remediation,
            "rule_file": self.rule_file,
            "entity_type": self.entity_type,
            "entity_name": self.entity_name,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CustomFinding":
        return cls(
            code=d.get("code", ""),
            title=d.get("title", ""),
            severity=d.get("severity", ""),
            verdict=d.get("verdict", ""),
            remediation=d.get("remediation", ""),
            rule_file=d.get("rule_file", ""),
            entity_type=d.get("entity_type", ""),
            entity_name=d.get("entity_name", ""),
        )


# ═══════════════════════════════════════════════════════════════════════
# DELTA (SCAN HISTORY DIFF) MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class DeltaEntry:
    """A single change between two guard scans."""
    change_type: str        # "new", "resolved", "changed", "new_entity", "removed_entity"
    entity_type: str        # "skill", "mcp", "agent"
    entity_name: str        # normalized skill path, server name, or agent type
    code: str = ""          # finding code (empty for entity-level changes)
    title: str = ""         # finding title or entity description
    old_verdict: str = ""   # for "changed" type
    new_verdict: str = ""   # for "changed" type
    severity: str = ""      # finding severity (empty for entity-level changes)

    def to_dict(self) -> dict:
        d = {
            "change_type": self.change_type,
            "entity_type": self.entity_type,
            "entity_name": self.entity_name,
        }
        if self.code:
            d["code"] = self.code
        if self.title:
            d["title"] = self.title
        if self.old_verdict:
            d["old_verdict"] = self.old_verdict
        if self.new_verdict:
            d["new_verdict"] = self.new_verdict
        if self.severity:
            d["severity"] = self.severity
        return d


@dataclass
class DeltaResult:
    """Result of comparing two guard scans."""
    previous_timestamp: str
    entries: list[DeltaEntry] = field(default_factory=list)

    @property
    def total_new(self) -> int:
        return sum(1 for e in self.entries if e.change_type in ("new", "new_entity"))

    @property
    def total_resolved(self) -> int:
        return sum(1 for e in self.entries if e.change_type in ("resolved", "removed_entity"))

    @property
    def total_changed(self) -> int:
        return sum(1 for e in self.entries if e.change_type == "changed")

    def to_dict(self) -> dict:
        return {
            "previous_timestamp": self.previous_timestamp,
            "entries": [e.to_dict() for e in self.entries],
            "total_new": self.total_new,
            "total_resolved": self.total_resolved,
            "total_changed": self.total_changed,
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
    custom_findings: list[CustomFinding] = field(default_factory=list)
    config_path: str = ""

    @property
    def total_dangers(self) -> int:
        skills = sum(1 for s in self.skill_results if s.verdict == GuardVerdict.DANGER)
        mcp = sum(1 for m in self.mcp_results if m.verdict == GuardVerdict.DANGER)
        runtime = sum(1 for r in self.mcp_runtime_results if r.verdict == GuardVerdict.DANGER)
        custom = sum(1 for c in self.custom_findings if c.verdict == "danger")
        return skills + mcp + runtime + custom

    @property
    def total_warnings(self) -> int:
        skills = sum(1 for s in self.skill_results if s.verdict == GuardVerdict.WARNING)
        mcp = sum(1 for m in self.mcp_results if m.verdict == GuardVerdict.WARNING)
        runtime = sum(1 for r in self.mcp_runtime_results if r.verdict == GuardVerdict.WARNING)
        custom = sum(1 for c in self.custom_findings if c.verdict == "warning")
        return skills + mcp + runtime + len(self.unlisted_findings) + custom

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
        all_findings: list[tuple[str, SkillFinding | MCPFinding | MCPRuntimeFinding | CustomFinding]] = []
        for s in self.skill_results:
            for f in s.findings:
                all_findings.append((s.name, f))
        for m in self.mcp_results:
            for f in m.findings:
                all_findings.append((m.name, f))
        for r in self.mcp_runtime_results:
            for f in r.findings:
                all_findings.append((r.server_name, f))
        for c in self.custom_findings:
            all_findings.append((c.entity_name, c))

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
        if self.custom_findings:
            d["custom_findings"] = [f.to_dict() for f in self.custom_findings]
        d["config_path"] = self.config_path or None
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "GuardReport":
        return cls(
            timestamp=d["timestamp"],
            duration_seconds=d["duration_seconds"],
            agents_found=[AgentConfigResult.from_dict(a) for a in d["agents_found"]],
            skill_results=[SkillResult.from_dict(s) for s in d["skill_results"]],
            mcp_results=[MCPServerResult.from_dict(m) for m in d["mcp_results"]],
            mcp_runtime_results=[],
            toxic_flows=[],
            baseline_changes=[],
            llm_tokens_used=d.get("llm_tokens_used", 0),
            unlisted_findings=[],
            custom_findings=[CustomFinding.from_dict(f) for f in d.get("custom_findings", [])],
            config_path=d.get("config_path") or "",
        )

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

        # Custom rule findings
        for cf in self.custom_findings:
            rule_idx = _ensure_rule(cf.code, cf.title)
            result = {
                "ruleId": cf.code,
                "ruleIndex": rule_idx,
                "level": _severity_to_level(cf.severity),
                "message": {"text": f"{cf.title} ({cf.entity_type}: {cf.entity_name})"},
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
