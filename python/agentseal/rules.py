"""YAML community rule engine for AgentSeal Guard.

Rules match against MCP servers, skills, or agents using glob patterns.
Includes inline test support via `guard test` subcommand.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

import yaml

from agentseal.guard_models import CustomFinding

_VALID_SEVERITIES = ("critical", "high", "medium", "low")
_VALID_VERDICTS = ("danger", "warning")
_VALID_TYPES = ("mcp", "skill", "agent")


@dataclass
class Rule:
    id: str
    title: str
    description: str
    severity: str
    verdict: str
    remediation: str
    match: dict           # {type: "mcp", command: ["*miner*"], ...}
    tests: list[dict]     # inline test cases
    source_file: str      # which YAML file


@dataclass
class RuleTestResult:
    rule_id: str
    test_name: str
    passed: bool
    expected: str
    actual: str


class RuleEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    @classmethod
    def from_paths(cls, paths: list[str]) -> "RuleEngine":
        """Load and validate rules from YAML files/directories.

        Validates: required fields, severity in valid set, verdict in valid set,
        type in valid set, unique IDs across files. Errors include file path.
        """
        rules: list[Rule] = []
        seen_ids: set[str] = set()

        resolved_files: list[Path] = []
        for p_str in paths:
            p = Path(p_str)
            if p.is_dir():
                resolved_files.extend(sorted(p.glob("*.yaml")))
                resolved_files.extend(sorted(p.glob("*.yml")))
            elif p.is_file():
                resolved_files.append(p)
            # Skip non-existent silently

        for fpath in resolved_files:
            try:
                data = yaml.safe_load(fpath.read_text(encoding="utf-8"))
            except Exception as e:
                raise ValueError(f"Cannot parse {fpath}: {e}") from e

            if not isinstance(data, dict) or "rules" not in data:
                continue  # skip files without rules key

            for i, raw in enumerate(data["rules"]):
                if not isinstance(raw, dict):
                    raise ValueError(f"{fpath}: rule {i} is not a mapping")

                # Required fields
                for req in ("id", "title", "severity", "verdict", "match"):
                    if req not in raw:
                        raise ValueError(f"{fpath}: rule {i} missing required field '{req}'")

                rid = raw["id"]
                if rid in seen_ids:
                    raise ValueError(f"{fpath}: duplicate rule ID '{rid}'")
                seen_ids.add(rid)

                if raw["severity"] not in _VALID_SEVERITIES:
                    raise ValueError(f"{fpath}: rule '{rid}' invalid severity '{raw['severity']}'")
                if raw["verdict"] not in _VALID_VERDICTS:
                    raise ValueError(f"{fpath}: rule '{rid}' invalid verdict '{raw['verdict']}'")

                match = raw["match"]
                if not isinstance(match, dict) or "type" not in match:
                    raise ValueError(f"{fpath}: rule '{rid}' match must have 'type' field")
                if match["type"] not in _VALID_TYPES:
                    raise ValueError(f"{fpath}: rule '{rid}' invalid match type '{match['type']}'")

                rules.append(Rule(
                    id=rid,
                    title=raw["title"],
                    description=raw.get("description", ""),
                    severity=raw["severity"],
                    verdict=raw["verdict"],
                    remediation=raw.get("remediation", ""),
                    match=match,
                    tests=raw.get("tests", []) or [],
                    source_file=str(fpath),
                ))

        return cls(rules)

    def _match_entity(self, rule: Rule, entity_data: dict) -> bool:
        """Check if an entity matches a rule's match patterns.

        Multiple patterns in one field = OR (any match).
        Multiple fields = AND (all must match).
        Uses fnmatch.fnmatchcase with explicit lower() for cross-platform determinism.
        """
        match = rule.match

        for match_field, patterns in match.items():
            if match_field == "type":
                continue  # type is used for dispatch, not matching

            if not isinstance(patterns, list):
                patterns = [patterns]

            # Empty pattern list means the field cannot match
            if not patterns:
                return False

            value = entity_data.get(match_field, "")
            if value is None:
                value = ""
            value_lower = str(value).lower()

            # OR logic within a field: any pattern must match
            field_matched = any(
                fnmatch.fnmatchcase(value_lower, str(p).lower())
                for p in patterns
            )

            if not field_matched:
                return False  # AND logic: all fields must match

        return True

    def evaluate_mcp(self, server, raw_config: dict) -> list[CustomFinding]:
        """Evaluate all MCP-type rules against a server."""
        findings = []
        for rule in self.rules:
            if rule.match.get("type") != "mcp":
                continue

            entity_data = {
                "name": getattr(server, "name", raw_config.get("name", "")),
                "command": getattr(server, "command", raw_config.get("command", "")),
                "args": " ".join(raw_config.get("args", []))
                if isinstance(raw_config.get("args"), list)
                else str(raw_config.get("args", "")),
                "env_keys": " ".join(raw_config.get("env", {}).keys())
                if isinstance(raw_config.get("env"), dict)
                else "",
                "env_values": " ".join(str(v) for v in raw_config.get("env", {}).values())
                if isinstance(raw_config.get("env"), dict)
                else "",
                "source_file": getattr(server, "source_file", raw_config.get("source_file", "")),
            }

            if self._match_entity(rule, entity_data):
                findings.append(CustomFinding(
                    code=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    verdict=rule.verdict,
                    remediation=rule.remediation,
                    rule_file=rule.source_file,
                    entity_type="mcp",
                    entity_name=entity_data["name"],
                ))

        return findings

    def evaluate_skill(self, skill, content: str) -> list[CustomFinding]:
        """Evaluate all skill-type rules against a skill file."""
        findings = []
        for rule in self.rules:
            if rule.match.get("type") != "skill":
                continue

            entity_data = {
                "name": getattr(skill, "name", ""),
                "path": getattr(skill, "path", ""),
                "content": content[:10240],
            }

            if self._match_entity(rule, entity_data):
                findings.append(CustomFinding(
                    code=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    verdict=rule.verdict,
                    remediation=rule.remediation,
                    rule_file=rule.source_file,
                    entity_type="skill",
                    entity_name=entity_data["name"],
                ))

        return findings

    def evaluate_agent(self, agent) -> list[CustomFinding]:
        """Evaluate all agent-type rules against an agent config."""
        findings = []
        for rule in self.rules:
            if rule.match.get("type") != "agent":
                continue

            entity_data = {
                "agent_type": getattr(agent, "agent_type", ""),
                "name": getattr(agent, "name", ""),
                "config_path": getattr(agent, "config_path", ""),
            }

            if self._match_entity(rule, entity_data):
                findings.append(CustomFinding(
                    code=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    verdict=rule.verdict,
                    remediation=rule.remediation,
                    rule_file=rule.source_file,
                    entity_type="agent",
                    entity_name=entity_data["name"],
                ))

        return findings

    def run_tests(self) -> list[RuleTestResult]:
        """Run inline tests for all loaded rules."""
        results = []
        for rule in self.rules:
            for test in rule.tests:
                test_name = test.get("name", "unnamed")
                test_input = test.get("input", {})
                expected = test.get("expect", "match")

                matched = self._match_entity(rule, test_input)
                actual = "match" if matched else "no_match"

                results.append(RuleTestResult(
                    rule_id=rule.id,
                    test_name=test_name,
                    passed=(actual == expected),
                    expected=expected,
                    actual=actual,
                ))

        return results
