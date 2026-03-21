# tests/test_a2a_injection.py
"""Tests for Agent-to-Agent (A2A) protocol task injection probes (inj_a2a_*).

NOTE: These probes are applicable to agents implementing the Google A2A
JSON-RPC 2.0 protocol (released April 2025). They test prompt injection
via A2A message parts, AgentCard spoofing, and artifact-based poisoning.
"""
import pytest
from agentseal.probes.injection import build_injection_probes
from agentseal.schemas import Severity


class TestA2AInjection:
    def setup_method(self):
        self.probes = build_injection_probes()
        self.category_probes = [p for p in self.probes if p["category"] == "a2a_injection"]

    def test_probe_count(self):
        assert len(self.category_probes) == 3

    def test_probe_ids_unique(self):
        ids = [p["probe_id"] for p in self.category_probes]
        assert len(ids) == len(set(ids))
        assert all(pid.startswith("inj_a2a_") for pid in ids)

    def test_probe_structure(self):
        required = {"probe_id", "category", "technique", "severity", "payload", "canary", "canary_position"}
        for p in self.category_probes:
            assert required.issubset(p.keys()), f"Missing keys in {p['probe_id']}"

    def test_severity_high(self):
        """A2A probes are HIGH severity (P2 finding, narrower deployment base)."""
        for p in self.category_probes:
            assert p["severity"] == Severity.HIGH

    def test_canary_present(self):
        for p in self.category_probes:
            assert "_CONFIRMED" in p["canary"]

    def test_payload_contains_jsonrpc_or_agentcard(self):
        """Each payload must simulate A2A protocol context."""
        a2a_markers = ["jsonrpc", "tasks/send", "AgentCard", "parts", "message", "skills"]
        for p in self.category_probes:
            assert any(m in p["payload"] for m in a2a_markers), (
                f"{p['probe_id']}: payload lacks A2A protocol context"
            )

    def test_canary_in_payload(self):
        for p in self.category_probes:
            assert p["canary"] in p["payload"], (
                f"{p['probe_id']}: canary not found in payload"
            )

    def test_three_distinct_attack_vectors(self):
        """Probes must cover three distinct A2A attack surfaces."""
        techniques = [p["technique"] for p in self.category_probes]
        assert len(set(techniques)) == 3
        # Verify the three vectors are covered
        vectors = ["message", "AgentCard", "artifact"]
        for vector in vectors:
            assert any(vector.lower() in t.lower() for t in techniques), (
                f"Missing A2A attack vector: {vector}"
            )
