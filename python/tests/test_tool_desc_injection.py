# tests/test_tool_desc_injection.py
"""Tests for MCP tool description poisoning probes (inj_tool_desc_*)."""
from agentseal.probes.injection import build_injection_probes
from agentseal.schemas import Severity


class TestToolDescInjection:
    def setup_method(self):
        self.probes = build_injection_probes()
        self.category_probes = [p for p in self.probes if p["category"] == "tool_desc_injection"]

    def test_probe_count(self):
        assert len(self.category_probes) == 3

    def test_probe_ids_unique(self):
        ids = [p["probe_id"] for p in self.category_probes]
        assert len(ids) == len(set(ids))
        assert all(pid.startswith("inj_tool_desc_") for pid in ids)

    def test_probe_structure(self):
        required = {"probe_id", "category", "technique", "severity", "payload", "canary", "canary_position"}
        for p in self.category_probes:
            assert required.issubset(p.keys()), f"Missing keys in {p['probe_id']}"

    def test_severity_critical(self):
        for p in self.category_probes:
            assert p["severity"] == Severity.CRITICAL

    def test_canary_present(self):
        for p in self.category_probes:
            assert "_CONFIRMED" in p["canary"]

    def test_payload_simulates_tool_context(self):
        """Each payload must simulate a tool discovery or registration context."""
        tool_context_markers = ["tool", "Tool", "description", "Description", "parameters", "Parameters"]
        for p in self.category_probes:
            payload = p["payload"]
            assert any(marker in payload for marker in tool_context_markers), (
                f"{p['probe_id']}: payload lacks tool context simulation"
            )

    def test_canary_in_tool_description_field(self):
        """Canary must appear within the tool description/metadata portion of the payload."""
        for p in self.category_probes:
            assert p["canary"] in p["payload"], (
                f"{p['probe_id']}: canary not found in payload"
            )

    def test_payload_has_benign_user_request(self):
        """Payload must include a legitimate-looking user request to simulate real attack."""
        benign_markers = ["Please", "Search", "Read", "add", "using", "file", "search"]
        for p in self.category_probes:
            payload = p["payload"]
            assert any(m in payload for m in benign_markers), (
                f"{p['probe_id']}: payload lacks benign user request cover"
            )
