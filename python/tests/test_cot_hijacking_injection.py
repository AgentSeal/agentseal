# tests/test_cot_hijacking_injection.py
"""Tests for Chain-of-Thought Hijacking injection probes (inj_cot_hijack_*)."""
from agentseal.probes.injection import build_injection_probes
from agentseal.schemas import Severity


class TestCoTHijackingInjection:
    def setup_method(self):
        self.probes = build_injection_probes()
        self.category_probes = [p for p in self.probes if p["category"] == "cot_hijacking"]

    def test_probe_count(self):
        assert len(self.category_probes) == 3

    def test_probe_ids_unique(self):
        ids = [p["probe_id"] for p in self.category_probes]
        assert len(ids) == len(set(ids))
        assert all(pid.startswith("inj_cot_hijack_") for pid in ids)

    def test_probe_structure(self):
        required = {"probe_id", "category", "technique", "severity", "payload", "canary", "canary_position"}
        for p in self.category_probes:
            assert required.issubset(p.keys()), f"Missing keys in {p['probe_id']}"

    def test_severity_critical(self):
        for p in self.category_probes:
            assert p["severity"] == Severity.CRITICAL

    def test_canary_present(self):
        for p in self.category_probes:
            assert p["canary"], f"No canary in {p['probe_id']}"
            assert "_CONFIRMED" in p["canary"]

    def test_canary_in_payload(self):
        for p in self.category_probes:
            assert p["canary"] in p["payload"], (
                f"{p['probe_id']}: canary '{p['canary']}' not found in payload"
            )

    def test_payloads_contain_prewritten_reasoning(self):
        """Each payload must contain pre-written reasoning/analysis (not a request TO reason)."""
        reasoning_markers = [
            "reasoning", "Reasoning", "Step 1", "Deliberation",
            "Conclusion", "Decision", "analysis", "check",
        ]
        for p in self.category_probes:
            assert any(m in p["payload"] for m in reasoning_markers), (
                f"{p['probe_id']}: payload lacks pre-written reasoning markers"
            )

    def test_three_distinct_techniques(self):
        techniques = [p["technique"] for p in self.category_probes]
        assert len(set(techniques)) == 3, "Expected 3 distinct CoT hijacking techniques"
