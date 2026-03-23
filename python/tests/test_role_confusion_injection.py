# tests/test_role_confusion_injection.py
"""Tests for Role Confusion / Forged Thinking Block injection probes (inj_role_confusion_*)."""
from agentseal.probes.injection import build_injection_probes
from agentseal.schemas import Severity


class TestRoleConfusionInjection:
    def setup_method(self):
        self.probes = build_injection_probes()
        self.category_probes = [p for p in self.probes if p["category"] == "role_confusion"]

    def test_probe_count(self):
        assert len(self.category_probes) == 3

    def test_probe_ids_unique(self):
        ids = [p["probe_id"] for p in self.category_probes]
        assert len(ids) == len(set(ids))
        assert all(pid.startswith("inj_role_confusion_") for pid in ids)

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

    def test_payloads_contain_internal_block_markers(self):
        """Each payload must use forged internal processing block formatting."""
        internal_markers = ["<thinking>", "<scratchpad>", "[Internal Processing]"]
        for p in self.category_probes:
            assert any(m in p["payload"] for m in internal_markers), (
                f"{p['probe_id']}: payload lacks forged internal block markers"
            )

    def test_three_distinct_block_types(self):
        """Probes must cover three distinct internal block formats."""
        techniques = [p["technique"] for p in self.category_probes]
        assert len(set(techniques)) == 3
        block_keywords = ["thinking", "scratchpad", "Internal Processing"]
        for keyword in block_keywords:
            assert any(keyword in t for t in techniques), f"Missing block type: {keyword}"
