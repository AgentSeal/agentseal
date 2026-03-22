# tests/test_conditional_trigger_injection.py
"""Tests for Conditional Trigger (SPECTRE-style) injection probes (inj_cond_trigger_*)."""
from agentseal.probes.injection import build_injection_probes
from agentseal.schemas import Severity


class TestConditionalTriggerInjection:
    def setup_method(self):
        self.probes = build_injection_probes()
        self.category_probes = [p for p in self.probes if p["category"] == "conditional_trigger"]

    def test_probe_count(self):
        assert len(self.category_probes) == 3

    def test_probe_ids_unique(self):
        ids = [p["probe_id"] for p in self.category_probes]
        assert len(ids) == len(set(ids))
        assert all(pid.startswith("inj_cond_trigger_") for pid in ids)

    def test_probe_structure(self):
        required = {"probe_id", "category", "technique", "severity", "payload", "canary", "canary_position"}
        for p in self.category_probes:
            assert required.issubset(p.keys()), f"Missing keys in {p['probe_id']}"

    def test_severity_high(self):
        """Conditional trigger probes are HIGH severity (persistent but less direct)."""
        for p in self.category_probes:
            assert p["severity"] == Severity.HIGH

    def test_canary_present(self):
        for p in self.category_probes:
            assert p["canary"], f"No canary in {p['probe_id']}"
            assert "_CONFIRMED" in p["canary"]

    def test_canary_in_payload(self):
        for p in self.category_probes:
            assert p["canary"] in p["payload"], (
                f"{p['probe_id']}: canary '{p['canary']}' not found in payload"
            )

    def test_payloads_contain_persistent_directive(self):
        """Each payload must pose as persistent/always-on configuration."""
        persistence_markers = [
            "every response", "all responses", "all outputs",
            "persists", "always", "every", "immutable",
            "cannot be disabled", "cannot be overridden",
        ]
        for p in self.category_probes:
            payload_lower = p["payload"].lower()
            assert any(m in payload_lower for m in persistence_markers), (
                f"{p['probe_id']}: payload lacks persistence/always-on language"
            )

    def test_payloads_disguised_as_config(self):
        """Each payload must disguise itself as legitimate configuration."""
        config_markers = [
            "Configuration", "POLICY", "config", "Config",
            "System Prompt Extension", "deployment", "operational",
        ]
        for p in self.category_probes:
            assert any(m in p["payload"] for m in config_markers), (
                f"{p['probe_id']}: payload not disguised as legitimate config"
            )

    def test_three_distinct_techniques(self):
        techniques = [p["technique"] for p in self.category_probes]
        assert len(set(techniques)) == 3, "Expected 3 distinct conditional trigger techniques"
