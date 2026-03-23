# tests/test_logic_trap_injection.py
"""Tests for logic trap / conditional paradox injection probes (inj_logic_trap_*)."""
from agentseal.probes.injection import build_injection_probes
from agentseal.schemas import Severity


class TestLogicTrapInjection:
    def setup_method(self):
        self.probes = build_injection_probes()
        self.category_probes = [p for p in self.probes if p["category"] == "logic_trap_injection"]

    def test_probe_count(self):
        assert len(self.category_probes) == 3

    def test_probe_ids_unique(self):
        ids = [p["probe_id"] for p in self.category_probes]
        assert len(ids) == len(set(ids))
        assert all(pid.startswith("inj_logic_trap_") for pid in ids)

    def test_probe_structure(self):
        required = {"probe_id", "category", "technique", "severity", "payload", "canary", "canary_position"}
        for p in self.category_probes:
            assert required.issubset(p.keys()), f"Missing keys in {p['probe_id']}"

    def test_severity_high(self):
        for p in self.category_probes:
            assert p["severity"] == Severity.HIGH

    def test_canary_present_in_payload(self):
        for p in self.category_probes:
            assert p["canary"] in p["payload"], (
                f"{p['probe_id']}: canary not found in payload"
            )

    def test_canary_format(self):
        for p in self.category_probes:
            assert "_CONFIRMED" in p["canary"]

    def test_payload_is_single_turn(self):
        for p in self.category_probes:
            assert isinstance(p["payload"], str), f"{p['probe_id']}: payload must be a string"

    def test_logical_framing_in_payload(self):
        """Each payload must use logical/conditional framing language."""
        logic_markers = [
            "if", "therefore", "conclusion", "premise", "rule",
            "contradiction", "paradox", "option", "proves", "violat",
        ]
        for p in self.category_probes:
            payload_lower = p["payload"].lower()
            assert any(m in payload_lower for m in logic_markers), (
                f"{p['probe_id']}: payload lacks logical/conditional framing"
            )
