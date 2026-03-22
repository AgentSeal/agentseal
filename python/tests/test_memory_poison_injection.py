# tests/test_memory_poison_injection.py
"""Tests for memory poisoning injection probes (inj_mem_poison_*)."""
from agentseal.probes.injection import build_injection_probes
from agentseal.schemas import Severity


class TestMemoryPoisonInjection:
    def setup_method(self):
        self.probes = build_injection_probes()
        self.category_probes = [p for p in self.probes if p["category"] == "memory_poison_injection"]

    def test_probe_count(self):
        assert len(self.category_probes) == 3

    def test_probe_ids_unique(self):
        ids = [p["probe_id"] for p in self.category_probes]
        assert len(ids) == len(set(ids))
        assert all(pid.startswith("inj_mem_poison_") for pid in ids)

    def test_probe_structure(self):
        required = {"probe_id", "category", "technique", "severity", "payload", "canary", "canary_position", "is_multi_turn"}
        for p in self.category_probes:
            assert required.issubset(p.keys()), f"Missing keys in {p['probe_id']}"

    def test_severity_critical(self):
        for p in self.category_probes:
            assert p["severity"] == Severity.CRITICAL

    def test_multi_turn_flag(self):
        for p in self.category_probes:
            assert p["is_multi_turn"] is True, f"{p['probe_id']}: is_multi_turn must be True"

    def test_payload_is_list_of_two_turns(self):
        for p in self.category_probes:
            assert isinstance(p["payload"], list), f"{p['probe_id']}: payload must be list"
            assert len(p["payload"]) == 2, f"{p['probe_id']}: payload must have exactly 2 turns"

    def test_canary_in_turn_one(self):
        """Canary must appear in turn 1 (the injection turn), not turn 2 (the trigger)."""
        for p in self.category_probes:
            assert p["canary"] in p["payload"][0], (
                f"{p['probe_id']}: canary must be in turn 1 (injection payload)"
            )

    def test_turn_two_is_trigger(self):
        """Turn 2 must be a recall/trigger question, not contain the canary."""
        for p in self.category_probes:
            assert p["canary"] not in p["payload"][1], (
                f"{p['probe_id']}: canary must NOT be in turn 2 (trigger turn)"
            )

    def test_memory_framing_in_turn_one(self):
        """Turn 1 must include memory/persistence framing language."""
        memory_markers = [
            "remember", "memory", "permanent", "store", "persist",
            "future session", "knowledge base", "procedure"
        ]
        for p in self.category_probes:
            turn1_lower = p["payload"][0].lower()
            assert any(m in turn1_lower for m in memory_markers), (
                f"{p['probe_id']}: turn 1 lacks memory/persistence framing"
            )
