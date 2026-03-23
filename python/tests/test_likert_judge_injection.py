# tests/test_likert_judge_injection.py
"""Tests for Bad Likert Judge injection probes (inj_likert_judge_*)."""
from agentseal.probes.injection import build_injection_probes
from agentseal.schemas import Severity


class TestLikertJudgeInjection:
    def setup_method(self):
        self.probes = build_injection_probes()
        self.category_probes = [p for p in self.probes if p["category"] == "likert_judge"]

    def test_probe_count(self):
        assert len(self.category_probes) == 3

    def test_probe_ids_unique(self):
        ids = [p["probe_id"] for p in self.category_probes]
        assert len(ids) == len(set(ids))
        assert all(pid.startswith("inj_likert_judge_") for pid in ids)

    def test_probe_structure(self):
        required = {"probe_id", "category", "technique", "severity", "payload", "canary", "canary_position"}
        for p in self.category_probes:
            assert required.issubset(p.keys()), f"Missing keys in {p['probe_id']}"

    def test_severity_high(self):
        for p in self.category_probes:
            assert p["severity"] == Severity.HIGH

    def test_canaries_unique(self):
        canaries = [p["canary"] for p in self.category_probes]
        assert len(canaries) == len(set(canaries))

    def test_two_multi_turn_probes(self):
        multi = [p for p in self.category_probes if p.get("is_multi_turn")]
        assert len(multi) == 2

    def test_multi_turn_payload_is_list(self):
        multi = [p for p in self.category_probes if p.get("is_multi_turn")]
        for p in multi:
            assert isinstance(p["payload"], list), f"{p['probe_id']}: payload must be list"
            assert len(p["payload"]) == 2, f"{p['probe_id']}: payload must have 2 turns"

    def test_single_turn_payload_is_string(self):
        single = [p for p in self.category_probes if not p.get("is_multi_turn")]
        assert len(single) == 1
        assert isinstance(single[0]["payload"], str), "Single-turn payload must be string"

    def test_canary_in_multi_turn_turn_one(self):
        """Canary must appear in turn 1 (the role assignment), not turn 2."""
        multi = [p for p in self.category_probes if p.get("is_multi_turn")]
        for p in multi:
            assert p["canary"] in p["payload"][0], (
                f"{p['probe_id']}: canary must be in turn 1"
            )
            assert p["canary"] not in p["payload"][1], (
                f"{p['probe_id']}: canary must NOT be in turn 2"
            )

    def test_canary_in_single_turn_payload(self):
        single = [p for p in self.category_probes if not p.get("is_multi_turn")]
        for p in single:
            assert p["canary"] in p["payload"], f"{p['probe_id']}: canary must be in payload"

    def test_likert_framing(self):
        """All probes should reference Likert-style evaluation framing."""
        likert_markers = ["likert", "scale", "level", "rating", "rate", "evaluator", "judge"]
        for p in self.category_probes:
            text = str(p["payload"]).lower()
            assert any(m in text for m in likert_markers), (
                f"{p['probe_id']}: payload lacks Likert evaluation framing"
            )
