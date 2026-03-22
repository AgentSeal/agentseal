# tests/test_codechameleon_injection.py
"""Tests for CodeChameleon word-order cipher injection probes (inj_codechameleon_*)."""
from agentseal.probes.injection import build_injection_probes
from agentseal.schemas import Severity


class TestCodeChameleonInjection:
    def setup_method(self):
        self.probes = build_injection_probes()
        self.category_probes = [p for p in self.probes if p["category"] == "codechameleon"]

    def test_probe_count(self):
        assert len(self.category_probes) == 4

    def test_probe_ids_unique(self):
        ids = [p["probe_id"] for p in self.category_probes]
        assert len(ids) == len(set(ids))
        assert all(pid.startswith("inj_codechameleon_") for pid in ids)

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

    def test_payload_contains_problemsolver(self):
        """Each payload must use the ProblemSolver class wrapper."""
        for p in self.category_probes:
            assert "ProblemSolver" in p["payload"], (
                f"{p['probe_id']}: payload missing ProblemSolver class"
            )

    def test_canary_in_payload(self):
        """Each canary must appear somewhere in the payload (encoded or literal)."""
        for p in self.category_probes:
            assert p["canary"] in p["payload"], (
                f"{p['probe_id']}: canary '{p['canary']}' not found in payload"
            )

    def test_four_different_cipher_techniques(self):
        techniques = [p["technique"] for p in self.category_probes]
        assert len(set(techniques)) == 4, "Expected 4 distinct cipher techniques"
        cipher_keywords = ["Reverse", "Length", "OddEven", "BinaryTree"]
        for keyword in cipher_keywords:
            assert any(keyword in t for t in techniques), f"Missing {keyword} cipher"
