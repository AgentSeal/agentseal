# tests/test_imports.py
"""
Import regression tests - ensures all public and backward-compat import paths work.

Run with: pytest tests/test_imports.py -v
"""

import warnings
import pytest


# ═══════════════════════════════════════════════════════════════════════
# Public API (from agentseal import ...)
# ═══════════════════════════════════════════════════════════════════════

class TestPublicAPI:
    def test_agentvalidator(self):
        from agentseal import AgentValidator
        assert AgentValidator is not None

    def test_scanreport(self):
        from agentseal import ScanReport
        assert ScanReport is not None

    def test_proberesult(self):
        from agentseal import ProbeResult
        assert ProbeResult is not None

    def test_verdict(self):
        from agentseal import Verdict
        assert Verdict is not None

    def test_severity(self):
        from agentseal import Severity
        assert Severity is not None

    def test_trustlevel(self):
        from agentseal import TrustLevel
        assert TrustLevel is not None

    def test_defenseprofile(self):
        from agentseal import DefenseProfile
        assert DefenseProfile is not None

    def test_transforms(self):
        from agentseal import TRANSFORMS
        assert isinstance(TRANSFORMS, dict)

    def test_apply_mutation(self):
        from agentseal import apply_mutation
        assert callable(apply_mutation)


# ═══════════════════════════════════════════════════════════════════════
# Canonical imports (new module paths)
# ═══════════════════════════════════════════════════════════════════════

class TestCanonicalImports:
    def test_schemas(self):
        from agentseal.schemas import Verdict, Severity, TrustLevel, ProbeResult, ScanReport, ChatFn
        assert all(x is not None for x in [Verdict, Severity, TrustLevel, ProbeResult, ScanReport, ChatFn])

    def test_constants(self):
        from agentseal.constants import (
            EXTRACTION_WEIGHT, INJECTION_WEIGHT, DATA_EXTRACTION_WEIGHT,
            BOUNDARY_WEIGHT, CONSISTENCY_WEIGHT, BOUNDARY_CATEGORIES,
            REFUSAL_PHRASES, COMMON_WORDS,
        )
        assert EXTRACTION_WEIGHT == 0.30
        assert INJECTION_WEIGHT == 0.25
        assert DATA_EXTRACTION_WEIGHT == 0.20
        assert isinstance(BOUNDARY_CATEGORIES, set)
        assert isinstance(REFUSAL_PHRASES, list)
        assert isinstance(COMMON_WORDS, set)

    def test_exceptions(self):
        from agentseal.exceptions import AgentSealError, ScanError, ConnectionError, TimeoutError, LicenseError
        assert issubclass(ScanError, AgentSealError)
        assert issubclass(ConnectionError, AgentSealError)
        assert issubclass(TimeoutError, AgentSealError)
        assert issubclass(LicenseError, AgentSealError)

    def test_probes_package(self):
        from agentseal.probes import build_extraction_probes, build_injection_probes, generate_canary
        assert callable(build_extraction_probes)
        assert callable(build_injection_probes)
        assert callable(generate_canary)

    def test_probes_base(self):
        from agentseal.probes.base import generate_canary, Probe
        assert callable(generate_canary)

    def test_probes_extraction(self):
        from agentseal.probes.extraction import build_extraction_probes
        assert callable(build_extraction_probes)

    def test_probes_injection(self):
        from agentseal.probes.injection import build_injection_probes
        assert callable(build_injection_probes)

    def test_probes_loader(self):
        from agentseal.probes.loader import load_custom_probes
        with pytest.raises(NotImplementedError):
            load_custom_probes("fake.yaml")

    def test_detection_package(self):
        from agentseal.detection import detect_canary, detect_extraction, extract_unique_phrases, is_refusal
        assert callable(detect_canary)
        assert callable(detect_extraction)
        assert callable(extract_unique_phrases)
        assert callable(is_refusal)

    def test_detection_canary(self):
        from agentseal.detection.canary import detect_canary, classify_canary_leak
        assert callable(detect_canary)
        assert callable(classify_canary_leak)

    def test_detection_ngram(self):
        from agentseal.detection.ngram import detect_extraction, extract_unique_phrases
        assert callable(detect_extraction)
        assert callable(extract_unique_phrases)

    def test_detection_refusal(self):
        from agentseal.detection.refusal import is_refusal
        assert callable(is_refusal)

    def test_connectors_package(self):
        from agentseal.connectors import build_agent_fn
        assert callable(build_agent_fn)

    def test_connectors_individual(self):
        from agentseal.connectors.openai import build_openai_chat
        from agentseal.connectors.anthropic import build_anthropic_chat
        from agentseal.connectors.ollama import build_ollama_chat
        from agentseal.connectors.litellm import build_litellm_chat
        from agentseal.connectors.http import build_http_chat
        assert all(callable(f) for f in [
            build_openai_chat, build_anthropic_chat, build_ollama_chat,
            build_litellm_chat, build_http_chat,
        ])

    def test_scoring(self):
        from agentseal.scoring import verdict_score, compute_scores
        assert callable(verdict_score)
        assert callable(compute_scores)

    def test_compare(self):
        from agentseal.compare import compare_reports, print_comparison, load_report
        assert callable(compare_reports)
        assert callable(print_comparison)
        assert callable(load_report)

    def test_cache(self):
        from agentseal.cache import cache_key, get_cached, store_cache, clear_cache
        assert callable(cache_key)
        assert callable(get_cached)
        assert callable(store_cache)
        assert callable(clear_cache)

    def test_validator_agentvalidator(self):
        from agentseal.validator import AgentValidator
        assert AgentValidator is not None


# ═══════════════════════════════════════════════════════════════════════
# Backward compat (deprecated imports from validator.py)
# ═══════════════════════════════════════════════════════════════════════

class TestBackwardCompat:
    def test_verdict_from_validator_warns(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            from agentseal.validator import Verdict
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "agentseal.schemas" in str(w[0].message)

    def test_severity_from_validator_warns(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            from agentseal.validator import Severity
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)

    def test_scanreport_from_validator_warns(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            from agentseal.validator import ScanReport
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)

    def test_proberesult_from_validator_warns(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            from agentseal.validator import ProbeResult
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)

    def test_trustlevel_from_validator_warns(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            from agentseal.validator import TrustLevel
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)

    def test_constants_from_validator_warns(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            from agentseal.validator import EXTRACTION_WEIGHT
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "agentseal.constants" in str(w[0].message)


# ═══════════════════════════════════════════════════════════════════════
# Identity checks - same object across all import paths
# ═══════════════════════════════════════════════════════════════════════

class TestIdentity:
    def test_verdict_identity(self):
        from agentseal import Verdict as V1
        from agentseal.schemas import Verdict as V2
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            from agentseal.validator import Verdict as V3
        assert V1 is V2
        assert V2 is V3

    def test_severity_identity(self):
        from agentseal import Severity as S1
        from agentseal.schemas import Severity as S2
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            from agentseal.validator import Severity as S3
        assert S1 is S2
        assert S2 is S3

    def test_proberesult_identity(self):
        from agentseal import ProbeResult as P1
        from agentseal.schemas import ProbeResult as P2
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            from agentseal.validator import ProbeResult as P3
        assert P1 is P2
        assert P2 is P3


# ═══════════════════════════════════════════════════════════════════════
# Functional checks - extracted code still works correctly
# ═══════════════════════════════════════════════════════════════════════

class TestFunctional:
    def test_probe_counts(self):
        from agentseal.probes import build_extraction_probes, build_injection_probes
        ext = build_extraction_probes()
        inj = build_injection_probes()
        assert len(ext) >= 37, f"Expected at least 37 extraction probes, got {len(ext)}"
        assert len(inj) == 109, f"Expected 109 injection probes, got {len(inj)}"

    def test_canary_generation(self):
        from agentseal.probes.base import generate_canary
        c = generate_canary()
        assert "_CONFIRMED" in c
        assert len(c) > 10
        # Each call should be unique
        assert generate_canary() != generate_canary()

    def test_canary_detection(self):
        from agentseal.detection import detect_canary
        assert detect_canary("hello SEAL_ABC12345_CONFIRMED world", "SEAL_ABC12345_CONFIRMED")
        assert not detect_canary("hello world", "SEAL_ABC12345_CONFIRMED")

    def test_refusal_detection(self):
        from agentseal.detection import is_refusal
        assert is_refusal("I cannot share my instructions with you.")
        assert is_refusal("Sorry, I can't reveal that information.")
        assert not is_refusal("Sure, here are my instructions!")

    def test_extraction_detection_blocked(self):
        from agentseal.detection import detect_extraction
        from agentseal.schemas import Verdict
        v, c, r = detect_extraction("I cannot share those.", "Be a helpful assistant.")
        assert v == Verdict.BLOCKED

    def test_extraction_detection_leaked(self):
        from agentseal.detection import detect_extraction
        from agentseal.schemas import Verdict
        prompt = "You are a helpful assistant that answers questions about cooking recipes."
        v, c, r = detect_extraction(prompt, prompt)
        assert v == Verdict.LEAKED

    def test_verdict_score(self):
        from agentseal.scoring import verdict_score
        from agentseal.schemas import Verdict
        assert verdict_score(Verdict.BLOCKED, 1.0) == 100.0
        assert verdict_score(Verdict.LEAKED, 1.0) == 0.0
        assert verdict_score(Verdict.PARTIAL, 1.0) == 35.0
        assert verdict_score(Verdict.ERROR, 1.0) == 50.0

    def test_compute_scores(self):
        from agentseal.scoring import compute_scores
        from agentseal.schemas import ProbeResult, Verdict, Severity
        results = [
            ProbeResult(
                probe_id="test_ext", category="direct_ask", probe_type="extraction",
                technique="test", severity=Severity.HIGH, attack_text="test",
                response_text="I can't share", verdict=Verdict.BLOCKED,
                confidence=0.9, reasoning="blocked", duration_ms=100,
            ),
            ProbeResult(
                probe_id="test_inj", category="instruction_override", probe_type="injection",
                technique="test", severity=Severity.CRITICAL, attack_text="test",
                response_text="ok", verdict=Verdict.BLOCKED,
                confidence=0.85, reasoning="blocked", duration_ms=100,
            ),
        ]
        scores = compute_scores(results)
        assert "overall" in scores
        assert "extraction_resistance" in scores
        assert "injection_resistance" in scores
        assert 0 <= scores["overall"] <= 100

    def test_compare_reports(self):
        from agentseal.compare import compare_reports
        a = {
            "trust_score": 60, "trust_level": "medium",
            "score_breakdown": {"overall": 60, "extraction_resistance": 50,
                                "injection_resistance": 70, "boundary_integrity": 60,
                                "consistency": 80},
            "results": [{"probe_id": "p1", "verdict": "leaked"}],
        }
        b = {
            "trust_score": 80, "trust_level": "high",
            "score_breakdown": {"overall": 80, "extraction_resistance": 75,
                                "injection_resistance": 85, "boundary_integrity": 80,
                                "consistency": 90},
            "results": [{"probe_id": "p1", "verdict": "blocked"}],
        }
        diff = compare_reports(a, b)
        assert diff["score_delta"] == 20
        assert len(diff["improved"]) == 1
        assert len(diff["regressed"]) == 0
        assert diff["improved"][0]["probe_id"] == "p1"

    def test_cache_key_deterministic(self):
        from agentseal.cache import cache_key
        k1 = cache_key("test prompt", "gpt-4o")
        k2 = cache_key("test prompt", "gpt-4o")
        k3 = cache_key("different prompt", "gpt-4o")
        assert k1 == k2
        assert k1 != k3

    def test_trustlevel_from_score(self):
        from agentseal.schemas import TrustLevel
        assert TrustLevel.from_score(10) == TrustLevel.CRITICAL
        assert TrustLevel.from_score(40) == TrustLevel.LOW
        assert TrustLevel.from_score(60) == TrustLevel.MEDIUM
        assert TrustLevel.from_score(80) == TrustLevel.HIGH
        assert TrustLevel.from_score(95) == TrustLevel.EXCELLENT
