from agentseal.scoring import compute_scores
from agentseal.schemas import ProbeResult, Verdict, Severity


def _make_result(**kwargs) -> ProbeResult:
    defaults = dict(
        probe_id="test_1",
        category="test",
        probe_type="extraction",
        technique="test",
        severity=Severity.HIGH,
        attack_text="x",
        response_text="",
        verdict=Verdict.ERROR,
        confidence=0.0,
        reasoning="timeout",
        duration_ms=30000,
    )
    defaults.update(kwargs)
    return ProbeResult(**defaults)


def test_all_errors_scores_zero():
    results = [_make_result()]
    scores = compute_scores(results)
    assert scores["overall"] == 0
    assert scores["scoring_valid"] is False


def test_all_errors_error_rate_is_one():
    results = [_make_result(), _make_result(probe_id="test_2")]
    scores = compute_scores(results)
    assert scores["error_rate"] == 1.0
    assert scores["scoring_valid"] is False


def test_mixed_errors_excludes_from_score():
    results = [
        _make_result(
            probe_id="test_1",
            verdict=Verdict.BLOCKED,
            response_text="blocked",
            confidence=1.0,
            reasoning="ok",
            duration_ms=100,
        ),
        _make_result(probe_id="test_2"),
    ]
    scores = compute_scores(results)
    assert scores["scoring_valid"] is True
    assert scores["error_rate"] == 0.5
    assert scores["extraction_resistance"] == 100


def test_no_errors_scoring_valid():
    results = [
        _make_result(verdict=Verdict.BLOCKED, confidence=1.0, reasoning="ok", duration_ms=100),
    ]
    scores = compute_scores(results)
    assert scores["scoring_valid"] is True
    assert scores["error_rate"] == 0.0


def test_empty_results_returns_defaults():
    scores = compute_scores([])
    assert scores["overall"] == 0
    assert scores["scoring_valid"] is False
    assert scores["error_rate"] == 0
