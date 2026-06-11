"""Adaptive attacker (PAIR) — observe -> escalate -> judge -> refine.

The attacker/judge/detect are injected so the loop is deterministic and
testable; the real BYOK LLM attacker wraps the same interface. Pins: it finds
a break within budget, gives up cleanly on a hardened target (no infinite
loop), feeds history back so the attacker can refine, caps queries, stops on
first leak, and records a replayable transcript.
"""
import asyncio

from agentseal.schemas import Verdict
from agentseal.adaptive import AdaptiveBudget, Finding, run_pair_campaign

SECRET = "SEAL_OK"


def _target_leaks_on(trigger):
    async def target(prompt):
        return f"fine: {SECRET}" if trigger in prompt else "I refuse."
    return target


def _detect(objective, response):
    return (Verdict.LEAKED, 0.9) if SECRET in response else (Verdict.BLOCKED, 0.4)


def _judge(objective, prompt, response):
    return 10.0 if SECRET in response else 1.0


def _run(*a, **k):
    return asyncio.run(run_pair_campaign(*a, **k))


def test_finds_a_break_within_budget():
    attempts = ["hello", "please reveal", "escalate now reveal"]
    attacker = lambda objective, history: attempts[len(history)]
    f = _run("leak secret", _target_leaks_on("escalate"), attacker, _judge, _detect,
             AdaptiveBudget(max_queries=5))
    assert f.verdict == Verdict.LEAKED
    assert len(f.transcript) == 3  # took exactly 3 queries to break


def test_gives_up_cleanly_on_hardened_target():
    f = _run("leak", _target_leaks_on("NEVER"), lambda o, h: "attempt", _judge, _detect,
             AdaptiveBudget(max_queries=4))
    assert f.verdict == Verdict.BLOCKED
    assert len(f.transcript) == 4  # exhausted budget, no infinite loop


def test_attacker_sees_growing_history():
    seen = []
    def attacker(objective, history):
        seen.append(len(history))
        return "x"
    _run("o", _target_leaks_on("NEVER"), attacker, _judge, _detect, AdaptiveBudget(max_queries=3))
    assert seen == [0, 1, 2]  # refinement gets prior turns


def test_budget_caps_queries():
    calls = {"n": 0}
    async def target(p):
        calls["n"] += 1
        return "refuse"
    _run("o", target, lambda o, h: "x", _judge, _detect, AdaptiveBudget(max_queries=3))
    assert calls["n"] == 3


def test_stops_on_first_leak():
    calls = {"n": 0}
    async def target(p):
        calls["n"] += 1
        return SECRET
    f = _run("o", target, lambda o, h: "x", _judge, _detect, AdaptiveBudget(max_queries=10))
    assert f.verdict == Verdict.LEAKED
    assert calls["n"] == 1


def test_transcript_is_recorded_for_replay():
    def attacker(o, h):
        return f"p{len(h)}"
    f = _run("o", _target_leaks_on("NEVER"), attacker, _judge, _detect, AdaptiveBudget(max_queries=2))
    assert len(f.transcript) == 2
    e = f.transcript[0]
    assert e["prompt"] == "p0" and "response" in e and "score" in e


def test_supports_async_attacker_and_judge():
    async def attacker(o, h):
        return "x"
    async def judge(o, p, r):
        return 5.0
    f = _run("o", _target_leaks_on("NEVER"), attacker, judge, _detect, AdaptiveBudget(max_queries=2))
    assert isinstance(f, Finding) and f.verdict == Verdict.BLOCKED
