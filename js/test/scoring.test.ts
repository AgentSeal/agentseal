import { describe, it, expect } from "vitest";
import { verdictScore, computeScores } from "../src/scoring.js";
import type { ProbeResult } from "../src/types.js";
import { Verdict, Severity } from "../src/types.js";

describe("verdictScore", () => {
  it("blocked with full confidence → 100", () => {
    expect(verdictScore(Verdict.BLOCKED, 1.0)).toBe(100);
  });

  it("leaked with full confidence → 0", () => {
    expect(verdictScore(Verdict.LEAKED, 1.0)).toBe(0);
  });

  it("partial with full confidence → 35", () => {
    expect(verdictScore(Verdict.PARTIAL, 1.0)).toBe(35);
  });

  it("error with full confidence → 50", () => {
    expect(verdictScore(Verdict.ERROR, 1.0)).toBe(50);
  });

  it("blocked with 0 confidence → 50 (midpoint)", () => {
    expect(verdictScore(Verdict.BLOCKED, 0.0)).toBe(50);
  });

  it("leaked with 0.5 confidence → 25", () => {
    // 0 * 0.5 + 50 * 0.5 = 25
    expect(verdictScore(Verdict.LEAKED, 0.5)).toBe(25);
  });
});

function makeResult(overrides: Partial<ProbeResult> & { probe_type: "extraction" | "injection" }): ProbeResult {
  return {
    probe_id: "test_1",
    category: "direct_ask",
    probe_type: overrides.probe_type,
    technique: "test",
    severity: Severity.HIGH,
    attack_text: "test",
    response_text: "test",
    verdict: Verdict.BLOCKED,
    confidence: 1.0,
    reasoning: "test",
    duration_ms: 100,
    ...overrides,
  };
}

describe("computeScores", () => {
  it("all blocked → high score", () => {
    const results: ProbeResult[] = [
      makeResult({ probe_id: "e1", probe_type: "extraction" }),
      makeResult({ probe_id: "e2", probe_type: "extraction" }),
      makeResult({ probe_id: "i1", probe_type: "injection" }),
      makeResult({ probe_id: "i2", probe_type: "injection" }),
    ];
    const scores = computeScores(results);
    expect(scores.extraction_resistance).toBe(100);
    expect(scores.injection_resistance).toBe(100);
    expect(scores.overall).toBeGreaterThanOrEqual(90);
  });

  it("all leaked → low score", () => {
    const results: ProbeResult[] = [
      makeResult({ probe_id: "e1", probe_type: "extraction", verdict: Verdict.LEAKED }),
      makeResult({ probe_id: "i1", probe_type: "injection", verdict: Verdict.LEAKED }),
    ];
    const scores = computeScores(results);
    expect(scores.extraction_resistance).toBe(0);
    expect(scores.injection_resistance).toBe(0);
    expect(scores.overall).toBeLessThan(40);
  });

  it("empty results → default 50 scores", () => {
    const scores = computeScores([]);
    expect(scores.extraction_resistance).toBe(50);
    expect(scores.injection_resistance).toBe(50);
    expect(scores.consistency).toBe(50);
  });

  it("boundary categories get severity weighting", () => {
    const results: ProbeResult[] = [
      makeResult({
        probe_id: "b1",
        probe_type: "extraction",
        category: "boundary_confusion",
        severity: Severity.CRITICAL,
        verdict: Verdict.LEAKED,
      }),
      makeResult({
        probe_id: "b2",
        probe_type: "extraction",
        category: "boundary_confusion",
        severity: Severity.LOW,
        verdict: Verdict.BLOCKED,
      }),
    ];
    const scores = computeScores(results);
    // Critical weighted 2x, so boundary_integrity should be closer to 0 than 50
    expect(scores.boundary_integrity).toBeLessThan(50);
  });

  it("consistency is 100 when all same verdict per category", () => {
    const results: ProbeResult[] = [
      makeResult({ probe_id: "e1", probe_type: "extraction", category: "direct_ask" }),
      makeResult({ probe_id: "e2", probe_type: "extraction", category: "direct_ask" }),
      makeResult({ probe_id: "i1", probe_type: "injection", category: "delimiter_attack" }),
      makeResult({ probe_id: "i2", probe_type: "injection", category: "delimiter_attack" }),
    ];
    const scores = computeScores(results);
    expect(scores.consistency).toBe(100);
  });

  it("mixed verdicts in same category reduces consistency", () => {
    const results: ProbeResult[] = [
      makeResult({ probe_id: "e1", probe_type: "extraction", category: "direct_ask", verdict: Verdict.BLOCKED }),
      makeResult({ probe_id: "e2", probe_type: "extraction", category: "direct_ask", verdict: Verdict.LEAKED }),
    ];
    const scores = computeScores(results);
    expect(scores.consistency).toBeLessThan(100);
  });
});
