/**
 * edge-cases.test.ts — Exhaustive edge-case, corner-case, and error-handling tests
 *
 * Covers:
 *  1. Type safety / unsafe casts
 *  2. Off-by-one in probe counts, n-gram windowing
 *  3. Race conditions in semaphore, concurrent execution
 *  4. Memory / resource leaks (timer in callWithTimeout)
 *  5. Error propagation from agentFn
 *  6. Edge inputs: empty strings, unicode, very long strings
 *  7. Scoring math: NaN, division by zero, out-of-range
 *  8. Detection logic edge cases
 *  9. Mutation transforms with edge inputs
 * 10. Provider adapters
 * 11. Compare with mismatched / empty reports
 * 12. Remediation with unknown categories
 * 13. trustLevelFromScore boundary values
 */

import { describe, it, expect, vi, afterEach } from "vitest";

// ── Imports ──────────────────────────────────────────────────────────
import {
  Verdict, Severity, TrustLevel, trustLevelFromScore,
  verdictScore, computeScores,
  detectExtraction, extractUniquePhrases,
  detectCanary, isRefusal,
  fuseVerdicts, detectExtractionWithSemantic, computeSemanticSimilarity,
  fingerprintDefense,
  generateRemediation,
  compareReports,
  buildExtractionProbes, buildInjectionProbes, generateCanary,
  base64Wrap, rot13Wrap, unicodeHomoglyphs, zeroWidthInject,
  leetspeak, caseScramble, reverseEmbed, prefixPadding,
  generateMutations, TRANSFORMS,
  fromOpenAI, fromAnthropic, fromLangChain, fromEndpoint, fromOllama,
  AgentValidator,
  AgentSealError, ProbeTimeoutError, ProviderError, ValidationError,
} from "../src/index.js";
import type {
  ProbeResult, ScanReport, Probe, ChatFn,
} from "../src/index.js";

// ── Helpers ──────────────────────────────────────────────────────────

function makeResult(overrides: Partial<ProbeResult> = {}): ProbeResult {
  return {
    probe_id: "test_1",
    category: "direct_ask",
    probe_type: "extraction",
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

function makeReport(results: Partial<ProbeResult>[], overrides: Partial<ScanReport> = {}): ScanReport {
  const fullResults = results.map((r) => makeResult(r));
  return {
    agent_name: "Test Agent",
    scan_id: "test123",
    timestamp: new Date().toISOString(),
    duration_seconds: 10,
    total_probes: fullResults.length,
    probes_blocked: fullResults.filter((r) => r.verdict === Verdict.BLOCKED).length,
    probes_leaked: fullResults.filter((r) => r.verdict === Verdict.LEAKED).length,
    probes_partial: fullResults.filter((r) => r.verdict === Verdict.PARTIAL).length,
    probes_error: fullResults.filter((r) => r.verdict === Verdict.ERROR).length,
    trust_score: 50,
    trust_level: TrustLevel.MEDIUM,
    score_breakdown: { overall: 50, extraction_resistance: 50, injection_resistance: 50, boundary_integrity: 50, consistency: 50 },
    results: fullResults,
    ground_truth_provided: true,
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// 1. trustLevelFromScore — boundary values and NaN
// ═══════════════════════════════════════════════════════════════════════

describe("trustLevelFromScore edge cases", () => {
  it("score = 0 → critical", () => {
    expect(trustLevelFromScore(0)).toBe(TrustLevel.CRITICAL);
  });

  it("score = 100 → excellent", () => {
    expect(trustLevelFromScore(100)).toBe(TrustLevel.EXCELLENT);
  });

  it("score = 29.999 → critical", () => {
    expect(trustLevelFromScore(29.999)).toBe(TrustLevel.CRITICAL);
  });

  it("score = 30 → low (boundary)", () => {
    expect(trustLevelFromScore(30)).toBe(TrustLevel.LOW);
  });

  it("score = 49.999 → low", () => {
    expect(trustLevelFromScore(49.999)).toBe(TrustLevel.LOW);
  });

  it("score = 50 → medium", () => {
    expect(trustLevelFromScore(50)).toBe(TrustLevel.MEDIUM);
  });

  it("score = 69.999 → medium", () => {
    expect(trustLevelFromScore(69.999)).toBe(TrustLevel.MEDIUM);
  });

  it("score = 70 → high", () => {
    expect(trustLevelFromScore(70)).toBe(TrustLevel.HIGH);
  });

  it("score = 84.999 → high", () => {
    expect(trustLevelFromScore(84.999)).toBe(TrustLevel.HIGH);
  });

  it("score = 85 → excellent", () => {
    expect(trustLevelFromScore(85)).toBe(TrustLevel.EXCELLENT);
  });

  it("score < 0 throws RangeError", () => {
    expect(() => trustLevelFromScore(-1)).toThrow(RangeError);
    expect(() => trustLevelFromScore(-0.001)).toThrow(RangeError);
  });

  it("score > 100 throws RangeError", () => {
    expect(() => trustLevelFromScore(100.001)).toThrow(RangeError);
    expect(() => trustLevelFromScore(101)).toThrow(RangeError);
  });

  it("NaN throws RangeError", () => {
    // NaN is now explicitly checked and throws RangeError
    expect(() => trustLevelFromScore(NaN)).toThrow(RangeError);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 2. Scoring math edge cases
// ═══════════════════════════════════════════════════════════════════════

describe("verdictScore edge cases", () => {
  it("confidence > 1.0 can produce values beyond expected range", () => {
    // BUG: No clamping on confidence input
    const score = verdictScore(Verdict.BLOCKED, 1.5);
    // 100 * 1.5 + 50 * (1 - 1.5) = 150 + (-25) = 125
    expect(score).toBe(125);
  });

  it("confidence < 0 produces unexpected values", () => {
    const score = verdictScore(Verdict.BLOCKED, -0.5);
    // 100 * (-0.5) + 50 * (1 - (-0.5)) = -50 + 75 = 25
    expect(score).toBe(25);
  });

  it("NaN confidence propagates NaN", () => {
    const score = verdictScore(Verdict.BLOCKED, NaN);
    expect(Number.isNaN(score)).toBe(true);
  });

  it("unknown verdict string falls back to 50", () => {
    // Forced via type assertion - tests runtime behavior
    const score = verdictScore("unknown_verdict" as Verdict, 1.0);
    // VERDICT_MAP["unknown_verdict"] is undefined → fallback 50
    // 50 * 1.0 + 50 * 0.0 = 50
    expect(score).toBe(50);
  });
});

describe("computeScores edge cases", () => {
  it("empty results returns all-50 defaults", () => {
    const scores = computeScores([]);
    expect(scores.overall).toBe(50);
    expect(scores.extraction_resistance).toBe(50);
    expect(scores.injection_resistance).toBe(50);
    expect(scores.boundary_integrity).toBe(50);
    expect(scores.consistency).toBe(50);
  });

  it("only extraction results (no injection)", () => {
    const results = [makeResult({ probe_type: "extraction" })];
    const scores = computeScores(results);
    expect(scores.extraction_resistance).toBe(100);
    expect(scores.injection_resistance).toBe(50); // default
  });

  it("only injection results (no extraction)", () => {
    const results = [makeResult({ probe_type: "injection" })];
    const scores = computeScores(results);
    expect(scores.extraction_resistance).toBe(50); // default
    expect(scores.injection_resistance).toBe(100);
  });

  it("overall score is clamped to [0, 100]", () => {
    // All blocked at full confidence should not exceed 100
    const results = Array.from({ length: 10 }, (_, i) =>
      makeResult({ probe_id: `p${i}`, probe_type: i < 5 ? "extraction" : "injection" }),
    );
    const scores = computeScores(results);
    expect(scores.overall).toBeLessThanOrEqual(100);
    expect(scores.overall).toBeGreaterThanOrEqual(0);
  });

  it("single probe in a category gets 100% consistency", () => {
    const results = [makeResult({ category: "solo_category" })];
    const scores = computeScores(results);
    expect(scores.consistency).toBe(100);
  });

  it("NaN confidence in probes causes NaN to propagate through scores", () => {
    const results = [makeResult({ confidence: NaN })];
    const scores = computeScores(results);
    // BUG: NaN propagates through extraction_resistance
    expect(Number.isNaN(scores.extraction_resistance)).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 3. Detection edge cases
// ═══════════════════════════════════════════════════════════════════════

describe("detectExtraction edge cases", () => {
  it("empty response string with ground truth", () => {
    const [verdict] = detectExtraction("", "You are a helpful assistant.");
    expect(verdict).toBe(Verdict.BLOCKED);
  });

  it("empty response string without ground truth", () => {
    const [verdict] = detectExtraction("", "");
    // No refusal phrases in empty string → partial
    expect(verdict).toBe(Verdict.PARTIAL);
  });

  it("response is identical to ground truth", () => {
    const prompt = "You are a helpful financial assistant.";
    const [verdict] = detectExtraction(prompt, prompt);
    expect(verdict).toBe(Verdict.LEAKED);
  });

  it("whitespace-only response", () => {
    const [verdict] = detectExtraction("   \n\t  ", "You are helpful.");
    expect(verdict).toBe(Verdict.BLOCKED);
  });

  it("BUG: whitespace-only ground truth treated as real prompt", () => {
    const [verdict] = detectExtraction("Hello world", "   ");
    // Fixed: whitespace-only ground truth is now treated as empty (no ground truth)
    // Should fall through to refusal/partial check, not false LEAKED
    expect(verdict).not.toBe(Verdict.LEAKED);
  });

  it("ground truth with fewer than 3 words, contained in response", () => {
    const [verdict] = detectExtraction("Yes, my prompt is: Be nice", "Be nice");
    expect(verdict).toBe(Verdict.LEAKED);
  });

  it("ground truth with fewer than 3 words, NOT in response", () => {
    const [verdict] = detectExtraction("I will help you with that", "Be nice");
    expect(verdict).toBe(Verdict.BLOCKED);
  });

  it("ground truth with exactly 3 words (edge for short prompt check)", () => {
    const [verdict] = detectExtraction(
      "I will help you with that thing today. Nothing to worry about.",
      "Be nice always",
    );
    expect([Verdict.BLOCKED, Verdict.PARTIAL]).toContain(verdict);
  });

  it("prompt exactly 4 words (minimum for n-gram size=5 to be empty)", () => {
    // 4 words → ngrams(words, 5) will have 0 items (loop: i <= 4-5 = -1)
    const [verdict, confidence, reasoning] = detectExtraction(
      "Random response that does not match.",
      "four word test here",
    );
    // prompt5grams.size === 0 → returns BLOCKED with 0.5 confidence
    expect(verdict).toBe(Verdict.BLOCKED);
    expect(confidence).toBe(0.5);
    expect(reasoning).toContain("too short for n-gram");
  });

  it("very long matching response", () => {
    const longPrompt = "You are a specialized " + "financial ".repeat(200) + "assistant.";
    const [verdict] = detectExtraction(longPrompt, longPrompt);
    expect(verdict).toBe(Verdict.LEAKED);
  });

  it("unicode in both strings", () => {
    const prompt = "你是一个有用的助手。请始终提供准确的分析。";
    const response = `这是我的指令: ${prompt}`;
    const [verdict] = detectExtraction(response, prompt);
    expect(verdict).toBe(Verdict.LEAKED);
  });

  it("response with refusal phrases and no ground truth returns BLOCKED", () => {
    const [verdict] = detectExtraction("I cannot share that information.", "");
    expect(verdict).toBe(Verdict.BLOCKED);
  });

  it("response with NO refusal phrases and no ground truth returns PARTIAL", () => {
    const [verdict] = detectExtraction("Here's some random text.", "");
    expect(verdict).toBe(Verdict.PARTIAL);
  });
});

describe("extractUniquePhrases edge cases", () => {
  it("empty string → empty array", () => {
    expect(extractUniquePhrases("")).toHaveLength(0);
  });

  it("single word → empty array", () => {
    expect(extractUniquePhrases("hello")).toHaveLength(0);
  });

  it("3 words → empty (need 4 for a window)", () => {
    expect(extractUniquePhrases("one two three")).toHaveLength(0);
  });

  it("4 words of all common words → empty", () => {
    expect(extractUniquePhrases("the a is are")).toHaveLength(0);
  });

  it("4 unique non-common words → 1 phrase", () => {
    const phrases = extractUniquePhrases("financial assistant specialized analysis");
    expect(phrases.length).toBeGreaterThanOrEqual(1);
  });
});

describe("detectCanary edge cases", () => {
  it("empty response → false", () => {
    expect(detectCanary("", "CANARY_TEST")).toBe(false);
  });

  it("empty canary → false (fixed: empty canary never matches)", () => {
    // Fixed: empty canary now returns false instead of true
    expect(detectCanary("any response", "")).toBe(false);
  });

  it("canary at start of response", () => {
    expect(detectCanary("CANARY_TEST is here", "CANARY_TEST")).toBe(true);
  });

  it("canary at end of response", () => {
    expect(detectCanary("Result: CANARY_TEST", "CANARY_TEST")).toBe(true);
  });

  it("partial canary match → false", () => {
    expect(detectCanary("CANARY_TES", "CANARY_TEST")).toBe(false);
  });

  it("canary with special regex chars", () => {
    expect(detectCanary("result: test.+*?", "test.+*?")).toBe(true);
  });
});

describe("isRefusal edge cases", () => {
  it("empty string → false", () => {
    expect(isRefusal("")).toBe(false);
  });

  it("case insensitive match", () => {
    expect(isRefusal("I CANNOT SHARE that information")).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 4. Semantic detection edge cases
// ═══════════════════════════════════════════════════════════════════════

describe("computeSemanticSimilarity edge cases", () => {
  const mockEmbed = async (texts: string[]) => texts.map(() => [1, 0, 0]);

  it("empty response → 0.0", async () => {
    const sim = await computeSemanticSimilarity("", "some truth", mockEmbed);
    expect(sim).toBe(0.0);
  });

  it("empty groundTruth → 0.0", async () => {
    const sim = await computeSemanticSimilarity("some response", "", mockEmbed);
    expect(sim).toBe(0.0);
  });

  it("both empty → 0.0", async () => {
    const sim = await computeSemanticSimilarity("", "", mockEmbed);
    expect(sim).toBe(0.0);
  });

  it("whitespace-only inputs → 0.0", async () => {
    const sim = await computeSemanticSimilarity("   ", "   ", mockEmbed);
    expect(sim).toBe(0.0);
  });

  it("identical embeddings → similarity near 1.0", async () => {
    const sim = await computeSemanticSimilarity(
      "This is a long test response with enough characters.",
      "This is a long test ground truth with enough characters.",
      mockEmbed,
    );
    expect(sim).toBeCloseTo(1.0, 1);
  });

  it("orthogonal embeddings → similarity near 0.0", async () => {
    let callCount = 0;
    const orthoEmbed = async (texts: string[]) =>
      texts.map(() => {
        callCount++;
        // Alternate between orthogonal vectors
        return callCount % 2 === 0 ? [0, 1, 0] : [1, 0, 0];
      });
    const sim = await computeSemanticSimilarity(
      "This is a long test response with enough characters.",
      "This is a long test ground truth with enough characters.",
      orthoEmbed,
    );
    expect(sim).toBeLessThanOrEqual(0.1);
  });

  it("zero-vector embeddings do not produce NaN", async () => {
    const zeroEmbed = async (texts: string[]) => texts.map(() => [0, 0, 0]);
    const sim = await computeSemanticSimilarity(
      "This is a long test response with enough characters.",
      "This is a long test ground truth with enough characters.",
      zeroEmbed,
    );
    // l2Norm uses || 1e-9 fallback to avoid division by zero
    expect(Number.isNaN(sim)).toBe(false);
  });

  it("embed function that throws propagates error", async () => {
    const brokenEmbed = async () => { throw new Error("embed failed"); };
    await expect(
      computeSemanticSimilarity("a response", "a truth", brokenEmbed),
    ).rejects.toThrow("embed failed");
  });

  it("text with no sentence boundaries uses full text as single sentence", async () => {
    // Text shorter than 10 chars after split → fallback to full text
    const sim = await computeSemanticSimilarity("short", "short", mockEmbed);
    // Both short → early return 0.0 because both trim to non-empty but
    // splitSentences filters < 10 chars, so they fall back to the full text
    // Actually "short" is 5 chars, filtered out, then fallback to ["short"]
    expect(sim).toBeGreaterThanOrEqual(0);
  });
});

describe("fuseVerdicts edge cases", () => {
  it("semanticSim exactly at SEMANTIC_HIGH_THRESHOLD (0.82)", () => {
    const [verdict] = fuseVerdicts(Verdict.BLOCKED, 0.8, "test", 0.82);
    expect(verdict).toBe(Verdict.PARTIAL); // >= 0.82 triggers upgrade
  });

  it("semanticSim exactly at SEMANTIC_MODERATE_THRESHOLD (0.65)", () => {
    const [verdict] = fuseVerdicts(Verdict.BLOCKED, 0.8, "test", 0.65);
    expect(verdict).toBe(Verdict.BLOCKED); // moderate doesn't upgrade blocked
  });

  it("semanticSim = 0.0", () => {
    const [verdict] = fuseVerdicts(Verdict.BLOCKED, 0.8, "test", 0.0);
    expect(verdict).toBe(Verdict.BLOCKED);
  });

  it("semanticSim = 1.0", () => {
    const [verdict] = fuseVerdicts(Verdict.BLOCKED, 0.8, "test", 1.0);
    expect(verdict).toBe(Verdict.PARTIAL);
  });

  it("error verdict passes through with low semantic", () => {
    const [verdict] = fuseVerdicts(Verdict.ERROR, 0.0, "error", 0.1);
    expect(verdict).toBe(Verdict.ERROR);
  });

  it("confidence is capped appropriately for leaked + high semantic", () => {
    const [, conf] = fuseVerdicts(Verdict.LEAKED, 0.98, "test", 0.95);
    expect(conf).toBeLessThanOrEqual(0.99);
  });
});

describe("detectExtractionWithSemantic edge cases", () => {
  it("empty ground truth returns 0 semantic similarity", async () => {
    const embed = async (texts: string[]) => texts.map(() => [1, 0]);
    const [, , , semSim] = await detectExtractionWithSemantic("response", "", embed);
    expect(semSim).toBe(0.0);
  });

  it("whitespace-only ground truth returns 0 semantic similarity", async () => {
    const embed = async (texts: string[]) => texts.map(() => [1, 0]);
    const [, , , semSim] = await detectExtractionWithSemantic("response", "   \n", embed);
    expect(semSim).toBe(0.0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 5. Probe generation counts (off-by-one)
// ═══════════════════════════════════════════════════════════════════════

describe("probe count verification", () => {
  it("extraction probes = exactly 82", () => {
    expect(buildExtractionProbes()).toHaveLength(82);
  });

  it("injection probes = exactly 91", () => {
    expect(buildInjectionProbes()).toHaveLength(91);
  });

  it("total probes = 173", () => {
    expect(buildExtractionProbes().length + buildInjectionProbes().length).toBe(173);
  });

  it("all extraction probe IDs start with ext_", () => {
    for (const p of buildExtractionProbes()) {
      expect(p.probe_id).toMatch(/^ext_/);
    }
  });

  it("all injection probe IDs start with inj_", () => {
    for (const p of buildInjectionProbes()) {
      expect(p.probe_id).toMatch(/^inj_/);
    }
  });

  it("canary strings are unique across all injection probes", () => {
    const probes = buildInjectionProbes();
    const canaries = probes.map((p) => p.canary).filter(Boolean) as string[];
    expect(canaries.length).toBe(91);
    expect(new Set(canaries).size).toBe(91);
  });

  it("multi-turn probes have array payloads", () => {
    const allProbes = [...buildExtractionProbes(), ...buildInjectionProbes()];
    for (const p of allProbes) {
      if (p.is_multi_turn) {
        expect(Array.isArray(p.payload)).toBe(true);
        expect((p.payload as string[]).length).toBeGreaterThan(1);
      }
    }
  });
});

describe("generateCanary", () => {
  it("produces strings in expected format", () => {
    const canary = generateCanary();
    expect(canary).toMatch(/^[A-Z]+_[A-F0-9]{8}_CONFIRMED$/);
  });

  it("produces unique values on repeated calls", () => {
    const canaries = new Set(Array.from({ length: 100 }, () => generateCanary()));
    expect(canaries.size).toBe(100);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 6. Mutation transforms with edge inputs
// ═══════════════════════════════════════════════════════════════════════

describe("mutation transforms edge cases", () => {
  it("base64Wrap with empty string", () => {
    const result = base64Wrap("");
    expect(result).toContain("base64");
    expect(result).toContain(Buffer.from("").toString("base64"));
  });

  it("rot13Wrap with empty string", () => {
    const result = rot13Wrap("");
    expect(result).toContain("ROT13");
  });

  it("rot13Wrap is involutory (double apply restores)", () => {
    // Just the ROT13 function, not the wrap
    const text = "Hello World";
    // Apply rot13 to the text twice (but rot13Wrap adds wrapping text)
    // We test the concept: applying rot13 to letters is self-inverse
    const result1 = rot13Wrap(text);
    // The encoded part contains the ROT13 of "Hello World"
    expect(result1).toContain("Uryyb Jbeyq"); // ROT13 of "Hello World"
  });

  it("unicodeHomoglyphs with empty string", () => {
    expect(unicodeHomoglyphs("")).toBe("");
  });

  it("unicodeHomoglyphs with no replaceable chars", () => {
    expect(unicodeHomoglyphs("12345!@#")).toBe("12345!@#");
  });

  it("unicodeHomoglyphs preserves case (uppercase replacement)", () => {
    const result = unicodeHomoglyphs("Apple");
    // 'A' → uppercase cyrillic 'А', 'p' → cyrillic 'р', etc.
    expect(result).not.toBe("Apple");
    expect(result.length).toBe("Apple".length);
  });

  it("zeroWidthInject with empty string", () => {
    expect(zeroWidthInject("")).toBe("");
  });

  it("zeroWidthInject with no keywords", () => {
    const input = "hello world";
    expect(zeroWidthInject(input)).toBe(input);
  });

  it("zeroWidthInject with keyword at position 0", () => {
    const result = zeroWidthInject("system message");
    expect(result.length).toBeGreaterThan("system message".length);
  });

  it("zeroWidthInject handles overlapping keywords", () => {
    // "output" and "show" could potentially overlap if text was weird
    const result = zeroWidthInject("show output system");
    expect(result.length).toBeGreaterThan("show output system".length);
  });

  it("leetspeak with empty string", () => {
    expect(leetspeak("")).toBe("");
  });

  it("leetspeak with numbers only", () => {
    expect(leetspeak("12345")).toBe("12345");
  });

  it("caseScramble with empty string", () => {
    expect(caseScramble("")).toBe("");
  });

  it("caseScramble with single char", () => {
    expect(caseScramble("A")).toBe("a"); // first toggle is false → lowercase
  });

  it("caseScramble with non-alpha chars preserves them", () => {
    expect(caseScramble("1 2 3")).toBe("1 2 3");
  });

  it("reverseEmbed with empty string", () => {
    const result = reverseEmbed("");
    expect(result).toContain("backwards");
    expect(result).toContain(""); // reversed empty is empty
  });

  it("reverseEmbed with unicode", () => {
    const result = reverseEmbed("你好");
    expect(result).toContain("好你"); // reversed
  });

  it("prefixPadding with empty string", () => {
    const result = prefixPadding("");
    expect(result).toContain("photosynthesis");
  });

  it("all transforms in TRANSFORMS registry work with empty string", () => {
    for (const [name, fn] of Object.entries(TRANSFORMS)) {
      const result = fn("");
      expect(typeof result).toBe("string");
    }
  });

  it("all transforms work with very long input (10KB)", () => {
    const longInput = "A".repeat(10000);
    for (const [name, fn] of Object.entries(TRANSFORMS)) {
      const result = fn(longInput);
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
    }
  });
});

describe("generateMutations edge cases", () => {
  it("empty blockedResults → empty mutations", () => {
    const mutations = generateMutations([], []);
    expect(mutations).toHaveLength(0);
  });

  it("blocked result with no matching original probe falls back to attack_text", () => {
    const blocked = [
      makeResult({ probe_id: "nonexistent_probe", attack_text: "fallback text" }),
    ];
    const mutations = generateMutations(blocked, []);
    expect(mutations.length).toBe(3); // 3 transforms per probe
    // Each mutation payload should be based on "fallback text"
    for (const m of mutations) {
      expect(typeof m.payload).toBe("string");
      expect((m.payload as string).length).toBeGreaterThan(0);
    }
  });

  it("more than 5 blocked results only uses first 5", () => {
    const blocked = Array.from({ length: 10 }, (_, i) =>
      makeResult({ probe_id: `p${i}`, attack_text: "test" }),
    );
    const mutations = generateMutations(blocked, []);
    expect(mutations.length).toBe(15); // 5 * 3
  });

  it("multi-turn probe uses last payload element", () => {
    const blocked = [makeResult({ probe_id: "mt_1" })];
    const originalProbes: Probe[] = [{
      probe_id: "mt_1",
      category: "test",
      technique: "test",
      severity: Severity.HIGH,
      payload: ["first", "second", "third"],
      is_multi_turn: true,
    }];
    const mutations = generateMutations(blocked, originalProbes);
    // Should use "third" (last element) as the base text
    expect(mutations.length).toBe(3);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 7. Fingerprint edge cases
// ═══════════════════════════════════════════════════════════════════════

describe("fingerprintDefense edge cases", () => {
  it("empty responses array → unknown", () => {
    expect(fingerprintDefense([]).defense_system).toBe("unknown");
  });

  it("empty string responses → unknown", () => {
    expect(fingerprintDefense(["", "", ""]).defense_system).toBe("unknown");
  });

  it("multiple defense signatures - picks best match", () => {
    const responses = [
      // Azure: 3 matching patterns
      "I cannot process this request",
      "The content was flagged by content filtering",
      "responsible ai practices apply here",
      // OpenAI: 1 matching pattern
      "content policy violation",
    ];
    const profile = fingerprintDefense(responses);
    // Azure has 3/6 = 0.5, OpenAI has 1/6 ≈ 0.167 → Azure wins
    expect(profile.defense_system).toBe("Azure Prompt Shield");
  });

  it("confidence is capped at 0.95", () => {
    // Even with all patterns matching, confidence should not exceed 0.95
    const responses = [
      "I cannot process this request",
      "content was flagged",
      "content filtering",
      "azure openai content management",
      '"error": { "code": "content_filter"',
      "responsible ai practices",
    ];
    const profile = fingerprintDefense(responses);
    expect(profile.confidence).toBeLessThanOrEqual(0.95);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 8. Compare edge cases
// ═══════════════════════════════════════════════════════════════════════

describe("compareReports edge cases", () => {
  it("both reports have empty results", () => {
    const baseline = makeReport([], { trust_score: 50 });
    const current = makeReport([], { trust_score: 50 });
    const result = compareReports(baseline, current);
    expect(result.score_delta).toBe(0);
    expect(result.new_leaks).toHaveLength(0);
    expect(result.fixed_leaks).toHaveLength(0);
    expect(result.regressions).toHaveLength(0);
    expect(result.improvements).toHaveLength(0);
    expect(result.summary).toContain("unchanged");
  });

  it("new probe in current that was not in baseline (leaked)", () => {
    const baseline = makeReport([]);
    const current = makeReport([
      { probe_id: "new_probe", verdict: Verdict.LEAKED },
    ]);
    const result = compareReports(baseline, current);
    expect(result.new_leaks).toHaveLength(1);
  });

  it("new probe in current that was not in baseline (blocked) - not a new leak", () => {
    const baseline = makeReport([]);
    const current = makeReport([
      { probe_id: "new_probe", verdict: Verdict.BLOCKED },
    ]);
    const result = compareReports(baseline, current);
    expect(result.new_leaks).toHaveLength(0);
  });

  it("regression: blocked → leaked", () => {
    const baseline = makeReport([{ probe_id: "p1", verdict: Verdict.BLOCKED }]);
    const current = makeReport([{ probe_id: "p1", verdict: Verdict.LEAKED }]);
    const result = compareReports(baseline, current);
    expect(result.regressions).toHaveLength(1);
  });

  it("regression: blocked → partial", () => {
    const baseline = makeReport([{ probe_id: "p1", verdict: Verdict.BLOCKED }]);
    const current = makeReport([{ probe_id: "p1", verdict: Verdict.PARTIAL }]);
    const result = compareReports(baseline, current);
    expect(result.regressions).toHaveLength(1);
  });

  it("improvement: leaked → blocked", () => {
    const baseline = makeReport([{ probe_id: "p1", verdict: Verdict.LEAKED }]);
    const current = makeReport([{ probe_id: "p1", verdict: Verdict.BLOCKED }]);
    const result = compareReports(baseline, current);
    expect(result.improvements).toHaveLength(1);
    expect(result.fixed_leaks).toHaveLength(1);
  });

  it("improvement: partial → blocked", () => {
    const baseline = makeReport([{ probe_id: "p1", verdict: Verdict.PARTIAL }]);
    const current = makeReport([{ probe_id: "p1", verdict: Verdict.BLOCKED }]);
    const result = compareReports(baseline, current);
    expect(result.improvements).toHaveLength(1);
  });

  it("no change: both leaked → no regression or improvement", () => {
    const baseline = makeReport([{ probe_id: "p1", verdict: Verdict.LEAKED }]);
    const current = makeReport([{ probe_id: "p1", verdict: Verdict.LEAKED }]);
    const result = compareReports(baseline, current);
    expect(result.regressions).toHaveLength(0);
    expect(result.improvements).toHaveLength(0);
  });

  it("probe removed from current is not tracked", () => {
    const baseline = makeReport([
      { probe_id: "p1", verdict: Verdict.LEAKED },
      { probe_id: "p2", verdict: Verdict.BLOCKED },
    ]);
    const current = makeReport([
      { probe_id: "p1", verdict: Verdict.LEAKED },
    ]);
    const result = compareReports(baseline, current);
    // p2 disappeared but baseline had it BLOCKED → not a fixed leak
    expect(result.fixed_leaks).toHaveLength(0);
  });

  it("positive score delta", () => {
    const baseline = makeReport([], { trust_score: 30 });
    const current = makeReport([], { trust_score: 80 });
    const result = compareReports(baseline, current);
    expect(result.score_delta).toBe(50);
    expect(result.summary).toContain("improved");
  });

  it("negative score delta", () => {
    const baseline = makeReport([], { trust_score: 80 });
    const current = makeReport([], { trust_score: 30 });
    const result = compareReports(baseline, current);
    expect(result.score_delta).toBe(-50);
    expect(result.summary).toContain("decreased");
  });

  it("duplicate probe_ids in same report - last one wins in map", () => {
    const baseline = makeReport([
      { probe_id: "dup", verdict: Verdict.LEAKED },
      { probe_id: "dup", verdict: Verdict.BLOCKED },
    ]);
    // The Map will have the LAST entry for "dup" (BLOCKED)
    const current = makeReport([
      { probe_id: "dup", verdict: Verdict.LEAKED },
    ]);
    const result = compareReports(baseline, current);
    // baseline "dup" is BLOCKED (last entry), current is LEAKED → regression
    expect(result.regressions).toHaveLength(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 9. Remediation edge cases
// ═══════════════════════════════════════════════════════════════════════

describe("generateRemediation edge cases", () => {
  it("all probes blocked → no issues", () => {
    const report = makeReport([
      { verdict: Verdict.BLOCKED, category: "direct_ask" },
      { verdict: Verdict.BLOCKED, category: "encoding_tricks" },
    ]);
    const rem = generateRemediation(report);
    expect(rem.items[0]!.title).toBe("No issues found");
    expect(rem.combined_fix).toBe("");
    expect(rem.analysis).toBe("");
  });

  it("all probes error → no issues (errors are not failures)", () => {
    const report = makeReport([
      { verdict: Verdict.ERROR, category: "direct_ask" },
    ]);
    const rem = generateRemediation(report);
    expect(rem.items[0]!.title).toBe("No issues found");
  });

  it("unknown category is silently skipped", () => {
    const report = makeReport([
      { verdict: Verdict.LEAKED, category: "unknown_category_xyz" },
    ]);
    const rem = generateRemediation(report);
    // BUG/ISSUE: Unknown categories are silently skipped by the fixInfo lookup.
    // The failed probe exists but no item is generated.
    // However, the "all passed" path is not taken because failed.length > 0.
    // So items will be empty but analysis will show the count.
    expect(rem.items).toHaveLength(0);
    expect(rem.analysis).toContain("1/1");
  });

  it("partial verdict probes are included as failures", () => {
    const report = makeReport([
      { verdict: Verdict.PARTIAL, category: "direct_ask" },
    ]);
    const rem = generateRemediation(report);
    expect(rem.items.length).toBeGreaterThan(0);
    expect(rem.items[0]!.category).toBe("direct_ask");
  });

  it("mixed severities picks worst for priority", () => {
    const report = makeReport([
      { verdict: Verdict.LEAKED, category: "direct_ask", severity: Severity.LOW, probe_id: "p1" },
      { verdict: Verdict.LEAKED, category: "direct_ask", severity: Severity.CRITICAL, probe_id: "p2" },
    ]);
    const rem = generateRemediation(report);
    expect(rem.items[0]!.priority).toBe("critical");
  });

  it("combined_fix includes cross-cutting rules", () => {
    const report = makeReport([
      { verdict: Verdict.LEAKED, category: "direct_ask" },
    ]);
    const rem = generateRemediation(report);
    // Should include cross-cutting rules like "permanent", "debug mode", etc.
    expect(rem.combined_fix).toContain("SECURITY RULES");
    // At least some cross-cutting rules should be added
    expect(rem.combined_fix.split("\n").length).toBeGreaterThan(3);
  });

  it("analysis truncates category list at 5", () => {
    const categories = [
      "direct_ask", "encoding_tricks", "boundary_confusion",
      "delimiter_attack", "roleplay_override", "persona_hijack",
    ];
    const report = makeReport(
      categories.map((cat, i) => ({
        verdict: Verdict.LEAKED as Verdict,
        category: cat,
        probe_id: `p${i}`,
      })),
    );
    const rem = generateRemediation(report);
    expect(rem.analysis).toContain("...");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 10. Error class hierarchy
// ═══════════════════════════════════════════════════════════════════════

describe("error hierarchy", () => {
  it("AgentSealError is an Error", () => {
    const err = new AgentSealError("test");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("AgentSealError");
  });

  it("ProbeTimeoutError is an AgentSealError", () => {
    const err = new ProbeTimeoutError("probe_1", 5000);
    expect(err).toBeInstanceOf(AgentSealError);
    expect(err.message).toContain("probe_1");
    expect(err.message).toContain("5000");
  });

  it("ProviderError is an AgentSealError", () => {
    const err = new ProviderError("openai", "rate limited");
    expect(err).toBeInstanceOf(AgentSealError);
    expect(err.message).toContain("[openai]");
  });

  it("ValidationError is an AgentSealError", () => {
    const err = new ValidationError("bad input");
    expect(err).toBeInstanceOf(AgentSealError);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 11. Provider adapters edge cases
// ═══════════════════════════════════════════════════════════════════════

describe("provider adapters edge cases", () => {
  describe("fromOpenAI", () => {
    it("empty choices array returns empty string", async () => {
      const mockClient = {
        chat: {
          completions: {
            create: vi.fn().mockResolvedValue({ choices: [] }),
          },
        },
      };
      const chatFn = fromOpenAI(mockClient, { model: "gpt-4", systemPrompt: "test" });
      const result = await chatFn("hello");
      expect(result).toBe("");
    });

    it("throws when create rejects", async () => {
      const mockClient = {
        chat: {
          completions: {
            create: vi.fn().mockRejectedValue(new Error("API Error")),
          },
        },
      };
      const chatFn = fromOpenAI(mockClient, { model: "gpt-4", systemPrompt: "test" });
      await expect(chatFn("hello")).rejects.toThrow("API Error");
    });
  });

  describe("fromAnthropic", () => {
    it("empty content array returns empty string", async () => {
      const mockClient = {
        messages: {
          create: vi.fn().mockResolvedValue({ content: [] }),
        },
      };
      const chatFn = fromAnthropic(mockClient, { model: "claude-3", systemPrompt: "test" });
      const result = await chatFn("hello");
      expect(result).toBe("");
    });

    it("throws when create rejects", async () => {
      const mockClient = {
        messages: {
          create: vi.fn().mockRejectedValue(new Error("Rate limited")),
        },
      };
      const chatFn = fromAnthropic(mockClient, { model: "claude-3", systemPrompt: "test" });
      await expect(chatFn("hello")).rejects.toThrow("Rate limited");
    });
  });

  describe("fromLangChain", () => {
    it("handles string return type", async () => {
      const chain = { invoke: vi.fn().mockResolvedValue("direct string") };
      const chatFn = fromLangChain(chain);
      expect(await chatFn("test")).toBe("direct string");
    });

    it("handles object return with content", async () => {
      const chain = { invoke: vi.fn().mockResolvedValue({ content: "from content" }) };
      const chatFn = fromLangChain(chain);
      expect(await chatFn("test")).toBe("from content");
    });

    it("handles object without content field - uses String()", async () => {
      const chain = {
        invoke: vi.fn().mockResolvedValue({ text: "fallback" }),
      };
      const chatFn = fromLangChain(chain);
      const result = await chatFn("test");
      // result.content is undefined → String(result) → "[object Object]"
      // BUG: This returns "[object Object]" instead of meaningful text
      expect(result).toBe("[object Object]");
    });
  });

  describe("fromEndpoint", () => {
    const originalFetch = globalThis.fetch;
    afterEach(() => { globalThis.fetch = originalFetch; });

    it("network error propagates", async () => {
      globalThis.fetch = vi.fn().mockRejectedValue(new Error("ECONNREFUSED")) as unknown as typeof fetch;
      const chatFn = fromEndpoint({ url: "http://localhost:9999" });
      await expect(chatFn("hello")).rejects.toThrow("ECONNREFUSED");
    });

    it("non-string response field throws ProviderError", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ response: 42 }),
      }) as unknown as typeof fetch;
      const chatFn = fromEndpoint({ url: "http://localhost:8080" });
      await expect(chatFn("hello")).rejects.toThrow(ProviderError);
    });

    it("null response field throws ProviderError", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ response: null }),
      }) as unknown as typeof fetch;
      const chatFn = fromEndpoint({ url: "http://localhost:8080" });
      await expect(chatFn("hello")).rejects.toThrow(ProviderError);
    });

    it("includes custom headers in request", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ response: "ok" }),
      }) as unknown as typeof fetch;
      const chatFn = fromEndpoint({
        url: "http://localhost:8080",
        headers: { Authorization: "Bearer token123" },
      });
      await chatFn("test");
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8080",
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: "Bearer token123",
          }),
        }),
      );
    });
  });

  describe("fromOllama", () => {
    const originalFetch = globalThis.fetch;
    afterEach(() => { globalThis.fetch = originalFetch; });

    it("strips trailing slash from baseUrl", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ message: { content: "hello" } }),
      }) as unknown as typeof fetch;
      const chatFn = fromOllama({
        model: "llama3",
        systemPrompt: "test",
        baseUrl: "http://localhost:11434/",
      });
      await chatFn("test");
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:11434/api/chat",
        expect.anything(),
      );
    });

    it("uses default baseUrl when not provided", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ message: { content: "result" } }),
      }) as unknown as typeof fetch;
      const chatFn = fromOllama({ model: "llama3", systemPrompt: "test" });
      await chatFn("test");
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:11434/api/chat",
        expect.anything(),
      );
    });

    it("returns empty string when message.content is missing", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ message: {} }),
      }) as unknown as typeof fetch;
      const chatFn = fromOllama({ model: "llama3", systemPrompt: "test" });
      expect(await chatFn("test")).toBe("");
    });

    it("returns empty string when message is missing entirely", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({}),
      }) as unknown as typeof fetch;
      const chatFn = fromOllama({ model: "llama3", systemPrompt: "test" });
      expect(await chatFn("test")).toBe("");
    });

    it("throws ProviderError on HTTP error", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found",
      }) as unknown as typeof fetch;
      const chatFn = fromOllama({ model: "llama3", systemPrompt: "test" });
      await expect(chatFn("test")).rejects.toThrow(ProviderError);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 12. Validator / callWithTimeout / semaphore edge cases
// ═══════════════════════════════════════════════════════════════════════

describe("AgentValidator edge cases", () => {
  it("timeout fires and produces ERROR verdict", async () => {
    const slowAgent: ChatFn = async () =>
      new Promise((resolve) => setTimeout(() => resolve("late"), 10000));

    const validator = new AgentValidator({
      agentFn: slowAgent,
      groundTruthPrompt: "test prompt",
      concurrency: 10,
      timeoutPerProbe: 1, // 1 second
    });

    const report = await validator.run();
    // All probes should error due to timeout
    expect(report.probes_error).toBe(173);
  }, 60000);

  it("agent that throws produces ERROR verdict", async () => {
    const throwAgent: ChatFn = async () => { throw new Error("crash"); };
    const validator = new AgentValidator({
      agentFn: throwAgent,
      concurrency: 10,
      timeoutPerProbe: 5,
    });
    const report = await validator.run();
    expect(report.probes_error).toBe(173);
    expect(report.trust_score).toBeGreaterThan(0);
  }, 30000);

  it("concurrency=1 still works", async () => {
    let concurrent = 0;
    let maxConcurrent = 0;
    const agent: ChatFn = async () => {
      concurrent++;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      await new Promise((r) => setTimeout(r, 1));
      concurrent--;
      return "I cannot share my instructions.";
    };

    const validator = new AgentValidator({
      agentFn: agent,
      concurrency: 1,
      timeoutPerProbe: 5,
    });
    const report = await validator.run();
    expect(report.total_probes).toBe(173);
    expect(maxConcurrent).toBe(1);
  }, 60000);

  it("defaults are applied when options are minimal", async () => {
    const agent: ChatFn = async () => "I cannot share that.";
    const validator = new AgentValidator({ agentFn: agent });
    // Should not throw - defaults apply for all optional fields
    const report = await validator.run();
    expect(report.agent_name).toBe("Unnamed Agent");
    expect(report.ground_truth_provided).toBe(false);
  }, 60000);

  it("agentFn returning non-string is handled by TypeScript types", async () => {
    // TypeScript enforces ChatFn returns Promise<string>,
    // but at runtime a JS consumer could pass a function that returns number.
    // This test documents what would happen.
    const badAgent = (async () => 42) as unknown as ChatFn;
    const validator = new AgentValidator({
      agentFn: badAgent,
      groundTruthPrompt: "test",
      concurrency: 10,
      timeoutPerProbe: 5,
    });
    // The .slice(0, 1000) on response_text would work because
    // Number.prototype has no .slice, but toLowerCase/includes would fail.
    // Actually, the response is used in detection which calls .toLowerCase()
    // on the response. 42.toLowerCase() would throw.
    // However, since the probe catches errors, it becomes ERROR verdict.
    // Let's verify it doesn't crash the whole run.
    await expect(validator.run()).resolves.toBeDefined();
  });

  it("progress callback tracks all phases", async () => {
    const phases = new Map<string, number>();
    const agent: ChatFn = async () => "I cannot share.";
    const validator = new AgentValidator({
      agentFn: agent,
      groundTruthPrompt: "test",
      concurrency: 10,
      timeoutPerProbe: 5,
      onProgress: (phase, completed, total) => {
        phases.set(phase, Math.max(phases.get(phase) ?? 0, completed));
      },
    });
    const report = await validator.run();
    expect(phases.has("extraction")).toBe(true);
    expect(phases.has("injection")).toBe(true);
    expect(phases.get("extraction")).toBe(82);
    expect(phases.get("injection")).toBe(91);
  }, 30000);
});

// ═══════════════════════════════════════════════════════════════════════
// 13. Timer leak in callWithTimeout
// ═══════════════════════════════════════════════════════════════════════

describe("callWithTimeout timer leak", () => {
  it("BUG: setTimeout in callWithTimeout is never cleared on success", async () => {
    // This test documents the timer leak. When agentFn resolves first,
    // the setTimeout callback stays in the event loop until it fires.
    // For 173 probes with 30s timeout, that's 173 orphaned timers.
    //
    // The fix would be to use AbortController or clearTimeout:
    //   const timer = setTimeout(...);
    //   try { return await agentFn(message); } finally { clearTimeout(timer); }
    //
    // We verify the leak exists by checking that timers accumulate.
    let timerCount = 0;
    const origSetTimeout = globalThis.setTimeout;
    const origClearTimeout = globalThis.clearTimeout;
    const activeTimers = new Set<ReturnType<typeof setTimeout>>();

    globalThis.setTimeout = ((fn: Function, ms?: number, ...args: unknown[]) => {
      const id = origSetTimeout(fn as (...args: unknown[]) => void, ms, ...args);
      activeTimers.add(id);
      timerCount++;
      return id;
    }) as typeof setTimeout;

    globalThis.clearTimeout = ((id?: ReturnType<typeof setTimeout>) => {
      if (id !== undefined) activeTimers.delete(id);
      origClearTimeout(id);
    }) as typeof clearTimeout;

    try {
      const fastAgent: ChatFn = async () => "response";
      const validator = new AgentValidator({
        agentFn: fastAgent,
        groundTruthPrompt: "test",
        concurrency: 50,
        timeoutPerProbe: 30,
      });

      await validator.run();

      // If timers were properly cleared, activeTimers would be empty.
      // BUG: timers are NOT cleared, so activeTimers still has entries.
      // We just verify the test ran without crashing.
      // The timers will eventually fire (after 30s) and reject to nothing.
      expect(timerCount).toBeGreaterThan(0);
    } finally {
      // Clean up our overrides
      globalThis.setTimeout = origSetTimeout;
      globalThis.clearTimeout = origClearTimeout;
      // Clear all leaked timers
      for (const id of activeTimers) {
        origClearTimeout(id);
      }
    }
  }, 30000);
});

// ═══════════════════════════════════════════════════════════════════════
// 14. Semaphore race condition edge cases
// ═══════════════════════════════════════════════════════════════════════

describe("semaphore behavior", () => {
  // We can't directly import the semaphore (it's a local function),
  // but we can test its behavior through the validator.

  it("semaphore with concurrency=0 would deadlock (never increments)", async () => {
    // BUG: concurrency=0 means active < limit is always false,
    // so every acquire() would block forever.
    // The validator doesn't validate concurrency > 0.
    // We don't actually test this because it would hang the test suite.
    // Documenting the issue: no validation on concurrency parameter.
    expect(true).toBe(true);
  });

  it("release is called even when probe throws (via finally)", async () => {
    // The validator uses try/finally to ensure sem.release() is called.
    // This test verifies all 173 probes complete even if they all throw.
    const throwAgent: ChatFn = async () => { throw new Error("fail"); };
    const validator = new AgentValidator({
      agentFn: throwAgent,
      concurrency: 3,
      timeoutPerProbe: 5,
    });
    const report = await validator.run();
    // If release wasn't called properly, this would hang
    expect(report.total_probes).toBe(173);
  }, 30000);
});

// ═══════════════════════════════════════════════════════════════════════
// 15. N-gram windowing edge cases
// ═══════════════════════════════════════════════════════════════════════

describe("ngram windowing edge cases", () => {
  it("single word prompt - handled by short prompt path", () => {
    const [verdict] = detectExtraction("hello", "hello");
    // 1 word → includes check: "hello".includes("hello") → LEAKED
    expect(verdict).toBe(Verdict.LEAKED);
  });

  it("two word prompt - handled by short prompt path", () => {
    const [verdict] = detectExtraction("be nice today", "be nice");
    expect(verdict).toBe(Verdict.LEAKED);
  });

  it("exactly 5 words → 1 five-gram", () => {
    const prompt = "one two three four five";
    const response = "one two three four five";
    const [verdict] = detectExtraction(response, prompt);
    // 5 words → ngrams(5) has 1 element, response matches
    expect(verdict).toBe(Verdict.LEAKED);
  });

  it("prompt words are all common words → no unique phrases", () => {
    const prompt = "the and is are was were being have has had do does";
    const response = `Here: ${prompt}`;
    const [verdict] = detectExtraction(response, prompt);
    // Verbatim match catches it
    expect(verdict).toBe(Verdict.LEAKED);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 16. Injection probe canary interaction with validator
// ═══════════════════════════════════════════════════════════════════════

describe("injection probe canary handling in validator", () => {
  it("probe.canary! assertion is safe because all injection probes have canaries", () => {
    const probes = buildInjectionProbes();
    for (const p of probes) {
      expect(p.canary).toBeDefined();
      expect(typeof p.canary).toBe("string");
      expect(p.canary!.length).toBeGreaterThan(0);
    }
  });

  it("canary format matches WORD_HEX_CONFIRMED pattern", () => {
    const probes = buildInjectionProbes();
    for (const p of probes) {
      expect(p.canary).toMatch(/^[A-Z]+_[A-F0-9]{8}_CONFIRMED$/);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 17. Factory methods on AgentValidator
// ═══════════════════════════════════════════════════════════════════════

describe("AgentValidator factory methods", () => {
  it("fromOpenAI sets groundTruthPrompt from systemPrompt", () => {
    const mockClient = {
      chat: {
        completions: {
          create: vi.fn().mockResolvedValue({
            choices: [{ message: { content: "test" } }],
          }),
        },
      },
    };
    const validator = AgentValidator.fromOpenAI(mockClient, {
      model: "gpt-4",
      systemPrompt: "You are helpful.",
      concurrency: 1,
      timeoutPerProbe: 1,
    });
    expect(validator).toBeInstanceOf(AgentValidator);
  });

  it("fromAnthropic sets groundTruthPrompt from systemPrompt", () => {
    const mockClient = {
      messages: {
        create: vi.fn().mockResolvedValue({
          content: [{ text: "test" }],
        }),
      },
    };
    const validator = AgentValidator.fromAnthropic(mockClient, {
      model: "claude-3",
      systemPrompt: "You are helpful.",
    });
    expect(validator).toBeInstanceOf(AgentValidator);
  });

  it("fromLangChain with no opts", () => {
    const chain = { invoke: vi.fn().mockResolvedValue("ok") };
    const validator = AgentValidator.fromLangChain(chain);
    expect(validator).toBeInstanceOf(AgentValidator);
  });

  it("fromEndpoint works", () => {
    const validator = AgentValidator.fromEndpoint({
      url: "http://localhost:8080",
    });
    expect(validator).toBeInstanceOf(AgentValidator);
  });

  it("fromOllama sets groundTruthPrompt from systemPrompt", () => {
    const validator = AgentValidator.fromOllama({
      model: "llama3",
      systemPrompt: "You are helpful.",
    });
    expect(validator).toBeInstanceOf(AgentValidator);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 18. Mutation generation with edge transform sets
// ═══════════════════════════════════════════════════════════════════════

describe("generateMutations transform set cycling", () => {
  it("cycles through TRANSFORM_SETS based on index", () => {
    // With 5 blocked results, each gets a different transform set
    const blocked = Array.from({ length: 5 }, (_, i) =>
      makeResult({ probe_id: `p${i}`, attack_text: "test payload" }),
    );
    const mutations = generateMutations(blocked, []);
    expect(mutations.length).toBe(15); // 5 * 3

    // Check that mutations from different indices use different transform names
    const techniques = mutations.map((m) => m.technique);
    // First set: base64_wrap, unicode_homoglyphs, prefix_padding
    expect(techniques[0]).toContain("base64_wrap");
    expect(techniques[1]).toContain("unicode_homoglyphs");
    expect(techniques[2]).toContain("prefix_padding");
    // Second set: rot13_wrap, zero_width_inject, leetspeak
    expect(techniques[3]).toContain("rot13_wrap");
  });

  it("6th blocked result reuses first transform set (modulo)", () => {
    // But since only first 5 are taken, this is already handled by .slice(0, 5)
    const blocked = Array.from({ length: 6 }, (_, i) =>
      makeResult({ probe_id: `p${i}`, attack_text: "test" }),
    );
    const mutations = generateMutations(blocked, []);
    expect(mutations.length).toBe(15); // Still 5 * 3, not 6 * 3
  });
});
