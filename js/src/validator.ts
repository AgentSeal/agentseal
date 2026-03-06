// validator.ts — The core 5-phase pipeline

import { randomUUID } from "node:crypto";
import type {
  ChatFn, EmbedFn, ValidatorOptions, ScanReport, ProbeResult,
  Probe, Verdict, ProgressFn,
} from "./types.js";
import { Verdict as V, Severity, trustLevelFromScore } from "./types.js";
import { buildExtractionProbes } from "./probes/extraction.js";
import { buildInjectionProbes } from "./probes/injection.js";
import { detectExtraction } from "./detection/ngram.js";
import { detectExtractionWithSemantic } from "./detection/fusion.js";
import { detectCanary } from "./detection/canary.js";
import { computeScores } from "./scoring.js";
import { fingerprintDefense } from "./fingerprint.js";
import { generateMutations } from "./mutations/generate.js";
import { fromOpenAI } from "./providers/openai.js";
import { fromAnthropic } from "./providers/anthropic.js";
import { fromVercelAI } from "./providers/vercel-ai.js";
import { fromLangChain } from "./providers/langchain.js";
import { fromEndpoint } from "./providers/http.js";
import { fromOllama } from "./providers/ollama.js";

// Simple concurrency limiter
function semaphore(limit: number) {
  let active = 0;
  const queue: (() => void)[] = [];
  return {
    async acquire() {
      if (active < limit) { active++; return; }
      await new Promise<void>((resolve) => queue.push(resolve));
      active++;
    },
    release() {
      active--;
      const next = queue.shift();
      if (next) next();
    },
  };
}

export class AgentValidator {
  private agentFn: ChatFn;
  private groundTruth: string | undefined;
  private agentName: string;
  private concurrency: number;
  private timeout: number;
  private verbose: boolean;
  private onProgress: ProgressFn | undefined;
  private adaptive: boolean;
  private embed: EmbedFn | undefined;

  constructor(options: ValidatorOptions) {
    this.agentFn = options.agentFn;
    this.groundTruth = options.groundTruthPrompt;
    this.agentName = options.agentName ?? "Unnamed Agent";
    this.concurrency = Math.max(1, options.concurrency ?? 3);
    this.timeout = (options.timeoutPerProbe ?? 30) * 1000; // Convert to ms
    this.verbose = options.verbose ?? false;
    this.onProgress = options.onProgress;
    this.adaptive = options.adaptive ?? false;
    this.embed = options.semantic?.embed;
  }

  // ── Factory methods ──────────────────────────────────────────────

  static fromOpenAI(
    client: Parameters<typeof fromOpenAI>[0],
    opts: Parameters<typeof fromOpenAI>[1] & Omit<ValidatorOptions, "agentFn">,
  ): AgentValidator {
    const agentFn = fromOpenAI(client, opts);
    return new AgentValidator({ ...opts, agentFn, groundTruthPrompt: opts.systemPrompt });
  }

  static fromAnthropic(
    client: Parameters<typeof fromAnthropic>[0],
    opts: Parameters<typeof fromAnthropic>[1] & Omit<ValidatorOptions, "agentFn">,
  ): AgentValidator {
    const agentFn = fromAnthropic(client, opts);
    return new AgentValidator({ ...opts, agentFn, groundTruthPrompt: opts.systemPrompt });
  }

  static fromVercelAI(
    opts: Parameters<typeof fromVercelAI>[0] & Omit<ValidatorOptions, "agentFn">,
  ): AgentValidator {
    const agentFn = fromVercelAI(opts);
    return new AgentValidator({ ...opts, agentFn, groundTruthPrompt: opts.systemPrompt });
  }

  static fromLangChain(
    chain: Parameters<typeof fromLangChain>[0],
    opts?: Omit<ValidatorOptions, "agentFn">,
  ): AgentValidator {
    const agentFn = fromLangChain(chain);
    return new AgentValidator({ ...opts, agentFn });
  }

  static fromEndpoint(
    opts: Parameters<typeof fromEndpoint>[0] & Omit<ValidatorOptions, "agentFn">,
  ): AgentValidator {
    const agentFn = fromEndpoint(opts);
    return new AgentValidator({ ...opts, agentFn });
  }

  static fromOllama(
    opts: Parameters<typeof fromOllama>[0] & Omit<ValidatorOptions, "agentFn">,
  ): AgentValidator {
    const agentFn = fromOllama(opts);
    return new AgentValidator({ ...opts, agentFn, groundTruthPrompt: opts.systemPrompt });
  }

  // ── Main pipeline ────────────────────────────────────────────────

  async run(): Promise<ScanReport> {
    const scanId = randomUUID().replace(/-/g, "").slice(0, 12);
    const startTime = performance.now();
    const allResults: ProbeResult[] = [];

    const extractionProbes = buildExtractionProbes();
    const injectionProbes = buildInjectionProbes();
    const sem = semaphore(this.concurrency);

    const icon: Record<string, string> = { blocked: "✓", leaked: "✗", partial: "◐", error: "⚠" };

    // ── Phase 1: Extraction ──────────────────────────────────────
    let extDone = 0;
    this.onProgress?.("extraction", 0, extractionProbes.length);

    const runExtractionProbe = async (probe: Probe): Promise<ProbeResult> => {
      await sem.acquire();
      const t0 = performance.now();
      let response: string;
      let verdict: Verdict;
      let confidence: number;
      let reasoning: string;
      let semScore: number | undefined;

      try {
        if (probe.is_multi_turn && Array.isArray(probe.payload)) {
          response = "";
          for (const msg of probe.payload) {
            response = await this.callWithTimeout(msg);
          }
        } else {
          response = await this.callWithTimeout(probe.payload as string);
        }

        if (this.embed) {
          const result = await detectExtractionWithSemantic(
            response, this.groundTruth ?? "", this.embed,
          );
          [verdict, confidence, reasoning, semScore] = result;
        } else {
          [verdict, confidence, reasoning] = detectExtraction(
            response, this.groundTruth ?? "",
          );
        }
      } catch (err) {
        response = `[ERROR: ${err}]`;
        verdict = V.ERROR;
        confidence = 0.0;
        reasoning = err instanceof Error && err.name === "AbortError"
          ? "Probe timed out" : `Error: ${err}`;
      } finally {
        sem.release();
      }

      const durationMs = performance.now() - t0;
      const payloadStr = Array.isArray(probe.payload) ? probe.payload.join(" → ") : probe.payload;

      const result: ProbeResult = {
        probe_id: probe.probe_id,
        category: probe.category,
        probe_type: "extraction",
        technique: probe.technique,
        severity: probe.severity,
        attack_text: payloadStr.slice(0, 500),
        response_text: response.slice(0, 1000),
        verdict,
        confidence,
        reasoning,
        duration_ms: durationMs,
        ...(semScore !== undefined ? { semantic_similarity: semScore } : {}),
      };

      if (this.verbose) {
        console.log(`  [${icon[verdict] ?? "?"}] ${probe.probe_id.padEnd(20)} → ${verdict.padEnd(8)}  (${reasoning.slice(0, 60)})`);
      }
      extDone++;
      this.onProgress?.("extraction", extDone, extractionProbes.length);
      return result;
    };

    const extractionResults = await Promise.all(extractionProbes.map(runExtractionProbe));
    allResults.push(...extractionResults);

    // ── Phase 2: Injection ───────────────────────────────────────
    let injDone = 0;
    this.onProgress?.("injection", 0, injectionProbes.length);

    const runInjectionProbe = async (probe: Probe): Promise<ProbeResult> => {
      await sem.acquire();
      const t0 = performance.now();
      let response: string;
      let verdict: Verdict;
      let confidence: number;
      let reasoning: string;

      try {
        if (probe.is_multi_turn && Array.isArray(probe.payload)) {
          response = "";
          for (const msg of probe.payload) {
            response = await this.callWithTimeout(msg);
          }
        } else {
          response = await this.callWithTimeout(probe.payload as string);
        }

        if (detectCanary(response, probe.canary!)) {
          verdict = V.LEAKED;
          confidence = 0.99;
          reasoning = `Canary '${probe.canary}' found in response`;
        } else {
          verdict = V.BLOCKED;
          confidence = 0.85;
          reasoning = "Canary not found in response";
        }
      } catch (err) {
        response = `[ERROR: ${err}]`;
        verdict = V.ERROR;
        confidence = 0.0;
        reasoning = err instanceof Error && err.name === "AbortError"
          ? "Probe timed out" : `Error: ${err}`;
      } finally {
        sem.release();
      }

      const durationMs = performance.now() - t0;
      const payloadStr = Array.isArray(probe.payload) ? probe.payload.join(" → ") : probe.payload;

      const result: ProbeResult = {
        probe_id: probe.probe_id,
        category: probe.category,
        probe_type: "injection",
        technique: probe.technique,
        severity: probe.severity,
        attack_text: payloadStr.slice(0, 500),
        response_text: response.slice(0, 1000),
        verdict,
        confidence,
        reasoning,
        duration_ms: durationMs,
      };

      if (this.verbose) {
        console.log(`  [${icon[verdict] ?? "?"}] ${probe.probe_id.padEnd(20)} → ${verdict.padEnd(8)}  (${reasoning.slice(0, 60)})`);
      }
      injDone++;
      this.onProgress?.("injection", injDone, injectionProbes.length);
      return result;
    };

    const injectionResults = await Promise.all(injectionProbes.map(runInjectionProbe));
    allResults.push(...injectionResults);

    // ── Phase 3: Defense Fingerprinting ──────────────────────────
    const allResponses = allResults.map((r) => r.response_text);
    const defenseProfile = fingerprintDefense(allResponses);

    // ── Phase 4: Mutations (if adaptive) ─────────────────────────
    let mutationResults: ProbeResult[] = [];
    let mutationResistance: number | undefined;

    if (this.adaptive) {
      const severityOrder: Record<string, number> = {
        [Severity.CRITICAL]: 0, [Severity.HIGH]: 1,
        [Severity.MEDIUM]: 2, [Severity.LOW]: 3,
      };
      const blockedExtraction = allResults
        .filter((r) => r.probe_type === "extraction" && r.verdict === V.BLOCKED)
        .sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));

      const topBlocked = blockedExtraction.slice(0, 5);

      if (topBlocked.length > 0) {
        const mutationProbes = generateMutations(topBlocked, extractionProbes);
        let mutDone = 0;
        this.onProgress?.("mutations", 0, mutationProbes.length);

        const runMutationProbe = async (mprobe: Probe): Promise<ProbeResult> => {
          await sem.acquire();
          const t0 = performance.now();
          let response: string;
          let verdict: Verdict;
          let confidence: number;
          let reasoning: string;
          let semScore: number | undefined;

          try {
            response = await this.callWithTimeout(mprobe.payload as string);
            if (this.embed) {
              [verdict, confidence, reasoning, semScore] = await detectExtractionWithSemantic(
                response, this.groundTruth ?? "", this.embed,
              );
            } else {
              [verdict, confidence, reasoning] = detectExtraction(
                response, this.groundTruth ?? "",
              );
            }
          } catch (err) {
            response = `[ERROR: ${err}]`;
            verdict = V.ERROR;
            confidence = 0.0;
            reasoning = `Error: ${err}`;
          } finally {
            sem.release();
          }

          mutDone++;
          this.onProgress?.("mutations", mutDone, mutationProbes.length);

          return {
            probe_id: mprobe.probe_id,
            category: "mutation",
            probe_type: "extraction",
            technique: mprobe.technique,
            severity: mprobe.severity,
            attack_text: (mprobe.payload as string).slice(0, 500),
            response_text: response.slice(0, 1000),
            verdict,
            confidence,
            reasoning,
            duration_ms: performance.now() - t0,
            ...(semScore !== undefined ? { semantic_similarity: semScore } : {}),
          };
        };

        mutationResults = await Promise.all(mutationProbes.map(runMutationProbe));

        const activeMutations = mutationResults.filter((r) => r.verdict !== V.ERROR);
        if (activeMutations.length > 0) {
          const blockedCount = activeMutations.filter((r) => r.verdict === V.BLOCKED).length;
          mutationResistance = (blockedCount / activeMutations.length) * 100;
        }
      }
    }

    // ── Phase 5: Score ───────────────────────────────────────────
    const scores = computeScores(allResults);
    const trustLevel = trustLevelFromScore(scores.overall);
    const durationSeconds = (performance.now() - startTime) / 1000;

    return {
      agent_name: this.agentName,
      scan_id: scanId,
      timestamp: new Date().toISOString(),
      duration_seconds: durationSeconds,
      total_probes: allResults.length,
      probes_blocked: allResults.filter((r) => r.verdict === V.BLOCKED).length,
      probes_leaked: allResults.filter((r) => r.verdict === V.LEAKED).length,
      probes_partial: allResults.filter((r) => r.verdict === V.PARTIAL).length,
      probes_error: allResults.filter((r) => r.verdict === V.ERROR).length,
      trust_score: scores.overall,
      trust_level: trustLevel,
      score_breakdown: scores,
      results: allResults,
      ground_truth_provided: this.groundTruth != null,
      defense_profile: defenseProfile.defense_system !== "unknown" ? defenseProfile : undefined,
      mutation_results: mutationResults.length > 0 ? mutationResults : undefined,
      mutation_resistance: mutationResistance,
    };
  }

  private callWithTimeout(message: string): Promise<string> {
    let timer: ReturnType<typeof setTimeout>;
    return Promise.race([
      this.agentFn(message).finally(() => clearTimeout(timer)),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          const err = new Error("Probe timed out");
          err.name = "AbortError";
          reject(err);
        }, this.timeout);
      }),
    ]);
  }
}
