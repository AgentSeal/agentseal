// agentseal/types.ts — Core data types (const objects, not TS enums)

// ═══════════════════════════════════════════════════════════════════════
// CONST-OBJECT ENUMS (tree-shakeable, works in plain JS)
// ═══════════════════════════════════════════════════════════════════════

export const Verdict = {
  BLOCKED: "blocked",
  LEAKED: "leaked",
  PARTIAL: "partial",
  ERROR: "error",
} as const;
export type Verdict = (typeof Verdict)[keyof typeof Verdict];

export const Severity = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
} as const;
export type Severity = (typeof Severity)[keyof typeof Severity];

export const TrustLevel = {
  CRITICAL: "critical",
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  EXCELLENT: "excellent",
} as const;
export type TrustLevel = (typeof TrustLevel)[keyof typeof TrustLevel];

export function trustLevelFromScore(score: number): TrustLevel {
  if (Number.isNaN(score) || score < 0 || score > 100) throw new RangeError(`Score must be 0-100, got ${score}`);
  if (score < 30) return TrustLevel.CRITICAL;
  if (score < 50) return TrustLevel.LOW;
  if (score < 70) return TrustLevel.MEDIUM;
  if (score < 85) return TrustLevel.HIGH;
  return TrustLevel.EXCELLENT;
}

// ═══════════════════════════════════════════════════════════════════════
// TYPE ALIASES
// ═══════════════════════════════════════════════════════════════════════

/** The simplest possible agent interface: string in, string out. */
export type ChatFn = (message: string) => Promise<string>;

/** Optional embedding function for semantic detection. */
export type EmbedFn = (texts: string[]) => Promise<number[][]>;

/** Progress callback: (phase, completed, total) */
export type ProgressFn = (phase: string, completed: number, total: number) => void;

// ═══════════════════════════════════════════════════════════════════════
// PROBE
// ═══════════════════════════════════════════════════════════════════════

export interface Probe {
  probe_id: string;
  category: string;
  technique: string;
  severity: Severity;
  payload: string | string[]; // string or string[] for multi-turn
  canary?: string;            // injection probes only
  canary_position?: "suffix" | "inline" | "prefix"; // where canary sits in payload
  is_multi_turn?: boolean;
}

// ═══════════════════════════════════════════════════════════════════════
// RESULTS
// ═══════════════════════════════════════════════════════════════════════

export interface ProbeResult {
  probe_id: string;
  category: string;
  probe_type: "extraction" | "injection" | "data_extraction";
  technique: string;
  severity: Severity;
  attack_text: string;
  response_text: string;
  verdict: Verdict;
  confidence: number;
  reasoning: string;
  duration_ms: number;
  semantic_similarity?: number;
}

export interface ScoreBreakdown {
  overall: number;
  extraction_resistance: number;
  injection_resistance: number;
  data_extraction_resistance: number;
  boundary_integrity: number;
  consistency: number;
}

export interface DefenseProfile {
  defense_system: string;
  confidence: number;
  patterns_matched: string[];
  weaknesses: string[];
  bypass_hints: string[];
}

export interface ScanReport {
  agent_name: string;
  scan_id: string;
  timestamp: string;
  duration_seconds: number;
  total_probes: number;
  probes_blocked: number;
  probes_leaked: number;
  probes_partial: number;
  probes_error: number;
  trust_score: number;
  trust_level: TrustLevel;
  score_breakdown: ScoreBreakdown;
  results: ProbeResult[];
  ground_truth_provided: boolean;
  defense_profile?: DefenseProfile;
  mutation_results?: ProbeResult[];
  mutation_resistance?: number;
}

// ═══════════════════════════════════════════════════════════════════════
// REMEDIATION
// ═══════════════════════════════════════════════════════════════════════

export interface AffectedProbe {
  probe_id: string;
  verdict: string;
}

export interface RemediationItem {
  priority: string;
  category: string;
  title: string;
  description: string;
  fix_text: string;
  affected_probes: AffectedProbe[];
}

export interface RemediationReport {
  items: RemediationItem[];
  combined_fix: string;
  analysis: string;
}

// ═══════════════════════════════════════════════════════════════════════
// COMPARE
// ═══════════════════════════════════════════════════════════════════════

export interface CompareResult {
  score_delta: number;
  new_leaks: ProbeResult[];
  fixed_leaks: ProbeResult[];
  regressions: ProbeResult[];
  improvements: ProbeResult[];
  summary: string;
}

// ═══════════════════════════════════════════════════════════════════════
// VALIDATOR OPTIONS
// ═══════════════════════════════════════════════════════════════════════

export interface ValidatorOptions {
  agentFn: ChatFn;
  groundTruthPrompt?: string;
  agentName?: string;
  concurrency?: number;
  timeoutPerProbe?: number;
  verbose?: boolean;
  onProgress?: ProgressFn;
  adaptive?: boolean;
  semantic?: { embed: EmbedFn };
}
