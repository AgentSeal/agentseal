// agentseal — Public barrel export

// Core types
export {
  Verdict, Severity, TrustLevel, trustLevelFromScore,
  type ChatFn, type EmbedFn, type ProgressFn,
  type Probe, type ProbeResult, type ScanReport,
  type ScoreBreakdown, type DefenseProfile,
  type ValidatorOptions,
  type AffectedProbe, type RemediationItem, type RemediationReport,
  type CompareResult,
} from "./types.js";

// Error classes
export {
  AgentSealError, ProbeTimeoutError,
  ProviderError, ValidationError,
} from "./errors.js";

// Constants
export {
  EXTRACTION_WEIGHT, INJECTION_WEIGHT, DATA_EXTRACTION_WEIGHT, BOUNDARY_WEIGHT, CONSISTENCY_WEIGHT,
  BOUNDARY_CATEGORIES, REFUSAL_PHRASES, COMMON_WORDS,
  SEMANTIC_HIGH_THRESHOLD, SEMANTIC_MODERATE_THRESHOLD,
} from "./constants.js";

// Validator (main class)
export { AgentValidator } from "./validator.js";

// Scoring
export { verdictScore, computeScores } from "./scoring.js";

// Fingerprinting
export { fingerprintDefense } from "./fingerprint.js";

// Detection
export {
  detectCanary, isRefusal, detectExtraction, extractUniquePhrases,
  computeSemanticSimilarity, fuseVerdicts, detectExtractionWithSemantic,
} from "./detection/index.js";

// Probes
export { generateCanary, buildExtractionProbes, buildInjectionProbes } from "./probes/index.js";

// Mutations
export {
  TRANSFORMS,
  base64Wrap, rot13Wrap, unicodeHomoglyphs, zeroWidthInject,
  leetspeak, caseScramble, reverseEmbed, prefixPadding,
  generateMutations,
} from "./mutations/index.js";

// Providers
export {
  fromOpenAI, fromAnthropic, fromVercelAI,
  fromLangChain, fromEndpoint, fromOllama,
} from "./providers/index.js";

// Remediation
export { generateRemediation } from "./remediation.js";

// Compare
export { compareReports } from "./compare.js";
