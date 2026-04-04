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
export {
  generateCanary, buildExtractionProbes, buildInjectionProbes,
  loadCustomProbes, loadAllCustomProbes,
  validateProbe, buildProbe, parseProbeFile,
} from "./probes/index.js";

// Profiles
export {
  PROFILES, resolveProfile, applyProfile, listProfiles,
  type ProfileConfig,
} from "./profiles.js";

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

// Deobfuscation
export {
  deobfuscate,
  stripZeroWidth, stripTagChars, stripVariationSelectors,
  stripBidiControls, stripHtmlComments, hasInvisibleChars,
  normalizeUnicode, decodeHtmlEntities, decodeBase64Blocks,
  unescapeSequences, expandStringConcat,
} from "./deobfuscate.js";

// Guard models
export {
  GuardVerdict, SEVERITY_ORDER,
  topSkillFinding, topMCPFinding,
  totalDangers, totalWarnings, totalSafe, hasCritical, allActions,
  guardReportFromDict,
  customFindingFromDict, customFindingToDict,
  unlistedFindingToDict, deltaEntryToDict,
  DeltaResult,
  type SkillFinding, type SkillResult,
  type MCPFinding, type MCPServerResult,
  type AgentConfigResult,
  type MCPRuntimeFinding, type MCPRuntimeResult,
  type ToxicFlowResult, type BaselineChangeResult,
  type GuardReport,
  type UnlistedFinding, type CustomFinding, type DeltaEntry,
} from "./guard-models.js";

// Skill scanner
export { SkillScanner, DANGER_CONCEPTS } from "./skill-scanner.js";

// Blocklist
export { Blocklist, sha256 } from "./blocklist.js";

// Toxic flows
export {
  analyzeToxicFlows, classifyServer,
  KNOWN_SERVER_LABELS,
  LABEL_PUBLIC_SINK, LABEL_DESTRUCTIVE, LABEL_UNTRUSTED, LABEL_PRIVATE,
} from "./toxic-flows.js";

// Baselines
export {
  BaselineStore,
  type BaselineEntry, type BaselineChange,
} from "./baselines.js";

// MCP config checker
export { MCPConfigChecker, shannonEntropy, verdictFromFindings } from "./mcp-checker.js";

// Guard
export {
  Guard, scanSkillFile, extractSkillName, computeVerdict,
  type GuardOptions, type GuardProgressFn,
} from "./guard.js";

// Machine discovery
export {
  scanMachine, scanDirectory, stripJsonComments, getWellKnownConfigs,
  PROJECT_MCP_CONFIGS, PROJECT_SKILL_FILES, PROJECT_SKILL_DIRS,
  type DiscoveryResult,
} from "./machine-discovery.js";

// Fix (quarantine + reports)
export {
  quarantineSkill, restoreSkill, listQuarantine,
  loadGuardReport, loadScanReport, saveReport,
  getFixableSkills,
  QUARANTINE_DIR, REPORTS_DIR, BACKUPS_DIR,
  type QuarantineEntry, type FixResult,
} from "./fix.js";

// Chains (attack chain detection)
export {
  detectChains,
  type AttackChain, type ChainStep,
} from "./chains.js";

// LLM Judge
export {
  LLMJudge, parseResponse, detectProvider, stripModelPrefix, truncateContent,
  SYSTEM_PROMPT, MAX_CONTENT_BYTES,
  type LLMJudgeResult, type LLMJudgeFinding, type LLMJudgeOptions,
} from "./llm-judge.js";

// Notifier
export { Notifier } from "./notify.js";

// Project config
export {
  loadProjectConfig, resolveProjectConfig,
  shouldIgnorePath, shouldIgnoreFinding, shouldFail,
  generateUnlistedFindings, generateConfigYaml, runGuardInit,
  type ProjectConfig, type IgnoreFindingEntry,
} from "./project-config.js";

// Registry client
export {
  slugify, extractPackageSlug, bulkCheck, enrichMcpResults,
} from "./registry-client.js";

// Rules engine
export {
  fnmatchCase, RuleEngine,
  type Rule, type RuleTest, type RuleTestResult,
} from "./rules.js";

// History & delta
export {
  normalizeSkillPath, HistoryStore, computeDelta,
} from "./history.js";

// Shield
export {
  Shield, DebouncedHandler, classifyPath, collectWatchPaths,
  type ShieldCallback, type ShieldOptions,
} from "./shield.js";

// Config
export { loadConfig, saveConfigKey, removeConfigKey, showConfig, CONFIG_KEYS } from "./config.js";

// Login / credentials
export { saveCredentials, loadCredentials, saveLicense, loadLicense } from "./login.js";

// Watch
export { selectCanaryProbes, checkRegression } from "./watch.js";

// MCP CLI renderer
export { renderMCPResults } from "./scan-mcp-cli.js";
