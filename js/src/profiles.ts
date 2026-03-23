/**
 * Scan profile presets for AgentValidator.
 *
 * Port of Python agentseal/profiles.py.
 */

// ═══════════════════════════════════════════════════════════════════════
// PROFILE CONFIG
// ═══════════════════════════════════════════════════════════════════════

export interface ProfileConfig {
  description: string;
  adaptive?: boolean;
  semantic?: boolean;
  mcp?: boolean;
  rag?: boolean;
  multimodal?: boolean;
  genome?: boolean;
  useCanaryOnly?: boolean;
  concurrency?: number;
  timeout?: number;
  output?: string;
  minScore?: number;
}

const BOOL_FLAGS = [
  "adaptive", "semantic", "mcp", "rag", "multimodal", "genome", "useCanaryOnly",
] as const;

const OPT_FIELDS = ["concurrency", "timeout", "output", "minScore"] as const;

// ═══════════════════════════════════════════════════════════════════════
// PROFILES
// ═══════════════════════════════════════════════════════════════════════

export const PROFILES: Record<string, ProfileConfig> = {
  quick: {
    description: "Fast canary check (5 probes, ~10s)",
    useCanaryOnly: true,
    concurrency: 5,
    timeout: 15,
  },
  default: {
    description: "Standard scan (225 probes)",
  },
  "code-agent": {
    description: "Coding assistant scan (225+ probes)",
    adaptive: true,
    mcp: true,
    semantic: true,
  },
  "support-bot": {
    description: "Customer-facing chatbot scan",
    adaptive: true,
    semantic: true,
  },
  "rag-agent": {
    description: "RAG pipeline agent scan",
    adaptive: true,
    rag: true,
    semantic: true,
  },
  "mcp-heavy": {
    description: "Multi-tool MCP agent scan",
    adaptive: true,
    mcp: true,
    semantic: true,
  },
  full: {
    description: "Full scan - all probes and analysis",
    adaptive: true,
    mcp: true,
    rag: true,
    multimodal: true,
    genome: true,
    semantic: true,
  },
  ci: {
    description: "CI/CD pipeline optimized",
    concurrency: 5,
    timeout: 15,
    output: "json",
  },
};

// ═══════════════════════════════════════════════════════════════════════
// FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

/** Return a profile by name, or throw with valid options. */
export function resolveProfile(name: string): ProfileConfig {
  const key = name.toLowerCase();
  if (key in PROFILES) return PROFILES[key]!;
  const valid = Object.keys(PROFILES).sort().join(", ");
  throw new Error(`Unknown profile '${name}'. Valid profiles: ${valid}`);
}

/**
 * Apply profile settings to an options object without overriding explicit user values.
 * Boolean flags are only set when the current value is falsy.
 * Optional fields are only set when the current value is undefined/null.
 */
export function applyProfile(
  opts: Record<string, any>,
  profile: ProfileConfig,
): void {
  for (const flag of BOOL_FLAGS) {
    if (!opts[flag]) {
      const val = profile[flag];
      if (val) opts[flag] = val;
    }
  }

  for (const field of OPT_FIELDS) {
    const val = profile[field];
    if (val !== undefined && val !== null && (opts[field] === undefined || opts[field] === null)) {
      opts[field] = val;
    }
  }
}

/** Return a formatted table of available profiles. */
export function listProfiles(): string {
  const lines: string[] = [];
  lines.push(`${"Profile".padEnd(14)} ${"Description".padEnd(42)} Enables`);
  lines.push("-".repeat(80));

  for (const [name, cfg] of Object.entries(PROFILES)) {
    const enabled: string[] = [];
    for (const f of BOOL_FLAGS) {
      if (cfg[f]) enabled.push(f);
    }
    const extras: string[] = [];
    for (const f of OPT_FIELDS) {
      const v = cfg[f];
      if (v !== undefined && v !== null) extras.push(`${f}=${v}`);
    }
    const parts = [...enabled, ...extras];
    lines.push(`${name.padEnd(14)} ${cfg.description.padEnd(42)} ${parts.join(", ") || "-"}`);
  }

  return lines.join("\n");
}
