/**
 * Client for agentseal.org MCP trust score enrichment API.
 *
 * Enriches local MCP scan results with registry intelligence
 * (trust score, risk level, finding counts) via bulk lookup.
 */

import type { MCPServerResult } from "./guard-models.js";

const API_URL = "https://agentseal.org/api/v1/mcp/intel/bulk-check";
const USER_AGENT = "agentseal-guard/0.8";
const TIMEOUT_MS = 8000;

// ═══════════════════════════════════════════════════════════════════════
// SLUG HELPERS
// ═══════════════════════════════════════════════════════════════════════

/** Convert a name to a URL-safe slug. */
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/^@([^/]+)\//, "$1-")
    .replace(/[^a-z0-9-]/g, "-");
}

/**
 * Extract a package name from a command string and slugify it.
 *
 * Recognises: npx, bunx, uvx, pip/pip3 install, docker run.
 * Strips @version suffixes. Returns null for bare binaries or
 * unparseable commands.
 */
export function extractPackageSlug(command: string): string | null {
  const trimmed = command.trim();
  if (!trimmed) return null;

  const tokens = trimmed.split(/\s+/);

  const runner = tokens[0];
  if (!runner) return null;

  let pkg: string | undefined;

  if (runner === "npx") {
    // Skip flags like -y, -p, --yes, etc.
    pkg = tokens.slice(1).find((t) => !t.startsWith("-"));
  } else if (runner === "bunx" || runner === "uvx") {
    pkg = tokens[1];
  } else if ((runner === "pip" || runner === "pip3") && tokens[1] === "install") {
    pkg = tokens[2];
  } else if (runner === "docker" && tokens[1] === "run") {
    // Skip docker flags before image name
    pkg = tokens.slice(2).find((t) => !t.startsWith("-"));
  } else {
    // Bare binary or unknown runner
    return null;
  }

  if (!pkg) return null;

  // Strip @version suffix (but not @scope prefix)
  // For scoped: @scope/pkg@1.2.3 → @scope/pkg
  // For unscoped: pkg@latest → pkg
  if (pkg.startsWith("@")) {
    const atIdx = pkg.indexOf("@", 1);
    if (atIdx !== -1) {
      pkg = pkg.slice(0, atIdx);
    }
  } else {
    const atIdx = pkg.indexOf("@");
    if (atIdx !== -1) {
      pkg = pkg.slice(0, atIdx);
    }
  }

  return slugify(pkg);
}

// ═══════════════════════════════════════════════════════════════════════
// API CLIENT
// ═══════════════════════════════════════════════════════════════════════

/**
 * POST a list of slugs to the bulk-check endpoint.
 *
 * Returns the parsed JSON on success, or {} on any error (timeout,
 * network failure, non-ok status).
 */
export async function bulkCheck(
  slugs: string[],
  apiKey?: string,
): Promise<Record<string, any>> {
  const unique = [...new Set(slugs)];
  if (unique.length === 0) return {};

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "User-Agent": USER_AGENT,
  };
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }

  try {
    const response = await globalThis.fetch(API_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({ slugs: unique }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });

    if (!response.ok) return {};
    return (await response.json()) as Record<string, any>;
  } catch {
    return {};
  }
}

// ═══════════════════════════════════════════════════════════════════════
// ENRICHMENT
// ═══════════════════════════════════════════════════════════════════════

/**
 * Enrich MCP scan results with registry intelligence (in-place).
 *
 * For each result, derives a name slug and a command slug, queries the
 * registry, then writes registry_score / registry_level /
 * registry_findings_count onto matching results.
 *
 * Results that already have registry_score set are skipped to prevent
 * double-enrichment.
 */
export async function enrichMcpResults(
  results: MCPServerResult[],
  apiKey?: string,
): Promise<void> {
  if (results.length === 0) return;

  // Build slug → result[] map
  const slugMap = new Map<string, MCPServerResult[]>();

  for (const result of results) {
    // Skip already-enriched results
    if (result.registry_score != null) continue;

    const nameSlug = slugify(result.name);
    const cmdSlug = extractPackageSlug(result.command);

    if (nameSlug) {
      const arr = slugMap.get(nameSlug) ?? [];
      arr.push(result);
      slugMap.set(nameSlug, arr);
    }
    if (cmdSlug && cmdSlug !== nameSlug) {
      const arr = slugMap.get(cmdSlug) ?? [];
      arr.push(result);
      slugMap.set(cmdSlug, arr);
    }
  }

  const allSlugs = [...slugMap.keys()];
  if (allSlugs.length === 0) return;

  const data = await bulkCheck(allSlugs, apiKey);

  for (const [slug, info] of Object.entries(data)) {
    const targets = slugMap.get(slug);
    if (!targets) continue;

    for (const target of targets) {
      // Guard against double-write if both name and cmd slugs matched
      if (target.registry_score != null) continue;

      target.registry_score = info.score;
      target.registry_level = info.level;
      target.registry_findings_count = info.findings_count;
    }
  }
}
