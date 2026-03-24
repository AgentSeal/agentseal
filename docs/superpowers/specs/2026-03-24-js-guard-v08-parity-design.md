# JS/TS Guard v0.8 Feature Parity Design Spec

**Date:** 2026-03-24
**Status:** Approved
**Scope:** Port all Python Guard v0.8 features to the TypeScript package

## Goal

Bring the JS/TS `agentseal` package to full feature parity with Python Guard v0.8. After this work, `npx agentseal guard` should produce identical functionality to `agentseal guard` in Python: project config, delta scanning, registry enrichment, custom YAML rules, and all security hardening.

## Architecture Overview

```
bin/agentseal.ts          # CLI: add guard command + subcommands
src/
  project-config.ts       # NEW: .agentseal.yaml loader, resolution, filtering
  history.ts              # NEW: SQLite history store + delta computation
  registry-client.ts      # NEW: agentseal.org registry API client
  rules.ts                # NEW: YAML community rule engine
  guard.ts                # UPDATE: wire new modules into scan flow
  guard-models.ts         # UPDATE: new types (Custom/Unlisted/Delta)
  deobfuscate.ts          # UPDATE: TR39 confusables, HTML entities, 2-pass
  blocklist.ts            # UPDATE: 12 seed hashes
  mcp-checker.ts          # UPDATE: 5 new supply chain checks
  baselines.ts            # UPDATE: URL + headers in fingerprint
  skill-scanner.ts        # UPDATE: markdown image exfil patterns
  index.ts                # UPDATE: export new modules
test/
  project-config.test.ts  # NEW: ~35 tests
  history.test.ts         # NEW: ~25 tests
  registry-client.test.ts # NEW: ~20 tests (mocked HTTP)
  rules.test.ts           # NEW: ~25 tests
  guard-models.test.ts    # NEW: ~15 tests (fromDict, delta)
  guard-v08.test.ts       # NEW: ~15 tests (integration)
  deobfuscate-v08.test.ts # NEW: ~10 tests (confusables, entities, 2-pass)
```

## New Modules

### 1. project-config.ts

Manages `.agentseal.yaml` project-level scanning policy.

**Interface:**
```typescript
interface ProjectConfig {
  fail_on: "danger" | "warning" | "safe";  // default: "danger"
  allowed_agents: string[];                 // agent type slugs
  allowed_mcp_servers: string[];            // "name" or "name@agent_type"
  ignore_paths: string[];                   // path segments to skip
  ignore_findings: IgnoreFindingEntry[];    // [{id, reason?}]
  rules_paths: string[];                    // YAML rule file/dir paths
  config_path: string;                      // resolved absolute path
}

interface IgnoreFindingEntry {
  id: string;      // "CODE" or "CODE:path"
  reason?: string; // warn to stderr if missing
}
```

**Functions:**
- `loadProjectConfig(path: string): ProjectConfig` — parse YAML, validate fail_on, warn on unknown keys. Handle YAML `null`/`~` values by coercing to empty arrays (`data.get("key") || []` pattern).
- `resolveProjectConfig(opts?: { configPath?: string; searchDir?: string }): ProjectConfig | null` — explicit path > CWD > walk parents to .git/HOME/root
- `shouldIgnorePath(config: ProjectConfig, path: string): boolean` — any path segment in ignore_paths
- `shouldIgnoreFinding(config: ProjectConfig, code: string, path?: string): boolean` — match bare code or code:path. Split on `:` with maxsplit=1 (i.e. `id.indexOf(":")` for first colon only) to handle codes like `MCP-CVE:file.json`.
- `shouldFail(failOn: string, verdicts: { hasDanger: boolean; hasWarning: boolean; hasSafe?: boolean }): boolean` — `danger` returns hasDanger, `warning` returns hasDanger||hasWarning, `safe` returns hasDanger||hasWarning||hasSafe. ERROR verdicts treated as danger.
- `generateUnlistedFindings(config: ProjectConfig, agents: AgentConfigResult[], mcpServers: Record<string, any>[]): UnlistedFinding[]` — filter out agents with status `not_installed` or `error` before checking allowlists. Only generate findings if the respective allowlist is non-empty.
- `generateConfigYaml(agents: AgentConfigResult[], mcpServers: Record<string, any>[]): string` — include sensible defaults for `ignore_paths`: `["node_modules", ".git", "__pycache__"]`.
- `runGuardInit(opts?: { targetDir?: string; force?: boolean; interactive?: boolean }): boolean` — `interactive` defaults to true, set false in tests to suppress prompts.

**Resolution order:** explicit --config > .agentseal.yaml in searchDir > walk parent dirs up to .git, HOME, or fs root. First match wins, no merging.

**YAML schema:**
```yaml
fail_on: danger
allowed_agents: []
allowed_mcp_servers: []
ignore_paths: []
ignore_findings: []
rules_paths: []
```

Known keys: `fail_on`, `allowed_agents`, `allowed_mcp_servers`, `ignore_paths`, `ignore_findings`, `rules_paths`. Unknown keys produce stderr warning. Missing `reason` on ignore_findings produces stderr warning.

### 2. history.ts

SQLite-backed scan history with delta/diff computation. Uses `better-sqlite3` for synchronous API matching Python's sqlite3.

**Schema:**
```sql
CREATE TABLE IF NOT EXISTS guard_scans (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    scan_path TEXT,
    report_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scope ON guard_scans(scan_path, timestamp);
```

**Class: HistoryStore**
```typescript
class HistoryStore {
  constructor(dbPath?: string, maxRows?: number, retentionDays?: number)
  // dbPath default: ~/.agentseal/history.db
  // maxRows default: 1000
  // retentionDays default: 90

  save(report: GuardReport, scanPath?: string): void
  // Normalize scanPath via path.resolve(). BEGIN IMMEDIATE transaction, insert report_json.
  // Calls prune() after save.

  loadPrevious(scanPath?: string): GuardReport | null
  // SELECT ... ORDER BY timestamp DESC LIMIT 1 OFFSET 1
  // Returns null on any error (sqlite, json parse, key error). Logs warning to stderr.

  prune(): void
  // DELETE older than retentionDays, DELETE beyond maxRows (by timestamp DESC)

  _count(): number
  // SELECT COUNT(*) — exposed for test assertions

  close(): void
}
```

**Functions:**
- `normalizeSkillPath(path: string, scanPath?: string): string` — normalize order: (1) HOME prefix becomes `~/remainder`, (2) scanPath prefix becomes relative path, (3) fallback: last 2 path segments. Normalize path separators to `/` on all platforms (Windows compat).
- `computeDelta(current: GuardReport, previous: GuardReport, scanPath?: string): DeltaResult`
  - Skills: key by normalizeSkillPath(path), detect new/resolved/changed findings
  - MCPs: key by `name:normalizeSkillPath(source_file)`, same logic
  - Agents: filter status found/installed_no_config only, new_entity/removed_entity only (no findings on agents)

**Graceful degradation:** `better-sqlite3` listed as `optionalDependencies` in package.json (not `dependencies`). Import wrapped in try/catch. If unavailable, HistoryStore constructor returns a no-op stub. Guard command works without history, just no delta output. Single warning logged to stderr on first use.

### 3. registry-client.ts

Client for agentseal.org MCP trust score enrichment.

**Functions:**
- `slugify(name: string): string` — lowercase, @scope/ becomes scope-, non-alnum becomes dash
- `extractPackageSlug(command: string): string | null` — parse npx/bunx/uvx/pip/docker commands, strip @version. Returns null for bare binaries, empty, or unparseable commands.
- `bulkCheck(slugs: string[], apiKey?: string): Promise<Record<string, RegistryResult>>` — POST to `https://agentseal.org/api/v1/mcp/intel/bulk-check`, User-Agent: `agentseal-guard/0.8`, 8s timeout via AbortController, returns {} on any error. Uses `globalThis.fetch` (Node 18+).
- `enrichMcpResults(results: MCPServerResult[], apiKey?: string): Promise<void>` — in-place mutation. Builds slug map from both name_slug and cmd_slug per result. Calls bulkCheck. Sets registry_score/level/findings_count. Skips if `registry_score` already set (prevents double-enrichment on multi-slug match).

**Error handling:** All errors (timeout, network, parse) caught silently, return empty. Guard works fully offline.

### 4. rules.ts

YAML community rule engine with glob matching.

**Interfaces:**
```typescript
interface Rule {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  verdict: "danger" | "warning";
  remediation: string;
  match: Record<string, string | string[]>;  // YAML may produce string or string[]
  tests: RuleTest[];
  source_file: string;
}

interface RuleTest {
  name: string;
  input: Record<string, string>;
  expect: "match" | "no_match";
}

interface RuleTestResult {
  rule_id: string;
  test_name: string;
  passed: boolean;
  expected: string;
  actual: string;
}
```

**Class: RuleEngine**
```typescript
class RuleEngine {
  static fromPaths(paths: string[]): RuleEngine
  // Resolve paths: files kept, dirs globbed for *.yaml/*.yml
  // Validate: required fields (id, title, severity, verdict, match), severity/verdict enum, match.type enum
  // No duplicate IDs across files. Errors include source file path in message.
  // Skip files without "rules" key.

  evaluateMcp(server: MCPServerResult, rawConfig: Record<string, any>): CustomFinding[]
  // entity_data: { name, command, args (space-joined), env_keys (space-joined), env_values (space-joined), source_file }

  evaluateSkill(skill: SkillResult, content: string): CustomFinding[]
  // entity_data: { name, path, content (truncated to 10240 chars) }

  evaluateAgent(agent: AgentConfigResult): CustomFinding[]
  // entity_data: { agent_type, name, config_path }

  // All use _matchEntity: AND across fields, OR within each field
  // Coerce non-array match values to [value] before matching
  // Null/undefined entity values treated as ""

  runTests(): RuleTestResult[]
  // Execute each rule's tests, return pass/fail per test
}
```

**Glob matching:** Implement inline `fnmatchCase(value: string, pattern: string): boolean`. Convert glob to regex: escape regex-special chars (`.$^+{}()|\\`), then `*` becomes `.*`, `?` becomes `.`, `[...]` passes through (including `[!...]` negation). Case-insensitive comparison. No external dependency.

**YAML rule format:**
```yaml
version: 1
rules:
  - id: "CUSTOM-001"
    title: "Block Slack MCP"
    description: "Slack MCP servers should not be used"
    severity: "high"
    verdict: "danger"
    remediation: "Remove this MCP server"
    match:
      type: "mcp"
      name: ["*slack*"]
    tests:
      - name: "matches slack"
        input: { name: "slack-mcp", command: "npx @slack/mcp" }
        expect: "match"
```

## Updated Modules

### 5. guard-models.ts

**New interfaces:**
```typescript
interface UnlistedFinding {
  code: string;        // "GUARD-001" or "GUARD-002"
  title: string;
  description: string;
  severity: string;    // default: "medium"
  item_name: string;
  item_type: string;   // "agent" or "mcp_server"
}

interface CustomFinding {
  code: string;        // Custom rule ID
  title: string;
  severity: string;
  verdict: string;
  remediation: string;
  rule_file: string;
  entity_type: string; // "mcp" | "skill" | "agent"
  entity_name: string;
}

interface DeltaEntry {
  change_type: "new" | "resolved" | "changed" | "new_entity" | "removed_entity";
  entity_type: "skill" | "mcp" | "agent";
  entity_name: string;
  code?: string;
  title?: string;
  old_verdict?: string;
  new_verdict?: string;
  severity?: string;
}

interface DeltaResult {
  previous_timestamp: string;
  entries: DeltaEntry[];
  // Computed getters:
  get total_new(): number;      // count where change_type in ("new", "new_entity")
  get total_resolved(): number; // count where change_type in ("resolved", "removed_entity")
  get total_changed(): number;  // count where change_type == "changed"
}
```

Note: `DeltaResult` uses computed getters (not stored values) matching Python's `@property` pattern.

**New fields on MCPServerResult:**
```typescript
registry_score?: number;
registry_level?: string;
registry_findings_count?: number;
```

**New fields on GuardReport:**
```typescript
unlisted_findings: UnlistedFinding[];
custom_findings: CustomFinding[];
config_path: string;
```

**Static methods:** `fromDict()` on GuardReport, MCPServerResult, SkillResult, CustomFinding, UnlistedFinding. GuardReport.fromDict fully deserializes all fields including custom_findings (via CustomFinding.fromDict), unlisted_findings, toxic_flows, baseline_changes, and mcp_runtime_results. This fixes a Python limitation where from_dict skips these fields.

**toDict():** MCPServerResult.toDict includes conditional `registry` nested object (only if registry_score is set). GuardReport.toDict includes conditional keys for mcp_runtime_results, toxic_flows, baseline_changes, unlisted_findings, custom_findings.

**SARIF support:** GuardReport.toSarif includes custom_findings in results. GUARD-001/002 included as SARIF rules.

### 6. deobfuscate.ts

**Add `CONFUSABLES` map** -- 80+ TR39 Unicode confusable character mappings:
- Cyrillic uppercase/lowercase (A,B,C,E,H,I,J,K,M,O,P,S,T,X,Y,Z / a,c,e,h,i,j,o,p,s,x,y)
- Greek uppercase/lowercase (A,B,E,H,I,K,M,N,O,P,T,X,Y,Z / o,a)
- Cherokee (D,R,T,G,W,S / s variants)
- Turkish dotless i
- Small caps (A,B,C)
- Fullwidth Latin A-Z and a-z (26+26 = 52 chars)

**Add `decodeHtmlEntities(text: string): string`** -- decode numeric (`&#99;`, `&#x63;`) and named (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`) HTML entities. Regex-based: match `&#(\d+);` and `&#x([0-9a-fA-F]+);` and convert via `String.fromCodePoint()`. Named entities via a small lookup map (no DOM dependency).

**Update `normalizeUnicode()`** -- apply CONFUSABLES character replacement after NFKC normalization. Iterate each character, replace if in CONFUSABLES map.

**Update `deobfuscate()`** -- 2-pass pipeline: extract single-pass function `_deobfuscatePass()`, main `deobfuscate()` calls it twice to catch obfuscation-within-obfuscation chains.

### 7. blocklist.ts

**Add `SEED_HASHES`** -- 12 canonical malicious skill hashes loaded on construction:
```
854aa9bd5a641b03fcf2e4a26affb33057af3238a10a83e194c05384f371734f  credential-theft-cursorrules
46315c1d4dcd39199c6d0e43985c5007c1156bc538e3a82ba9b2883f363eab35  markdown-image-exfil
0b2ca8fedb87a97de9f5c462e09110febf887516dd62877d7e95a5556ef90905  reverse-shell-instruction
2b5a339d00216894c7bd3620e008e5443f4e30b9e9883a2b15c082d076775084  curl-exfil-instruction
eccb3a65c459a6b69223d38726e3fddb6184a6e7c52935148fdcd84961a6f9df  prompt-injection-override
f554a511faaca2431265399a9d5b2f7184778b9521952dc757257dbe0aab2a46  supply-chain-install
323b9121b6e320fb04bae89c963690069c5172dca017469be2917e5feaec886c  obfuscated-credential-theft
4826c0e8aef00f902190ab32519e4533b7e4b725f46fb70156705ea8708a7385  social-engineering-exfil
3951cdb38bbc37e28f98448e0478b93d319d892783efb23462b59fedea52189d  mcp-config-injection
a7ddd5ce6c41055b4ef808810ac6f1b09dc4ae05eecc2f89dc64ac4682502d99  keylogger-instruction
eab3b7330de3b61fae1b5cba738ae499424e1c45ef1b025c560cca410e6cd16b  crypto-miner-injection
d71ceee36d1e136a5cddc0d5b416210d94635a71fa90f9ef817f4f74a7b21603  dns-exfil-instruction
```

Seed hashes always present. On remote/cache load, UNION seed hashes with loaded hashes (never replace). This fixes a Python bug where file load could overwrite seeds.

### 8. mcp-checker.ts

**Add 5 new supply chain checks (MCP-007):**

| Package Manager | Detection Pattern | Version Pin Check |
|----------------|-------------------|-------------------|
| bunx | `bunx\s+(@?[\w_./-]+(?:@[^\s]+)?)` | `@version` in last path segment |
| deno | `deno\s+run\s+(?:--allow-\S+\s+)*(\S+)` | `@version` in module, skip local paths (`.`, `/`) |
| docker | `docker\s+run\s+(?:-[^\s]+\s+)*([\w_./-]+(?::[^\s]+)?)` | `:tag` present and not `:latest` |
| pip | `pip3?\s+install\s+([\w_.-]+)` | `==version` after package name, skip flags (`-e`, `-r`, `--upgrade`) |
| go | `go\s+run\s+([\w_./-]+)` | `@version` in module, skip local paths |

All patterns build `all_str` from command + args (space-joined), same as existing npx/uvx checks.

**Add symlink resolution** in `_checkSensitivePaths` -- use `fs.realpathSync()` before checking against sensitive path list. Catch ENOENT (broken symlinks).

### 9. baselines.ts

**Update `configFingerprint()`:**
```typescript
// Before (v0.7):
SHA256(command | JSON(sorted_args) | JSON(sorted_env_keys))

// After (v0.8):
SHA256(command | JSON(sorted_args) | JSON(sorted_env_keys) | url | JSON(sorted_header_keys))
```

URL and sorted header keys (not values) added. Attackers could swap the URL to a malicious endpoint without changing command/args -- URL MUST be in the fingerprint.

### 10. skill-scanner.ts

**Add 3 markdown image exfiltration patterns (SKILL-002):**
1. `!\[.*?\]\(https?://[^\s)]+\?[^\s)]*(?:data|content|file|secret|key|token|d)=` -- markdown image with exfil query params
2. `<img\s+[^>]*src=["']https?://[^"']+\?[^"']*(?:data|content|file|secret|key|token|d)=` -- HTML img tag with exfil query params
3. `(?:render|display|show|include)\s+(?:an?\s+)?(?:image|img|markdown)\s+(?:tag|link)?\s*.*https?://` -- instruction to render external images

### 11. guard.ts

**Wire in new modules to Guard.run():**

```
Guard.run() flow:
  1. Resolve project config (if --config or .agentseal.yaml exists)
  2. Resolve rules: --rules flag > config.rules_paths > .agentseal/rules/ default dir
  3. Discover agents/MCPs/skills (existing) -- keep raw MCP config dicts for rule evaluation
  4. Filter by ignore_paths (new)
  5. Scan skills (existing) + evaluate custom rules on skills (new)
  6. Check MCP configs (existing) + evaluate custom rules on MCPs (new, uses raw config dicts)
  7. Evaluate custom rules on agents (new)
  8. Enrich MCP results from registry (new, unless --no-registry)
  9. Generate unlisted findings (new, if config has allowlists)
  10. Toxic flows + baselines (existing)
  11. Apply ignore_findings filter (new)
  12. Save raw report to history BEFORE filtering (new, unless --no-diff)
  13. Compute delta against filtered previous report (new, unless --no-diff)
  14. Build GuardReport with all new fields
```

Note: Step 3 must preserve raw MCP config dicts (the original parsed JSON objects) alongside MCPServerResult objects. Custom rules need raw configs for field matching (args as array, env as dict, etc). This avoids re-scanning.

**GuardOptions additions:**
```typescript
interface GuardOptions {
  // existing:
  verbose?: boolean;
  scanPath?: string;
  onProgress?: GuardProgressFn;
  semantic?: boolean;
  embedFn?: EmbedFn;
  // new:
  config?: ProjectConfig;
  noRegistry?: boolean;
  noDiff?: boolean;
  rulesPaths?: string[];
  fromJson?: string;       // path to JSON report for re-rendering
  failOn?: string;         // override config fail_on
}
```

### 12. CLI (bin/agentseal.ts)

**New `guard` command** using commander `.command()` subcommand pattern:

```
agentseal guard [path]           # scan machine or directory
agentseal guard init             # generate .agentseal.yaml
agentseal guard test             # validate YAML rules

Options:
  --verbose                      # show all findings
  --no-registry                  # skip agentseal.org enrichment
  --no-diff                      # skip delta comparison
  --from-json <path>             # re-render saved JSON report
  --fail-on <level>              # danger|warning|safe (exit code control)
  --rules <path>                 # custom YAML rules path
  --config <path>                # explicit .agentseal.yaml path
  --output <format>              # terminal|json|sarif
  --save <path>                  # save JSON report to file
  --reset-baselines              # re-trust all MCP servers
```

**guard init defaults:** when no `--rules` provided, `guard test` checks `.agentseal/rules/` in CWD.

**Terminal output format:** Match Python's docker/kubectl-inspired layout:
- ANSI-aware column padding (strip ANSI escape codes for width calculation)
- Section separators (AGENTS, SKILLS, MCP SERVERS, CUSTOM RULES, POLICY, DELTA)
- Column headers (NAME, STATUS, VERDICT, SEVERITY, FINDING)
- REGISTRY column for MCP servers (score + level when available)
- Summary box with severity/status counts
- Exit code: 0 (pass), 1 (fail per fail_on), 2 (error). ERROR verdicts treated as danger for fail_on purposes.

**CLI flags NOT ported** (Python-only, require MCP runtime or LLM):

| Flag | Reason |
|------|--------|
| `--connect` | Requires MCP runtime (subprocess stdio) |
| `--timeout` | MCP runtime connection timeout |
| `--concurrency` | MCP runtime parallelism |
| `--model` / `--api-key` / `--ollama-url` / `--litellm-url` | LLM judge (optional, not in scope) |
| `--llm-all` | LLM judge flag |
| `--no-semantic` | Semantic analysis toggle |
| `--output html` | HTML report generation (future work) |

## Dependencies

**New (optionalDependencies):**
- `better-sqlite3` -- optional dependency. npm proceeds if native build fails on target platform. Code wraps import in try/catch for graceful degradation.

**New (devDependencies):**
- `@types/better-sqlite3` -- type definitions

**No new dependencies for:**
- YAML parsing -- use `yaml` package (check if already present, else add)
- Glob matching -- inline `fnmatchCase` implementation
- HTML entity decoding -- inline regex implementation
- HTTP client -- use `globalThis.fetch` (Node 18+, stable in Node 21+). Node 18 may emit experimental warning, acceptable for our target audience.

**Graceful degradation:** If `better-sqlite3` is not installed (optionalDependencies allows this), history features silently disable. Guard still works, just without delta output. Single warning logged to stderr on first use.

## Testing Strategy

**Framework:** Vitest (existing)
**Isolation:** mkdtempSync per test
**Total new tests:** ~150

| Module | Tests | Strategy |
|--------|-------|----------|
| project-config | ~35 | YAML parsing (including null values), resolution walk-up, filtering, fail_on logic (including hasSafe), unlisted generation (agent status filtering), init with interactive=false |
| history | ~25 | SQLite CRUD, normalize_skill_path (cross-platform separators), compute_delta, retention/cap, graceful failure when better-sqlite3 missing, _count() for assertions |
| registry-client | ~20 | slugify, extractPackageSlug, mocked fetch for bulkCheck/enrich, skip-if-already-set behavior |
| rules | ~25 | YAML loading, validation (required fields, enums, duplicate IDs), glob matching (*, ?, [!...], escaping), evaluate per entity type, coerce string to [string], runTests |
| guard-models | ~15 | fromDict round-trip (all types including CustomFinding, UnlistedFinding), DeltaResult computed getters, registry fields, toSarif with custom findings |
| guard-v08 (integration) | ~15 | Full guard.run() with config + rules + history, --from-json re-render |
| deobfuscate-v08 | ~10 | Confusables mapping, HTML entities (numeric, hex, named), 2-pass catches nested obfuscation |
| blocklist-v08 | ~5 | Seed hashes present on construction, seed hashes survive file load (union not replace) |

**Registry client mocking:** Use Vitest's `vi.fn()` to mock `globalThis.fetch`. No live API calls in tests.

## What's NOT Ported

| Feature | Reason |
|---------|--------|
| MCP runtime (subprocess stdio) | Python-only architecture, JS has no equivalent |
| Client pool randomization | Only relevant for MCP runtime |
| Toxic flows readOnlyHint fix | JS already has different trust model in toxic-flows.ts |
| GitHub Action | Shared infrastructure, already done in .github/actions/guard/ |
| ASCII seal logo | Python terminal only, JS CLI uses its own banner |
| HTML report output (`--output html`) | Future work, not in Python v0.8 core |
| LLM judge flags | Optional expensive feature, not in scope for parity |

## Version

This ships as part of the existing `agentseal` npm package. Version bump from 0.5.2 to 0.6.0 (minor bump for new features).

## File Count Summary

- **4 new source files** (project-config, history, registry-client, rules)
- **7 new test files**
- **7 updated source files** (guard, guard-models, deobfuscate, blocklist, mcp-checker, baselines, skill-scanner)
- **1 updated CLI** (bin/agentseal.ts)
- **1 updated barrel export** (index.ts)
- **~150 new tests**
