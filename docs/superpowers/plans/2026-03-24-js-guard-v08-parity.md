# JS/TS Guard v0.8 Feature Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port all Python Guard v0.8 features to the TypeScript package so `npx agentseal guard` has full feature parity.

**Architecture:** 4 new modules (project-config, history, registry-client, rules), 7 updated modules (guard-models, guard, deobfuscate, blocklist, mcp-checker, baselines, skill-scanner), CLI guard command. TDD throughout. Each module is self-contained with its own test file.

**Tech Stack:** TypeScript, Vitest, better-sqlite3 (optional), Node.js 18+ fetch, js-yaml

**Spec:** `docs/superpowers/specs/2026-03-24-js-guard-v08-parity-design.md`

---

## File Structure

### New Files
| File | Responsibility |
|------|---------------|
| `src/project-config.ts` | .agentseal.yaml loader, resolution, filtering, guard init |
| `src/history.ts` | SQLite history store, delta computation, path normalization |
| `src/registry-client.ts` | agentseal.org API client, slug generation, enrichment |
| `src/rules.ts` | YAML rule engine, glob matching, guard test |
| `test/project-config.test.ts` | ~35 tests |
| `test/history.test.ts` | ~25 tests |
| `test/registry-client.test.ts` | ~20 tests |
| `test/rules.test.ts` | ~25 tests |
| `test/guard-models-v08.test.ts` | ~15 tests |
| `test/guard-v08.test.ts` | ~15 tests |
| `test/deobfuscate-v08.test.ts` | ~10 tests |

### Modified Files
| File | Changes |
|------|---------|
| `src/guard-models.ts` | Add UnlistedFinding, CustomFinding, DeltaEntry, DeltaResult, fromDict methods, registry fields |
| `src/guard.ts` | Wire project config, rules, registry, history, delta into run() |
| `src/deobfuscate.ts` | CONFUSABLES map, decodeHtmlEntities, 2-pass pipeline |
| `src/blocklist.ts` | 12 seed hashes, union on load |
| `src/mcp-checker.ts` | 5 new supply chain checks, symlink resolution |
| `src/baselines.ts` | URL + headers in fingerprint |
| `src/skill-scanner.ts` | 3 markdown exfil patterns |
| `src/index.ts` | Export new modules |
| `bin/agentseal.ts` | guard command + init + test subcommands |
| `package.json` | optionalDependencies, version bump |

---

## Task 1: Update guard-models.ts with new types

**Files:**
- Modify: `js/src/guard-models.ts:68-74` (MCPServerResult), `js/src/guard-models.ts:150-160` (GuardReport)
- Create: `js/test/guard-models-v08.test.ts`

- [ ] **Step 1: Write failing tests for new types**

Create `js/test/guard-models-v08.test.ts`:

```typescript
import { describe, it, expect } from "vitest";

// ═══════════════════════════════════════════════════════════════
// UNLISTED FINDING
// ═══════════════════════════════════════════════════════════════

describe("UnlistedFinding", () => {
  it("has required fields", () => {
    const f: any = {
      code: "GUARD-001",
      title: "Unlisted agent",
      description: "Agent 'cursor' is not in allowed_agents",
      severity: "medium",
      item_name: "cursor",
      item_type: "agent",
    };
    expect(f.code).toBe("GUARD-001");
    expect(f.item_type).toBe("agent");
  });
});

// ═══════════════════════════════════════════════════════════════
// CUSTOM FINDING
// ═══════════════════════════════════════════════════════════════

describe("CustomFinding", () => {
  it("round-trips through toDict/fromDict", () => {
    // Will import CustomFinding helpers once implemented
    const cf = {
      code: "CUSTOM-001",
      title: "Test rule",
      severity: "high",
      verdict: "danger",
      remediation: "Fix it",
      rule_file: "/rules/test.yaml",
      entity_type: "mcp",
      entity_name: "slack-mcp",
    };
    // Test fromDict and toDict once available
    expect(cf.code).toBe("CUSTOM-001");
  });
});

// ═══════════════════════════════════════════════════════════════
// DELTA RESULT
// ═══════════════════════════════════════════════════════════════

describe("DeltaResult", () => {
  it("computes total_new correctly", () => {
    // Will use createDeltaResult helper once implemented
    expect(true).toBe(true); // placeholder
  });

  it("computes total_resolved correctly", () => {
    expect(true).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════
// MCPServerResult registry fields
// ═══════════════════════════════════════════════════════════════

describe("MCPServerResult registry", () => {
  it("includes registry in toDict when score set", () => {
    expect(true).toBe(true);
  });

  it("omits registry from toDict when score not set", () => {
    expect(true).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════
// GuardReport.fromDict
// ═══════════════════════════════════════════════════════════════

describe("GuardReport.fromDict", () => {
  it("round-trips all fields", () => {
    expect(true).toBe(true);
  });
});
```

- [ ] **Step 2: Run tests to verify they pass (placeholders)**

Run: `cd js && npx vitest run test/guard-models-v08.test.ts`

- [ ] **Step 3: Add UnlistedFinding and CustomFinding interfaces to guard-models.ts**

Add after the existing `MCPFinding` interface (~line 55):

```typescript
export interface UnlistedFinding {
  code: string;
  title: string;
  description: string;
  severity: string;
  item_name: string;
  item_type: string;
}

export interface CustomFinding {
  code: string;
  title: string;
  severity: string;
  verdict: string;
  remediation: string;
  rule_file: string;
  entity_type: string;
  entity_name: string;
}

export function customFindingFromDict(d: Record<string, any>): CustomFinding {
  return {
    code: d.code ?? "",
    title: d.title ?? "",
    severity: d.severity ?? "medium",
    verdict: d.verdict ?? "warning",
    remediation: d.remediation ?? "",
    rule_file: d.rule_file ?? "",
    entity_type: d.entity_type ?? "",
    entity_name: d.entity_name ?? "",
  };
}

export function customFindingToDict(f: CustomFinding): Record<string, any> {
  return { ...f };
}

export function unlistedFindingToDict(f: UnlistedFinding): Record<string, any> {
  return { ...f };
}
```

- [ ] **Step 4: Add DeltaEntry and DeltaResult**

Add after CustomFinding:

```typescript
export interface DeltaEntry {
  change_type: string;
  entity_type: string;
  entity_name: string;
  code?: string;
  title?: string;
  old_verdict?: string;
  new_verdict?: string;
  severity?: string;
}

export function deltaEntryToDict(e: DeltaEntry): Record<string, any> {
  const d: Record<string, any> = {
    change_type: e.change_type,
    entity_type: e.entity_type,
    entity_name: e.entity_name,
  };
  if (e.code) d.code = e.code;
  if (e.title) d.title = e.title;
  if (e.old_verdict) d.old_verdict = e.old_verdict;
  if (e.new_verdict) d.new_verdict = e.new_verdict;
  if (e.severity) d.severity = e.severity;
  return d;
}

export class DeltaResult {
  previous_timestamp: string;
  entries: DeltaEntry[];

  constructor(previous_timestamp: string, entries: DeltaEntry[] = []) {
    this.previous_timestamp = previous_timestamp;
    this.entries = entries;
  }

  get total_new(): number {
    return this.entries.filter(
      (e) => e.change_type === "new" || e.change_type === "new_entity"
    ).length;
  }

  get total_resolved(): number {
    return this.entries.filter(
      (e) => e.change_type === "resolved" || e.change_type === "removed_entity"
    ).length;
  }

  get total_changed(): number {
    return this.entries.filter((e) => e.change_type === "changed").length;
  }

  toDict(): Record<string, any> {
    return {
      previous_timestamp: this.previous_timestamp,
      entries: this.entries.map(deltaEntryToDict),
      total_new: this.total_new,
      total_resolved: this.total_resolved,
      total_changed: this.total_changed,
    };
  }
}
```

- [ ] **Step 5: Add registry fields to MCPServerResult**

In the `MCPServerResult` interface (~line 68), add:

```typescript
  registry_score?: number;
  registry_level?: string;
  registry_findings_count?: number;
```

- [ ] **Step 6: Add new fields to GuardReport and fromDict**

In the `GuardReport` interface (~line 150), add fields as **optional** (to avoid breaking existing Guard.run() until Task 9 wires them in):

```typescript
  unlisted_findings?: UnlistedFinding[];
  custom_findings?: CustomFinding[];
  config_path?: string;
```

Add `guardReportFromDict` function:

```typescript
export function guardReportFromDict(d: Record<string, any>): GuardReport {
  return {
    timestamp: d.timestamp ?? "",
    duration_seconds: d.duration_seconds ?? 0,
    agents_found: d.agents_found ?? [],
    skill_results: d.skill_results ?? [],
    mcp_results: (d.mcp_results ?? []).map((m: any) => ({
      ...m,
      registry_score: m.registry?.score ?? m.registry_score,
      registry_level: m.registry?.level ?? m.registry_level,
      registry_findings_count: m.registry?.findings_count ?? m.registry_findings_count,
    })),
    mcp_runtime_results: d.mcp_runtime_results ?? [],
    toxic_flows: d.toxic_flows ?? [],
    baseline_changes: d.baseline_changes ?? [],
    llm_tokens_used: d.llm_tokens_used ?? 0,
    unlisted_findings: d.unlisted_findings ?? [],
    custom_findings: (d.custom_findings ?? []).map(customFindingFromDict),
    config_path: d.config_path ?? "",
  };
}
```

- [ ] **Step 7: Replace placeholder tests with real assertions**

Update `test/guard-models-v08.test.ts` to import and test all new types with real assertions.

- [ ] **Step 8: Run all tests**

Run: `cd js && npx vitest run test/guard-models-v08.test.ts`
Expected: All pass

- [ ] **Step 9: Commit**

```bash
git add js/src/guard-models.ts js/test/guard-models-v08.test.ts
git commit -m "feat(js): add UnlistedFinding, CustomFinding, DeltaResult types and fromDict helpers"
```

---

## Task 2: Security hardening - deobfuscate.ts

**Files:**
- Modify: `js/src/deobfuscate.ts:94-96` (normalizeUnicode), `js/src/deobfuscate.ts:208-219` (deobfuscate)
- Create: `js/test/deobfuscate-v08.test.ts`

- [ ] **Step 1: Write failing tests**

Create `js/test/deobfuscate-v08.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { deobfuscate, normalizeUnicode } from "../src/deobfuscate.js";

describe("TR39 confusables", () => {
  it("maps Cyrillic a to Latin a", () => {
    expect(normalizeUnicode("\u0430")).toBe("a");
  });

  it("maps Cyrillic C to Latin C", () => {
    expect(normalizeUnicode("\u0421")).toBe("C");
  });

  it("maps fullwidth A to Latin A", () => {
    expect(normalizeUnicode("\uff21")).toBe("A");
  });

  it("maps Greek omicron to Latin o", () => {
    expect(normalizeUnicode("\u03bf")).toBe("o");
  });

  it("maps Turkish dotless i to Latin i", () => {
    expect(normalizeUnicode("\u0131")).toBe("i");
  });

  it("normalizes mixed Cyrillic/Latin word", () => {
    // "curl" with Cyrillic с and Latin url
    const input = "\u0441url";
    expect(normalizeUnicode(input)).toBe("curl");
  });
});

describe("decodeHtmlEntities", () => {
  it("decodes numeric entities", () => {
    expect(deobfuscate("&#99;&#117;&#114;&#108;")).toBe("curl");
  });

  it("decodes hex entities", () => {
    expect(deobfuscate("&#x63;&#x75;&#x72;&#x6c;")).toBe("curl");
  });

  it("decodes named entities", () => {
    expect(deobfuscate("&amp; &lt; &gt;")).toBe("& < >");
  });
});

describe("2-pass pipeline", () => {
  it("catches base64 inside zero-width split", () => {
    // First pass strips zero-width, second pass decodes base64
    const zw = "\u200B";
    const b64 = btoa("curl http://evil.com");
    const obfuscated = b64.slice(0, 4) + zw + b64.slice(4);
    const result = deobfuscate(obfuscated);
    expect(result).toContain("curl");
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd js && npx vitest run test/deobfuscate-v08.test.ts`
Expected: FAIL (normalizeUnicode doesn't handle confusables yet, no decodeHtmlEntities)

- [ ] **Step 3: Add CONFUSABLES map to deobfuscate.ts**

Add before the `normalizeUnicode` function (~line 90):

```typescript
const CONFUSABLES = new Map<string, string>([
  // Cyrillic uppercase
  ["\u0410", "A"], ["\u0412", "B"], ["\u0421", "C"], ["\u0415", "E"],
  ["\u041d", "H"], ["\u0406", "I"], ["\u0408", "J"], ["\u041a", "K"],
  ["\u041c", "M"], ["\u041e", "O"], ["\u0420", "P"], ["\u0405", "S"],
  ["\u0422", "T"], ["\u0425", "X"], ["\u0423", "Y"], ["\u0417", "Z"],
  // Cyrillic lowercase
  ["\u0430", "a"], ["\u0441", "c"], ["\u0435", "e"], ["\u04bb", "h"],
  ["\u0456", "i"], ["\u0458", "j"], ["\u043e", "o"], ["\u0440", "p"],
  ["\u0455", "s"], ["\u0445", "x"], ["\u0443", "y"],
  // Greek uppercase
  ["\u0391", "A"], ["\u0392", "B"], ["\u0395", "E"], ["\u0397", "H"],
  ["\u0399", "I"], ["\u039a", "K"], ["\u039c", "M"], ["\u039d", "N"],
  ["\u039f", "O"], ["\u03a1", "P"], ["\u03a4", "T"], ["\u03a7", "X"],
  ["\u03a5", "Y"], ["\u0396", "Z"],
  // Greek lowercase
  ["\u03bf", "o"], ["\u03b1", "a"],
  // Cherokee
  ["\u13a0", "D"], ["\u13a1", "R"], ["\u13a2", "T"], ["\u13aa", "G"],
  ["\u13b3", "W"], ["\u13d2", "S"], ["\u13da", "S"],
  ["\uab4e", "s"], ["\uab4f", "s"], ["\uaba3", "s"], ["\uabaa", "s"],
  // Turkish dotless i
  ["\u0131", "i"],
  // Small caps
  ["\u1d00", "A"], ["\u0299", "B"], ["\u1d04", "C"],
  // Fullwidth Latin uppercase
  ["\uff21", "A"], ["\uff22", "B"], ["\uff23", "C"], ["\uff24", "D"],
  ["\uff25", "E"], ["\uff26", "F"], ["\uff27", "G"], ["\uff28", "H"],
  ["\uff29", "I"], ["\uff2a", "J"], ["\uff2b", "K"], ["\uff2c", "L"],
  ["\uff2d", "M"], ["\uff2e", "N"], ["\uff2f", "O"], ["\uff30", "P"],
  ["\uff31", "Q"], ["\uff32", "R"], ["\uff33", "S"], ["\uff34", "T"],
  ["\uff35", "U"], ["\uff36", "V"], ["\uff37", "W"], ["\uff38", "X"],
  ["\uff39", "Y"], ["\uff3a", "Z"],
  // Fullwidth Latin lowercase
  ["\uff41", "a"], ["\uff42", "b"], ["\uff43", "c"], ["\uff44", "d"],
  ["\uff45", "e"], ["\uff46", "f"], ["\uff47", "g"], ["\uff48", "h"],
  ["\uff49", "i"], ["\uff4a", "j"], ["\uff4b", "k"], ["\uff4c", "l"],
  ["\uff4d", "m"], ["\uff4e", "n"], ["\uff4f", "o"], ["\uff50", "p"],
  ["\uff51", "q"], ["\uff52", "r"], ["\uff53", "s"], ["\uff54", "t"],
  ["\uff55", "u"], ["\uff56", "v"], ["\uff57", "w"], ["\uff58", "x"],
  ["\uff59", "y"], ["\uff5a", "z"],
]);
```

- [ ] **Step 4: Update normalizeUnicode to apply confusables**

Replace the existing `normalizeUnicode` function:

```typescript
export function normalizeUnicode(text: string): string {
  let result = text.normalize("NFKC");
  let out = "";
  for (const ch of result) {
    out += CONFUSABLES.get(ch) ?? ch;
  }
  return out;
}
```

- [ ] **Step 5: Add decodeHtmlEntities function**

Add before the deobfuscate function:

```typescript
const NAMED_ENTITIES: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'",
  nbsp: "\u00A0", copy: "\u00A9", reg: "\u00AE",
};

export function decodeHtmlEntities(text: string): string {
  return text
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) =>
      String.fromCodePoint(parseInt(hex, 16))
    )
    .replace(/&#(\d+);/g, (_, dec) =>
      String.fromCodePoint(parseInt(dec, 10))
    )
    .replace(/&([a-zA-Z]+);/g, (match, name) =>
      NAMED_ENTITIES[name.toLowerCase()] ?? match
    );
}
```

- [ ] **Step 6: Refactor deobfuscate to 2-pass pipeline**

Replace the existing `deobfuscate` function:

```typescript
function _deobfuscatePass(text: string): string {
  text = stripZeroWidth(text);
  text = stripTagChars(text);
  text = stripVariationSelectors(text);
  text = stripBidiControls(text);
  text = stripHtmlComments(text);
  text = decodeHtmlEntities(text);
  text = normalizeUnicode(text);
  text = decodeBase64Blocks(text);
  text = unescapeSequences(text);
  text = expandStringConcat(text);
  return text;
}

export function deobfuscate(text: string): string {
  text = _deobfuscatePass(text);
  text = _deobfuscatePass(text);
  return text;
}
```

- [ ] **Step 7: Export decodeHtmlEntities from deobfuscate.ts and index.ts**

Add `decodeHtmlEntities` to the exports in `src/index.ts` alongside existing deobfuscate exports.

- [ ] **Step 8: Run tests**

Run: `cd js && npx vitest run test/deobfuscate-v08.test.ts`
Expected: All pass

- [ ] **Step 9: Run full existing deobfuscate tests to verify no regressions**

Run: `cd js && npx vitest run test/deobfuscate.test.ts`
Expected: All existing tests still pass

- [ ] **Step 10: Commit**

```bash
git add js/src/deobfuscate.ts js/test/deobfuscate-v08.test.ts js/src/index.ts
git commit -m "feat(js): add TR39 confusables, HTML entity decoding, 2-pass deobfuscation"
```

---

## Task 3: Security hardening - blocklist.ts seed hashes

**Files:**
- Modify: `js/src/blocklist.ts:20-28` (constructor, _hashes), `js/src/blocklist.ts:69-78` (_loadFromFile)

- [ ] **Step 1: Write failing test**

Add to bottom of existing `js/test/blocklist.test.ts`:

```typescript
describe("seed hashes", () => {
  it("has 12 seed hashes on construction", () => {
    const bl = new Blocklist(mkdtempSync(join(tmpdir(), "bl-")));
    expect(bl.size).toBeGreaterThanOrEqual(12);
  });

  it("recognizes credential-theft-cursorrules hash", () => {
    const bl = new Blocklist(mkdtempSync(join(tmpdir(), "bl-")));
    expect(bl.isBlocked("854aa9bd5a641b03fcf2e4a26affb33057af3238a10a83e194c05384f371734f")).toBe(true);
  });

  it("seed hashes survive file load", () => {
    const dir = mkdtempSync(join(tmpdir(), "bl-"));
    writeFileSync(join(dir, "blocklist.json"), JSON.stringify({ sha256_hashes: ["aaa"], updated: new Date().toISOString() }));
    const bl = new Blocklist(dir);
    expect(bl.isBlocked("854aa9bd5a641b03fcf2e4a26affb33057af3238a10a83e194c05384f371734f")).toBe(true);
    expect(bl.isBlocked("aaa")).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd js && npx vitest run test/blocklist.test.ts`

- [ ] **Step 3: Add SEED_HASHES constant and update constructor**

In `blocklist.ts`, add before the Blocklist class:

```typescript
const SEED_HASHES = new Set([
  "854aa9bd5a641b03fcf2e4a26affb33057af3238a10a83e194c05384f371734f",
  "46315c1d4dcd39199c6d0e43985c5007c1156bc538e3a82ba9b2883f363eab35",
  "0b2ca8fedb87a97de9f5c462e09110febf887516dd62877d7e95a5556ef90905",
  "2b5a339d00216894c7bd3620e008e5443f4e30b9e9883a2b15c082d076775084",
  "eccb3a65c459a6b69223d38726e3fddb6184a6e7c52935148fdcd84961a6f9df",
  "f554a511faaca2431265399a9d5b2f7184778b9521952dc757257dbe0aab2a46",
  "323b9121b6e320fb04bae89c963690069c5172dca017469be2917e5feaec886c",
  "4826c0e8aef00f902190ab32519e4533b7e4b725f46fb70156705ea8708a7385",
  "3951cdb38bbc37e28f98448e0478b93d319d892783efb23462b59fedea52189d",
  "a7ddd5ce6c41055b4ef808810ac6f1b09dc4ae05eecc2f89dc64ac4682502d99",
  "eab3b7330de3b61fae1b5cba738ae499424e1c45ef1b025c560cca410e6cd16b",
  "d71ceee36d1e136a5cddc0d5b416210d94635a71fa90f9ef817f4f74a7b21603",
]);
```

In constructor, initialize `_hashes` with seeds:
```typescript
this._hashes = new Set(SEED_HASHES);
```

In `_loadFromFile`, change to UNION instead of replace:
```typescript
// OLD: this._hashes = new Set(data.sha256_hashes);
// NEW:
for (const h of (data.sha256_hashes ?? [])) {
  this._hashes.add(h);
}
```

- [ ] **Step 4: Update existing blocklist tests for seed hashes**

Existing tests assert `bl.size === 0` for empty blocklists. With 12 seed hashes, these break. Update:
- `expect(bl.size).toBe(0)` -> `expect(bl.size).toBe(12)` (empty cache = seeds only)
- `expect(bl.size).toBe(2)` -> `expect(bl.size).toBe(14)` (2 from cache + 12 seeds)
- Any test that calls `bl.addHashes(["x"])` then checks size: add 12 to expected count

- [ ] **Step 5: Run tests**

Run: `cd js && npx vitest run test/blocklist.test.ts`
Expected: All pass (new + updated existing)

- [ ] **Step 6: Commit**

```bash
git add js/src/blocklist.ts js/test/blocklist.test.ts
git commit -m "feat(js): add 12 seed hashes to blocklist, union on file load"
```

---

## Task 4: Security hardening - mcp-checker.ts supply chain + baselines + skill-scanner

**Files:**
- Modify: `js/src/mcp-checker.ts:294-350` (_checkSupplyChain), `js/src/mcp-checker.ts:154-176` (_checkSensitivePaths)
- Modify: `js/src/baselines.ts:50-61` (configFingerprint)
- Modify: `js/src/skill-scanner.ts` (SKILL-002 patterns)

- [ ] **Step 1: Write failing tests for new supply chain checks**

Add to existing `js/test/mcp-checker.test.ts`:

```typescript
describe("supply chain - bunx", () => {
  it("detects unpinned bunx package", () => {
    const result = checker.check({ name: "test", command: "bunx", args: ["@scope/pkg"], source_file: "f" });
    expect(result.findings.some((f: any) => f.code === "MCP-007")).toBe(true);
  });
});

describe("supply chain - deno", () => {
  it("detects unpinned deno module", () => {
    const result = checker.check({ name: "test", command: "deno", args: ["run", "npm:pkg"], source_file: "f" });
    expect(result.findings.some((f: any) => f.code === "MCP-007")).toBe(true);
  });
});

describe("supply chain - docker", () => {
  it("detects docker run with :latest", () => {
    const result = checker.check({ name: "test", command: "docker", args: ["run", "myimg:latest"], source_file: "f" });
    expect(result.findings.some((f: any) => f.code === "MCP-007")).toBe(true);
  });

  it("detects docker run without tag", () => {
    const result = checker.check({ name: "test", command: "docker", args: ["run", "myimg"], source_file: "f" });
    expect(result.findings.some((f: any) => f.code === "MCP-007")).toBe(true);
  });
});

describe("supply chain - pip", () => {
  it("detects unpinned pip install", () => {
    const result = checker.check({ name: "test", command: "pip", args: ["install", "requests"], source_file: "f" });
    expect(result.findings.some((f: any) => f.code === "MCP-007")).toBe(true);
  });
});

describe("supply chain - go", () => {
  it("detects unpinned go run", () => {
    const result = checker.check({ name: "test", command: "go", args: ["run", "github.com/user/tool"], source_file: "f" });
    expect(result.findings.some((f: any) => f.code === "MCP-007")).toBe(true);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd js && npx vitest run test/mcp-checker.test.ts`

- [ ] **Step 3: Add bunx/deno/docker/pip/go checks to _checkSupplyChain**

In `_checkSupplyChain` method, after the existing npx and uvx checks, add:

```typescript
// bunx (Bun's npx)
const bunxMatch = allStr.match(/bunx\s+(@?[a-zA-Z0-9_./-]+(?:@[^\s]+)?)/);
if (bunxMatch) {
  const pkg = bunxMatch[1];
  const parts = pkg.split("/");
  const last = parts[parts.length - 1] || pkg;
  const hasVersion = last.includes("@") && !last.startsWith("@");
  if (!hasVersion) {
    findings.push({
      code: "MCP-007", title: "Unpinned bunx package",
      description: `Package "${pkg}" has no version pin. Use @version.`,
      severity: "medium", remediation: `Pin: bunx ${pkg}@<version>`,
    });
  }
}

// deno run
if (/deno\s+run/.test(allStr)) {
  const denoMatch = allStr.match(/deno\s+run\s+(?:--allow-\S+\s+)*(\S+)/);
  if (denoMatch) {
    const mod = denoMatch[1];
    if (!mod.startsWith(".") && !mod.startsWith("/") && !mod.includes("@")) {
      findings.push({
        code: "MCP-007", title: "Unpinned deno module",
        description: `Module "${mod}" has no version pin.`,
        severity: "medium", remediation: `Pin: ${mod}@<version>`,
      });
    }
  }
}

// docker run
const dockerMatch = allStr.match(/docker\s+run\s+(?:-[^\s]+\s+)*([a-zA-Z0-9_./-]+(?::[^\s]+)?)/);
if (dockerMatch) {
  const image = dockerMatch[1];
  if (!image.includes(":") || image.endsWith(":latest")) {
    findings.push({
      code: "MCP-007", title: "Unpinned Docker image",
      description: `Image "${image}" uses no tag or :latest.`,
      severity: "medium", remediation: `Pin: ${image.split(":")[0]}:<specific-tag>`,
    });
  }
}

// pip install
const pipMatch = allStr.match(/pip3?\s+install\s+([a-zA-Z0-9_.-]+)/);
if (pipMatch) {
  const pkg = pipMatch[1];
  if (!["-e", "-r", "--upgrade"].includes(pkg)) {
    const after = allStr.split(pkg)[1] || "";
    if (!after.slice(0, 20).includes("==")) {
      findings.push({
        code: "MCP-007", title: "Unpinned pip package",
        description: `Package "${pkg}" has no ==version pin.`,
        severity: "medium", remediation: `Pin: ${pkg}==<version>`,
      });
    }
  }
}

// go run
const goMatch = allStr.match(/go\s+run\s+([a-zA-Z0-9_./-]+)/);
if (goMatch) {
  const mod = goMatch[1];
  if (!mod.startsWith(".") && !mod.startsWith("/") && !mod.includes("@")) {
    findings.push({
      code: "MCP-007", title: "Unpinned Go module",
      description: `Module "${mod}" has no @version pin.`,
      severity: "medium", remediation: `Pin: ${mod}@<version>`,
    });
  }
}
```

- [ ] **Step 4: Add symlink resolution to _checkSensitivePaths**

Add `realpathSync` to the top-level imports at the top of `mcp-checker.ts`:

```typescript
import { realpathSync } from "node:fs";
```

Then at the start of `_checkSensitivePaths`, resolve symlinks:

```typescript
const resolvedArgs = args.map((a: string) => {
  try { return realpathSync(a); } catch { return a; }
});
```

Use `resolvedArgs` instead of `args` for the sensitive path check.

- [ ] **Step 5: Update baselines.ts configFingerprint**

In `configFingerprint` (~line 50), add `url` and `headers` to the existing parts array. Keep the existing `createHash` pattern (do NOT use `sha256` from blocklist):

```typescript
function configFingerprint(server: Record<string, any>): string {
  const parts = [
    server.command ?? "",
    JSON.stringify([...(server.args ?? [])].map(String).sort()),
    JSON.stringify(Object.keys(server.env ?? {}).map(String).sort()),
    server.url ?? "",
    JSON.stringify(Object.keys(server.headers ?? {}).map(String).sort()),
  ];
  return createHash("sha256").update(parts.join("|")).digest("hex");
}
```

- [ ] **Step 6: Add markdown exfil patterns to skill-scanner.ts**

Find the existing SKILL-002 rule in the `PATTERN_RULES` array (~line 58-74). It has a `patterns: RegExp[]` array. **Append** 3 new RegExp entries to this existing array:

```typescript
// Add to the existing SKILL-002 patterns array:
/!\[.*?\]\(https?:\/\/[^\s)]+\?[^\s)]*(?:data|content|file|secret|key|token|d)=/i,
/<img\s+[^>]*src=["']https?:\/\/[^"']+\?[^"']*(?:data|content|file|secret|key|token|d)=/i,
/(?:render|display|show|include)\s+(?:an?\s+)?(?:image|img|markdown)\s+(?:tag|link)?\s*.*https?:\/\//i,
```

Do NOT create new rule objects — add to the existing SKILL-002 `patterns` array.

- [ ] **Step 7: Run all modified test files**

Run: `cd js && npx vitest run test/mcp-checker.test.ts test/baselines.test.ts test/skill-scanner.test.ts`
Expected: All pass

- [ ] **Step 8: Commit**

```bash
git add js/src/mcp-checker.ts js/src/baselines.ts js/src/skill-scanner.ts js/test/mcp-checker.test.ts
git commit -m "feat(js): add 5 supply chain checks, URL in fingerprint, markdown exfil patterns"
```

---

## Task 5: project-config.ts

**Files:**
- Create: `js/src/project-config.ts`
- Create: `js/test/project-config.test.ts`

- [ ] **Step 0: Add yaml dependency**

In `js/package.json`, add to `dependencies`:
```json
"yaml": "^2.4.0"
```

Run: `cd js && npm install`

The `yaml` package has built-in TypeScript types (no separate @types needed).

- [ ] **Step 1: Write failing tests**

Create `js/test/project-config.test.ts` with tests for:
- `loadProjectConfig`: valid YAML, invalid fail_on, unknown keys warning, null values coerced
- `resolveProjectConfig`: explicit path, walk-up to .git, HOME boundary, null when nothing found
- `shouldIgnorePath`: segment matching ("node_modules" matches "foo/node_modules/bar")
- `shouldIgnoreFinding`: bare code match, code:path match, maxsplit=1 for colons
- `shouldFail`: all three levels including hasSafe
- `generateUnlistedFindings`: filters not_installed/error agents, empty allowlist = no findings
- `generateConfigYaml`: includes default ignore_paths
- `runGuardInit`: interactive=false creates file, force overwrites

~35 tests total. Each test creates a temp directory with `mkdtempSync`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd js && npx vitest run test/project-config.test.ts`

- [ ] **Step 3: Implement project-config.ts**

Create `js/src/project-config.ts` implementing all functions from the spec. Key implementation notes:
- Use `js-yaml` or `yaml` package for YAML parsing (check which is in dependencies, add if needed)
- `resolveProjectConfig` walks parent dirs checking for `.agentseal.yaml`, stops at `.git`, HOME, or root
- `shouldIgnoreFinding` uses `id.indexOf(":")` for first-colon split
- `shouldFail` with "safe" level checks all three booleans
- `generateUnlistedFindings` filters agents by status before checking allowlist
- `generateConfigYaml` uses template strings, defaults `ignore_paths: [node_modules, .git, __pycache__]`
- `runGuardInit` calls `scanMachine()` + `scanDirectory()`, prompts unless `interactive=false`

- [ ] **Step 4: Run tests**

Run: `cd js && npx vitest run test/project-config.test.ts`
Expected: All pass

- [ ] **Step 5: Export from index.ts**

Add project-config exports to `src/index.ts`.

- [ ] **Step 6: Commit**

```bash
git add js/src/project-config.ts js/test/project-config.test.ts js/src/index.ts
git commit -m "feat(js): add project-config module — .agentseal.yaml loader, resolution, filtering"
```

---

## Task 6: registry-client.ts

**Files:**
- Create: `js/src/registry-client.ts`
- Create: `js/test/registry-client.test.ts`

- [ ] **Step 1: Write failing tests**

Create `js/test/registry-client.test.ts` with tests for:
- `slugify`: "@anthropic/filesystem" -> "anthropic-filesystem", "my_tool" -> "my-tool"
- `extractPackageSlug`: npx, bunx, uvx, pip, docker, bare binary returns null
- `bulkCheck`: mocked fetch returning data, mocked fetch timeout returns {}, empty slugs returns {}
- `enrichMcpResults`: sets registry fields, skips if already set, handles no results

~20 tests total. Mock `globalThis.fetch` with `vi.fn()`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd js && npx vitest run test/registry-client.test.ts`

- [ ] **Step 3: Implement registry-client.ts**

Create `js/src/registry-client.ts`:
- `slugify(name)`: lowercase, replace `@scope/` with `scope-`, replace `[^a-z0-9-]` with `-`
- `extractPackageSlug(command)`: regex for npx/bunx/uvx/pip/docker, strip @version, return slugify(pkg)
- `bulkCheck(slugs, apiKey?)`: POST with `AbortSignal.timeout(8000)`, User-Agent header, catch all errors
- `enrichMcpResults(results, apiKey?)`: build slug map from name + command, call bulkCheck, set fields if not already set

- [ ] **Step 4: Run tests**

Run: `cd js && npx vitest run test/registry-client.test.ts`
Expected: All pass

- [ ] **Step 5: Export from index.ts**

- [ ] **Step 6: Commit**

```bash
git add js/src/registry-client.ts js/test/registry-client.test.ts js/src/index.ts
git commit -m "feat(js): add registry client for MCP trust score enrichment"
```

---

## Task 7: rules.ts

**Files:**
- Create: `js/src/rules.ts`
- Create: `js/test/rules.test.ts`

- [ ] **Step 1: Write failing tests**

Create `js/test/rules.test.ts` with tests for:
- `fnmatchCase`: basic `*`, `?`, `[abc]`, `[!abc]`, regex-special char escaping
- `RuleEngine.fromPaths`: valid YAML, missing required fields throws, invalid severity throws, duplicate IDs throws, dir globbing
- `evaluateMcp`: AND across fields, OR within field, coerce string to [string]
- `evaluateSkill`: content truncated to 10240, path matching
- `evaluateAgent`: agent_type matching
- `runTests`: pass and fail cases

~25 tests total.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd js && npx vitest run test/rules.test.ts`

- [ ] **Step 3: Implement fnmatchCase**

```typescript
export function fnmatchCase(value: string, pattern: string): boolean {
  const re = pattern
    .replace(/[.+^${}()|\\]/g, "\\$&")  // escape regex specials
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${re}$`, "i").test(value);
}
```

Handle `[...]` and `[!...]` by passing them through to regex unchanged (they're valid regex character classes).

- [ ] **Step 4: Implement RuleEngine class**

Create `js/src/rules.ts` with:
- YAML loading via js-yaml/yaml
- Validation: required fields, enum values, no duplicate IDs
- `_matchEntity`: AND across fields, OR within field, coerce string to array
- `evaluateMcp/Skill/Agent`: build entity_data dict, filter rules by match.type, call _matchEntity
- `runTests`: iterate rules' tests, call _matchEntity, compare result

- [ ] **Step 5: Run tests**

Run: `cd js && npx vitest run test/rules.test.ts`
Expected: All pass

- [ ] **Step 6: Export from index.ts**

- [ ] **Step 7: Commit**

```bash
git add js/src/rules.ts js/test/rules.test.ts js/src/index.ts
git commit -m "feat(js): add YAML community rule engine with glob matching"
```

---

## Task 8: history.ts

**Files:**
- Create: `js/src/history.ts`
- Create: `js/test/history.test.ts`

- [ ] **Step 1: Add better-sqlite3 to optionalDependencies**

In `js/package.json`, add:
```json
"optionalDependencies": {
  "better-sqlite3": "^11.0.0"
},
```

In devDependencies, add:
```json
"@types/better-sqlite3": "^7.6.0"
```

Run: `cd js && npm install`

- [ ] **Step 2: Write failing tests**

Create `js/test/history.test.ts` with tests for:
- `HistoryStore`: constructor creates DB file, save/loadPrevious round-trip, loadPrevious returns null on first scan, prune removes old entries, prune enforces max_rows, _count helper
- `normalizeSkillPath`: HOME prefix, scanPath prefix, fallback to last 2 segments, Windows separator normalization
- `computeDelta`: new skill, resolved skill, changed verdict, new MCP, removed MCP, new agent, removed agent, agent status filtering

~25 tests total. Each test uses mkdtempSync for DB path.

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd js && npx vitest run test/history.test.ts`

- [ ] **Step 4: Implement history.ts**

Create `js/src/history.ts`:

```typescript
import { createRequire } from "node:module";
const _require = createRequire(import.meta.url);

let Database: any = null;
try {
  Database = _require("better-sqlite3");
} catch {
  // better-sqlite3 not installed — history features disabled
}
```

Note: `createRequire` is needed because the package is ESM (`"type": "module"`). Regular `require()` is not available in ESM. This keeps the synchronous API that `better-sqlite3` is chosen for.

- `HistoryStore` class: wraps better-sqlite3, creates table + index on construction, save with BEGIN IMMEDIATE, loadPrevious with OFFSET 1, prune on save, _count for tests
- If `Database` is null, constructor returns a no-op stub (save does nothing, loadPrevious returns null)
- `normalizeSkillPath`: replace HOME with `~/`, replace scanPath with relative, fallback last 2 segments, normalize `\` to `/`
- `computeDelta`: compare current vs previous by normalized keys, emit DeltaEntry for each diff

- [ ] **Step 5: Run tests**

Run: `cd js && npx vitest run test/history.test.ts`
Expected: All pass (if better-sqlite3 installed) or skip gracefully

- [ ] **Step 6: Export from index.ts**

- [ ] **Step 7: Commit**

```bash
git add js/src/history.ts js/test/history.test.ts js/package.json js/src/index.ts
git commit -m "feat(js): add SQLite history store with delta scanning"
```

---

## Task 9: Wire everything into guard.ts

**Files:**
- Modify: `js/src/guard.ts:38-49` (GuardOptions), `js/src/guard.ts:189-263` (run method)
- Create: `js/test/guard-v08.test.ts`

- [ ] **Step 1: Write integration tests**

Create `js/test/guard-v08.test.ts` with tests for:
- Guard with project config (ignore_paths filters results)
- Guard with custom rules (produces CustomFinding)
- Guard with --from-json (re-renders existing report)
- Guard with history (saves and computes delta)
- Guard without registry (noRegistry option skips enrichment)
- Guard exit code logic (fail_on levels, ERROR as danger)
- Guard unlisted findings (agents not in allowlist)

~15 tests. Each creates temp dirs with .agentseal.yaml and test skill files.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd js && npx vitest run test/guard-v08.test.ts`

- [ ] **Step 3: Update GuardOptions interface**

Add to the existing `GuardOptions` interface:

```typescript
  config?: ProjectConfig;
  noRegistry?: boolean;
  noDiff?: boolean;
  rulesPaths?: string[];
  fromJson?: string;
  failOn?: string;
```

- [ ] **Step 4: Update Guard.run() to wire new modules**

Update the `run()` method following the flow from the spec:
1. If `fromJson` provided, read file, parse via `guardReportFromDict`, return immediately
2. Resolve project config (resolveProjectConfig or use provided config)
3. Resolve rules paths (options > config > .agentseal/rules/)
4. Run existing discovery (keep raw MCP config dicts)
5. Filter by ignore_paths
6. Scan skills + evaluate custom rules
7. Check MCPs + evaluate custom rules (using raw config dicts)
8. Evaluate custom rules on agents
9. Enrich from registry (unless noRegistry)
10. Generate unlisted findings
11. Existing toxic flows + baselines
12. Apply ignore_findings
13. Save to history (unless noDiff)
14. Compute delta (unless noDiff)
15. Build full GuardReport

- [ ] **Step 5: Run tests**

Run: `cd js && npx vitest run test/guard-v08.test.ts`
Expected: All pass

- [ ] **Step 6: Run ALL existing guard tests for regression**

Run: `cd js && npx vitest run test/guard.test.ts`
Expected: All existing tests still pass

- [ ] **Step 7: Commit**

```bash
git add js/src/guard.ts js/test/guard-v08.test.ts
git commit -m "feat(js): wire project config, rules, registry, history into guard"
```

---

## Task 10: CLI guard command

**Files:**
- Modify: `js/bin/agentseal.ts:290-319` (add guard command after compare)

- [ ] **Step 1: Add guard command to CLI**

After the existing `compare` command, add:

```typescript
const guardCmd = program
  .command("guard")
  .description("Scan machine for AI agent security issues")
  .argument("[path]", "directory to scan (default: entire machine)")
  .option("--verbose", "show all findings")
  .option("--no-registry", "skip agentseal.org enrichment")
  .option("--no-diff", "skip delta comparison")
  .option("--from-json <path>", "re-render saved JSON report")
  .option("--fail-on <level>", "exit code threshold: danger|warning|safe")
  .option("--rules <path>", "custom YAML rules path")
  .option("--config <path>", "explicit .agentseal.yaml path")
  .option("-o, --output <format>", "output format: terminal|json|sarif", "terminal")
  .option("--save <path>", "save JSON report to file")
  .option("--reset-baselines", "re-trust all MCP servers")
  .action(async (scanPath, opts) => {
    // Implementation: build GuardOptions from CLI opts, run Guard, render output
  });

guardCmd
  .command("init")
  .description("Generate .agentseal.yaml config file")
  .option("--force", "overwrite existing config")
  .action(async (opts) => {
    // Implementation: call runGuardInit
  });

guardCmd
  .command("test")
  .description("Validate YAML rules")
  .option("--rules <path>", "rules path (default: .agentseal/rules/)")
  .action(async (opts) => {
    // Implementation: load rules, run tests, print results
  });
```

- [ ] **Step 2: Implement guard action handler**

The handler should:
1. Print banner
2. If `--from-json`, read file and re-render
3. Build GuardOptions from CLI opts
4. Resolve project config (--config or auto-detect)
5. Create Guard instance and run
6. Render output (terminal/json/sarif)
7. If `--save`, write JSON to file
8. Exit with code based on fail_on

- [ ] **Step 3: Implement terminal output renderer**

Create a `_renderGuardTerminal(report, delta?, verbose?)` function with:
- ANSI-aware column padding (strip escape codes for width)
- Section separators and headers
- Color-coded verdicts (green=safe, yellow=warning, red=danger)
- REGISTRY column for MCPs
- DELTA section showing new/resolved/changed
- Summary box

- [ ] **Step 4: Implement guard init handler**

Call `runGuardInit({ force: opts.force, interactive: true })`.

- [ ] **Step 5: Implement guard test handler**

Load rules from `--rules` or `.agentseal/rules/`, call `engine.runTests()`, print pass/fail table.

- [ ] **Step 6: Manual test**

Run: `cd js && npm run build && node dist/agentseal.js guard --help`
Expected: Shows guard command with all options

Run: `cd js && node dist/agentseal.js guard`
Expected: Scans machine, shows terminal output

- [ ] **Step 7: Commit**

```bash
git add js/bin/agentseal.ts
git commit -m "feat(js): add guard CLI command with init, test subcommands"
```

---

## Task 11: Package updates and final integration

**Files:**
- Modify: `js/package.json` (version, optionalDependencies)
- Modify: `js/src/index.ts` (all new exports)

- [ ] **Step 1: Bump version to 0.6.0**

In `package.json`, change `"version": "0.5.2"` to `"version": "0.6.0"`.

- [ ] **Step 2: Verify all exports in index.ts**

Ensure all new modules are exported:
- `project-config.ts`: ProjectConfig, loadProjectConfig, resolveProjectConfig, shouldIgnorePath, shouldIgnoreFinding, shouldFail, generateUnlistedFindings, runGuardInit
- `history.ts`: HistoryStore, normalizeSkillPath, computeDelta
- `registry-client.ts`: slugify, extractPackageSlug, bulkCheck, enrichMcpResults
- `rules.ts`: RuleEngine, fnmatchCase, Rule, RuleTestResult, CustomFinding
- `guard-models.ts`: UnlistedFinding, CustomFinding, DeltaEntry, DeltaResult, guardReportFromDict

- [ ] **Step 3: Run FULL test suite**

Run: `cd js && npx vitest run`
Expected: All tests pass (existing + ~150 new)

- [ ] **Step 4: Build and verify**

Run: `cd js && npm run build`
Expected: Build succeeds, no type errors

- [ ] **Step 5: Run typecheck**

Run: `cd js && npx tsc --noEmit`
Expected: No type errors

- [ ] **Step 6: Test CLI end-to-end**

```bash
cd js && node dist/agentseal.js guard
cd js && node dist/agentseal.js guard --output json
cd js && node dist/agentseal.js guard init --force
cd js && node dist/agentseal.js guard test
```

- [ ] **Step 7: Commit everything**

```bash
git add js/
git commit -m "chore(js): bump to 0.6.0, export all new guard v0.8 modules"
```

---

## Task 12: Triple verification pass

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite 3 times**

```bash
cd js && npx vitest run && npx vitest run && npx vitest run
```

All 3 runs must pass with identical results.

- [ ] **Step 2: Verify Python/JS parity checklist**

Check each feature exists in both:
- [ ] project-config: loadProjectConfig, resolveProjectConfig, shouldIgnorePath, shouldIgnoreFinding, shouldFail, generateUnlistedFindings, runGuardInit
- [ ] history: HistoryStore (save, loadPrevious, prune), normalizeSkillPath, computeDelta
- [ ] registry-client: slugify, extractPackageSlug, bulkCheck, enrichMcpResults
- [ ] rules: RuleEngine (fromPaths, evaluateMcp/Skill/Agent, runTests), fnmatchCase
- [ ] guard-models: UnlistedFinding, CustomFinding, DeltaEntry, DeltaResult, fromDict, registry fields
- [ ] deobfuscate: CONFUSABLES (80+), decodeHtmlEntities, 2-pass pipeline
- [ ] blocklist: 12 seed hashes, union on load
- [ ] mcp-checker: bunx, deno, docker, pip, go supply chain checks
- [ ] baselines: URL + headers in fingerprint
- [ ] skill-scanner: 3 markdown exfil patterns
- [ ] CLI: guard, guard init, guard test, all flags

- [ ] **Step 3: Verify graceful degradation**

Temporarily rename `node_modules/better-sqlite3` and run:
```bash
cd js && npx vitest run test/guard-v08.test.ts
```

Guard tests should still pass (history features disabled, no crash).

Restore: `mv node_modules/better-sqlite3.bak node_modules/better-sqlite3`

- [ ] **Step 4: Final commit if any fixes needed**

```bash
git add js/src/ js/test/ js/bin/ js/package.json
git commit -m "fix(js): triple verification fixes"
```
