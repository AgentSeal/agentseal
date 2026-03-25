import { describe, it, expect } from "vitest";
import {
  type UnlistedFinding,
  type CustomFinding,
  type DeltaEntry,
  DeltaResult,
  customFindingFromDict,
  customFindingToDict,
  unlistedFindingToDict,
  deltaEntryToDict,
  guardReportFromDict,
  type MCPServerResult,
  GuardVerdict,
} from "../src/guard-models.js";

// ═══════════════════════════════════════════════════════════════════════
// UNLISTED FINDING
// ═══════════════════════════════════════════════════════════════════════

describe("UnlistedFinding", () => {
  it("can be created with all fields", () => {
    const f: UnlistedFinding = {
      code: "GUARD-001",
      title: "Unlisted MCP server",
      description: "Server not in any known registry",
      severity: "medium",
      item_name: "shady-server",
      item_type: "mcp_server",
    };
    expect(f.code).toBe("GUARD-001");
    expect(f.title).toBe("Unlisted MCP server");
    expect(f.description).toBe("Server not in any known registry");
    expect(f.severity).toBe("medium");
    expect(f.item_name).toBe("shady-server");
    expect(f.item_type).toBe("mcp_server");
  });

  it("toDict returns a plain object with all fields", () => {
    const f: UnlistedFinding = {
      code: "GUARD-002",
      title: "Unlisted agent",
      description: "Agent not recognized",
      severity: "high",
      item_name: "rogue-agent",
      item_type: "agent",
    };
    const d = unlistedFindingToDict(f);
    expect(d.code).toBe("GUARD-002");
    expect(d.title).toBe("Unlisted agent");
    expect(d.severity).toBe("high");
    expect(d.item_name).toBe("rogue-agent");
    expect(d.item_type).toBe("agent");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// CUSTOM FINDING
// ═══════════════════════════════════════════════════════════════════════

describe("CustomFinding", () => {
  it("fromDict with full data", () => {
    const d = {
      code: "CUSTOM-001",
      title: "Hardcoded key",
      severity: "critical",
      verdict: "danger",
      remediation: "Remove the key",
      rule_file: "rules/keys.yaml",
      entity_type: "mcp_server",
      entity_name: "my-server",
    };
    const f = customFindingFromDict(d);
    expect(f.code).toBe("CUSTOM-001");
    expect(f.title).toBe("Hardcoded key");
    expect(f.severity).toBe("critical");
    expect(f.verdict).toBe("danger");
    expect(f.remediation).toBe("Remove the key");
    expect(f.rule_file).toBe("rules/keys.yaml");
    expect(f.entity_type).toBe("mcp_server");
    expect(f.entity_name).toBe("my-server");
  });

  it("fromDict applies defaults for missing fields", () => {
    const f = customFindingFromDict({});
    expect(f.code).toBe("");
    expect(f.title).toBe("");
    expect(f.severity).toBe("medium");
    expect(f.verdict).toBe("warning");
    expect(f.remediation).toBe("");
    expect(f.rule_file).toBe("");
    expect(f.entity_type).toBe("");
    expect(f.entity_name).toBe("");
  });

  it("fromDict applies defaults for partial data", () => {
    const f = customFindingFromDict({ code: "C-99", title: "Partial" });
    expect(f.code).toBe("C-99");
    expect(f.title).toBe("Partial");
    expect(f.severity).toBe("medium");
    expect(f.verdict).toBe("warning");
  });

  it("toDict round-trip preserves all fields", () => {
    const original: CustomFinding = {
      code: "CUSTOM-002",
      title: "Unsafe pattern",
      severity: "high",
      verdict: "danger",
      remediation: "Refactor",
      rule_file: "rules/safety.yaml",
      entity_type: "agent",
      entity_name: "test-agent",
    };
    const d = customFindingToDict(original);
    const restored = customFindingFromDict(d);
    expect(restored).toEqual(original);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// DELTA ENTRY + DELTA RESULT
// ═══════════════════════════════════════════════════════════════════════

describe("DeltaEntry", () => {
  it("deltaEntryToDict includes required fields", () => {
    const e: DeltaEntry = {
      change_type: "new",
      entity_type: "mcp_server",
      entity_name: "test-server",
    };
    const d = deltaEntryToDict(e);
    expect(d.change_type).toBe("new");
    expect(d.entity_type).toBe("mcp_server");
    expect(d.entity_name).toBe("test-server");
    // optional fields should not appear
    expect(d.code).toBeUndefined();
    expect(d.title).toBeUndefined();
  });

  it("deltaEntryToDict includes optional fields when present", () => {
    const e: DeltaEntry = {
      change_type: "changed",
      entity_type: "mcp_server",
      entity_name: "server-a",
      code: "MCP-001",
      title: "Insecure transport",
      old_verdict: "warning",
      new_verdict: "danger",
      severity: "high",
    };
    const d = deltaEntryToDict(e);
    expect(d.code).toBe("MCP-001");
    expect(d.title).toBe("Insecure transport");
    expect(d.old_verdict).toBe("warning");
    expect(d.new_verdict).toBe("danger");
    expect(d.severity).toBe("high");
  });
});

describe("DeltaResult", () => {
  function makeDelta(): DeltaResult {
    return new DeltaResult("2026-03-01T00:00:00Z", [
      { change_type: "new", entity_type: "mcp_server", entity_name: "a" },
      { change_type: "new_entity", entity_type: "mcp_server", entity_name: "b" },
      { change_type: "resolved", entity_type: "mcp_server", entity_name: "c" },
      { change_type: "removed_entity", entity_type: "mcp_server", entity_name: "d" },
      { change_type: "changed", entity_type: "mcp_server", entity_name: "e", old_verdict: "safe", new_verdict: "danger" },
      { change_type: "changed", entity_type: "agent", entity_name: "f" },
    ]);
  }

  it("total_new counts 'new' + 'new_entity'", () => {
    expect(makeDelta().total_new).toBe(2);
  });

  it("total_resolved counts 'resolved' + 'removed_entity'", () => {
    expect(makeDelta().total_resolved).toBe(2);
  });

  it("total_changed counts 'changed'", () => {
    expect(makeDelta().total_changed).toBe(2);
  });

  it("empty entries yield zero totals", () => {
    const empty = new DeltaResult("2026-01-01T00:00:00Z");
    expect(empty.total_new).toBe(0);
    expect(empty.total_resolved).toBe(0);
    expect(empty.total_changed).toBe(0);
    expect(empty.entries).toEqual([]);
  });

  it("toDict includes computed fields", () => {
    const d = makeDelta().toDict();
    expect(d.previous_timestamp).toBe("2026-03-01T00:00:00Z");
    expect(d.total_new).toBe(2);
    expect(d.total_resolved).toBe(2);
    expect(d.total_changed).toBe(2);
    expect(d.entries).toHaveLength(6);
    // verify entries are plain objects
    expect(d.entries[0].change_type).toBe("new");
    expect(d.entries[0].entity_name).toBe("a");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// MCP SERVER RESULT — REGISTRY FIELDS
// ═══════════════════════════════════════════════════════════════════════

describe("MCPServerResult registry fields", () => {
  it("accepts optional registry fields", () => {
    const result: MCPServerResult = {
      name: "test-server",
      command: "npx test-server",
      source_file: "/config.json",
      verdict: GuardVerdict.SAFE,
      findings: [],
      registry_score: 85,
      registry_level: "verified",
      registry_findings_count: 2,
    };
    expect(result.registry_score).toBe(85);
    expect(result.registry_level).toBe("verified");
    expect(result.registry_findings_count).toBe(2);
  });

  it("works without registry fields (backward compatible)", () => {
    const result: MCPServerResult = {
      name: "test-server",
      command: "npx test-server",
      source_file: "/config.json",
      verdict: GuardVerdict.SAFE,
      findings: [],
    };
    expect(result.registry_score).toBeUndefined();
    expect(result.registry_level).toBeUndefined();
    expect(result.registry_findings_count).toBeUndefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// GUARD REPORT FROM DICT
// ═══════════════════════════════════════════════════════════════════════

describe("guardReportFromDict", () => {
  it("parses a full report dict", () => {
    const d = {
      timestamp: "2026-03-24T12:00:00Z",
      duration_seconds: 5.5,
      agents_found: [{ name: "Claude Desktop", config_path: "/c", agent_type: "claude-desktop", mcp_servers: 3, skills_count: 0, status: "found" }],
      skill_results: [],
      mcp_results: [
        { name: "s1", command: "npx", source_file: "/f", verdict: "safe", findings: [] },
      ],
      mcp_runtime_results: [],
      toxic_flows: [],
      baseline_changes: [],
      llm_tokens_used: 100,
      unlisted_findings: [
        { code: "GUARD-001", title: "Unlisted", description: "Not registered", severity: "medium", item_name: "x", item_type: "mcp_server" },
      ],
      custom_findings: [
        { code: "C-1", title: "Bad pattern", severity: "high", verdict: "danger", remediation: "Fix it", rule_file: "r.yaml", entity_type: "agent", entity_name: "a1" },
      ],
      config_path: "/project/.agentseal.yaml",
    };
    const report = guardReportFromDict(d);
    expect(report.timestamp).toBe("2026-03-24T12:00:00Z");
    expect(report.duration_seconds).toBe(5.5);
    expect(report.agents_found).toHaveLength(1);
    expect(report.mcp_results).toHaveLength(1);
    expect(report.llm_tokens_used).toBe(100);
    expect(report.unlisted_findings).toHaveLength(1);
    expect(report.unlisted_findings![0].code).toBe("GUARD-001");
    expect(report.custom_findings).toHaveLength(1);
    expect(report.custom_findings![0].severity).toBe("high");
    expect(report.config_path).toBe("/project/.agentseal.yaml");
  });

  it("handles missing optional fields with defaults", () => {
    const report = guardReportFromDict({});
    expect(report.timestamp).toBe("");
    expect(report.duration_seconds).toBe(0);
    expect(report.agents_found).toEqual([]);
    expect(report.skill_results).toEqual([]);
    expect(report.mcp_results).toEqual([]);
    expect(report.mcp_runtime_results).toEqual([]);
    expect(report.toxic_flows).toEqual([]);
    expect(report.baseline_changes).toEqual([]);
    expect(report.llm_tokens_used).toBe(0);
    expect(report.unlisted_findings).toEqual([]);
    expect(report.custom_findings).toEqual([]);
    expect(report.config_path).toBe("");
  });

  it("handles nested registry object in mcp_results", () => {
    const d = {
      mcp_results: [
        {
          name: "s1",
          command: "npx",
          source_file: "/f",
          verdict: "safe",
          findings: [],
          registry: { score: 92, level: "verified", findings_count: 1 },
        },
      ],
    };
    const report = guardReportFromDict(d);
    expect(report.mcp_results[0].registry_score).toBe(92);
    expect(report.mcp_results[0].registry_level).toBe("verified");
    expect(report.mcp_results[0].registry_findings_count).toBe(1);
  });

  it("handles flat registry fields in mcp_results", () => {
    const d = {
      mcp_results: [
        {
          name: "s1",
          command: "npx",
          source_file: "/f",
          verdict: "safe",
          findings: [],
          registry_score: 75,
          registry_level: "basic",
          registry_findings_count: 3,
        },
      ],
    };
    const report = guardReportFromDict(d);
    expect(report.mcp_results[0].registry_score).toBe(75);
    expect(report.mcp_results[0].registry_level).toBe("basic");
    expect(report.mcp_results[0].registry_findings_count).toBe(3);
  });

  it("custom_findings fromDict applies defaults for partial entries", () => {
    const d = {
      custom_findings: [{ code: "C-99" }],
    };
    const report = guardReportFromDict(d);
    expect(report.custom_findings).toHaveLength(1);
    expect(report.custom_findings![0].code).toBe("C-99");
    expect(report.custom_findings![0].severity).toBe("medium");
    expect(report.custom_findings![0].verdict).toBe("warning");
  });
});
