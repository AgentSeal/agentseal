import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";

// Mock fetch before imports
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

import {
  slugify,
  extractPackageSlug,
  bulkCheck,
  enrichMcpResults,
} from "../src/registry-client.js";
import type { MCPServerResult } from "../src/guard-models.js";
import { GuardVerdict } from "../src/guard-models.js";

// ═══════════════════════════════════════════════════════════════════════
// slugify
// ═══════════════════════════════════════════════════════════════════════

describe("slugify", () => {
  it("converts @scope/pkg to scope-pkg", () => {
    expect(slugify("@anthropic/filesystem")).toBe("anthropic-filesystem");
  });

  it("replaces underscores with dashes", () => {
    expect(slugify("my_tool")).toBe("my-tool");
  });

  it("leaves already-slugified names unchanged", () => {
    expect(slugify("my-server")).toBe("my-server");
  });

  it("lowercases names", () => {
    expect(slugify("MyTool")).toBe("mytool");
  });

  it("handles multiple special characters", () => {
    expect(slugify("my tool!v2")).toBe("my-tool-v2");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// extractPackageSlug
// ═══════════════════════════════════════════════════════════════════════

describe("extractPackageSlug", () => {
  it("extracts npx @scope/pkg", () => {
    expect(extractPackageSlug("npx @anthropic/server-filesystem")).toBe("anthropic-server-filesystem");
  });

  it("extracts npx -y @scope/pkg", () => {
    expect(extractPackageSlug("npx -y @modelcontextprotocol/server-fs")).toBe(
      "modelcontextprotocol-server-fs",
    );
  });

  it("extracts bunx pkg", () => {
    expect(extractPackageSlug("bunx my-server")).toBe("my-server");
  });

  it("extracts uvx pkg", () => {
    expect(extractPackageSlug("uvx mcp-tool")).toBe("mcp-tool");
  });

  it("extracts pip install pkg", () => {
    expect(extractPackageSlug("pip install my_package")).toBe("my-package");
  });

  it("extracts pip3 install pkg", () => {
    expect(extractPackageSlug("pip3 install my_package")).toBe("my-package");
  });

  it("extracts docker run img", () => {
    expect(extractPackageSlug("docker run my-image")).toBe("my-image");
  });

  it("returns null for bare binary", () => {
    expect(extractPackageSlug("/usr/bin/myserver")).toBeNull();
  });

  it("returns null for empty string", () => {
    expect(extractPackageSlug("")).toBeNull();
  });

  it("strips @version suffix", () => {
    expect(extractPackageSlug("npx @scope/pkg@1.2.3")).toBe("scope-pkg");
  });

  it("strips version from non-scoped pkg", () => {
    expect(extractPackageSlug("npx my-tool@latest")).toBe("my-tool");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// bulkCheck
// ═══════════════════════════════════════════════════════════════════════

describe("bulkCheck", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("returns parsed data on success", async () => {
    const responseData = {
      "my-server": { score: 85, level: "high", findings_count: 0 },
    };
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => responseData,
    });

    const result = await bulkCheck(["my-server"]);
    expect(result).toEqual(responseData);
    expect(mockFetch).toHaveBeenCalledOnce();

    const [url, opts] = mockFetch.mock.calls[0]!;
    expect(url).toBe("https://agentseal.org/api/v1/mcp/intel/bulk-check");
    expect(opts.method).toBe("POST");
    expect(opts.headers["Content-Type"]).toBe("application/json");
    expect(opts.headers["User-Agent"]).toBe("agentseal-guard/0.8");
    expect(JSON.parse(opts.body)).toEqual({ slugs: ["my-server"] });
  });

  it("returns {} on timeout / abort", async () => {
    mockFetch.mockRejectedValueOnce(new DOMException("Aborted", "AbortError"));
    const result = await bulkCheck(["test"]);
    expect(result).toEqual({});
  });

  it("returns {} on network error", async () => {
    mockFetch.mockRejectedValueOnce(new Error("fetch failed"));
    const result = await bulkCheck(["test"]);
    expect(result).toEqual({});
  });

  it("returns {} for empty slugs array", async () => {
    const result = await bulkCheck([]);
    expect(result).toEqual({});
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("deduplicates slugs", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({}),
    });

    await bulkCheck(["a", "b", "a"]);
    const body = JSON.parse(mockFetch.mock.calls[0]![1].body);
    expect(body.slugs).toHaveLength(2);
    expect(body.slugs).toContain("a");
    expect(body.slugs).toContain("b");
  });

  it("sends Authorization header when apiKey provided", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({}),
    });

    await bulkCheck(["test"], "my-key-123");
    const headers = mockFetch.mock.calls[0]![1].headers;
    expect(headers["Authorization"]).toBe("Bearer my-key-123");
  });

  it("returns {} on non-ok response", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
    });
    const result = await bulkCheck(["test"]);
    expect(result).toEqual({});
  });
});

// ═══════════════════════════════════════════════════════════════════════
// enrichMcpResults
// ═══════════════════════════════════════════════════════════════════════

function makeMcpResult(overrides: Partial<MCPServerResult> = {}): MCPServerResult {
  return {
    name: "test-server",
    command: "npx -y @scope/test-server",
    source_file: "/config.json",
    verdict: GuardVerdict.SAFE,
    findings: [],
    ...overrides,
  };
}

describe("enrichMcpResults", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("sets registry fields on matching results", async () => {
    const results = [makeMcpResult({ name: "my-server", command: "npx my-server" })];

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        "my-server": { score: 72, level: "medium", findings_count: 3 },
      }),
    });

    await enrichMcpResults(results);

    expect(results[0]!.registry_score).toBe(72);
    expect(results[0]!.registry_level).toBe("medium");
    expect(results[0]!.registry_findings_count).toBe(3);
  });

  it("skips results that already have registry_score", async () => {
    const results = [
      makeMcpResult({
        name: "my-server",
        command: "npx my-server",
        registry_score: 90,
        registry_level: "high",
        registry_findings_count: 0,
      }),
    ];

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        "my-server": { score: 50, level: "low", findings_count: 5 },
      }),
    });

    await enrichMcpResults(results);

    // Should keep original values
    expect(results[0]!.registry_score).toBe(90);
    expect(results[0]!.registry_level).toBe("high");
    expect(results[0]!.registry_findings_count).toBe(0);
  });

  it("handles empty results array", async () => {
    await enrichMcpResults([]);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("handles no matches from registry", async () => {
    const results = [makeMcpResult({ name: "unknown-server", command: "npx unknown-server" })];

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({}),
    });

    await enrichMcpResults(results);

    expect(results[0]!.registry_score).toBeUndefined();
    expect(results[0]!.registry_level).toBeUndefined();
  });

  it("enriches via command slug when name slug has no match", async () => {
    const results = [
      makeMcpResult({
        name: "filesystem",
        command: "npx -y @modelcontextprotocol/server-filesystem",
      }),
    ];

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        "modelcontextprotocol-server-filesystem": {
          score: 95,
          level: "excellent",
          findings_count: 0,
        },
      }),
    });

    await enrichMcpResults(results);

    expect(results[0]!.registry_score).toBe(95);
    expect(results[0]!.registry_level).toBe("excellent");
  });
});
