import { describe, it, expect } from "vitest";
import { MCPConfigChecker, shannonEntropy } from "../src/mcp-checker.js";
import { GuardVerdict } from "../src/guard-models.js";

const checker = new MCPConfigChecker();

// ═══════════════════════════════════════════════════════════════════════
// MCP-001: Sensitive paths
// ═══════════════════════════════════════════════════════════════════════

describe("MCP-001: Sensitive paths", () => {
  it("flags .ssh access", () => {
    const result = checker.check({
      name: "fs-server",
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem", "~/.ssh"],
    });
    expect(result.findings.some((f) => f.code === "MCP-001")).toBe(true);
    expect(result.verdict).toBe(GuardVerdict.DANGER);
  });

  it("flags .aws access", () => {
    const result = checker.check({
      name: "fs-server",
      command: "npx",
      args: ["-y", "server", "~/.aws"],
    });
    expect(result.findings.some((f) => f.code === "MCP-001")).toBe(true);
  });

  it("passes clean paths", () => {
    const result = checker.check({
      name: "safe",
      command: "npx",
      args: ["-y", "server", "/Users/test/projects/myapp"],
    });
    expect(result.findings.filter((f) => f.code === "MCP-001")).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// MCP-002: Env credentials
// ═══════════════════════════════════════════════════════════════════════

describe("MCP-002: Env credentials", () => {
  it("flags hardcoded OpenAI key", () => {
    const result = checker.check({
      name: "ai-server",
      command: "node",
      env: { OPENAI_API_KEY: "sk-proj-abcdefghijklmnopqrstuvwx" },
    });
    expect(result.findings.some((f) => f.code === "MCP-002")).toBe(true);
  });

  it("flags hardcoded AWS key", () => {
    const result = checker.check({
      name: "aws",
      command: "node",
      env: { AWS_KEY: "AKIAIOSFODNN7EXAMPLE" },
    });
    expect(result.findings.some((f) => f.code === "MCP-002")).toBe(true);
  });

  it("passes env var references", () => {
    const result = checker.check({
      name: "safe",
      command: "node",
      env: { API_KEY: "${OPENAI_API_KEY}" },
    });
    expect(result.findings.filter((f) => f.code === "MCP-002")).toHaveLength(0);
  });

  it("passes $VAR references", () => {
    const result = checker.check({
      name: "safe",
      command: "node",
      env: { API_KEY: "$OPENAI_API_KEY" },
    });
    expect(result.findings.filter((f) => f.code === "MCP-002")).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// MCP-003: Broad access
// ═══════════════════════════════════════════════════════════════════════

describe("MCP-003: Broad access", () => {
  it("flags root access", () => {
    const result = checker.check({ name: "fs", command: "npx", args: ["/"] });
    expect(result.findings.some((f) => f.code === "MCP-003")).toBe(true);
  });

  it("flags ~ access", () => {
    const result = checker.check({ name: "fs", command: "npx", args: ["~"] });
    expect(result.findings.some((f) => f.code === "MCP-003")).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// MCP-005: Insecure HTTP
// ═══════════════════════════════════════════════════════════════════════

describe("MCP-005: Insecure HTTP", () => {
  it("flags HTTP URL in args", () => {
    const result = checker.check({
      name: "remote",
      command: "node",
      args: ["http://evil.com/api"],
    });
    expect(result.findings.some((f) => f.code === "MCP-005")).toBe(true);
  });

  it("passes localhost HTTP", () => {
    const result = checker.check({
      name: "local",
      command: "node",
      args: ["http://localhost:8080"],
    });
    expect(result.findings.filter((f) => f.code === "MCP-005")).toHaveLength(0);
  });

  it("passes HTTPS", () => {
    const result = checker.check({
      name: "secure",
      command: "node",
      args: ["https://api.example.com"],
    });
    expect(result.findings.filter((f) => f.code === "MCP-005")).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// MCP-006: HTTP server
// ═══════════════════════════════════════════════════════════════════════

describe("MCP-006: HTTP server", () => {
  it("flags insecure remote endpoint", () => {
    const result = checker.check({
      name: "remote",
      command: "",
      url: "http://api.evil.com/mcp",
    });
    expect(result.findings.some((f) => f.code === "MCP-006" && f.severity === "critical")).toBe(true);
  });

  it("flags hardcoded API key in apiKey field", () => {
    const result = checker.check({
      name: "remote",
      command: "",
      url: "https://api.example.com",
      apiKey: "sk-proj-abcdefghijklmnopqrstuvwx",
    });
    expect(result.findings.some((f) => f.code === "MCP-006" && f.title.includes("apiKey"))).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// MCP-007: Supply chain
// ═══════════════════════════════════════════════════════════════════════

describe("MCP-007: Supply chain", () => {
  it("flags unpinned npx package", () => {
    const result = checker.check({
      name: "fs",
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem"],
    });
    expect(result.findings.some((f) => f.code === "MCP-007")).toBe(true);
  });

  it("passes pinned npx package", () => {
    const result = checker.check({
      name: "fs",
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem@1.0.0"],
    });
    expect(result.findings.filter((f) => f.code === "MCP-007")).toHaveLength(0);
  });

  it("flags known malicious package", () => {
    const result = checker.check({
      name: "evil",
      command: "npx",
      args: ["-y", "crossenv"],
    });
    const finding = result.findings.find((f) => f.code === "MCP-007" && f.severity === "critical");
    expect(finding).toBeDefined();
  });

  it("flags unpinned uvx package", () => {
    const result = checker.check({
      name: "py",
      command: "uvx",
      args: ["mcp-server-git"],
    });
    expect(result.findings.some((f) => f.code === "MCP-007")).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// MCP-008: Command injection
// ═══════════════════════════════════════════════════════════════════════

describe("MCP-008: Command injection", () => {
  it("flags bash as server command", () => {
    const result = checker.check({
      name: "shell",
      command: "bash",
      args: ["-c", "echo hello"],
    });
    expect(result.findings.some((f) => f.code === "MCP-008" && f.severity === "critical")).toBe(true);
    expect(result.verdict).toBe(GuardVerdict.DANGER);
  });

  it("flags shell metacharacters in args", () => {
    const result = checker.check({
      name: "inject",
      command: "node",
      args: ["server.js", "; rm -rf /"],
    });
    expect(result.findings.some((f) => f.code === "MCP-008")).toBe(true);
  });

  it("passes normal args", () => {
    const result = checker.check({
      name: "safe",
      command: "node",
      args: ["server.js", "--port", "3000"],
    });
    expect(result.findings.filter((f) => f.code === "MCP-008")).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// MCP-009: Missing auth
// ═══════════════════════════════════════════════════════════════════════

describe("MCP-009: Missing auth", () => {
  it("flags remote server without auth", () => {
    const result = checker.check({
      name: "remote",
      command: "",
      url: "https://api.example.com/mcp",
    });
    expect(result.findings.some((f) => f.code === "MCP-009")).toBe(true);
  });

  it("passes with apiKey", () => {
    const result = checker.check({
      name: "remote",
      command: "",
      url: "https://api.example.com/mcp",
      apiKey: "${MY_KEY}",
    });
    expect(result.findings.filter((f) => f.code === "MCP-009")).toHaveLength(0);
  });

  it("passes localhost without auth", () => {
    const result = checker.check({
      name: "local",
      command: "",
      url: "http://localhost:3000",
    });
    expect(result.findings.filter((f) => f.code === "MCP-009")).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// MCP-CVE: Known CVEs
// ═══════════════════════════════════════════════════════════════════════

describe("MCP-CVE: Known CVEs", () => {
  it("flags path traversal in args", () => {
    const result = checker.check({
      name: "fs",
      command: "node",
      args: ["--path", "../../etc/passwd"],
    });
    expect(result.findings.some((f) => f.code === "MCP-CVE" && f.title.includes("53110"))).toBe(true);
  });

  it("flags unrestricted git MCP", () => {
    const result = checker.check({
      name: "git",
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-git"],
    });
    expect(result.findings.some((f) => f.code === "MCP-CVE" && f.title.includes("68143"))).toBe(true);
  });

  it("passes restricted git MCP", () => {
    const result = checker.check({
      name: "git",
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-git", "--allowed-path", "/repo"],
    });
    expect(result.findings.filter((f) => f.title.includes("68143"))).toHaveLength(0);
  });

  it("flags project-level .mcp.json", () => {
    const result = checker.check({
      name: "fs",
      command: "node",
      source_file: "/path/to/project/.mcp.json",
    });
    expect(result.findings.some((f) => f.title.includes("59536"))).toBe(true);
  });

  it("flags mcp-remote usage", () => {
    const result = checker.check({
      name: "remote",
      command: "npx",
      args: ["-y", "mcp-remote", "https://example.com"],
    });
    expect(result.findings.some((f) => f.title.includes("6514"))).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// High entropy
// ═══════════════════════════════════════════════════════════════════════

describe("High entropy secrets", () => {
  it("flags high-entropy env values", () => {
    const result = checker.check({
      name: "server",
      command: "node",
      env: { UNKNOWN_KEY: "aB3$kL9mNpQ2rStUvWxYz1234567890" },
    });
    expect(result.findings.some((f) => f.description.includes("entropy"))).toBe(true);
  });

  it("passes low-entropy values", () => {
    const result = checker.check({
      name: "server",
      command: "node",
      env: { MODE: "production-environment-setting" },
    });
    // "production-environment-setting" has low entropy
    expect(result.findings.filter((f) => f.description.includes("entropy"))).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Shannon entropy helper
// ═══════════════════════════════════════════════════════════════════════

describe("shannonEntropy", () => {
  it("returns 0 for empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("returns 0 for single char repeated", () => {
    expect(shannonEntropy("aaaa")).toBe(0);
  });

  it("returns higher entropy for random-looking strings", () => {
    const low = shannonEntropy("aaaaaaa");
    const high = shannonEntropy("aB3$kL9m");
    expect(high).toBeGreaterThan(low);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// checkAll
// ═══════════════════════════════════════════════════════════════════════

describe("checkAll", () => {
  it("checks multiple servers", () => {
    const results = checker.checkAll([
      { name: "safe", command: "node", args: ["server.js"] },
      { name: "evil", command: "bash", args: ["-c", "echo pwned"] },
    ]);
    expect(results).toHaveLength(2);
    expect(results[0]!.verdict).toBe(GuardVerdict.SAFE);
    expect(results[1]!.verdict).toBe(GuardVerdict.DANGER);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Edge cases
// ═══════════════════════════════════════════════════════════════════════

describe("Edge cases", () => {
  it("handles empty server config", () => {
    const result = checker.check({});
    expect(result.name).toBe("unknown");
    expect(result.verdict).toBe(GuardVerdict.SAFE);
  });

  it("handles non-string args gracefully", () => {
    const result = checker.check({
      name: "test",
      command: "node",
      args: [123, null, undefined, "valid"],
    });
    // Should not throw
    expect(result.name).toBe("test");
  });

  it("handles missing env gracefully", () => {
    const result = checker.check({
      name: "test",
      command: "node",
    });
    expect(result.name).toBe("test");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// MCP-007: Supply chain — bunx, deno, docker, pip, go
// ═══════════════════════════════════════════════════════════════════════

describe("supply chain - bunx", () => {
  it("detects unpinned bunx package", () => {
    const result = checker.check({ name: "t", command: "bunx", args: ["@scope/pkg"], source_file: "f" });
    expect(result.findings.some((f: any) => f.code === "MCP-007")).toBe(true);
  });

  it("passes pinned bunx package", () => {
    const result = checker.check({ name: "t", command: "bunx", args: ["@scope/pkg@1.2.3"], source_file: "f" });
    expect(result.findings.filter((f: any) => f.code === "MCP-007" && f.title.includes("bunx"))).toHaveLength(0);
  });
});

describe("supply chain - deno", () => {
  it("detects unpinned deno run", () => {
    const result = checker.check({ name: "t", command: "deno", args: ["run", "--allow-net", "npm:express"], source_file: "f" });
    expect(result.findings.some((f: any) => f.code === "MCP-007" && f.title.includes("deno"))).toBe(true);
  });

  it("skips local deno run path", () => {
    const result = checker.check({ name: "t", command: "deno", args: ["run", "./main.ts"], source_file: "f" });
    expect(result.findings.filter((f: any) => f.title.includes("deno"))).toHaveLength(0);
  });
});

describe("supply chain - docker", () => {
  it("detects docker image with :latest tag", () => {
    const result = checker.check({ name: "t", command: "docker", args: ["run", "myimage:latest"], source_file: "f" });
    expect(result.findings.some((f: any) => f.code === "MCP-007" && f.title.includes("docker"))).toBe(true);
  });

  it("detects docker image with no tag", () => {
    const result = checker.check({ name: "t", command: "docker", args: ["run", "myimage"], source_file: "f" });
    expect(result.findings.some((f: any) => f.code === "MCP-007" && f.title.includes("docker"))).toBe(true);
  });

  it("passes docker image with specific tag", () => {
    const result = checker.check({ name: "t", command: "docker", args: ["run", "myimage:1.2.3"], source_file: "f" });
    expect(result.findings.filter((f: any) => f.title.includes("docker"))).toHaveLength(0);
  });
});

describe("supply chain - pip", () => {
  it("detects unpinned pip install", () => {
    const result = checker.check({ name: "t", command: "pip", args: ["install", "requests"], source_file: "f" });
    expect(result.findings.some((f: any) => f.code === "MCP-007" && f.title.includes("pip"))).toBe(true);
  });

  it("passes pinned pip install", () => {
    const result = checker.check({ name: "t", command: "pip", args: ["install", "requests==2.31.0"], source_file: "f" });
    expect(result.findings.filter((f: any) => f.title.includes("pip"))).toHaveLength(0);
  });
});

describe("supply chain - go", () => {
  it("detects unpinned go run", () => {
    const result = checker.check({ name: "t", command: "go", args: ["run", "github.com/user/tool"], source_file: "f" });
    expect(result.findings.some((f: any) => f.code === "MCP-007" && f.title.includes("go"))).toBe(true);
  });

  it("passes pinned go run", () => {
    const result = checker.check({ name: "t", command: "go", args: ["run", "github.com/user/tool@v1.0.0"], source_file: "f" });
    expect(result.findings.filter((f: any) => f.title.includes("go"))).toHaveLength(0);
  });

  it("skips local go run path", () => {
    const result = checker.check({ name: "t", command: "go", args: ["run", "./cmd/server"], source_file: "f" });
    expect(result.findings.filter((f: any) => f.title.includes("go"))).toHaveLength(0);
  });
});
