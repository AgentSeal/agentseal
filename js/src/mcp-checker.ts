/**
 * MCP Config Checker — static analysis of MCP server configurations.
 *
 * Reads JSON config dicts and flags dangerous permissions, exposed credentials,
 * and supply chain risks. Does NOT connect to MCP servers.
 *
 * Port of Python agentseal/mcp_checker.py — same checks, same codes.
 */

import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename } from "node:path";
import { GuardVerdict, type MCPFinding, type MCPServerResult } from "./guard-models.js";

// ═══════════════════════════════════════════════════════════════════════
// SENSITIVE PATH DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════

const SENSITIVE_PATHS: Array<[string, string]> = [
  [".ssh", "SSH private keys"],
  [".aws", "AWS credentials"],
  [".gnupg", "GPG private keys"],
  [".config/gh", "GitHub CLI credentials"],
  [".npmrc", "NPM auth tokens"],
  [".pypirc", "PyPI credentials"],
  [".docker", "Docker credentials"],
  [".kube", "Kubernetes credentials"],
  [".netrc", "Network login credentials"],
  [".bitcoin", "Bitcoin wallet"],
  [".ethereum", "Ethereum wallet"],
  ["Library/Keychains", "macOS Keychain"],
  [".gitconfig", "Git credentials"],
  [".clawdbot/.env", "OpenClaw credentials"],
  [".openclaw/.env", "OpenClaw credentials"],
];

const CREDENTIAL_PATTERNS: Array<[RegExp, string]> = [
  [/sk-(?:proj-)?[a-zA-Z0-9]{20,}/, "OpenAI API key"],
  [/sk_live_[a-zA-Z0-9]+/, "Stripe live key"],
  [/sk_test_[a-zA-Z0-9]+/, "Stripe test key"],
  [/AKIA[0-9A-Z]{16}/, "AWS access key"],
  [/ghp_[a-zA-Z0-9]{36}/, "GitHub personal token"],
  [/gho_[a-zA-Z0-9]{36}/, "GitHub OAuth token"],
  [/xoxb-[a-zA-Z0-9-]+/, "Slack bot token"],
  [/xoxp-[a-zA-Z0-9-]+/, "Slack user token"],
  [/glpat-[a-zA-Z0-9_-]{20,}/, "GitLab personal token"],
  [/SG\.[a-zA-Z0-9_-]{22,}/, "SendGrid API key"],
  [/sk-ant-api03-[A-Za-z0-9_-]{90,}/, "Anthropic API key"],
  [/AIza[A-Za-z0-9_-]{35}/, "Google/Gemini API key"],
  [/gsk_[A-Za-z0-9]{20,}/, "Groq API key"],
  [/co-[A-Za-z0-9]{20,}/, "Cohere API key"],
  [/r8_[A-Za-z0-9]{20,}/, "Replicate API token"],
  [/hf_[A-Za-z0-9]{20,}/, "HuggingFace token"],
  [/pcsk_[A-Za-z0-9_-]{20,}/, "Pinecone API key"],
  [/sbp_[a-f0-9]{40,}/, "Supabase token"],
  [/vercel_[A-Za-z0-9_-]{20,}/, "Vercel token"],
  [/fw_[A-Za-z0-9]{20,}/, "Fireworks API key"],
  [/pplx-[a-f0-9]{48,}/, "Perplexity API key"],
  [/SK[a-f0-9]{32}/, "Twilio API key"],
  [/dd[a-z][a-f0-9]{40}/, "Datadog API key"],
  [/el_[A-Za-z0-9]{20,}/, "ElevenLabs API key"],
  [/voyage-[A-Za-z0-9_-]{20,}/, "Voyage AI key"],
  [/tog-[A-Za-z0-9]{20,}/, "Together AI key"],
  [/csk-[A-Za-z0-9]{20,}/, "Cerebras API key"],
  [/v1\.0-[a-f0-9]{24}-[a-f0-9]{64,}/, "Cloudflare API token"],
  [/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, "PEM private key"],
];

const KNOWN_MALICIOUS_PACKAGES = new Set([
  "crossenv", "d3.js", "fabric-js", "ffmepg", "grequsts",
  "http-proxy.js", "mariadb", "mssql-node", "mssql.js",
  "mysqljs", "node-fabric", "node-opencv", "node-opensl",
  "node-openssl", "nodecaffe", "nodefabric", "nodeffmpeg",
  "nodemailer-js", "nodemssql", "noderequest", "nodesass",
  "nodesqlite", "opencv.js", "openssl.js", "proxy.js",
  "shadowsock", "smb", "sqlite.js", "sqliter", "sqlserver",
  "tkinter",
]);

const DANGEROUS_SHELLS = new Set(["bash", "sh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"]);
const SHELL_META = /[;|&`$()]/;
const HTTP_NON_LOCAL = /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])/;

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════

function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq: Record<string, number> = {};
  for (const c of s) {
    freq[c] = (freq[c] ?? 0) + 1;
  }
  const len = s.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function verdictFromFindings(findings: MCPFinding[]): GuardVerdict {
  if (findings.length === 0) return GuardVerdict.SAFE;
  if (findings.some((f) => f.severity === "critical")) return GuardVerdict.DANGER;
  if (findings.some((f) => f.severity === "high" || f.severity === "medium")) return GuardVerdict.WARNING;
  return GuardVerdict.SAFE;
}

// ═══════════════════════════════════════════════════════════════════════
// MCP CONFIG CHECKER
// ═══════════════════════════════════════════════════════════════════════

export class MCPConfigChecker {
  /** Check a single MCP server config dict for security issues. */
  check(server: Record<string, any>): MCPServerResult {
    const name: string = server.name ?? "unknown";
    const command: string = server.command ?? "";
    const args: any[] = server.args ?? [];
    const env: Record<string, any> = server.env ?? {};
    const source: string = server.source_file ?? "";
    const url: string = server.url ?? "";

    const findings: MCPFinding[] = [];

    findings.push(...this._checkSensitivePaths(name, args));
    findings.push(...this._checkEnvCredentials(name, env));
    findings.push(...this._checkBroadAccess(name, args));
    findings.push(...this._checkInsecureUrls(name, args, env));
    if (url) findings.push(...this._checkHttpServer(name, server));
    findings.push(...this._checkSupplyChain(name, command, args));
    findings.push(...this._checkCommandInjection(name, command, args));
    findings.push(...this._checkMissingAuth(name, server));
    findings.push(...this._checkKnownCVEs(name, server));
    findings.push(...this._checkHighEntropySecrets(name, env));

    const verdict = verdictFromFindings(findings);

    return {
      name,
      command: command || url,
      source_file: source,
      verdict,
      findings,
    };
  }

  /** Check multiple MCP server configs. */
  checkAll(servers: Array<Record<string, any>>): MCPServerResult[] {
    return servers.map((s) => this.check(s));
  }

  // ── Individual checks ──────────────────────────────────────────────

  private _checkSensitivePaths(name: string, args: any[]): MCPFinding[] {
    const findings: MCPFinding[] = [];
    const home = homedir();

    const resolvedArgs = args.map((a: string) => {
      try { return realpathSync(a); } catch { return a; }
    });

    for (const arg of resolvedArgs) {
      if (typeof arg !== "string") continue;
      const expanded = arg.startsWith("~") ? home + arg.slice(1) : arg;
      for (const [suffix, description] of SENSITIVE_PATHS) {
        const full = `${home}/${suffix}`;
        if (expanded.includes(full) || arg.includes(suffix)) {
          findings.push({
            code: "MCP-001",
            title: `Access to ${description}`,
            description: `MCP server '${name}' has filesystem access to ${suffix} (${description}). This is a critical security risk.`,
            severity: "critical",
            remediation: `Restrict '${name}' MCP server: remove ${suffix} from allowed paths. It does not need access to ${description}.`,
          });
          break;
        }
      }
    }
    return findings;
  }

  private _checkEnvCredentials(name: string, env: Record<string, any>): MCPFinding[] {
    const findings: MCPFinding[] = [];
    for (const [envKey, envValue] of Object.entries(env)) {
      if (typeof envValue !== "string") continue;
      if (envValue.startsWith("${") || envValue.startsWith("$")) continue;

      for (const [pattern, credType] of CREDENTIAL_PATTERNS) {
        if (pattern.test(envValue)) {
          const redacted = envValue.length > 14
            ? envValue.slice(0, 6) + "..." + envValue.slice(-4)
            : "***";
          findings.push({
            code: "MCP-002",
            title: `Hardcoded ${credType}`,
            description: `MCP server '${name}' has a hardcoded ${credType} in env var ${envKey} (${redacted}). Credentials should not be stored in config files.`,
            severity: "high",
            remediation: `Move ${envKey} for '${name}' to a secrets manager or environment variable. Do not store API keys in MCP config files.`,
          });
          break;
        }
      }
    }
    return findings;
  }

  private _checkBroadAccess(name: string, args: any[]): MCPFinding[] {
    const home = homedir();
    for (const arg of args) {
      if (typeof arg !== "string") continue;
      const expanded = arg.replace("~", home);
      if (expanded === "/" || expanded === home || arg === "~" || arg === "/") {
        return [{
          code: "MCP-003",
          title: "Overly broad filesystem access",
          description: `MCP server '${name}' has access to the entire ${expanded === home ? "home directory" : "filesystem"}. This grants access to all files including credentials.`,
          severity: "high",
          remediation: `Restrict '${name}' to specific project directories only.`,
        }];
      }
    }
    return [];
  }

  private _checkInsecureUrls(name: string, args: any[], env: Record<string, any>): MCPFinding[] {
    const allValues = args.filter((a): a is string => typeof a === "string");
    for (const v of Object.values(env)) {
      if (typeof v === "string") allValues.push(v);
    }

    for (const value of allValues) {
      if (HTTP_NON_LOCAL.test(value)) {
        return [{
          code: "MCP-005",
          title: "Insecure HTTP connection",
          description: `MCP server '${name}' uses an unencrypted HTTP connection. Data sent to this server could be intercepted.`,
          severity: "medium",
          remediation: `Use HTTPS for '${name}' MCP server connections.`,
        }];
      }
    }
    return [];
  }

  private _checkHttpServer(name: string, server: Record<string, any>): MCPFinding[] {
    const findings: MCPFinding[] = [];
    const url: string = server.url ?? "";
    const headers: Record<string, any> = server.headers ?? {};
    const apiKey: string = server.apiKey ?? "";

    if (typeof url === "string" && HTTP_NON_LOCAL.test(url)) {
      findings.push({
        code: "MCP-006",
        title: "Insecure remote MCP endpoint",
        description: `MCP server '${name}' connects to a remote HTTP endpoint without TLS. All JSON-RPC traffic can be intercepted.`,
        severity: "critical",
        remediation: `Use HTTPS for remote MCP server '${name}': change ${url} to use https://`,
      });
    }

    if (typeof apiKey === "string" && apiKey && !apiKey.startsWith("${")) {
      for (const [pattern, credType] of CREDENTIAL_PATTERNS) {
        if (pattern.test(apiKey)) {
          const redacted = apiKey.length > 14 ? apiKey.slice(0, 6) + "..." + apiKey.slice(-4) : "***";
          findings.push({
            code: "MCP-006",
            title: `Hardcoded ${credType} in apiKey`,
            description: `MCP server '${name}' has a hardcoded ${credType} in apiKey field (${redacted}). Use environment variable references.`,
            severity: "high",
            remediation: `Move apiKey for '${name}' to a secrets manager or env var reference.`,
          });
          break;
        }
      }
    }

    if (typeof headers === "object" && headers !== null) {
      const authVal = headers.Authorization ?? "";
      if (typeof authVal === "string" && authVal && !authVal.startsWith("${")) {
        for (const [pattern, credType] of CREDENTIAL_PATTERNS) {
          if (pattern.test(authVal)) {
            findings.push({
              code: "MCP-006",
              title: `Hardcoded ${credType} in Authorization header`,
              description: `MCP server '${name}' has a hardcoded credential in the Authorization header. Use environment variable references.`,
              severity: "high",
              remediation: `Move Authorization header for '${name}' to env var reference.`,
            });
            break;
          }
        }
      }
    }

    return findings;
  }

  private _checkSupplyChain(name: string, command: string, args: any[]): MCPFinding[] {
    const findings: MCPFinding[] = [];
    const allStr = [command, ...args.filter((a): a is string => typeof a === "string")].join(" ");

    // npx -y package without @version
    const npxMatch = allStr.match(/npx\s+-y\s+(@?[a-zA-Z0-9_./-]+(?:@[^\s]+)?)/);
    if (npxMatch) {
      const pkg = npxMatch[1]!;
      const parts = pkg.split("/");
      const lastPart = parts[parts.length - 1] ?? pkg;
      const hasVersion = lastPart.includes("@") && !lastPart.startsWith("@");
      if (!hasVersion) {
        findings.push({
          code: "MCP-007",
          title: "Unpinned npx package",
          description: `MCP server '${name}' installs '${pkg}' via npx without version pinning. A supply chain attack could inject malicious code.`,
          severity: "high",
          remediation: `Pin the version: npx -y ${pkg}@<version>`,
        });
      }
    }

    // uvx package without ==version
    const uvxMatch = allStr.match(/uvx\s+([a-zA-Z0-9_.-]+)/);
    if (uvxMatch) {
      const pkg = uvxMatch[1]!;
      const afterPkg = allStr.split(pkg).slice(1).join("").slice(0, 20);
      if (!afterPkg.includes("==")) {
        findings.push({
          code: "MCP-007",
          title: "Unpinned uvx package",
          description: `MCP server '${name}' installs '${pkg}' via uvx without version pinning.`,
          severity: "high",
          remediation: `Pin the version: uvx ${pkg}==<version>`,
        });
      }
    }

    // bunx package without @version
    const bunxMatch = allStr.match(/bunx\s+(@?[a-zA-Z0-9_./-]+(?:@[^\s]+)?)/);
    if (bunxMatch) {
      const pkg = bunxMatch[1]!;
      const parts = pkg.split("/");
      const lastPart = parts[parts.length - 1] ?? pkg;
      const hasVersion = lastPart.includes("@") && !lastPart.startsWith("@");
      if (!hasVersion) {
        findings.push({
          code: "MCP-007",
          title: "Unpinned bunx package",
          description: `MCP server '${name}' installs '${pkg}' via bunx without version pinning. A supply chain attack could inject malicious code.`,
          severity: "medium",
          remediation: `Pin the version: bunx ${pkg}@<version>`,
        });
      }
    }

    // deno run without @version
    const denoMatch = allStr.match(/deno\s+run\s+(?:--allow-\S+\s+)*(\S+)/);
    if (denoMatch) {
      const target = denoMatch[1]!;
      if (!target.startsWith(".") && !target.startsWith("/")) {
        if (!target.includes("@")) {
          findings.push({
            code: "MCP-007",
            title: "Unpinned deno package",
            description: `MCP server '${name}' runs '${target}' via deno without version pinning.`,
            severity: "medium",
            remediation: `Pin the version: deno run ${target}@<version>`,
          });
        }
      }
    }

    // docker run without tag or with :latest
    const dockerMatch = allStr.match(/docker\s+run\s+(?:-[^\s]+\s+)*([a-zA-Z0-9_./-]+(?::[^\s]+)?)/);
    if (dockerMatch) {
      const image = dockerMatch[1]!;
      if (!image.includes(":")) {
        findings.push({
          code: "MCP-007",
          title: "Unpinned docker image",
          description: `MCP server '${name}' runs docker image '${image}' without a tag. This defaults to :latest which is mutable.`,
          severity: "medium",
          remediation: `Pin the image tag: docker run ${image}:<version>`,
        });
      } else if (image.endsWith(":latest")) {
        findings.push({
          code: "MCP-007",
          title: "Unpinned docker image (:latest)",
          description: `MCP server '${name}' runs docker image '${image}' with :latest tag. This is mutable and not reproducible.`,
          severity: "medium",
          remediation: `Pin a specific image tag instead of :latest`,
        });
      }
    }

    // pip install without ==version
    const pipMatch = allStr.match(/pip3?\s+install\s+([a-zA-Z0-9_.-]+)/);
    if (pipMatch) {
      const pkg = pipMatch[1]!;
      if (!pkg.startsWith("-")) {
        const afterPkg = allStr.split(pipMatch[0]!).slice(1).join("").slice(0, 30);
        if (!afterPkg.includes("==")) {
          findings.push({
            code: "MCP-007",
            title: "Unpinned pip package",
            description: `MCP server '${name}' installs '${pkg}' via pip without version pinning.`,
            severity: "medium",
            remediation: `Pin the version: pip install ${pkg}==<version>`,
          });
        }
      }
    }

    // go run without @version
    const goMatch = allStr.match(/go\s+run\s+([a-zA-Z0-9_./@-]+)/);
    if (goMatch) {
      const target = goMatch[1]!;
      if (!target.startsWith(".") && !target.startsWith("/")) {
        if (!target.includes("@")) {
          findings.push({
            code: "MCP-007",
            title: "Unpinned go package",
            description: `MCP server '${name}' runs '${target}' via go run without version pinning.`,
            severity: "medium",
            remediation: `Pin the version: go run ${target}@<version>`,
          });
        }
      }
    }

    // Known malicious packages
    const allArgs = [command, ...args.filter((a): a is string => typeof a === "string")];
    for (const arg of allArgs) {
      for (const pkgName of KNOWN_MALICIOUS_PACKAGES) {
        if (arg.toLowerCase().includes(pkgName)) {
          findings.push({
            code: "MCP-007",
            title: `Known malicious package: ${pkgName}`,
            description: `MCP server '${name}' references known malicious package '${pkgName}'.`,
            severity: "critical",
            remediation: `Remove MCP server '${name}' immediately.`,
          });
          return findings;
        }
      }
    }

    return findings;
  }

  private _checkCommandInjection(name: string, command: string, args: any[]): MCPFinding[] {
    const findings: MCPFinding[] = [];
    const cmdBase = basename(command).toLowerCase();

    if (DANGEROUS_SHELLS.has(cmdBase)) {
      findings.push({
        code: "MCP-008",
        title: "Shell binary as MCP server",
        description: `MCP server '${name}' uses '${cmdBase}' as its binary. This allows arbitrary command execution.`,
        severity: "critical",
        remediation: `Replace shell command for '${name}' with a dedicated MCP server binary.`,
      });
    }

    for (const arg of args) {
      if (typeof arg === "string" && SHELL_META.test(arg)) {
        findings.push({
          code: "MCP-008",
          title: "Shell metacharacters in arguments",
          description: `MCP server '${name}' has shell metacharacters in args: '${arg.slice(0, 60)}'. This may allow command injection.`,
          severity: "high",
          remediation: `Remove shell metacharacters from '${name}' arguments.`,
        });
        break;
      }
    }

    return findings;
  }

  private _checkMissingAuth(name: string, server: Record<string, any>): MCPFinding[] {
    const url = server.url;
    if (!url || typeof url !== "string") return [];

    const localhostPattern = /^https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])/;
    if (localhostPattern.test(url)) return [];

    const hasApiKey = Boolean(server.apiKey);
    const headers = server.headers;
    const hasAuthHeader = typeof headers === "object" && headers !== null && Boolean(headers.Authorization);
    const hasOAuth = Boolean(server.oauth || server.auth);

    if (!hasApiKey && !hasAuthHeader && !hasOAuth) {
      return [{
        code: "MCP-009",
        title: "Missing authentication",
        description: `Remote MCP server '${name}' at ${url} has no authentication configured. Anyone who discovers the endpoint can use it.`,
        severity: "high",
        remediation: `Add apiKey, Authorization header, or OAuth config for '${name}'.`,
      }];
    }
    return [];
  }

  private _checkKnownCVEs(name: string, server: Record<string, any>): MCPFinding[] {
    const findings: MCPFinding[] = [];
    const command: string = server.command ?? "";
    const args: any[] = server.args ?? [];
    const source: string = server.source_file ?? "";
    const allArgsStr = args.filter((a): a is string => typeof a === "string").join(" ");

    // CVE-2025-53110: Path traversal
    for (const arg of args) {
      if (typeof arg === "string" && arg.includes("../")) {
        findings.push({
          code: "MCP-CVE",
          title: "CVE-2025-53110: Path traversal in arguments",
          description: `MCP server '${name}' has path traversal sequence '../' in arguments.`,
          severity: "high",
          remediation: "Remove path traversal sequences from MCP server arguments.",
        });
        break;
      }
    }

    // CVE-2025-68143: Unrestricted git MCP
    const isGitServer = /\bgit\b/.test(command.toLowerCase()) || /server-git|mcp-git/.test(allArgsStr.toLowerCase());
    if (isGitServer && !args.some((a) => typeof a === "string" && (a.includes("--allowed") || a.toLowerCase().includes("path")))) {
      findings.push({
        code: "MCP-CVE",
        title: "CVE-2025-68143: Unrestricted git MCP server",
        description: `Git MCP server '${name}' has no path restrictions configured. It can access any repository on the machine.`,
        severity: "high",
        remediation: `Add --allowed-path restrictions to git MCP server '${name}'.`,
      });
    }

    // CVE-2025-59536: Project .mcp.json
    if (source && basename(source) === ".mcp.json") {
      findings.push({
        code: "MCP-CVE",
        title: "CVE-2025-59536: Project-level MCP config",
        description: `MCP server '${name}' is defined in a project-level .mcp.json file. Cloning a malicious repo could auto-register MCP servers.`,
        severity: "medium",
        remediation: "Review project-level MCP configs carefully. Consider using global configs only.",
      });
    }

    // CVE-2025-6514: mcp-remote
    if (command.includes("mcp-remote") || allArgsStr.includes("mcp-remote")) {
      findings.push({
        code: "MCP-CVE",
        title: "CVE-2025-6514: mcp-remote OAuth vulnerability",
        description: `MCP server '${name}' uses mcp-remote which has known OAuth vulnerabilities.`,
        severity: "medium",
        remediation: "Update mcp-remote to the latest version or use direct SSE connections.",
      });
    }

    return findings;
  }

  private _checkHighEntropySecrets(name: string, env: Record<string, any>): MCPFinding[] {
    const findings: MCPFinding[] = [];
    for (const [envKey, envValue] of Object.entries(env)) {
      if (typeof envValue !== "string" || envValue.length < 20) continue;
      if (envValue.startsWith("${") || envValue.startsWith("$")) continue;

      // Skip if already matched by explicit patterns
      let matched = false;
      for (const [pattern] of CREDENTIAL_PATTERNS) {
        if (pattern.test(envValue)) {
          matched = true;
          break;
        }
      }
      if (matched) continue;

      const entropy = shannonEntropy(envValue);
      if (entropy > 4.5) {
        const redacted = envValue.length > 12
          ? envValue.slice(0, 4) + "..." + envValue.slice(-4)
          : "***";
        findings.push({
          code: "MCP-002",
          title: `High-entropy secret in ${envKey}`,
          description: `MCP server '${name}' has a high-entropy string in env var ${envKey} (${redacted}, entropy=${entropy.toFixed(1)}). This may be a credential from an unknown provider.`,
          severity: "medium",
          remediation: `Move ${envKey} for '${name}' to a secrets manager or env var reference.`,
        });
      }
    }
    return findings;
  }
}

// Re-export for convenience
export { shannonEntropy, verdictFromFindings };
