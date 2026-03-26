# agentseal/mcp_checker.py
"""
MCP Config Checker — static analysis of MCP server configurations.

Reads JSON config files and flags dangerous permissions, exposed credentials,
and unsigned binaries. Does NOT connect to MCP servers (that's Phase 2).
Fast and safe: no network, no process spawning (except macOS codesign check).
"""

import logging
import math
import os
import platform
import re
import stat
import subprocess
from pathlib import Path
from typing import Optional

from agentseal.detection.fs_safety import check_case_sensitivity_risk
from agentseal.guard_models import GuardVerdict, MCPFinding, MCPServerResult

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# SENSITIVE PATH DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════

_SENSITIVE_PATHS: list[tuple[str, str]] = [
    (".ssh", "SSH private keys"),
    (".aws", "AWS credentials"),
    (".gnupg", "GPG private keys"),
    (".config/gh", "GitHub CLI credentials"),
    (".npmrc", "NPM auth tokens"),
    (".pypirc", "PyPI credentials"),
    (".docker", "Docker credentials"),
    (".kube", "Kubernetes credentials"),
    (".netrc", "Network login credentials"),
    (".bitcoin", "Bitcoin wallet"),
    (".ethereum", "Ethereum wallet"),
    ("Library/Keychains", "macOS Keychain"),
    (".gitconfig", "Git credentials"),
    (".clawdbot/.env", "OpenClaw credentials"),
    (".openclaw/.env", "OpenClaw credentials"),
]

_CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"sk-(?:proj-)?[a-zA-Z0-9]{20,}"), "OpenAI API key"),
    (re.compile(r"sk_live_[a-zA-Z0-9]+"), "Stripe live key"),
    (re.compile(r"sk_test_[a-zA-Z0-9]+"), "Stripe test key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub personal token"),
    (re.compile(r"gho_[a-zA-Z0-9]{36}"), "GitHub OAuth token"),
    (re.compile(r"xoxb-[a-zA-Z0-9-]+"), "Slack bot token"),
    (re.compile(r"xoxp-[a-zA-Z0-9-]+"), "Slack user token"),
    (re.compile(r"glpat-[a-zA-Z0-9_-]{20,}"), "GitLab personal token"),
    (re.compile(r"SG\.[a-zA-Z0-9_-]{22,}"), "SendGrid API key"),
    # ── Extended credential patterns (GAP 4) ──────────────────────
    (re.compile(r"sk-ant-api03-[A-Za-z0-9_-]{90,}"), "Anthropic API key"),
    (re.compile(r"AIza[A-Za-z0-9_-]{35}"), "Google/Gemini API key"),
    (re.compile(r"gsk_[A-Za-z0-9]{20,}"), "Groq API key"),
    (re.compile(r"co-[A-Za-z0-9]{20,}"), "Cohere API key"),
    (re.compile(r"r8_[A-Za-z0-9]{20,}"), "Replicate API token"),
    (re.compile(r"hf_[A-Za-z0-9]{20,}"), "HuggingFace token"),
    (re.compile(r"pcsk_[A-Za-z0-9_-]{20,}"), "Pinecone API key"),
    (re.compile(r"sbp_[a-f0-9]{40,}"), "Supabase token"),
    (re.compile(r"vercel_[A-Za-z0-9_-]{20,}"), "Vercel token"),
    (re.compile(r"fw_[A-Za-z0-9]{20,}"), "Fireworks API key"),
    (re.compile(r"pplx-[a-f0-9]{48,}"), "Perplexity API key"),
    (re.compile(r"SK[a-f0-9]{32}"), "Twilio API key"),
    (re.compile(r"dd[a-z][a-f0-9]{40}"), "Datadog API key"),
    (re.compile(r"el_[A-Za-z0-9]{20,}"), "ElevenLabs API key"),
    (re.compile(r"voyage-[A-Za-z0-9_-]{20,}"), "Voyage AI key"),
    (re.compile(r"tog-[A-Za-z0-9]{20,}"), "Together AI key"),
    (re.compile(r"csk-[A-Za-z0-9]{20,}"), "Cerebras API key"),
    (re.compile(r"v1\.0-[a-f0-9]{24}-[a-f0-9]{64,}"), "Cloudflare API token"),
    (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "PEM private key"),
]


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# Known malicious package names for supply chain checks (GAP 3)
_KNOWN_MALICIOUS_PACKAGES = {
    "crossenv", "d3.js", "fabric-js", "ffmepg", "grequsts",
    "http-proxy.js", "mariadb", "mssql-node", "mssql.js",
    "mysqljs", "node-fabric", "node-opencv", "node-opensl",
    "node-openssl", "nodecaffe", "nodefabric", "nodeffmpeg",
    "nodemailer-js", "nodemssql", "noderequest", "nodesass",
    "nodesqlite", "opencv.js", "openssl.js", "proxy.js",
    "shadowsock", "smb", "sqlite.js", "sqliter", "sqlserver",
    "tkinter",
}


class MCPConfigChecker:
    """Static analysis of MCP server configurations."""

    def check(self, server: dict) -> MCPServerResult:
        """Check a single MCP server config dict for security issues."""
        name = server.get("name", "unknown")
        raw_cmd = server.get("command", "")
        args = server.get("args", [])
        # command can be a list in some MCP configs (e.g. Opencode: ["npx", "-y", "@foo/bar"])
        if isinstance(raw_cmd, list):
            command = str(raw_cmd[0]) if raw_cmd else ""
            args = [str(a) for a in raw_cmd[1:]] + list(args)
        else:
            command = str(raw_cmd)
        env = server.get("env", {})
        source = server.get("source_file", "")
        url = server.get("url", "")

        findings: list[MCPFinding] = []

        findings.extend(self._check_sensitive_paths(name, args))
        findings.extend(self._check_env_credentials(name, env))
        findings.extend(self._check_broad_access(name, args))
        findings.extend(self._check_binary_signing(name, command))
        findings.extend(self._check_insecure_urls(name, args, env))
        if url:
            findings.extend(self._check_http_server(name, server))
        findings.extend(self._check_supply_chain(name, command, args))
        findings.extend(self._check_command_injection(name, command, args))
        findings.extend(self._check_missing_auth(name, server))
        findings.extend(self._check_context_oversharing(name, args))
        findings.extend(self._check_known_cves(name, server))
        findings.extend(self._check_file_permissions(name, source))
        findings.extend(self._check_high_entropy_secrets(name, env))
        findings.extend(self._check_case_sensitivity(name, args))

        verdict = _verdict_from_findings(findings)

        # Build full command string for registry slug matching
        full_command = command or url
        if command and args:
            full_command = command + " " + " ".join(str(a) for a in args)

        return MCPServerResult(
            name=name,
            command=full_command,
            source_file=source,
            verdict=verdict,
            findings=findings,
        )

    def check_all(self, servers: list[dict]) -> list[MCPServerResult]:
        """Check multiple MCP server configs."""
        return [self.check(s) for s in servers]

    # ── Individual checks ──────────────────────────────────────────────

    def _check_sensitive_paths(self, name: str, args: list) -> list[MCPFinding]:
        """MCP-001: Check if server has access to sensitive directories."""
        findings = []
        home = str(Path.home())

        for arg in args:
            if not isinstance(arg, str):
                continue
            # Expand leading ~ only (not ~ in middle of path)
            expanded = arg if not arg.startswith("~") else home + arg[1:]
            # Resolve symlinks to catch /tmp/innocent -> ~/.ssh bypasses
            try:
                resolved = os.path.realpath(expanded)
            except (OSError, ValueError):
                resolved = expanded
            for sensitive_suffix, description in _SENSITIVE_PATHS:
                sensitive_full = os.path.join(home, sensitive_suffix)
                if sensitive_full in expanded or sensitive_suffix in arg or sensitive_full in resolved:
                    findings.append(MCPFinding(
                        code="MCP-001",
                        title=f"Access to {description}",
                        description=f"MCP server '{name}' has filesystem access to "
                                    f"{sensitive_suffix} ({description}). "
                                    f"This is a critical security risk.",
                        severity="critical",
                        remediation=f"Restrict '{name}' MCP server: remove {sensitive_suffix} "
                                    f"from allowed paths. It does not need access to {description}.",
                    ))
                    break  # One finding per sensitive path per server

        return findings

    def _check_env_credentials(self, name: str, env: dict) -> list[MCPFinding]:
        """MCP-002: Check for hardcoded credentials in environment variables."""
        findings = []

        for env_key, env_value in env.items():
            if not isinstance(env_value, str):
                continue
            # Skip env var references like ${VAR} or $VAR
            if env_value.startswith("${") or env_value.startswith("$"):
                continue

            for pattern, cred_type in _CREDENTIAL_PATTERNS:
                if pattern.search(env_value):
                    # Redact the value for display
                    redacted = env_value[:6] + "..." + env_value[-4:] if len(env_value) > 14 else "***"
                    findings.append(MCPFinding(
                        code="MCP-002",
                        title=f"Hardcoded {cred_type}",
                        description=f"MCP server '{name}' has a hardcoded {cred_type} "
                                    f"in env var {env_key} ({redacted}). "
                                    f"Credentials should not be stored in config files.",
                        severity="high",
                        remediation=f"Move {env_key} for '{name}' to a secrets manager "
                                    f"or environment variable. Do not store API keys in MCP config files.",
                    ))
                    break  # One finding per env var

        return findings

    def _check_broad_access(self, name: str, args: list) -> list[MCPFinding]:
        """MCP-003: Check for overly broad filesystem access."""
        findings = []
        home = str(Path.home())

        for arg in args:
            if not isinstance(arg, str):
                continue
            expanded = arg.replace("~", home)
            # Root-level access
            if expanded == "/" or expanded == home or arg == "~" or arg == "/":
                findings.append(MCPFinding(
                    code="MCP-003",
                    title="Overly broad filesystem access",
                    description=f"MCP server '{name}' has access to the entire "
                                f"{'home directory' if expanded == home else 'filesystem'}. "
                                f"This grants access to all files including credentials.",
                    severity="high",
                    remediation=f"Restrict '{name}' to specific project directories only. "
                                f"Example: /Users/you/projects/my-app instead of ~ or /",
                ))
                break

        return findings

    def _check_binary_signing(self, name: str, command: str) -> list[MCPFinding]:
        """MCP-004: Check if MCP server binary is code-signed (macOS only)."""
        if platform.system() != "Darwin":
            return []

        if not command:
            return []

        # Only check absolute paths to binaries (not npx, uvx, etc.)
        binary_path = Path(command)
        if not binary_path.is_absolute() or not binary_path.is_file():
            return []

        try:
            result = subprocess.run(
                ["codesign", "-v", str(binary_path)],
                capture_output=True,
                timeout=5,
            )
            if result.returncode != 0:
                return [MCPFinding(
                    code="MCP-004",
                    title="Unsigned binary",
                    description=f"MCP server '{name}' binary at {command} "
                                f"is not code-signed. This could indicate a "
                                f"tampered or untrusted binary.",
                    severity="medium",
                    remediation=f"Verify the source of '{name}' binary. "
                                f"Consider using an npm/pip package instead.",
                )]
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            logger.debug("Codesign check failed for MCP server '%s' binary: %s", name, command)

        return []

    def _check_http_server(self, name: str, server: dict) -> list[MCPFinding]:
        """MCP-006: Check HTTP/remote server configuration for security issues."""
        findings = []
        url = server.get("url", "")
        headers = server.get("headers", {})
        api_key = server.get("apiKey", "")

        # Insecure HTTP endpoint (non-localhost)
        http_pattern = re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])")
        if isinstance(url, str) and http_pattern.search(url):
            findings.append(MCPFinding(
                code="MCP-006",
                title="Insecure remote MCP endpoint",
                description=f"MCP server '{name}' connects to a remote HTTP endpoint "
                            f"without TLS. All JSON-RPC traffic including tool definitions "
                            f"and any auth tokens can be intercepted.",
                severity="critical",
                remediation=f"Use HTTPS for remote MCP server '{name}': change {url} to use https://",
            ))

        # Hardcoded API key in config
        if isinstance(api_key, str) and api_key and not api_key.startswith("${"):
            for pattern, cred_type in _CREDENTIAL_PATTERNS:
                if pattern.search(api_key):
                    redacted = api_key[:6] + "..." + api_key[-4:] if len(api_key) > 14 else "***"
                    findings.append(MCPFinding(
                        code="MCP-006",
                        title=f"Hardcoded {cred_type} in apiKey",
                        description=f"MCP server '{name}' has a hardcoded {cred_type} "
                                    f"in apiKey field ({redacted}). Use environment variable references.",
                        severity="high",
                        remediation=f"Move apiKey for '{name}' to a secrets manager or env var reference.",
                    ))
                    break

        # Hardcoded auth in headers
        if isinstance(headers, dict):
            auth_val = headers.get("Authorization", "")
            if isinstance(auth_val, str) and auth_val and not auth_val.startswith("${"):
                for pattern, cred_type in _CREDENTIAL_PATTERNS:
                    if pattern.search(auth_val):
                        findings.append(MCPFinding(
                            code="MCP-006",
                            title=f"Hardcoded {cred_type} in Authorization header",
                            description=f"MCP server '{name}' has a hardcoded credential "
                                        f"in the Authorization header. Use environment variable references.",
                            severity="high",
                            remediation=f"Move Authorization header for '{name}' to env var reference.",
                        ))
                        break

        return findings

    def _check_insecure_urls(self, name: str, args: list, env: dict) -> list[MCPFinding]:
        """MCP-005: Check for HTTP (not HTTPS) endpoints."""
        findings = []
        http_pattern = re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])")

        all_values = [a for a in args if isinstance(a, str)]
        all_values.extend(v for v in env.values() if isinstance(v, str))

        for value in all_values:
            if http_pattern.search(value):
                findings.append(MCPFinding(
                    code="MCP-005",
                    title="Insecure HTTP connection",
                    description=f"MCP server '{name}' uses an unencrypted HTTP connection. "
                                f"Data sent to this server could be intercepted.",
                    severity="medium",
                    remediation=f"Use HTTPS for '{name}' MCP server connections.",
                ))
                break  # One finding is enough

        return findings

    # ── GAP 3: OWASP MCP Top 10 checks ──────────────────────────────

    def _check_supply_chain(self, name: str, command: str, args: list) -> list[MCPFinding]:
        """MCP-007: Supply chain risks — unpinned packages and known malicious."""
        findings = []
        all_str = " ".join([command] + [a for a in args if isinstance(a, str)])

        # npx -y @scope/pkg without @version
        npx_match = re.search(r"npx\s+-y\s+(@?[a-zA-Z0-9_./-]+(?:@[^\s]+)?)", all_str)
        if npx_match:
            pkg = npx_match.group(1)
            # Check if there's a version pin: @scope/pkg@version or pkg@version
            # A scoped package has format @scope/name — version would be @scope/name@version
            parts = pkg.split("/")
            last_part = parts[-1] if parts else pkg
            has_version = "@" in last_part and not last_part.startswith("@")
            if not has_version:
                findings.append(MCPFinding(
                    code="MCP-007",
                    title="Unpinned npx package",
                    description=f"MCP server '{name}' installs '{pkg}' via npx without version pinning. "
                                f"A supply chain attack could inject malicious code.",
                    severity="high",
                    remediation=f"Pin the version: npx -y {pkg}@<version>",
                ))

        # uvx package without ==version
        uvx_match = re.search(r"uvx\s+([a-zA-Z0-9_.-]+)", all_str)
        if uvx_match:
            pkg = uvx_match.group(1)
            if "==" not in all_str.split(pkg)[-1][:20]:
                findings.append(MCPFinding(
                    code="MCP-007",
                    title="Unpinned uvx package",
                    description=f"MCP server '{name}' installs '{pkg}' via uvx without version pinning.",
                    severity="high",
                    remediation=f"Pin the version: uvx {pkg}==<version>",
                ))

        # bunx (Bun's npx equivalent) without @version
        bunx_match = re.search(r"bunx\s+(@?[a-zA-Z0-9_./-]+(?:@[^\s]+)?)", all_str)
        if bunx_match:
            pkg = bunx_match.group(1)
            parts = pkg.split("/")
            last_part = parts[-1] if parts else pkg
            has_version = "@" in last_part and not last_part.startswith("@")
            if not has_version:
                findings.append(MCPFinding(
                    code="MCP-007",
                    title="Unpinned bunx package",
                    description=f"MCP server '{name}' installs '{pkg}' via bunx without version pinning.",
                    severity="high",
                    remediation=f"Pin the version: bunx {pkg}@<version>",
                ))

        # deno run without version pin (--import-map or @version)
        if re.search(r"deno\s+run", all_str):
            deno_pkg = re.search(r"deno\s+run\s+(?:--allow-\S+\s+)*(\S+)", all_str)
            if deno_pkg:
                pkg = deno_pkg.group(1)
                if "@" not in pkg.split("/")[-1] and not pkg.startswith(".") and not pkg.startswith("/"):
                    findings.append(MCPFinding(
                        code="MCP-007",
                        title="Unpinned deno module",
                        description=f"MCP server '{name}' runs '{pkg}' via deno without version pinning.",
                        severity="high",
                        remediation=f"Pin the version in the import URL or use --lock flag.",
                    ))

        # docker run with :latest or no tag
        docker_match = re.search(r"docker\s+run\s+(?:-[^\s]+\s+)*([a-zA-Z0-9_./-]+(?::[^\s]+)?)", all_str)
        if docker_match:
            image = docker_match.group(1)
            if ":" not in image or image.endswith(":latest"):
                findings.append(MCPFinding(
                    code="MCP-007",
                    title="Unpinned Docker image",
                    description=f"MCP server '{name}' uses Docker image '{image}' without a specific tag. "
                                f"The image could be replaced with a malicious version.",
                    severity="high",
                    remediation=f"Pin the image to a specific digest: docker run {image}@sha256:<digest>",
                ))

        # pip install without ==version
        pip_match = re.search(r"pip3?\s+install\s+([a-zA-Z0-9_.-]+)", all_str)
        if pip_match:
            pkg = pip_match.group(1)
            if "==" not in all_str.split(pkg)[-1][:20] and pkg not in ("-e", "-r", "--upgrade"):
                findings.append(MCPFinding(
                    code="MCP-007",
                    title="Unpinned pip package",
                    description=f"MCP server '{name}' installs '{pkg}' via pip without version pinning.",
                    severity="high",
                    remediation=f"Pin the version: pip install {pkg}==<version>",
                ))

        # go run without @version
        go_match = re.search(r"go\s+run\s+([a-zA-Z0-9_./-]+)", all_str)
        if go_match:
            pkg = go_match.group(1)
            if "@" not in pkg and not pkg.startswith(".") and not pkg.startswith("/"):
                findings.append(MCPFinding(
                    code="MCP-007",
                    title="Unpinned Go module",
                    description=f"MCP server '{name}' runs '{pkg}' via go run without version pinning.",
                    severity="high",
                    remediation=f"Pin the version: go run {pkg}@<version>",
                ))

        # Known malicious packages
        for arg in [command] + [a for a in args if isinstance(a, str)]:
            for pkg_name in _KNOWN_MALICIOUS_PACKAGES:
                if pkg_name in arg.lower():
                    findings.append(MCPFinding(
                        code="MCP-007",
                        title=f"Known malicious package: {pkg_name}",
                        description=f"MCP server '{name}' references known malicious package '{pkg_name}'.",
                        severity="critical",
                        remediation=f"Remove MCP server '{name}' immediately.",
                    ))
                    return findings  # One is enough

        return findings

    def _check_command_injection(self, name: str, command: str, args: list) -> list[MCPFinding]:
        """MCP-008: Command injection risks — dangerous shell binaries and metacharacters."""
        findings = []

        # Dangerous shell binaries as the server command
        dangerous_shells = {"bash", "sh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
        cmd_base = Path(command).name.lower() if command else ""
        if cmd_base in dangerous_shells:
            findings.append(MCPFinding(
                code="MCP-008",
                title="Shell binary as MCP server",
                description=f"MCP server '{name}' uses '{cmd_base}' as its binary. "
                            f"This allows arbitrary command execution.",
                severity="critical",
                remediation=f"Replace shell command for '{name}' with a dedicated MCP server binary.",
            ))

        # Shell metacharacters in args
        shell_meta = re.compile(r"[;|&`$()]")
        for arg in args:
            if isinstance(arg, str) and shell_meta.search(arg):
                findings.append(MCPFinding(
                    code="MCP-008",
                    title="Shell metacharacters in arguments",
                    description=f"MCP server '{name}' has shell metacharacters in args: "
                                f"'{arg[:60]}'. This may allow command injection.",
                    severity="high",
                    remediation=f"Remove shell metacharacters from '{name}' arguments.",
                ))
                break

        return findings

    def _check_missing_auth(self, name: str, server: dict) -> list[MCPFinding]:
        """MCP-009: Missing authentication for remote servers."""
        url = server.get("url", "")
        if not url or not isinstance(url, str):
            return []

        # Skip localhost — local servers don't need auth
        localhost_pattern = re.compile(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])")
        if localhost_pattern.match(url):
            return []

        # Check for auth configuration
        has_api_key = bool(server.get("apiKey"))
        headers = server.get("headers", {})
        has_auth_header = isinstance(headers, dict) and bool(headers.get("Authorization"))
        has_oauth = bool(server.get("oauth") or server.get("auth"))

        if not (has_api_key or has_auth_header or has_oauth):
            return [MCPFinding(
                code="MCP-009",
                title="Missing authentication",
                description=f"Remote MCP server '{name}' at {url} has no authentication configured. "
                            f"Anyone who discovers the endpoint can use it.",
                severity="high",
                remediation=f"Add apiKey, Authorization header, or OAuth config for '{name}'.",
            )]
        return []

    def _check_context_oversharing(self, name: str, args: list) -> list[MCPFinding]:
        """MCP-010: Context oversharing — filesystem servers with broad read+write."""
        home = str(Path.home())
        broad_scopes = {"/", home, "~"}
        has_read = False
        has_write = False

        for arg in args:
            if not isinstance(arg, str):
                continue
            expanded = arg.replace("~", home)
            if expanded in broad_scopes or arg in broad_scopes:
                # Check for read/write flags in args
                has_read = True
                has_write = True

        # Also check for explicit read/write capability markers
        all_args_str = " ".join(str(a) for a in args)
        if "read" in all_args_str.lower() and "write" in all_args_str.lower():
            has_read = True
            has_write = True

        if has_read and has_write:
            return [MCPFinding(
                code="MCP-010",
                title="Context oversharing",
                description=f"MCP server '{name}' has both read and write access to broad filesystem scope. "
                            f"This violates the principle of least privilege (OWASP MCP10).",
                severity="medium",
                remediation=f"Restrict '{name}' to specific project directories only.",
            )]
        return []

    # ── GAP 5: CVE-specific checks ───────────────────────────────────

    def _check_known_cves(self, name: str, server: dict) -> list[MCPFinding]:
        """MCP-CVE: Check for known CVE patterns in MCP configurations."""
        findings = []
        raw_cmd = server.get("command", "")
        if isinstance(raw_cmd, list):
            command = str(raw_cmd[0]) if raw_cmd else ""
            args = [str(a) for a in raw_cmd[1:]] + list(server.get("args", []))
        else:
            command = str(raw_cmd)
            args = server.get("args", [])
        source = server.get("source_file", "")
        all_args_str = " ".join(str(a) for a in args)

        # CVE-2025-53110: Path traversal in args
        for arg in args:
            if isinstance(arg, str) and "../" in arg:
                findings.append(MCPFinding(
                    code="MCP-CVE",
                    title="CVE-2025-53110: Path traversal in arguments",
                    description=f"MCP server '{name}' has path traversal sequence '../' in arguments.",
                    severity="high",
                    remediation="Remove path traversal sequences from MCP server arguments.",
                ))
                break

        # CVE-2025-68143: Unrestricted git MCP
        # Check both command name AND args (for npx -y @modelcontextprotocol/server-git)
        is_git_server = re.search(r"\bgit\b", command.lower()) or re.search(
            r"server-git|mcp-git", all_args_str.lower()
        )
        if is_git_server and not any("--allowed" in str(a) or "path" in str(a).lower() for a in args):
            if True:
                findings.append(MCPFinding(
                    code="MCP-CVE",
                    title="CVE-2025-68143: Unrestricted git MCP server",
                    description=f"Git MCP server '{name}' has no path restrictions configured. "
                                f"It can access any repository on the machine.",
                    severity="high",
                    remediation=f"Add --allowed-path restrictions to git MCP server '{name}'.",
                ))

        # CVE-2025-59536: Project .mcp.json RCE
        if source and os.path.basename(source) == ".mcp.json":
            findings.append(MCPFinding(
                code="MCP-CVE",
                title="CVE-2025-59536: Project-level MCP config",
                description=f"MCP server '{name}' is defined in a project-level .mcp.json file. "
                            f"Cloning a malicious repo could auto-register MCP servers.",
                severity="medium",
                remediation="Review project-level MCP configs carefully. Consider using global configs only.",
            ))

        # CVE-2025-6514: mcp-remote usage
        if "mcp-remote" in command or "mcp-remote" in all_args_str:
            findings.append(MCPFinding(
                code="MCP-CVE",
                title="CVE-2025-6514: mcp-remote OAuth vulnerability",
                description=f"MCP server '{name}' uses mcp-remote which has known OAuth vulnerabilities.",
                severity="medium",
                remediation="Update mcp-remote to the latest version or use direct SSE connections.",
            ))

        return findings

    # ── GAP 8: File permissions check ─────────────────────────────────

    def _check_file_permissions(self, name: str, source_file: str) -> list[MCPFinding]:
        """MCP-011: Check if MCP config file is world-readable (Unix only)."""
        if platform.system() == "Windows" or not source_file:
            return []

        try:
            st = os.stat(source_file)
        except OSError:
            return []

        if st.st_mode & stat.S_IROTH:
            return [MCPFinding(
                code="MCP-011",
                title="World-readable config file",
                description=f"MCP config file for '{name}' at {source_file} is world-readable. "
                            f"Other users on this machine can read credentials.",
                severity="medium",
                remediation=f"Fix permissions: chmod 600 {source_file}",
            )]
        return []

    # ── GAP 4: High entropy secret detection ──────────────────────────

    def _check_high_entropy_secrets(self, name: str, env: dict) -> list[MCPFinding]:
        """Detect potential secrets using Shannon entropy for unknown providers."""
        findings = []
        # Skip env vars that were already caught by pattern matching
        already_matched: set[str] = set()
        for env_key, env_value in env.items():
            if not isinstance(env_value, str) or len(env_value) < 20:
                continue
            if env_value.startswith("${") or env_value.startswith("$"):
                continue
            # Skip if already matched by explicit patterns
            matched = False
            for pattern, _ in _CREDENTIAL_PATTERNS:
                if pattern.search(env_value):
                    matched = True
                    break
            if matched:
                continue

            # Check entropy — high entropy strings are likely secrets
            entropy = _shannon_entropy(env_value)
            if entropy > 4.5:
                redacted = env_value[:4] + "..." + env_value[-4:] if len(env_value) > 12 else "***"
                findings.append(MCPFinding(
                    code="MCP-002",
                    title=f"High-entropy secret in {env_key}",
                    description=f"MCP server '{name}' has a high-entropy string in env var "
                                f"{env_key} ({redacted}, entropy={entropy:.1f}). "
                                f"This may be a credential from an unknown provider.",
                    severity="medium",
                    remediation=f"Move {env_key} for '{name}' to a secrets manager or env var reference.",
                ))

        return findings


    def _check_case_sensitivity(self, name: str, args: list) -> list[MCPFinding]:
        """MCP-012: Case-insensitive filesystem path restriction bypass."""
        path_args = [a for a in args if isinstance(a, str) and not a.startswith("-")]
        if not path_args:
            return []

        warning = check_case_sensitivity_risk(path_args)
        if warning:
            return [MCPFinding(
                code="MCP-012",
                title="Case-insensitive filesystem bypass risk",
                description=f"MCP server '{name}': {warning}",
                severity="medium",
                remediation=f"Use canonical paths and consider additional access controls for '{name}'.",
            )]
        return []


def _verdict_from_findings(findings: list[MCPFinding]) -> GuardVerdict:
    """Determine verdict from findings."""
    if not findings:
        return GuardVerdict.SAFE
    if any(f.severity == "critical" for f in findings):
        return GuardVerdict.DANGER
    if any(f.severity in ("high", "medium") for f in findings):
        return GuardVerdict.WARNING
    return GuardVerdict.SAFE
