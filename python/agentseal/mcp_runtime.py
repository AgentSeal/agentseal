# agentseal/mcp_runtime.py
"""
MCP runtime connection engine — connect to MCP servers, extract capabilities.

Implements a minimal JSON-RPC 2.0 MCP client (no SDK dependency) supporting:
  - stdio transport (subprocess stdin/stdout)
  - Streamable HTTP transport (POST with JSON or SSE response)
  - SSE transport (legacy GET + POST)

Only performs introspection (list_tools, list_prompts, list_resources).
Never calls tools/call. Zero side effects beyond the connection itself.

Requires: httpx (already an agentseal dependency).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import httpx


# ═══════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════

# Mimic a common MCP client to prevent detection evasion.
# Malicious servers can serve clean tool descriptions when they detect
# a security scanner by client name, then serve poisoned ones to real agents.
_CLIENT_POOL = [
    ("claude-ai", "1.0.8"),
    ("cursor", "0.48.2"),
    ("vscode-mcp", "1.2.0"),
    ("windsurf", "1.5.1"),
]

def _pick_client():
    import random
    return random.choice(_CLIENT_POOL)

CLIENT_NAME, CLIENT_VERSION = _pick_client()
PROTOCOL_VERSION = "2025-03-26"

# Limits — prevent resource exhaustion from malicious/broken servers
MAX_TOOLS_PER_SERVER = 500           # No legitimate server needs more; caps memory usage
MAX_PROMPTS_PER_SERVER = 200         # Prompts are less common, lower cap is safe
MAX_RESOURCES_PER_SERVER = 200       # Same rationale as prompts
MAX_DESCRIPTION_BYTES = 50 * 1024    # 50KB — enough for any real description, blocks payload stuffing
MAX_LINE_BYTES = 10 * 1024 * 1024    # 10MB — allows large schemas while blocking unbounded reads
MAX_PAGINATION_PAGES = 10            # Prevents infinite cursor loops from buggy servers

# Timeouts (seconds)
DEFAULT_TIMEOUT = 30.0
PROCESS_SHUTDOWN_TIMEOUT = 5.0
PROCESS_KILL_TIMEOUT = 2.0

# Environment vars that must NEVER be inherited by spawned servers
_SENSITIVE_ENV_KEYS = frozenset({
    "SSH_AUTH_SOCK", "SSH_AGENT_PID",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "DATABASE_URL", "MONGO_URI", "REDIS_URL",
    "STRIPE_SECRET_KEY", "SENDGRID_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
    "NPM_TOKEN", "PYPI_TOKEN",
})


# ═══════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class MCPToolSnapshot:
    """A single tool definition extracted from an MCP server."""
    name: str
    description: str
    input_schema: dict
    annotations: dict
    signature_hash: str   # SHA256 of canonical (name, description, schema)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "annotations": self.annotations,
            "signature_hash": self.signature_hash,
        }


@dataclass
class MCPPromptSnapshot:
    """A single prompt template extracted from an MCP server."""
    name: str
    description: str
    arguments: list[dict]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "arguments": self.arguments,
        }


@dataclass
class MCPResourceSnapshot:
    """A single resource definition extracted from an MCP server."""
    uri: str
    name: str
    description: str
    mime_type: str

    def to_dict(self) -> dict:
        return {
            "uri": self.uri,
            "name": self.name,
            "description": self.description,
            "mime_type": self.mime_type,
        }


@dataclass
class MCPServerSnapshot:
    """Complete capability snapshot from one MCP server."""
    server_name: str
    server_version: str
    protocol_version: str
    instructions: str
    capabilities: dict
    tools: list[MCPToolSnapshot]
    prompts: list[MCPPromptSnapshot]
    resources: list[MCPResourceSnapshot]
    connected_at: str
    connection_duration_ms: float

    @property
    def tools_hash(self) -> str:
        """Combined hash of all tool signatures, order-independent."""
        if not self.tools:
            return ""
        hashes = sorted(t.signature_hash for t in self.tools)
        return hashlib.sha256("|".join(hashes).encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "server_name": self.server_name,
            "server_version": self.server_version,
            "protocol_version": self.protocol_version,
            "instructions": self.instructions,
            "capabilities": self.capabilities,
            "tools": [t.to_dict() for t in self.tools],
            "prompts": [p.to_dict() for p in self.prompts],
            "resources": [r.to_dict() for r in self.resources],
            "connected_at": self.connected_at,
            "connection_duration_ms": self.connection_duration_ms,
        }


@dataclass
class MCPConnectionError:
    """Describes a failed connection attempt."""
    server_name: str
    error_type: str   # "timeout", "crash", "auth", "invalid", "missing_binary", "spawn_failed"
    detail: str

    def to_dict(self) -> dict:
        return {
            "server_name": self.server_name,
            "error_type": self.error_type,
            "detail": self.detail,
        }


# ═══════════════════════════════════════════════════════════════════════
# EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════

class MCPProtocolError(Exception):
    """Raised when the server sends an invalid JSON-RPC response."""
    def __init__(self, message: str, code: int = 0):
        super().__init__(message)
        self.code = code


# ═══════════════════════════════════════════════════════════════════════
# JSON-RPC 2.0 HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _make_request(method: str, params: dict | None = None, req_id: int = 1) -> bytes:
    """Build a JSON-RPC 2.0 request as newline-terminated bytes."""
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg, separators=(",", ":")).encode("utf-8") + b"\n"


def _make_notification(method: str, params: dict | None = None) -> bytes:
    """Build a JSON-RPC 2.0 notification (no id, no response expected)."""
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg, separators=(",", ":")).encode("utf-8") + b"\n"


def _parse_jsonrpc(data: bytes | str) -> dict:
    """Parse a JSON-RPC message, returning the parsed dict.

    Raises MCPProtocolError on invalid JSON or non-object message.
    """
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        msg = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise MCPProtocolError(f"Invalid JSON from server: {e}")
    if not isinstance(msg, dict):
        raise MCPProtocolError(f"Expected JSON object, got {type(msg).__name__}")
    return msg


def _extract_result(msg: dict, expected_id: int) -> dict:
    """Extract the 'result' from a JSON-RPC response.

    Raises MCPProtocolError on error responses or ID mismatches.
    """
    if "error" in msg:
        err = msg["error"]
        code = err.get("code", 0)
        message = err.get("message", "Unknown server error")
        raise MCPProtocolError(f"Server error ({code}): {message}", code=code)
    if msg.get("id") != expected_id:
        raise MCPProtocolError(
            f"Response ID mismatch: expected {expected_id}, got {msg.get('id')}"
        )
    return msg.get("result", {})


# ═══════════════════════════════════════════════════════════════════════
# TOOL HASH COMPUTATION
# ═══════════════════════════════════════════════════════════════════════

def compute_tool_hash(name: str, description: str, input_schema: dict) -> str:
    """Compute a deterministic SHA256 hash for a tool definition.

    Uses canonical JSON (sorted keys) so hash is stable across runs.
    """
    canonical = json.dumps(
        {"name": name, "description": description, "inputSchema": input_schema},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ═══════════════════════════════════════════════════════════════════════
# DESCRIPTION TRUNCATION
# ═══════════════════════════════════════════════════════════════════════

def _truncate_description(text: str) -> str:
    """Truncate description to MAX_DESCRIPTION_BYTES, preserving valid UTF-8."""
    if len(text.encode("utf-8")) <= MAX_DESCRIPTION_BYTES:
        return text
    truncated = text.encode("utf-8")[:MAX_DESCRIPTION_BYTES].decode("utf-8", errors="ignore")
    return truncated


# ═══════════════════════════════════════════════════════════════════════
# SNAPSHOT BUILDERS
# ═══════════════════════════════════════════════════════════════════════

def _build_tool_snapshot(raw: dict) -> MCPToolSnapshot:
    """Build an MCPToolSnapshot from a raw tools/list entry."""
    name = str(raw.get("name", ""))
    description = _truncate_description(str(raw.get("description", "")))
    input_schema = raw.get("inputSchema", {})
    if not isinstance(input_schema, dict):
        input_schema = {}
    annotations = raw.get("annotations", {})
    if not isinstance(annotations, dict):
        annotations = {}
    return MCPToolSnapshot(
        name=name,
        description=description,
        input_schema=input_schema,
        annotations=annotations,
        signature_hash=compute_tool_hash(name, description, input_schema),
    )


def _build_prompt_snapshot(raw: dict) -> MCPPromptSnapshot:
    """Build an MCPPromptSnapshot from a raw prompts/list entry."""
    return MCPPromptSnapshot(
        name=str(raw.get("name", "")),
        description=_truncate_description(str(raw.get("description", ""))),
        arguments=raw.get("arguments", []) if isinstance(raw.get("arguments"), list) else [],
    )


def _build_resource_snapshot(raw: dict) -> MCPResourceSnapshot:
    """Build an MCPResourceSnapshot from a raw resources/list entry."""
    return MCPResourceSnapshot(
        uri=str(raw.get("uri", "")),
        name=str(raw.get("name", "")),
        description=_truncate_description(str(raw.get("description", ""))),
        mime_type=str(raw.get("mimeType", "")),
    )


# ═══════════════════════════════════════════════════════════════════════
# ENVIRONMENT SANITIZATION
# ═══════════════════════════════════════════════════════════════════════

def sanitize_env(server_env: dict | None) -> dict[str, str]:
    """Build a safe environment for spawning an MCP server subprocess.

    Strategy:
      1. Start with minimal base (PATH, HOME from parent)
      2. Add server-declared env vars (from config)
      3. Block sensitive keys from the parent environment from leaking in,
         but allow server-declared env vars through (the server needs them
         to function; mcp_checker MCP-002 warns about them separately)

    Returns a dict suitable for subprocess env= parameter.
    """
    safe: dict[str, str] = {}

    # Minimal base: PATH is required to find binaries (node, python, etc.)
    if "PATH" in os.environ:
        safe["PATH"] = os.environ["PATH"]

    # On some systems HOME is needed for package managers (npm, pip)
    if "HOME" in os.environ:
        safe["HOME"] = os.environ["HOME"]

    # Windows needs SystemRoot and COMSPEC
    if sys.platform == "win32":
        for k in ("SystemRoot", "COMSPEC", "TEMP", "TMP"):
            if k in os.environ:
                safe[k] = os.environ[k]

    # Add server-declared env vars (from config file).
    # These are explicitly configured by the user, so we pass them through.
    # mcp_checker MCP-002 flags sensitive keys in config separately.
    if server_env:
        for key, value in server_env.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            safe[key] = value

    return safe


# ═══════════════════════════════════════════════════════════════════════
# SSE PARSER
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class _SSEEvent:
    event: str = "message"
    data: str = ""
    id: str = ""


def _parse_sse_stream(text: str) -> list[_SSEEvent]:
    """Parse a Server-Sent Events stream into a list of events.

    Follows the SSE specification:
      - Lines starting with ":" are comments (ignored)
      - "event:" sets event type (default "message")
      - "data:" appends to data buffer (joined with newline)
      - "id:" sets event ID
      - Empty line dispatches the current event
    """
    events: list[_SSEEvent] = []
    current_data: list[str] = []
    current_event = "message"
    current_id = ""

    for line in text.split("\n"):
        if line == "" or line == "\r":
            # Empty line → dispatch event if we have data
            if current_data:
                events.append(_SSEEvent(
                    event=current_event,
                    data="\n".join(current_data),
                    id=current_id,
                ))
                current_data = []
                current_event = "message"
                current_id = ""
            continue

        # Strip trailing \r (for \r\n line endings)
        line = line.rstrip("\r")

        if line.startswith(":"):
            continue  # comment

        if ":" in line:
            field, _, value = line.partition(":")
            # Strip single leading space from value (per spec)
            if value.startswith(" "):
                value = value[1:]
        else:
            # Line with no colon: treat entire line as field name, empty value
            field = line
            value = ""

        if field == "data":
            current_data.append(value)
        elif field == "event":
            current_event = value
        elif field == "id":
            current_id = value
        # "retry:" and unknown fields are ignored

    # Trailing data without empty line — don't dispatch (per spec, but be lenient)
    if current_data:
        events.append(_SSEEvent(
            event=current_event,
            data="\n".join(current_data),
            id=current_id,
        ))

    return events


# ═══════════════════════════════════════════════════════════════════════
# STDIO TRANSPORT
# ═══════════════════════════════════════════════════════════════════════

async def _read_response_line(
    stdout: asyncio.StreamReader,
    expected_id: int,
    timeout: float,
) -> dict:
    """Read lines from stdout until we get a JSON-RPC response matching expected_id.

    Skips notifications (messages without 'id') from the server.
    Raises asyncio.TimeoutError if deadline is exceeded.
    Raises MCPProtocolError on invalid messages.
    Raises ConnectionError if stdout is closed.
    """
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise asyncio.TimeoutError("Timeout waiting for server response")

        try:
            line = await asyncio.wait_for(stdout.readline(), timeout=remaining)
        except asyncio.TimeoutError:
            raise asyncio.TimeoutError("Timeout waiting for server response")

        if not line:
            raise ConnectionError("Server closed stdout unexpectedly")

        # Skip empty lines
        stripped = line.strip()
        if not stripped:
            continue

        # Guard against oversized messages
        if len(stripped) > MAX_LINE_BYTES:
            raise MCPProtocolError(
                f"Server message exceeds {MAX_LINE_BYTES} bytes, aborting"
            )

        msg = _parse_jsonrpc(stripped)

        # Skip notifications (no "id" field) — server may send these at any time
        if "id" not in msg:
            continue

        return msg


async def _stdio_request(
    stdin: asyncio.StreamWriter,
    stdout: asyncio.StreamReader,
    method: str,
    params: dict | None,
    req_id: int,
    timeout: float,
) -> dict:
    """Send a JSON-RPC request over stdio and wait for the response."""
    data = _make_request(method, params, req_id)
    stdin.write(data)
    await stdin.drain()
    msg = await _read_response_line(stdout, req_id, timeout)
    return _extract_result(msg, req_id)


async def _stdio_notify(
    stdin: asyncio.StreamWriter,
    method: str,
    params: dict | None = None,
) -> None:
    """Send a JSON-RPC notification over stdio (no response expected)."""
    data = _make_notification(method, params)
    stdin.write(data)
    await stdin.drain()


async def _cleanup_process(proc: asyncio.subprocess.Process) -> None:
    """Cleanly shut down a subprocess: close stdin → wait → SIGTERM → SIGKILL."""
    if proc.returncode is not None:
        return  # already exited

    # Close stdin to signal we're done
    try:
        if proc.stdin and not proc.stdin.is_closing():
            proc.stdin.close()
            await proc.stdin.wait_closed()
    except Exception:
        pass

    # Wait for graceful exit
    try:
        await asyncio.wait_for(proc.wait(), timeout=PROCESS_SHUTDOWN_TIMEOUT)
        return
    except asyncio.TimeoutError:
        pass

    # SIGTERM
    try:
        proc.terminate()
        await asyncio.wait_for(proc.wait(), timeout=PROCESS_KILL_TIMEOUT)
        return
    except (asyncio.TimeoutError, ProcessLookupError, OSError):
        pass

    # SIGKILL (last resort)
    try:
        proc.kill()
        await proc.wait()
    except (ProcessLookupError, OSError):
        pass


async def _list_paginated(
    request_fn,
    method: str,
    items_key: str,
    limit: int,
    timeout: float,
    id_counter: list[int],
) -> list[dict]:
    """Fetch all pages of a paginated MCP list method.

    Args:
        request_fn: Callable(method, params, req_id, timeout) → result dict
        method: JSON-RPC method name (e.g., "tools/list")
        items_key: Key in result containing the items (e.g., "tools")
        limit: Maximum total items to collect
        timeout: Per-request timeout
        id_counter: Mutable list[int] used as a shared request ID counter
    """
    all_items: list[dict] = []
    cursor: str | None = None

    for _page in range(MAX_PAGINATION_PAGES):
        params: dict[str, Any] = {}
        if cursor:
            params["cursor"] = cursor

        req_id = id_counter[0]
        id_counter[0] += 1

        result = await request_fn(method, params, req_id, timeout)
        items = result.get(items_key, [])
        if not isinstance(items, list):
            break

        all_items.extend(items)

        if len(all_items) >= limit:
            all_items = all_items[:limit]
            break

        cursor = result.get("nextCursor")
        if not cursor:
            break

    return all_items


async def connect_stdio(
    command: str,
    args: list[str],
    env: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    server_name: str = "",
) -> MCPServerSnapshot | MCPConnectionError:
    """Connect to an MCP server via stdio (subprocess).

    Spawns the server as a subprocess, performs the MCP handshake,
    extracts all capabilities, then cleanly shuts down.

    Args:
        command: Executable to run (e.g., "node", "python", "uvx")
        args: Arguments to pass to the executable
        env: Environment variables from server config (will be sanitized)
        timeout: Total timeout for the entire connection + extraction
        server_name: Human-readable server name (for error reporting)

    Returns:
        MCPServerSnapshot on success, MCPConnectionError on failure.
    """
    name = server_name or command
    start_time = time.monotonic()
    proc: asyncio.subprocess.Process | None = None

    try:
        safe_env = sanitize_env(env)

        proc = await asyncio.create_subprocess_exec(
            command, *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=safe_env,
            limit=MAX_LINE_BYTES,
        )

        assert proc.stdin is not None
        assert proc.stdout is not None

        # Helper that wraps _stdio_request with our proc's stdin/stdout
        async def request_fn(method: str, params: dict | None, req_id: int, t: float) -> dict:
            assert proc is not None and proc.stdin is not None and proc.stdout is not None
            return await _stdio_request(proc.stdin, proc.stdout, method, params, req_id, t)

        # ── Initialize ────────────────────────────────────────────────
        init_params = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
        }

        id_counter = [1]
        req_id = id_counter[0]
        id_counter[0] += 1

        init_result = await _stdio_request(
            proc.stdin, proc.stdout, "initialize", init_params, req_id, timeout,
        )

        # Send initialized notification
        await _stdio_notify(proc.stdin, "notifications/initialized")

        # ── Extract capabilities ──────────────────────────────────────
        capabilities = init_result.get("capabilities", {})
        server_info = init_result.get("serverInfo", {})
        instructions = str(init_result.get("instructions", ""))

        remaining = timeout - (time.monotonic() - start_time)
        if remaining <= 0:
            raise asyncio.TimeoutError("Timeout after initialize")

        # List tools (if server declares tools capability)
        raw_tools: list[dict] = []
        if capabilities.get("tools") is not None:
            raw_tools = await _list_paginated(
                request_fn, "tools/list", "tools",
                MAX_TOOLS_PER_SERVER, min(remaining, timeout), id_counter,
            )

        remaining = timeout - (time.monotonic() - start_time)
        if remaining <= 0:
            raise asyncio.TimeoutError("Timeout after tools/list")

        # List prompts (if server declares prompts capability)
        raw_prompts: list[dict] = []
        if capabilities.get("prompts") is not None:
            raw_prompts = await _list_paginated(
                request_fn, "prompts/list", "prompts",
                MAX_PROMPTS_PER_SERVER, min(remaining, timeout), id_counter,
            )

        remaining = timeout - (time.monotonic() - start_time)
        if remaining <= 0:
            raise asyncio.TimeoutError("Timeout after prompts/list")

        # List resources (if server declares resources capability)
        raw_resources: list[dict] = []
        if capabilities.get("resources") is not None:
            raw_resources = await _list_paginated(
                request_fn, "resources/list", "resources",
                MAX_RESOURCES_PER_SERVER, min(remaining, timeout), id_counter,
            )

        # ── Build snapshot ────────────────────────────────────────────
        duration_ms = (time.monotonic() - start_time) * 1000

        return MCPServerSnapshot(
            server_name=name,
            server_version=str(server_info.get("version", "")),
            protocol_version=str(init_result.get("protocolVersion", "")),
            instructions=_truncate_description(instructions),
            capabilities=capabilities,
            tools=[_build_tool_snapshot(t) for t in raw_tools if isinstance(t, dict)],
            prompts=[_build_prompt_snapshot(p) for p in raw_prompts if isinstance(p, dict)],
            resources=[_build_resource_snapshot(r) for r in raw_resources if isinstance(r, dict)],
            connected_at=datetime.now(timezone.utc).isoformat(),
            connection_duration_ms=round(duration_ms, 1),
        )

    except FileNotFoundError:
        return MCPConnectionError(
            server_name=name,
            error_type="missing_binary",
            detail=f"Command not found: {command}",
        )
    except PermissionError:
        return MCPConnectionError(
            server_name=name,
            error_type="spawn_failed",
            detail=f"Permission denied when spawning: {command}",
        )
    except asyncio.TimeoutError:
        return MCPConnectionError(
            server_name=name,
            error_type="timeout",
            detail=f"Server did not respond within {timeout}s",
        )
    except ConnectionError as e:
        return MCPConnectionError(
            server_name=name,
            error_type="crash",
            detail=f"Server connection lost: {e}",
        )
    except MCPProtocolError as e:
        return MCPConnectionError(
            server_name=name,
            error_type="invalid",
            detail=f"Protocol error: {e}",
        )
    except ValueError as e:
        # asyncio StreamReader raises ValueError when line exceeds limit
        return MCPConnectionError(
            server_name=name,
            error_type="invalid",
            detail=f"Server sent oversized message: {e}",
        )
    except OSError as e:
        return MCPConnectionError(
            server_name=name,
            error_type="spawn_failed",
            detail=f"Failed to spawn server: {e}",
        )
    finally:
        if proc is not None:
            await _cleanup_process(proc)


# ═══════════════════════════════════════════════════════════════════════
# HTTP TRANSPORT (Streamable HTTP)
# ═══════════════════════════════════════════════════════════════════════

async def connect_http(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    server_name: str = "",
) -> MCPServerSnapshot | MCPConnectionError:
    """Connect to an MCP server via Streamable HTTP.

    Sends JSON-RPC requests as HTTP POST to the given URL.
    Handles both application/json and text/event-stream responses.

    Args:
        url: HTTP(S) endpoint URL
        headers: Additional HTTP headers (e.g., Authorization)
        timeout: Total timeout for the entire connection + extraction
        server_name: Human-readable server name (for error reporting)
    """
    name = server_name or url
    start_time = time.monotonic()
    session_id: str | None = None

    req_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if headers:
        req_headers.update(headers)

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:

            async def http_request(method: str, params: dict | None, req_id: int, t: float) -> dict:
                nonlocal session_id
                body = _make_request(method, params, req_id)

                hdrs = dict(req_headers)
                if session_id:
                    hdrs["Mcp-Session-Id"] = session_id

                resp = await client.post(url, content=body, headers=hdrs)

                # Guard against oversized response bodies
                content_length = resp.headers.get("content-length")
                if content_length and int(content_length) > MAX_LINE_BYTES:
                    raise MCPProtocolError(
                        f"Response body too large: {content_length} bytes"
                    )

                # Capture session ID from response
                if "mcp-session-id" in resp.headers:
                    session_id = resp.headers["mcp-session-id"]

                if resp.status_code == 401 or resp.status_code == 403:
                    raise MCPProtocolError(f"Authentication failed: HTTP {resp.status_code}", code=resp.status_code)
                if resp.status_code == 404:
                    raise MCPProtocolError(f"Endpoint not found: HTTP 404", code=404)
                if resp.status_code >= 400:
                    raise MCPProtocolError(f"HTTP error: {resp.status_code}", code=resp.status_code)

                content_type = resp.headers.get("content-type", "")

                if "text/event-stream" in content_type:
                    # Parse SSE events, find our response
                    events = _parse_sse_stream(resp.text)
                    for event in events:
                        try:
                            msg = _parse_jsonrpc(event.data)
                            if msg.get("id") == req_id:
                                return _extract_result(msg, req_id)
                        except (MCPProtocolError, json.JSONDecodeError):
                            continue
                    raise MCPProtocolError("No matching response in SSE stream")

                # Default: application/json
                msg = _parse_jsonrpc(resp.text)
                return _extract_result(msg, req_id)

            async def http_notify(method: str, params: dict | None = None) -> None:
                nonlocal session_id
                body = _make_notification(method, params)
                hdrs = dict(req_headers)
                if session_id:
                    hdrs["Mcp-Session-Id"] = session_id
                await client.post(url, content=body, headers=hdrs)

            # ── Initialize ────────────────────────────────────────────
            id_counter = [1]
            req_id = id_counter[0]
            id_counter[0] += 1

            init_params = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
            }
            init_result = await http_request("initialize", init_params, req_id, timeout)
            await http_notify("notifications/initialized")

            # ── Extract capabilities ──────────────────────────────────
            capabilities = init_result.get("capabilities", {})
            server_info = init_result.get("serverInfo", {})
            instructions = str(init_result.get("instructions", ""))

            remaining = timeout - (time.monotonic() - start_time)
            if remaining <= 0:
                raise asyncio.TimeoutError("Timeout after initialize")

            raw_tools: list[dict] = []
            if capabilities.get("tools") is not None:
                raw_tools = await _list_paginated(
                    http_request, "tools/list", "tools",
                    MAX_TOOLS_PER_SERVER, min(remaining, timeout), id_counter,
                )

            remaining = timeout - (time.monotonic() - start_time)
            raw_prompts: list[dict] = []
            if remaining > 0 and capabilities.get("prompts") is not None:
                raw_prompts = await _list_paginated(
                    http_request, "prompts/list", "prompts",
                    MAX_PROMPTS_PER_SERVER, min(remaining, timeout), id_counter,
                )

            remaining = timeout - (time.monotonic() - start_time)
            raw_resources: list[dict] = []
            if remaining > 0 and capabilities.get("resources") is not None:
                raw_resources = await _list_paginated(
                    http_request, "resources/list", "resources",
                    MAX_RESOURCES_PER_SERVER, min(remaining, timeout), id_counter,
                )

            duration_ms = (time.monotonic() - start_time) * 1000

            return MCPServerSnapshot(
                server_name=name,
                server_version=str(server_info.get("version", "")),
                protocol_version=str(init_result.get("protocolVersion", "")),
                instructions=_truncate_description(instructions),
                capabilities=capabilities,
                tools=[_build_tool_snapshot(t) for t in raw_tools if isinstance(t, dict)],
                prompts=[_build_prompt_snapshot(p) for p in raw_prompts if isinstance(p, dict)],
                resources=[_build_resource_snapshot(r) for r in raw_resources if isinstance(r, dict)],
                connected_at=datetime.now(timezone.utc).isoformat(),
                connection_duration_ms=round(duration_ms, 1),
            )

    except httpx.TimeoutException:
        return MCPConnectionError(
            server_name=name,
            error_type="timeout",
            detail=f"HTTP request timed out after {timeout}s",
        )
    except httpx.ConnectError as e:
        return MCPConnectionError(
            server_name=name,
            error_type="crash",
            detail=f"Failed to connect to {url}: {e}",
        )
    except MCPProtocolError as e:
        error_type = "auth" if e.code in (401, 403) else "invalid"
        return MCPConnectionError(
            server_name=name,
            error_type=error_type,
            detail=str(e),
        )
    except asyncio.TimeoutError:
        return MCPConnectionError(
            server_name=name,
            error_type="timeout",
            detail=f"Server did not respond within {timeout}s",
        )
    except (httpx.HTTPError, OSError, ValueError) as e:
        return MCPConnectionError(
            server_name=name,
            error_type="invalid",
            detail=f"Unexpected error: {type(e).__name__}: {e}",
        )


# ═══════════════════════════════════════════════════════════════════════
# PACKAGE SPECIFIER PARSING
# ═══════════════════════════════════════════════════════════════════════

def parse_package_specifier(spec: str) -> tuple[str, list[str]] | None:
    """Parse a package specifier into (command, args) for stdio connection.

    Supported formats:
        pypi:package-name  → ("uvx", ["package-name"])
        npm:package-name   → ("npx", ["-y", "package-name"])

    Returns None if the specifier is not recognized.
    """
    spec = spec.strip()
    if spec.startswith("pypi:"):
        package = spec[5:].strip()
        if not package or not _is_safe_package_name(package):
            return None
        return ("uvx", [package])
    if spec.startswith("npm:"):
        package = spec[4:].strip()
        if not package or not _is_safe_package_name(package):
            return None
        return ("npx", ["-y", package])
    return None


_SAFE_PACKAGE_RE = re.compile(r"^[@a-zA-Z0-9][a-zA-Z0-9._\-/]*$")


def _is_safe_package_name(name: str) -> bool:
    """Check if a package name is safe to pass to a subprocess.

    Rejects names with shell metacharacters, path traversal, etc.
    """
    if not name:
        return False
    if len(name) > 200:
        return False
    if ".." in name:
        return False
    # Allow alphanumeric, hyphens, underscores, dots, slashes (for scoped npm),
    # and @ (for npm scoped packages like @org/package)
    return bool(_SAFE_PACKAGE_RE.match(name))


# ═══════════════════════════════════════════════════════════════════════
# HIGH-LEVEL API
# ═══════════════════════════════════════════════════════════════════════

def _detect_transport(server: dict) -> str:
    """Detect transport type from server config dict.

    Returns "http" if the config has a url field, "stdio" if it has command,
    or "unknown" if neither is present.
    """
    if server.get("url"):
        return "http"
    if server.get("command"):
        return "stdio"
    return "unknown"


def _build_http_headers(server: dict) -> dict[str, str]:
    """Build HTTP headers from server config.

    Merges headers from multiple sources:
      1. Explicit "headers" dict in config
      2. Authorization from "apiKey" field (Claude Desktop format)
      3. Authorization from env vars with known auth key names

    Returns combined headers dict ready for connect_http().
    """
    headers: dict[str, str] = {}

    # Source 1: explicit headers dict
    raw_headers = server.get("headers", {})
    if isinstance(raw_headers, dict):
        for k, v in raw_headers.items():
            if isinstance(k, str) and isinstance(v, str):
                headers[k] = v

    # Source 2: apiKey field (Claude Desktop HTTP server format)
    api_key = server.get("apiKey")
    if isinstance(api_key, str) and api_key and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {api_key}"

    # Source 3: auth-related env vars → Authorization header
    # Some configs put API keys in env vars even for HTTP servers
    env = server.get("env", {})
    if isinstance(env, dict) and "Authorization" not in headers:
        for env_key in ("API_KEY", "AUTH_TOKEN", "BEARER_TOKEN", "ACCESS_TOKEN"):
            val = env.get(env_key)
            if isinstance(val, str) and val and not val.startswith("${"):
                headers["Authorization"] = f"Bearer {val}"
                break

    return headers


async def scan_server(
    server: dict,
    timeout: float = DEFAULT_TIMEOUT,
) -> MCPServerSnapshot | MCPConnectionError:
    """Scan a single MCP server from its config dict.

    Supports both stdio and HTTP transport. The transport is auto-detected:
      - "url" present → HTTP transport (Streamable HTTP)
      - "command" present → stdio transport (subprocess)

    Config dict keys:
      Stdio: name, command, args, env
      HTTP:  name, url, headers, apiKey, env
    """
    name = server.get("name", "")
    transport = _detect_transport(server)

    if transport == "http":
        url = server["url"]
        name = name or url
        headers = _build_http_headers(server)
        return await connect_http(
            url, headers=headers or None, timeout=timeout, server_name=name,
        )

    if transport == "stdio":
        command = server["command"]
        name = name or command
        args = [str(a) for a in server.get("args", []) if isinstance(a, (str, int, float))]
        env = server.get("env")
        return await connect_stdio(
            command, args, env=env, timeout=timeout, server_name=name,
        )

    # Neither url nor command
    return MCPConnectionError(
        server_name=name or "unknown",
        error_type="invalid",
        detail="Server config has no command or url",
    )


async def scan_servers(
    servers: list[dict],
    concurrency: int = 3,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[MCPServerSnapshot | MCPConnectionError]:
    """Scan multiple MCP servers concurrently.

    Args:
        servers: List of server config dicts from machine_discovery
        concurrency: Max simultaneous connections
        timeout: Per-server timeout

    Returns:
        List of results (snapshot or error) in same order as input.
    """
    if not servers:
        return []

    semaphore = asyncio.Semaphore(concurrency)

    async def _scan_with_limit(server: dict) -> MCPServerSnapshot | MCPConnectionError:
        async with semaphore:
            return await scan_server(server, timeout=timeout)

    tasks = [_scan_with_limit(srv) for srv in servers]
    return list(await asyncio.gather(*tasks))
