# agentseal/toxic_flows.py
"""
Toxic flow detection — static and runtime analysis.

Classifies MCP servers by capability labels and detects dangerous
combinations that could enable data exfiltration, remote code execution,
or data destruction.

Two modes:
  Static (Wave 2): classification from config only (names + args).
  Runtime (Phase 2): classification from actual tool definitions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════
# Capability Labels
# ═══════════════════════════════════════════════════════════════════════

LABEL_PUBLIC_SINK = "public_sink"       # sends data externally
LABEL_DESTRUCTIVE = "destructive"       # modifies/deletes data
LABEL_UNTRUSTED = "untrusted_content"   # fetches external data
LABEL_PRIVATE = "private_data"          # reads sensitive data

ALL_LABELS = {LABEL_PUBLIC_SINK, LABEL_DESTRUCTIVE, LABEL_UNTRUSTED, LABEL_PRIVATE}


# ═══════════════════════════════════════════════════════════════════════
# Known Server Classifications
# ═══════════════════════════════════════════════════════════════════════

# Curated mapping of well-known MCP server packages to their capability labels.
KNOWN_SERVER_LABELS: dict[str, set[str]] = {
    # Filesystem
    "filesystem": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "fs": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    # Communication / sinks
    "slack": {LABEL_PUBLIC_SINK},
    "discord": {LABEL_PUBLIC_SINK},
    "email": {LABEL_PUBLIC_SINK},
    "gmail": {LABEL_PUBLIC_SINK},
    "smtp": {LABEL_PUBLIC_SINK},
    "sendgrid": {LABEL_PUBLIC_SINK},
    "twilio": {LABEL_PUBLIC_SINK},
    "telegram": {LABEL_PUBLIC_SINK},
    "teams": {LABEL_PUBLIC_SINK},
    "webhook": {LABEL_PUBLIC_SINK},
    # Code/project platforms
    "github": {LABEL_PUBLIC_SINK, LABEL_PRIVATE},
    "gitlab": {LABEL_PUBLIC_SINK, LABEL_PRIVATE},
    "bitbucket": {LABEL_PUBLIC_SINK, LABEL_PRIVATE},
    "linear": {LABEL_PUBLIC_SINK, LABEL_PRIVATE},
    "jira": {LABEL_PUBLIC_SINK, LABEL_PRIVATE},
    "notion": {LABEL_PUBLIC_SINK, LABEL_PRIVATE},
    "asana": {LABEL_PUBLIC_SINK, LABEL_PRIVATE},
    # Databases
    "postgres": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "postgresql": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "mysql": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "sqlite": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "mongo": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "mongodb": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "redis": {LABEL_PRIVATE, LABEL_DESTRUCTIVE},
    "supabase": {LABEL_PRIVATE, LABEL_DESTRUCTIVE, LABEL_PUBLIC_SINK},
    # Web / external content
    "fetch": {LABEL_UNTRUSTED},
    "puppeteer": {LABEL_UNTRUSTED},
    "playwright": {LABEL_UNTRUSTED},
    "browser": {LABEL_UNTRUSTED},
    "brave-search": {LABEL_UNTRUSTED},
    "tavily": {LABEL_UNTRUSTED},
    "web-search": {LABEL_UNTRUSTED},
    "scraper": {LABEL_UNTRUSTED},
    "crawl": {LABEL_UNTRUSTED},
    # Infrastructure
    "aws": {LABEL_PRIVATE, LABEL_DESTRUCTIVE, LABEL_PUBLIC_SINK},
    "gcp": {LABEL_PRIVATE, LABEL_DESTRUCTIVE, LABEL_PUBLIC_SINK},
    "azure": {LABEL_PRIVATE, LABEL_DESTRUCTIVE, LABEL_PUBLIC_SINK},
    "docker": {LABEL_DESTRUCTIVE},
    "kubernetes": {LABEL_DESTRUCTIVE},
    "k8s": {LABEL_DESTRUCTIVE},
    "terraform": {LABEL_DESTRUCTIVE},
    # Execution
    "shell": {LABEL_DESTRUCTIVE, LABEL_UNTRUSTED},
    "terminal": {LABEL_DESTRUCTIVE, LABEL_UNTRUSTED},
    "exec": {LABEL_DESTRUCTIVE},
    "code-runner": {LABEL_DESTRUCTIVE},
    "sandbox": {LABEL_DESTRUCTIVE},
    # Memory / state
    "memory": {LABEL_PRIVATE},
    "knowledge": {LABEL_PRIVATE},
    "vector": {LABEL_PRIVATE},
    # Monitoring
    "sentry": {LABEL_PRIVATE},
    "datadog": {LABEL_PRIVATE},
    "grafana": {LABEL_PRIVATE},
    # Storage
    "s3": {LABEL_PRIVATE, LABEL_PUBLIC_SINK, LABEL_DESTRUCTIVE},
    "gcs": {LABEL_PRIVATE, LABEL_PUBLIC_SINK, LABEL_DESTRUCTIVE},
    "drive": {LABEL_PRIVATE, LABEL_PUBLIC_SINK},
    "dropbox": {LABEL_PRIVATE, LABEL_PUBLIC_SINK},
}


# Heuristic patterns for servers not in the known list.
_NAME_HEURISTICS: list[tuple[re.Pattern, set[str]]] = [
    (re.compile(r"(?:file|fs|disk)", re.I), {LABEL_PRIVATE, LABEL_DESTRUCTIVE}),
    (re.compile(r"(?:mail|email|smtp)", re.I), {LABEL_PUBLIC_SINK}),
    (re.compile(r"(?:http|fetch|web|browser|scrape|crawl)", re.I), {LABEL_UNTRUSTED}),
    (re.compile(r"(?:db|sql|database|mongo|redis)", re.I), {LABEL_PRIVATE}),
    (re.compile(r"(?:exec|shell|command|terminal|run)", re.I), {LABEL_DESTRUCTIVE}),
    (re.compile(r"(?:slack|discord|teams|telegram|chat)", re.I), {LABEL_PUBLIC_SINK}),
    (re.compile(r"(?:github|gitlab|bitbucket|jira|linear)", re.I), {LABEL_PUBLIC_SINK, LABEL_PRIVATE}),
    (re.compile(r"(?:aws|gcp|azure|cloud)", re.I), {LABEL_PRIVATE, LABEL_DESTRUCTIVE}),
    (re.compile(r"(?:docker|k8s|kubernetes|terraform)", re.I), {LABEL_DESTRUCTIVE}),
    (re.compile(r"(?:s3|gcs|storage|drive|dropbox)", re.I), {LABEL_PRIVATE, LABEL_PUBLIC_SINK}),
]


def classify_server(server: dict) -> set[str]:
    """Classify an MCP server by its capability labels.

    Checks known package names first, then falls back to name heuristics.
    """
    name = server.get("name", "").lower().strip()
    raw_cmd = server.get("command", "")
    command = (" ".join(raw_cmd) if isinstance(raw_cmd, list) else str(raw_cmd)).lower()
    args_str = " ".join(str(a) for a in server.get("args", []) if isinstance(a, str)).lower()

    # Check known server names (exact match)
    if name in KNOWN_SERVER_LABELS:
        return set(KNOWN_SERVER_LABELS[name])

    # Check if any known name appears in the server name
    for known, labels in KNOWN_SERVER_LABELS.items():
        if known in name:
            return set(labels)

    # Check if any known name appears in command or args (package names)
    search_text = f"{command} {args_str}"
    for known, labels in KNOWN_SERVER_LABELS.items():
        if known in search_text:
            return set(labels)

    # Fall back to heuristic patterns
    labels: set[str] = set()
    for pattern, heuristic_labels in _NAME_HEURISTICS:
        if pattern.search(name) or pattern.search(command) or pattern.search(args_str):
            labels |= heuristic_labels

    return labels


# ═══════════════════════════════════════════════════════════════════════
# Dangerous Combinations
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ToxicFlow:
    """A detected dangerous combination of server capabilities."""
    risk_level: str  # "high", "medium"
    risk_type: str   # "data_exfiltration", "remote_code_execution", "data_destruction", "full_chain"
    title: str
    description: str
    servers_involved: list[str]
    labels_involved: list[str]
    remediation: str


def _detect_combos(
    server_labels: dict[str, set[str]],
) -> list[ToxicFlow]:
    """Detect dangerous capability combinations across servers."""
    flows: list[ToxicFlow] = []

    # Collect all labels across all servers
    all_labels: set[str] = set()
    for labels in server_labels.values():
        all_labels |= labels

    # Servers by label
    by_label: dict[str, list[str]] = {}
    for name, labels in server_labels.items():
        for label in labels:
            by_label.setdefault(label, []).append(name)

    has_private = LABEL_PRIVATE in all_labels
    has_sink = LABEL_PUBLIC_SINK in all_labels
    has_untrusted = LABEL_UNTRUSTED in all_labels
    has_destructive = LABEL_DESTRUCTIVE in all_labels

    # Full chain: untrusted + private + sink (highest risk)
    if has_untrusted and has_private and has_sink:
        flows.append(ToxicFlow(
            risk_level="high",
            risk_type="full_chain",
            title="Full attack chain detected",
            description=(
                "This agent can fetch external content, read private data, "
                "and send data externally. An attacker could inject instructions "
                "via fetched content, read sensitive files, and exfiltrate them."
            ),
            servers_involved=sorted(set(
                by_label.get(LABEL_UNTRUSTED, []) +
                by_label.get(LABEL_PRIVATE, []) +
                by_label.get(LABEL_PUBLIC_SINK, [])
            )),
            labels_involved=[LABEL_UNTRUSTED, LABEL_PRIVATE, LABEL_PUBLIC_SINK],
            remediation=(
                "Scope filesystem access to non-sensitive directories. "
                "Remove or restrict external communication servers."
            ),
        ))
        return flows  # Full chain subsumes the individual combos

    # Data exfiltration: private + sink
    if has_private and has_sink:
        flows.append(ToxicFlow(
            risk_level="high",
            risk_type="data_exfiltration",
            title="Data exfiltration path detected",
            description=(
                "This agent can read private data and send it externally. "
                "A prompt injection could instruct the agent to read sensitive "
                "files and leak them via an external service."
            ),
            servers_involved=sorted(set(
                by_label.get(LABEL_PRIVATE, []) +
                by_label.get(LABEL_PUBLIC_SINK, [])
            )),
            labels_involved=[LABEL_PRIVATE, LABEL_PUBLIC_SINK],
            remediation=(
                "Scope filesystem access to non-sensitive directories only. "
                "Review which external services truly need write access."
            ),
        ))

    # Remote code execution: untrusted + destructive
    if has_untrusted and has_destructive:
        flows.append(ToxicFlow(
            risk_level="high",
            risk_type="remote_code_execution",
            title="Remote code execution path detected",
            description=(
                "This agent can fetch external content and execute destructive "
                "operations. Fetched content could contain malicious instructions "
                "that modify files, execute commands, or alter databases."
            ),
            servers_involved=sorted(set(
                by_label.get(LABEL_UNTRUSTED, []) +
                by_label.get(LABEL_DESTRUCTIVE, [])
            )),
            labels_involved=[LABEL_UNTRUSTED, LABEL_DESTRUCTIVE],
            remediation=(
                "Add confirmation steps before destructive operations. "
                "Restrict or sandbox the execution server."
            ),
        ))

    # Data destruction: private + destructive (from different servers)
    if has_private and has_destructive:
        private_servers = set(by_label.get(LABEL_PRIVATE, []))
        destructive_servers = set(by_label.get(LABEL_DESTRUCTIVE, []))
        # Only flag if the capability spans multiple servers
        # (a single server like filesystem inherently has both)
        if private_servers != destructive_servers:
            flows.append(ToxicFlow(
                risk_level="medium",
                risk_type="data_destruction",
                title="Data destruction path detected",
                description=(
                    "This agent can read private data from one source and "
                    "perform destructive operations on another. This could "
                    "lead to data corruption or deletion."
                ),
                servers_involved=sorted(private_servers | destructive_servers),
                labels_involved=[LABEL_PRIVATE, LABEL_DESTRUCTIVE],
                remediation=(
                    "Review whether both data read and write capabilities "
                    "are necessary. Consider read-only access where possible."
                ),
            ))

    return flows


def analyze_toxic_flows(servers: list[dict]) -> list[ToxicFlow]:
    """Analyze MCP servers for dangerous capability combinations.

    Args:
        servers: List of MCP server config dicts (as returned by scan_machine).

    Returns:
        List of detected toxic flows (empty if no dangerous combos found).
    """
    if len(servers) < 2:
        return []  # Need at least 2 servers for a cross-server flow

    server_labels: dict[str, set[str]] = {}
    for srv in servers:
        name = srv.get("name", "unknown")
        labels = classify_server(srv)
        if labels:
            server_labels[name] = labels

    if not server_labels:
        return []

    return _detect_combos(server_labels)


# ═══════════════════════════════════════════════════════════════════════
# RUNTIME CLASSIFICATION (Phase 2) — Tool-Level Analysis
# ═══════════════════════════════════════════════════════════════════════

from agentseal.mcp_runtime import MCPServerSnapshot, MCPToolSnapshot


@dataclass
class ToolCapability:
    """Classification result for a single MCP tool."""
    tool_name: str
    server_name: str
    labels: set[str]       # subset of ALL_LABELS
    confidence: float      # 0.0–1.0 (highest evidence confidence)


# Keyword → capability label mapping for tool name/description analysis.
TOOL_KEYWORD_LABELS: dict[str, set[str]] = {
    # private_data indicators
    "read": {LABEL_PRIVATE},
    "get": {LABEL_PRIVATE},
    "list": {LABEL_PRIVATE},
    "query": {LABEL_PRIVATE},
    "search": {LABEL_PRIVATE},
    # untrusted_content indicators
    "fetch": {LABEL_UNTRUSTED},
    "download": {LABEL_UNTRUSTED},
    "browse": {LABEL_UNTRUSTED},
    "crawl": {LABEL_UNTRUSTED},
    "scrape": {LABEL_UNTRUSTED},
    # public_sink indicators
    "send": {LABEL_PUBLIC_SINK},
    "post": {LABEL_PUBLIC_SINK},
    "publish": {LABEL_PUBLIC_SINK},
    "notify": {LABEL_PUBLIC_SINK},
    "upload": {LABEL_PUBLIC_SINK},
    "email": {LABEL_PUBLIC_SINK},
    "message": {LABEL_PUBLIC_SINK},
    "tweet": {LABEL_PUBLIC_SINK},
    "share": {LABEL_PUBLIC_SINK},
    # destructive indicators
    "delete": {LABEL_DESTRUCTIVE},
    "remove": {LABEL_DESTRUCTIVE},
    "drop": {LABEL_DESTRUCTIVE},
    "execute": {LABEL_DESTRUCTIVE},
    "run": {LABEL_DESTRUCTIVE},
    "write": {LABEL_DESTRUCTIVE},
    "create": {LABEL_DESTRUCTIVE},
    "update": {LABEL_DESTRUCTIVE},
    "modify": {LABEL_DESTRUCTIVE},
    "truncate": {LABEL_DESTRUCTIVE},
}

# Pre-compiled word-boundary patterns for each keyword (performance).
_KEYWORD_PATTERNS: dict[str, re.Pattern] = {
    kw: re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE)
    for kw in TOOL_KEYWORD_LABELS
}

# Parameter name → capability label mapping.
PARAM_NAME_LABELS: dict[str, set[str]] = {
    "file_path": {LABEL_PRIVATE},
    "filepath": {LABEL_PRIVATE},
    "filename": {LABEL_PRIVATE},
    "path": {LABEL_PRIVATE},
    "directory": {LABEL_PRIVATE},
    "dir": {LABEL_PRIVATE},
    "query": {LABEL_PRIVATE},
    "sql": {LABEL_PRIVATE},
    "table": {LABEL_PRIVATE},
    "database": {LABEL_PRIVATE},
    "url": {LABEL_UNTRUSTED},
    "uri": {LABEL_UNTRUSTED},
    "endpoint": {LABEL_UNTRUSTED},
    "href": {LABEL_UNTRUSTED},
    "command": {LABEL_DESTRUCTIVE},
    "cmd": {LABEL_DESTRUCTIVE},
    "script": {LABEL_DESTRUCTIVE},
    "shell": {LABEL_DESTRUCTIVE},
    "recipient": {LABEL_PUBLIC_SINK},
    "to": {LABEL_PUBLIC_SINK},
    "channel": {LABEL_PUBLIC_SINK},
    "webhook": {LABEL_PUBLIC_SINK},
    "webhook_url": {LABEL_PUBLIC_SINK},
}

# Patterns that indicate a "url" param is used for outbound sending.
_OUTBOUND_URL_PATTERNS: re.Pattern = re.compile(
    r"\b(?:post|send|upload|push|forward|submit)\b", re.IGNORECASE
)


def classify_tool(tool: MCPToolSnapshot, server_name: str) -> ToolCapability:
    """Classify a single tool by its name, description, params, and annotations.

    Three analysis layers:
      1. Keyword matching on name + description
      2. Parameter name analysis
      3. Annotation analysis (destructiveHint, readOnlyHint)

    Returns:
        ToolCapability with labels and confidence score.
    """
    labels: set[str] = set()
    max_confidence = 0.0

    text_name = tool.name or ""
    text_desc = tool.description or ""

    # ── Layer 1: Keyword matching ─────────────────────────────────────
    # Tool names use underscores/hyphens as separators (e.g. "read_file").
    # Since _ is a word character in regex, \bread\b won't match inside
    # "read_file". Split name into segments for accurate matching.
    name_segments = set(re.split(r"[_\-.]", text_name.lower()))

    for keyword, kw_labels in TOOL_KEYWORD_LABELS.items():
        # Check name via segment matching (more reliable for tool names)
        if keyword in name_segments:
            labels |= kw_labels
            max_confidence = max(max_confidence, 0.8)
        # Check description via word boundary regex (natural language)
        elif _KEYWORD_PATTERNS[keyword].search(text_desc):
            labels |= kw_labels
            max_confidence = max(max_confidence, 0.7)

    # ── Layer 2: Parameter name analysis ──────────────────────────────
    schema = tool.input_schema or {}
    properties = schema.get("properties", {})
    if isinstance(properties, dict):
        for param_name in properties:
            if not isinstance(param_name, str):
                continue
            param_lower = param_name.lower()
            if param_lower in PARAM_NAME_LABELS:
                param_labels = PARAM_NAME_LABELS[param_lower]
                labels |= param_labels
                max_confidence = max(max_confidence, 0.6)

                # Special: url param + outbound verb in description → also public_sink
                if param_lower in ("url", "uri", "endpoint", "href"):
                    if _OUTBOUND_URL_PATTERNS.search(text_desc):
                        labels.add(LABEL_PUBLIC_SINK)

    # ── Layer 3: Annotation analysis ──────────────────────────────────
    annotations = tool.annotations or {}
    if annotations.get("destructiveHint") is True:
        labels.add(LABEL_DESTRUCTIVE)
        max_confidence = max(max_confidence, 1.0)

    if annotations.get("readOnlyHint") is True:
        # Annotations are attacker-controlled. A malicious server can set
        # readOnlyHint=true on a destructive tool to evade detection.
        # Only use annotations to ADD labels, never to REMOVE them.
        pass

    if annotations.get("openWorldHint") is True:
        labels.add(LABEL_UNTRUSTED)
        max_confidence = max(max_confidence, 1.0)

    return ToolCapability(
        tool_name=tool.name,
        server_name=server_name,
        labels=labels,
        confidence=max_confidence,
    )


def classify_server_runtime(
    snapshot: MCPServerSnapshot,
) -> list[ToolCapability]:
    """Classify all tools in a server snapshot using runtime tool definitions.

    Classification strategy:
      1. Known server name → apply known labels to all tools (fast path)
         PLUS union with tool-level analysis for additional labels.
      2. Unknown server → classify each tool individually.
      3. No tools → fall back to server name heuristics.
    """
    server_name = snapshot.server_name
    server_name_lower = server_name.lower().strip()

    # Resolve known server labels (if any)
    known_labels: set[str] = set()
    if server_name_lower in KNOWN_SERVER_LABELS:
        known_labels = set(KNOWN_SERVER_LABELS[server_name_lower])
    else:
        for known, labels in KNOWN_SERVER_LABELS.items():
            if known in server_name_lower:
                known_labels = set(labels)
                break

    # If no tools, fall back to name-based classification
    if not snapshot.tools:
        if not known_labels:
            # Try heuristic patterns on server name
            for pattern, h_labels in _NAME_HEURISTICS:
                if pattern.search(server_name_lower):
                    known_labels |= h_labels
        if known_labels:
            # Known server name → 1.0; heuristic match → 0.5
            conf = 1.0 if server_name_lower in KNOWN_SERVER_LABELS else 0.5
            return [ToolCapability(
                tool_name="",
                server_name=server_name,
                labels=known_labels,
                confidence=conf,
            )]
        return []

    # Classify each tool individually
    capabilities: list[ToolCapability] = []
    for tool in snapshot.tools:
        cap = classify_tool(tool, server_name)
        # Union with known labels (known server always applies to all tools)
        if known_labels:
            cap.labels |= known_labels
            cap.confidence = max(cap.confidence, 1.0)
        capabilities.append(cap)

    return capabilities


def _detect_tool_combos(
    capabilities: list[ToolCapability],
) -> list[ToxicFlow]:
    """Detect dangerous tool combinations WITHIN a single server.

    Only flags when DIFFERENT tools provide the dangerous labels.
    A single tool having multiple labels is normal (e.g. file manager).
    """
    flows: list[ToxicFlow] = []

    # Group capabilities by server
    by_server: dict[str, list[ToolCapability]] = {}
    for cap in capabilities:
        by_server.setdefault(cap.server_name, []).append(cap)

    for server_name, tools in by_server.items():
        if len(tools) < 2:
            continue

        # Build per-tool label mapping: label → set of tool names
        label_tools: dict[str, set[str]] = {}
        for cap in tools:
            for label in cap.labels:
                label_tools.setdefault(label, set()).add(cap.tool_name)

        # All labels available on this server
        all_labels = set(label_tools.keys())

        # Check dangerous combos where different tools provide the labels
        def _diff_tools(label_a: str, label_b: str) -> bool:
            """True if the two labels come from at least some different tools."""
            tools_a = label_tools.get(label_a, set())
            tools_b = label_tools.get(label_b, set())
            return bool(tools_a - tools_b) or bool(tools_b - tools_a)

        # Full chain: untrusted + private + sink from different tools
        if (LABEL_UNTRUSTED in all_labels
                and LABEL_PRIVATE in all_labels
                and LABEL_PUBLIC_SINK in all_labels):
            # At least two of the three must come from different tools
            labels_to_check = [LABEL_UNTRUSTED, LABEL_PRIVATE, LABEL_PUBLIC_SINK]
            has_separation = any(
                _diff_tools(labels_to_check[i], labels_to_check[j])
                for i in range(len(labels_to_check))
                for j in range(i + 1, len(labels_to_check))
            )
            if has_separation:
                flows.append(ToxicFlow(
                    risk_level="high",
                    risk_type="full_chain",
                    title="Intra-server full attack chain",
                    description=(
                        f"Server '{server_name}' has tools that collectively can "
                        f"fetch external content, read private data, and send data "
                        f"externally — enabling a full attack chain within one server."
                    ),
                    servers_involved=[server_name],
                    labels_involved=[LABEL_UNTRUSTED, LABEL_PRIVATE, LABEL_PUBLIC_SINK],
                    remediation=(
                        f"Review server '{server_name}' tool permissions. "
                        f"Consider splitting into separate servers with reduced scope."
                    ),
                ))
                continue  # Full chain subsumes individual combos

        # Data exfiltration: private + sink from different tools
        if (LABEL_PRIVATE in all_labels
                and LABEL_PUBLIC_SINK in all_labels
                and _diff_tools(LABEL_PRIVATE, LABEL_PUBLIC_SINK)):
            flows.append(ToxicFlow(
                risk_level="high",
                risk_type="data_exfiltration",
                title="Intra-server data exfiltration path",
                description=(
                    f"Server '{server_name}' has tools that can read private "
                    f"data and send it externally within the same server."
                ),
                servers_involved=[server_name],
                labels_involved=[LABEL_PRIVATE, LABEL_PUBLIC_SINK],
                remediation=(
                    f"Review server '{server_name}'. Consider removing "
                    f"external communication tools or restricting data access."
                ),
            ))

        # RCE: untrusted + destructive from different tools
        if (LABEL_UNTRUSTED in all_labels
                and LABEL_DESTRUCTIVE in all_labels
                and _diff_tools(LABEL_UNTRUSTED, LABEL_DESTRUCTIVE)):
            flows.append(ToxicFlow(
                risk_level="high",
                risk_type="remote_code_execution",
                title="Intra-server remote code execution path",
                description=(
                    f"Server '{server_name}' has tools that can fetch external "
                    f"content and execute destructive operations."
                ),
                servers_involved=[server_name],
                labels_involved=[LABEL_UNTRUSTED, LABEL_DESTRUCTIVE],
                remediation=(
                    f"Review server '{server_name}'. Consider sandboxing "
                    f"destructive operations or restricting external content access."
                ),
            ))

    return flows


def analyze_toxic_flows_runtime(
    snapshots: list[MCPServerSnapshot],
) -> list[ToxicFlow]:
    """Analyze MCP servers for dangerous capability combinations using runtime data.

    Uses actual tool definitions (names, descriptions, parameters, annotations)
    for more accurate classification than static name-based analysis.

    Detects both cross-server and intra-server dangerous tool combinations.

    Args:
        snapshots: List of MCPServerSnapshot objects from mcp_runtime.

    Returns:
        List of detected toxic flows (empty if safe).
    """
    if not snapshots:
        return []

    # Step 1: Classify all tools across all servers
    all_capabilities: list[ToolCapability] = []
    for snapshot in snapshots:
        caps = classify_server_runtime(snapshot)
        all_capabilities.extend(caps)

    if not all_capabilities:
        return []

    # Step 2: Build server-level label union for cross-server detection
    server_labels: dict[str, set[str]] = {}
    for cap in all_capabilities:
        server_labels.setdefault(cap.server_name, set()).update(cap.labels)

    # Remove servers with no labels
    server_labels = {k: v for k, v in server_labels.items() if v}

    flows: list[ToxicFlow] = []

    # Step 3: Cross-server combo detection (reuse existing logic, needs 2+ servers)
    if len(server_labels) >= 2:
        cross_flows = _detect_combos(server_labels)
        # Annotate cross-server flows with tool-level detail
        for flow in cross_flows:
            tools_involved = _collect_tools_for_flow(
                flow.labels_involved, all_capabilities, flow.servers_involved,
            )
            flow.servers_involved = flow.servers_involved  # already set
            # Enrich description with tool-level detail if available
            if tools_involved:
                tool_detail = ", ".join(tools_involved[:10])
                flow.description += f" Tools involved: {tool_detail}."
        flows.extend(cross_flows)

    # Step 4: Intra-server tool combo detection
    intra_flows = _detect_tool_combos(all_capabilities)
    flows.extend(intra_flows)

    return flows


def _collect_tools_for_flow(
    labels: list[str],
    capabilities: list[ToolCapability],
    servers: list[str],
) -> list[str]:
    """Collect qualified tool names (server:tool) that contribute to a flow."""
    result: list[str] = []
    server_set = set(servers)
    for cap in capabilities:
        if cap.server_name not in server_set:
            continue
        if not cap.tool_name:
            continue
        contributing_labels = cap.labels & set(labels)
        if contributing_labels:
            label_str = "+".join(sorted(contributing_labels))
            qualified = f"{cap.server_name}:{cap.tool_name} ({label_str})"
            if qualified not in result:
                result.append(qualified)
    return result
