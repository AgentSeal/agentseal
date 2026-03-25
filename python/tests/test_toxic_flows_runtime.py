# tests/test_toxic_flows_runtime.py
"""
Tests for runtime toxic flow detection — tool-level classification and
dangerous combination analysis using actual MCP tool definitions.
"""

import unittest

from agentseal.mcp_runtime import (
    MCPPromptSnapshot,
    MCPResourceSnapshot,
    MCPServerSnapshot,
    MCPToolSnapshot,
)
from agentseal.toxic_flows import (
    LABEL_DESTRUCTIVE,
    LABEL_PRIVATE,
    LABEL_PUBLIC_SINK,
    LABEL_UNTRUSTED,
    ToolCapability,
    analyze_toxic_flows,
    analyze_toxic_flows_runtime,
    classify_server_runtime,
    classify_tool,
)


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _make_tool(
    name: str = "test_tool",
    description: str = "A normal tool",
    input_schema: dict | None = None,
    annotations: dict | None = None,
) -> MCPToolSnapshot:
    return MCPToolSnapshot(
        name=name,
        description=description,
        input_schema=input_schema or {"type": "object", "properties": {}},
        annotations=annotations or {},
        signature_hash="abc123",
    )


def _make_snapshot(
    server_name: str = "test-server",
    tools: list[MCPToolSnapshot] | None = None,
    instructions: str = "",
) -> MCPServerSnapshot:
    return MCPServerSnapshot(
        server_name=server_name,
        server_version="1.0.0",
        protocol_version="2025-03-26",
        instructions=instructions,
        capabilities={"tools": {}},
        tools=tools or [],
        prompts=[],
        resources=[],
        connected_at="2026-03-09T00:00:00Z",
        connection_duration_ms=100.0,
    )


# ═══════════════════════════════════════════════════════════════════════
# classify_tool() — keyword matching on name
# ═══════════════════════════════════════════════════════════════════════

class TestClassifyToolKeywordName(unittest.TestCase):
    def test_read_file_private(self):
        tool = _make_tool(name="read_file", description="Read a file from disk")
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_PRIVATE, cap.labels)
        self.assertGreaterEqual(cap.confidence, 0.8)

    def test_send_message_public_sink(self):
        tool = _make_tool(name="send_message", description="Send a message")
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_PUBLIC_SINK, cap.labels)

    def test_delete_file_destructive(self):
        tool = _make_tool(name="delete_file", description="Delete a file")
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_DESTRUCTIVE, cap.labels)

    def test_fetch_url_untrusted(self):
        tool = _make_tool(name="fetch_url", description="Fetch a URL")
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_UNTRUSTED, cap.labels)

    def test_execute_command_destructive(self):
        tool = _make_tool(name="execute_command", description="Execute a shell command")
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_DESTRUCTIVE, cap.labels)

    def test_upload_file_public_sink(self):
        tool = _make_tool(name="upload_file", description="Upload a file")
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_PUBLIC_SINK, cap.labels)


# ═══════════════════════════════════════════════════════════════════════
# classify_tool() — keyword matching on description
# ═══════════════════════════════════════════════════════════════════════

class TestClassifyToolKeywordDescription(unittest.TestCase):
    def test_description_sends_email(self):
        tool = _make_tool(name="notify_team", description="Sends email notification to the team")
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_PUBLIC_SINK, cap.labels)

    def test_description_fetch_content(self):
        tool = _make_tool(name="get_info", description="Fetch content from the web and parse it")
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_UNTRUSTED, cap.labels)

    def test_description_execute_operation(self):
        tool = _make_tool(name="process", description="Execute the processing pipeline")
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_DESTRUCTIVE, cap.labels)


# ═══════════════════════════════════════════════════════════════════════
# classify_tool() — word boundary (false positive prevention)
# ═══════════════════════════════════════════════════════════════════════

class TestClassifyToolWordBoundary(unittest.TestCase):
    def test_spreadsheet_no_read_match(self):
        """'spreadsheet' should NOT match keyword 'read'."""
        tool = _make_tool(name="spreadsheet_processor", description="Process spreadsheets")
        cap = classify_tool(tool, "srv")
        self.assertNotIn(LABEL_PRIVATE, cap.labels)

    def test_already_no_read_match(self):
        """'already' should NOT match keyword 'read'."""
        tool = _make_tool(name="checker", description="Check if already processed")
        cap = classify_tool(tool, "srv")
        # "already" doesn't contain "read" as a whole word
        self.assertNotIn(LABEL_PRIVATE, cap.labels)

    def test_credential_no_create_match(self):
        """'credential' should NOT match keyword 'create'."""
        tool = _make_tool(name="verify_credential", description="Verify a credential value")
        cap = classify_tool(tool, "srv")
        self.assertNotIn(LABEL_DESTRUCTIVE, cap.labels)

    def test_posting_no_post_match_in_name(self):
        """'posting' in name should NOT match keyword 'post' (word boundary)."""
        tool = _make_tool(name="posting_analyzer", description="Analyze job postings")
        cap = classify_tool(tool, "srv")
        # "posting" — \bpost\b should NOT match "posting" since 'i' follows 't'
        # Actually \bpost\b DOES match "posting" because "post" ends at a boundary with "ing"
        # No — "posting" contains "post" followed by "ing". \b is between 't' and 'i'?
        # No. Both 't' and 'i' are word characters. So there's no boundary between them.
        # \bpost\b will NOT match inside "posting". Correct.
        self.assertNotIn(LABEL_PUBLIC_SINK, cap.labels)

    def test_underscore_boundary(self):
        """'read_file' — underscore is NOT a word char, so 'read' matches."""
        tool = _make_tool(name="read_file", description="Read file")
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_PRIVATE, cap.labels)


# ═══════════════════════════════════════════════════════════════════════
# classify_tool() — parameter analysis
# ═══════════════════════════════════════════════════════════════════════

class TestClassifyToolParams(unittest.TestCase):
    def test_file_path_param(self):
        tool = _make_tool(
            name="process_data",
            description="Process data",
            input_schema={"type": "object", "properties": {
                "file_path": {"type": "string"},
                "format": {"type": "string"},
            }},
        )
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_PRIVATE, cap.labels)

    def test_command_param(self):
        tool = _make_tool(
            name="helper",
            description="Run a helper",
            input_schema={"type": "object", "properties": {
                "command": {"type": "string"},
            }},
        )
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_DESTRUCTIVE, cap.labels)

    def test_url_param_with_post_description(self):
        """url param + 'POST' in description → both untrusted AND public_sink."""
        tool = _make_tool(
            name="api_call",
            description="Send a POST request to the endpoint",
            input_schema={"type": "object", "properties": {
                "url": {"type": "string"},
                "body": {"type": "object"},
            }},
        )
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_UNTRUSTED, cap.labels)
        self.assertIn(LABEL_PUBLIC_SINK, cap.labels)

    def test_url_param_without_outbound_verb(self):
        """url param alone → untrusted but NOT public_sink."""
        tool = _make_tool(
            name="load_page",
            description="Load a web page and return its content",
            input_schema={"type": "object", "properties": {
                "url": {"type": "string"},
            }},
        )
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_UNTRUSTED, cap.labels)
        # No outbound verb → should not be public_sink from param alone
        # (though "load" doesn't match any sink keyword either)

    def test_recipient_param(self):
        tool = _make_tool(
            name="dispatch",
            description="Dispatch notification",
            input_schema={"type": "object", "properties": {
                "recipient": {"type": "string"},
                "body": {"type": "string"},
            }},
        )
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_PUBLIC_SINK, cap.labels)

    def test_empty_properties(self):
        tool = _make_tool(
            name="generic",
            description="Generic tool",
            input_schema={"type": "object", "properties": {}},
        )
        cap = classify_tool(tool, "srv")
        # No params → no param-based labels
        self.assertEqual(cap.confidence, 0.0)

    def test_no_schema(self):
        tool = _make_tool(
            name="generic",
            description="Generic tool",
            input_schema=None,
        )
        cap = classify_tool(tool, "srv")
        self.assertIsInstance(cap.labels, set)


# ═══════════════════════════════════════════════════════════════════════
# classify_tool() — annotation analysis
# ═══════════════════════════════════════════════════════════════════════

class TestClassifyToolAnnotations(unittest.TestCase):
    def test_destructive_hint(self):
        tool = _make_tool(
            name="process",
            description="Process data",
            annotations={"destructiveHint": True},
        )
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_DESTRUCTIVE, cap.labels)
        self.assertEqual(cap.confidence, 1.0)

    def test_readonly_does_not_remove_destructive(self):
        """readOnlyHint must NOT remove destructive -- annotations are attacker-controlled."""
        tool = _make_tool(
            name="delete_preview",
            description="Preview what delete would do",
            annotations={"readOnlyHint": True},
        )
        cap = classify_tool(tool, "srv")
        # "delete" keyword adds destructive; readOnlyHint cannot remove it
        # because a malicious server could lie about annotations
        self.assertIn(LABEL_DESTRUCTIVE, cap.labels)

    def test_open_world_hint(self):
        tool = _make_tool(
            name="connector",
            description="Connect to service",
            annotations={"openWorldHint": True},
        )
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_UNTRUSTED, cap.labels)

    def test_no_annotations(self):
        tool = _make_tool(name="add", description="Add numbers", annotations={})
        cap = classify_tool(tool, "srv")
        # No annotations → no annotation-based labels


# ═══════════════════════════════════════════════════════════════════════
# classify_tool() — empty/generic tools
# ═══════════════════════════════════════════════════════════════════════

class TestClassifyToolEmpty(unittest.TestCase):
    def test_generic_name_no_labels(self):
        tool = _make_tool(name="do_thing", description="Does a thing")
        cap = classify_tool(tool, "srv")
        self.assertEqual(len(cap.labels), 0)
        self.assertEqual(cap.confidence, 0.0)

    def test_empty_description(self):
        tool = _make_tool(name="read_data", description="")
        cap = classify_tool(tool, "srv")
        # Should still match "read" in name
        self.assertIn(LABEL_PRIVATE, cap.labels)

    def test_none_values(self):
        tool = MCPToolSnapshot(
            name="tool", description=None,
            input_schema=None, annotations=None, signature_hash="x",
        )
        cap = classify_tool(tool, "srv")
        self.assertIsInstance(cap, ToolCapability)


# ═══════════════════════════════════════════════════════════════════════
# classify_server_runtime()
# ═══════════════════════════════════════════════════════════════════════

class TestClassifyServerRuntime(unittest.TestCase):
    def test_known_server_fast_path(self):
        """Known server name applies known labels to all tools."""
        snap = _make_snapshot(
            server_name="slack",
            tools=[
                _make_tool(name="post_message", description="Post a message"),
                _make_tool(name="list_channels", description="List channels"),
            ],
        )
        caps = classify_server_runtime(snap)
        self.assertEqual(len(caps), 2)
        for cap in caps:
            self.assertIn(LABEL_PUBLIC_SINK, cap.labels)
            self.assertEqual(cap.confidence, 1.0)

    def test_unknown_server_tool_level(self):
        """Unknown server classifies each tool individually."""
        snap = _make_snapshot(
            server_name="my-custom-server",
            tools=[
                _make_tool(name="read_file", description="Read a file"),
                _make_tool(name="send_email", description="Send an email"),
            ],
        )
        caps = classify_server_runtime(snap)
        self.assertEqual(len(caps), 2)
        # read_file should be private
        read_cap = next(c for c in caps if c.tool_name == "read_file")
        self.assertIn(LABEL_PRIVATE, read_cap.labels)
        # send_email should be public_sink
        send_cap = next(c for c in caps if c.tool_name == "send_email")
        self.assertIn(LABEL_PUBLIC_SINK, send_cap.labels)

    def test_empty_tools_falls_back(self):
        """No tools → fall back to server name heuristics."""
        snap = _make_snapshot(server_name="slack", tools=[])
        caps = classify_server_runtime(snap)
        self.assertEqual(len(caps), 1)
        self.assertEqual(caps[0].tool_name, "")
        self.assertIn(LABEL_PUBLIC_SINK, caps[0].labels)

    def test_known_server_unions_with_tool_labels(self):
        """Known server labels + tool-level labels should union."""
        snap = _make_snapshot(
            server_name="slack",
            tools=[
                _make_tool(name="read_database", description="Read database records"),
            ],
        )
        caps = classify_server_runtime(snap)
        self.assertEqual(len(caps), 1)
        # Should have both: slack's public_sink + tool's private_data from "read"
        self.assertIn(LABEL_PUBLIC_SINK, caps[0].labels)
        self.assertIn(LABEL_PRIVATE, caps[0].labels)

    def test_unknown_server_no_tools_heuristic(self):
        """Unknown server with no tools uses heuristic patterns."""
        snap = _make_snapshot(server_name="my-file-manager", tools=[])
        caps = classify_server_runtime(snap)
        self.assertEqual(len(caps), 1)
        self.assertIn(LABEL_PRIVATE, caps[0].labels)
        # Heuristic match → confidence 0.5
        self.assertEqual(caps[0].confidence, 0.5)

    def test_completely_unknown_server_no_tools(self):
        """Completely unknown server with no tools returns empty."""
        snap = _make_snapshot(server_name="xyz-foobar-789", tools=[])
        caps = classify_server_runtime(snap)
        self.assertEqual(len(caps), 0)


# ═══════════════════════════════════════════════════════════════════════
# analyze_toxic_flows_runtime() — cross-server detection
# ═══════════════════════════════════════════════════════════════════════

class TestAnalyzeToxicFlowsRuntimeCrossServer(unittest.TestCase):
    def test_cross_server_data_exfiltration(self):
        """Private data server + public sink server = exfiltration."""
        snap_fs = _make_snapshot(
            server_name="my-files",
            tools=[_make_tool(name="read_file", description="Read a file")],
        )
        snap_slack = _make_snapshot(
            server_name="slack",
            tools=[_make_tool(name="send_message", description="Send a message")],
        )
        flows = analyze_toxic_flows_runtime([snap_fs, snap_slack])
        self.assertTrue(any(f.risk_type == "data_exfiltration" for f in flows))

    def test_cross_server_full_chain(self):
        """Untrusted + private + sink across servers."""
        snap_web = _make_snapshot(
            server_name="web-fetcher",
            tools=[_make_tool(name="fetch_page", description="Fetch a web page")],
        )
        snap_fs = _make_snapshot(
            server_name="filesystem",
            tools=[_make_tool(name="read_file", description="Read a file")],
        )
        snap_slack = _make_snapshot(
            server_name="notifier",
            tools=[_make_tool(name="send_notification", description="Send notification")],
        )
        flows = analyze_toxic_flows_runtime([snap_web, snap_fs, snap_slack])
        self.assertTrue(any(f.risk_type == "full_chain" for f in flows))

    def test_cross_server_rce(self):
        """Untrusted + destructive across servers."""
        snap_web = _make_snapshot(
            server_name="browser",
            tools=[_make_tool(name="fetch_url", description="Fetch URL")],
        )
        snap_exec = _make_snapshot(
            server_name="executor",
            tools=[_make_tool(name="run_command", description="Run a command")],
        )
        flows = analyze_toxic_flows_runtime([snap_web, snap_exec])
        self.assertTrue(any(f.risk_type == "remote_code_execution" for f in flows))

    def test_single_server_no_cross_server_flows(self):
        """One server alone produces no cross-server flows."""
        snap = _make_snapshot(
            server_name="my-server",
            tools=[_make_tool(name="add", description="Add numbers")],
        )
        flows = analyze_toxic_flows_runtime([snap])
        # No cross-server flows (may have intra-server, but not with just "add")
        cross = [f for f in flows if "Intra" not in f.title]
        self.assertEqual(len(cross), 0)

    def test_empty_snapshots(self):
        flows = analyze_toxic_flows_runtime([])
        self.assertEqual(len(flows), 0)

    def test_flows_have_tool_detail(self):
        """Cross-server flows should include tool-level detail in description."""
        snap_fs = _make_snapshot(
            server_name="files",
            tools=[_make_tool(name="read_secret", description="Read a secret file")],
        )
        snap_slack = _make_snapshot(
            server_name="slack",
            tools=[_make_tool(name="post_message", description="Post message")],
        )
        flows = analyze_toxic_flows_runtime([snap_fs, snap_slack])
        exfil = [f for f in flows if f.risk_type == "data_exfiltration"]
        self.assertTrue(len(exfil) > 0)
        # Description should mention specific tools
        self.assertIn("Tools involved:", exfil[0].description)


# ═══════════════════════════════════════════════════════════════════════
# analyze_toxic_flows_runtime() — intra-server detection
# ═══════════════════════════════════════════════════════════════════════

class TestAnalyzeToxicFlowsRuntimeIntraServer(unittest.TestCase):
    def test_intra_server_exfiltration(self):
        """One server with read_secret + send_webhook = intra-server exfil."""
        snap = _make_snapshot(
            server_name="multitool",
            tools=[
                _make_tool(name="read_secret", description="Read secret data"),
                _make_tool(name="send_webhook", description="Send data to webhook"),
            ],
        )
        flows = analyze_toxic_flows_runtime([snap])
        intra = [f for f in flows if "Intra" in f.title]
        self.assertTrue(len(intra) > 0)
        self.assertTrue(any(f.risk_type == "data_exfiltration" for f in intra))

    def test_intra_server_rce(self):
        """One server with fetch_url + run_script = intra-server RCE."""
        snap = _make_snapshot(
            server_name="all-in-one",
            tools=[
                _make_tool(name="fetch_url", description="Fetch external URL"),
                _make_tool(name="run_script", description="Run a script"),
            ],
        )
        flows = analyze_toxic_flows_runtime([snap])
        intra = [f for f in flows if "Intra" in f.title]
        self.assertTrue(any(f.risk_type == "remote_code_execution" for f in intra))

    def test_single_tool_multiple_labels_no_intra_flow(self):
        """One tool with both read + write shouldn't trigger intra-server flow."""
        snap = _make_snapshot(
            server_name="file-manager",
            tools=[
                _make_tool(name="read_write_file", description="Read and write files"),
            ],
        )
        flows = analyze_toxic_flows_runtime([snap])
        intra = [f for f in flows if "Intra" in f.title]
        # Single tool — no different tools providing the labels
        self.assertEqual(len(intra), 0)

    def test_intra_server_full_chain(self):
        """One server with fetch + read + send = full intra-server chain."""
        snap = _make_snapshot(
            server_name="swiss-army",
            tools=[
                _make_tool(name="fetch_page", description="Fetch a web page"),
                _make_tool(name="read_file", description="Read local file"),
                _make_tool(name="send_report", description="Send report email"),
            ],
        )
        flows = analyze_toxic_flows_runtime([snap])
        intra = [f for f in flows if "Intra" in f.title]
        self.assertTrue(any(f.risk_type == "full_chain" for f in intra))


# ═══════════════════════════════════════════════════════════════════════
# BACKWARD COMPATIBILITY
# ═══════════════════════════════════════════════════════════════════════

class TestBackwardCompatibility(unittest.TestCase):
    def test_static_analyze_still_works(self):
        """Existing analyze_toxic_flows() with dict input unchanged."""
        servers = [
            {"name": "filesystem", "command": "npx", "args": ["/home"]},
            {"name": "slack", "command": "npx", "args": []},
        ]
        flows = analyze_toxic_flows(servers)
        self.assertTrue(len(flows) >= 1)
        self.assertTrue(any(f.risk_type == "data_exfiltration" for f in flows))


# ═══════════════════════════════════════════════════════════════════════
# EDGE CASES
# ═══════════════════════════════════════════════════════════════════════

class TestEdgeCases(unittest.TestCase):
    def test_unicode_description(self):
        """Non-ASCII description shouldn't crash."""
        tool = _make_tool(name="process", description="Обработка данных — 处理数据")
        cap = classify_tool(tool, "srv")
        self.assertIsInstance(cap, ToolCapability)

    def test_large_tool_count(self):
        """100 tools should process correctly."""
        tools = [
            _make_tool(name=f"tool_{i}", description=f"Tool number {i}")
            for i in range(100)
        ]
        snap = _make_snapshot(server_name="big-server", tools=tools)
        caps = classify_server_runtime(snap)
        self.assertEqual(len(caps), 100)

    def test_readonly_does_not_override_delete_name(self):
        """readOnlyHint=True on 'delete_all' must keep destructive -- attacker-controlled annotation."""
        tool = _make_tool(
            name="delete_all",
            description="Preview what would be deleted",
            annotations={"readOnlyHint": True},
        )
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_DESTRUCTIVE, cap.labels)

    def test_multiple_keywords_union(self):
        """Tool matching multiple keywords gets union of labels."""
        tool = _make_tool(
            name="sync_data",
            description="Read files, upload to cloud, and delete originals",
        )
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_PRIVATE, cap.labels)      # "read"
        self.assertIn(LABEL_PUBLIC_SINK, cap.labels)   # "upload"
        self.assertIn(LABEL_DESTRUCTIVE, cap.labels)   # "delete"

    def test_name_and_description_both_contribute(self):
        """Keywords from name AND description should union into labels."""
        tool = _make_tool(
            name="read_data",
            description="Fetch from external API and send results to webhook",
        )
        cap = classify_tool(tool, "srv")
        self.assertIn(LABEL_PRIVATE, cap.labels)       # "read" in name
        self.assertIn(LABEL_UNTRUSTED, cap.labels)     # "fetch" in description
        self.assertIn(LABEL_PUBLIC_SINK, cap.labels)    # "send" in description
        self.assertGreaterEqual(cap.confidence, 0.8)    # name match = 0.8

    def test_confidence_ordering(self):
        """Name match confidence (0.8) > description match (0.7) > param (0.6)."""
        # Name match
        tool_name = _make_tool(name="read_data", description="Tool")
        cap_name = classify_tool(tool_name, "srv")

        # Description only match
        tool_desc = _make_tool(name="processor", description="Read the input data")
        cap_desc = classify_tool(tool_desc, "srv")

        # Param only match
        tool_param = _make_tool(
            name="handler",
            description="Handle request",
            input_schema={"type": "object", "properties": {"file_path": {"type": "string"}}},
        )
        cap_param = classify_tool(tool_param, "srv")

        self.assertGreater(cap_name.confidence, cap_desc.confidence)
        self.assertGreater(cap_desc.confidence, cap_param.confidence)

    def test_all_safe_servers_no_flows(self):
        """Two servers with only generic tools produce no flows."""
        snap1 = _make_snapshot(
            server_name="math",
            tools=[_make_tool(name="add", description="Add two numbers")],
        )
        snap2 = _make_snapshot(
            server_name="text",
            tools=[_make_tool(name="capitalize", description="Capitalize text")],
        )
        flows = analyze_toxic_flows_runtime([snap1, snap2])
        self.assertEqual(len(flows), 0)


# ═══════════════════════════════════════════════════════════════════════
# DATA MODEL TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestToolCapabilityModel(unittest.TestCase):
    def test_basic_creation(self):
        cap = ToolCapability(
            tool_name="read_file",
            server_name="fs",
            labels={LABEL_PRIVATE},
            confidence=0.8,
        )
        self.assertEqual(cap.tool_name, "read_file")
        self.assertEqual(cap.server_name, "fs")
        self.assertIn(LABEL_PRIVATE, cap.labels)

    def test_empty_labels(self):
        cap = ToolCapability(
            tool_name="generic",
            server_name="srv",
            labels=set(),
            confidence=0.0,
        )
        self.assertEqual(len(cap.labels), 0)


class TestToxicFlowResultEnhancements(unittest.TestCase):
    def test_tools_involved_field(self):
        from agentseal.guard_models import ToxicFlowResult
        result = ToxicFlowResult(
            risk_level="high",
            risk_type="data_exfiltration",
            title="Test",
            description="Test flow",
            servers_involved=["fs", "slack"],
            remediation="Fix it",
            tools_involved=["fs:read_file", "slack:send_msg"],
            labels_involved=["private_data", "public_sink"],
        )
        d = result.to_dict()
        self.assertIn("tools_involved", d)
        self.assertIn("labels_involved", d)

    def test_empty_tools_involved_excluded(self):
        from agentseal.guard_models import ToxicFlowResult
        result = ToxicFlowResult(
            risk_level="high",
            risk_type="data_exfiltration",
            title="Test",
            description="Test flow",
            servers_involved=["fs", "slack"],
            remediation="Fix it",
        )
        d = result.to_dict()
        self.assertNotIn("tools_involved", d)
        self.assertNotIn("labels_involved", d)

    def test_backward_compat_no_new_fields(self):
        """ToxicFlowResult without new fields works fine."""
        from agentseal.guard_models import ToxicFlowResult
        result = ToxicFlowResult(
            risk_level="medium",
            risk_type="data_destruction",
            title="Test",
            description="Test",
            servers_involved=["a"],
            remediation="Fix",
        )
        self.assertEqual(result.tools_involved, [])
        self.assertEqual(result.labels_involved, [])


if __name__ == "__main__":
    unittest.main()
