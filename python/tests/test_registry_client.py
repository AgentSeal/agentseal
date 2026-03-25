"""Tests for registry_client module — MCP registry trust score enrichment."""

import json
import urllib.error
from unittest.mock import MagicMock, patch

from agentseal.guard_models import GuardVerdict, MCPServerResult
from agentseal.registry_client import (
    BULK_CHECK_URL,
    bulk_check,
    enrich_mcp_results,
    extract_package_slug,
    slugify,
)


def _mcp(name: str, command: str) -> MCPServerResult:
    """Create a minimal MCPServerResult for testing."""
    return MCPServerResult(
        name=name,
        command=command,
        source_file="/tmp/config.json",
        verdict=GuardVerdict.SAFE,
    )


# ═══════════════════════════════════════════════════════════════════════
# slugify
# ═══════════════════════════════════════════════════════════════════════


class TestSlugify:
    def test_simple_name(self):
        assert slugify("brave-search") == "brave-search"

    def test_scoped_package(self):
        assert slugify("@anthropic/mcp-server") == "anthropic-mcp-server"

    def test_spaces_and_special_chars(self):
        assert slugify("My Cool Server!") == "my-cool-server-"

    def test_uppercase(self):
        assert slugify("BraveSearch") == "bravesearch"

    def test_empty_string(self):
        assert slugify("") == ""

    def test_dashes_preserved(self):
        assert slugify("mcp-server-fetch") == "mcp-server-fetch"

    def test_dots_replaced(self):
        assert slugify("server.name.here") == "server-name-here"

    def test_underscores_replaced(self):
        assert slugify("my_server") == "my-server"


# ═══════════════════════════════════════════════════════════════════════
# extract_package_slug
# ═══════════════════════════════════════════════════════════════════════


class TestExtractPackageSlug:
    def test_npx_scoped(self):
        assert extract_package_slug("npx @anthropic/mcp-server") == "anthropic-mcp-server"

    def test_npx_unscoped(self):
        assert extract_package_slug("npx brave-search") == "brave-search"

    def test_uvx(self):
        assert extract_package_slug("uvx mcp-server-sqlite") == "mcp-server-sqlite"

    def test_docker_run(self):
        assert extract_package_slug("docker run mcp/fetch:latest") == "mcp-fetch"

    def test_bare_binary(self):
        assert extract_package_slug("/usr/bin/myserver") is None

    def test_npx_with_version(self):
        assert extract_package_slug("npx @scope/pkg@1.2.3") == "scope-pkg"

    def test_empty_command(self):
        assert extract_package_slug("") is None

    def test_none_command(self):
        assert extract_package_slug(None) is None

    def test_single_word(self):
        assert extract_package_slug("myserver") is None

    def test_bunx(self):
        assert extract_package_slug("bunx @anthropic/tool") == "anthropic-tool"

    def test_pipx(self):
        assert extract_package_slug("pipx mcp-tool") == "mcp-tool"

    def test_docker_no_run(self):
        # docker build ... should not match
        assert extract_package_slug("docker build .") is None


# ═══════════════════════════════════════════════════════════════════════
# bulk_check
# ═══════════════════════════════════════════════════════════════════════


class TestBulkCheck:
    def test_empty_slugs_returns_empty_no_http(self):
        # Should not make any HTTP call
        with patch("agentseal.registry_client.urllib.request.urlopen") as mock_open:
            result = bulk_check([])
            assert result == {}
            mock_open.assert_not_called()

    def test_successful_response(self):
        response_data = {
            "brave-search": {"trust_score": 85.0, "trust_level": "EXCELLENT", "findings_count": 0},
            "shady-tool": {"trust_score": 22.0, "trust_level": "CRITICAL", "findings_count": 7},
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(response_data).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("agentseal.registry_client.urllib.request.urlopen", return_value=mock_resp) as mock_open:
            result = bulk_check(["brave-search", "shady-tool"])
            assert result == response_data
            mock_open.assert_called_once()

    def test_timeout_returns_empty(self):
        with patch("agentseal.registry_client.urllib.request.urlopen", side_effect=TimeoutError):
            result = bulk_check(["some-slug"])
            assert result == {}

    def test_http_error_returns_empty(self):
        err = urllib.error.HTTPError(
            url=BULK_CHECK_URL, code=500, msg="Server Error",
            hdrs=None, fp=None,  # type: ignore[arg-type]
        )
        with patch("agentseal.registry_client.urllib.request.urlopen", side_effect=err):
            result = bulk_check(["some-slug"])
            assert result == {}

    def test_url_error_returns_empty(self):
        with patch(
            "agentseal.registry_client.urllib.request.urlopen",
            side_effect=urllib.error.URLError("DNS failure"),
        ):
            result = bulk_check(["some-slug"])
            assert result == {}

    def test_invalid_json_returns_empty(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"not json at all"
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("agentseal.registry_client.urllib.request.urlopen", return_value=mock_resp):
            result = bulk_check(["some-slug"])
            assert result == {}

    def test_non_dict_response_returns_empty(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(["not", "a", "dict"]).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("agentseal.registry_client.urllib.request.urlopen", return_value=mock_resp):
            result = bulk_check(["some-slug"])
            assert result == {}

    def test_api_key_sent_as_bearer(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("agentseal.registry_client.urllib.request.urlopen", return_value=mock_resp) as mock_open:
            bulk_check(["slug"], api_key="sk-test-123")
            call_args = mock_open.call_args
            req = call_args[0][0]
            assert req.get_header("Authorization") == "Bearer sk-test-123"

    def test_deduplicates_slugs(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("agentseal.registry_client.urllib.request.urlopen", return_value=mock_resp) as mock_open:
            bulk_check(["slug-a", "slug-a", "slug-b"])
            call_args = mock_open.call_args
            req = call_args[0][0]
            sent = json.loads(req.data)
            assert sorted(sent["slugs"]) == ["slug-a", "slug-b"]

    def test_content_type_json(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("agentseal.registry_client.urllib.request.urlopen", return_value=mock_resp) as mock_open:
            bulk_check(["slug"])
            req = mock_open.call_args[0][0]
            assert req.get_header("Content-type") == "application/json"


# ═══════════════════════════════════════════════════════════════════════
# enrich_mcp_results
# ═══════════════════════════════════════════════════════════════════════


class TestEnrichMCPResults:
    def test_match_by_name_slug(self):
        results = [_mcp("brave-search", "/usr/bin/brave")]
        registry_data = {
            "brave-search": {"trust_score": 90.0, "trust_level": "EXCELLENT", "findings_count": 0},
        }
        with patch("agentseal.registry_client.bulk_check", return_value=registry_data):
            enrich_mcp_results(results)
        assert results[0].registry_score == 90.0
        assert results[0].registry_level == "EXCELLENT"
        assert results[0].registry_findings_count == 0

    def test_match_by_command_slug(self):
        results = [_mcp("my-local-name", "npx @anthropic/mcp-server")]
        registry_data = {
            "anthropic-mcp-server": {"trust_score": 75.0, "trust_level": "HIGH", "findings_count": 2},
        }
        with patch("agentseal.registry_client.bulk_check", return_value=registry_data):
            enrich_mcp_results(results)
        assert results[0].registry_score == 75.0
        assert results[0].registry_level == "HIGH"
        assert results[0].registry_findings_count == 2

    def test_no_match_leaves_none(self):
        results = [_mcp("unknown-tool", "npx unknown-tool")]
        with patch("agentseal.registry_client.bulk_check", return_value={}):
            enrich_mcp_results(results)
        assert results[0].registry_score is None
        assert results[0].registry_level is None
        assert results[0].registry_findings_count is None

    def test_empty_results_list(self):
        with patch("agentseal.registry_client.bulk_check") as mock_bc:
            enrich_mcp_results([])
            mock_bc.assert_not_called()

    def test_none_results(self):
        # Should not raise
        with patch("agentseal.registry_client.bulk_check") as mock_bc:
            enrich_mcp_results(None)
            mock_bc.assert_not_called()

    def test_already_enriched_not_overwritten(self):
        """If registry_score is already set, it should not be overwritten."""
        r = _mcp("brave-search", "npx brave-search")
        r.registry_score = 50.0
        r.registry_level = "MEDIUM"
        r.registry_findings_count = 3

        registry_data = {
            "brave-search": {"trust_score": 99.0, "trust_level": "EXCELLENT", "findings_count": 0},
        }
        with patch("agentseal.registry_client.bulk_check", return_value=registry_data):
            enrich_mcp_results([r])
        # Original values preserved
        assert r.registry_score == 50.0
        assert r.registry_level == "MEDIUM"
        assert r.registry_findings_count == 3

    def test_multiple_results_enriched(self):
        results = [
            _mcp("brave-search", "npx brave-search"),
            _mcp("fetch", "npx @mcp/fetch"),
        ]
        registry_data = {
            "brave-search": {"trust_score": 88.0, "trust_level": "EXCELLENT", "findings_count": 1},
            "mcp-fetch": {"trust_score": 72.0, "trust_level": "HIGH", "findings_count": 3},
        }
        with patch("agentseal.registry_client.bulk_check", return_value=registry_data):
            enrich_mcp_results(results)
        assert results[0].registry_score == 88.0
        assert results[1].registry_score == 72.0

    def test_api_key_passed_through(self):
        results = [_mcp("test", "npx test")]
        with patch("agentseal.registry_client.bulk_check", return_value={}) as mock_bc:
            enrich_mcp_results(results, api_key="sk-key-456")
            mock_bc.assert_called_once()
            _, kwargs = mock_bc.call_args
            assert kwargs["api_key"] == "sk-key-456"
