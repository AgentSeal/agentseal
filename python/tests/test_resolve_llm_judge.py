"""
Tests for _resolve_llm_judge helper in cli.py.

Covers:
- No model configured → returns None
- CLI args override saved config
- Ollama URL rewriting (appends /v1)
- LiteLLM URL passthrough (no rewriting)
- Saved config fallback when no CLI args
"""

from types import SimpleNamespace
from unittest.mock import patch

from agentseal.cli import _resolve_llm_judge


def _make_args(**kwargs):
    """Build a minimal args namespace with defaults matching argparse."""
    defaults = {
        "model": None,
        "api_key": None,
        "litellm_url": None,
        "ollama_url": None,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class TestResolveLLMJudgeNoModel:
    def test_returns_none_when_no_model_anywhere(self):
        args = _make_args()
        with patch("agentseal.config.get_llm_config", return_value={}):
            assert _resolve_llm_judge(args) is None

    def test_returns_none_when_saved_config_has_no_model(self):
        args = _make_args()
        saved = {"api_key": "sk-xxx", "ollama_url": "http://localhost:11434"}
        with patch("agentseal.config.get_llm_config", return_value=saved):
            assert _resolve_llm_judge(args) is None


class TestResolveLLMJudgeCLIOverride:
    def test_cli_model_overrides_saved(self):
        args = _make_args(model="gpt-4o")
        saved = {"model": "gpt-3.5-turbo"}
        with patch("agentseal.config.get_llm_config", return_value=saved):
            judge = _resolve_llm_judge(args)
            assert judge is not None
            assert judge.model == "gpt-4o"

    def test_cli_api_key_overrides_saved(self):
        args = _make_args(model="gpt-4o", api_key="cli-key")
        saved = {"model": "gpt-3.5-turbo", "api_key": "saved-key"}
        with patch("agentseal.config.get_llm_config", return_value=saved):
            judge = _resolve_llm_judge(args)
            assert judge.api_key == "cli-key"

    def test_falls_back_to_saved_model(self):
        args = _make_args()
        saved = {"model": "gpt-4o"}
        with patch("agentseal.config.get_llm_config", return_value=saved):
            judge = _resolve_llm_judge(args)
            assert judge is not None
            assert judge.model == "gpt-4o"


class TestResolveLLMJudgeOllamaRewriting:
    def test_cli_ollama_url_gets_v1_appended(self):
        args = _make_args(model="ollama/llama3", ollama_url="http://myhost:11434")
        with patch("agentseal.config.get_llm_config", return_value={}):
            judge = _resolve_llm_judge(args)
            assert judge.base_url == "http://myhost:11434/v1"

    def test_cli_ollama_url_strips_trailing_slash(self):
        args = _make_args(model="ollama/llama3", ollama_url="http://myhost:11434/")
        with patch("agentseal.config.get_llm_config", return_value={}):
            judge = _resolve_llm_judge(args)
            assert judge.base_url == "http://myhost:11434/v1"

    def test_default_ollama_url_ignored_on_cli(self):
        """The sentinel default (localhost:11434) is NOT rewritten from CLI args.

        _resolve_llm_judge should pass base_url=None to LLMJudge, letting the
        constructor's own default kick in rather than doing /v1 rewriting.
        """
        args = _make_args(model="ollama/llama3", ollama_url="http://localhost:11434")
        with patch("agentseal.config.get_llm_config", return_value={}), \
             patch("agentseal.llm_judge.LLMJudge.__init__", return_value=None) as mock_init:
            _resolve_llm_judge(args)
            mock_init.assert_called_once()
            _, kwargs = mock_init.call_args
            assert kwargs.get("base_url") is None

    def test_saved_ollama_url_gets_v1_appended(self):
        args = _make_args(model="ollama/llama3")
        saved = {"ollama_url": "http://myhost:11434"}
        with patch("agentseal.config.get_llm_config", return_value=saved):
            judge = _resolve_llm_judge(args)
            assert judge.base_url == "http://myhost:11434/v1"


class TestResolveLLMJudgeLiteLLMPassthrough:
    def test_cli_litellm_url_passed_directly(self):
        args = _make_args(model="gpt-4o", litellm_url="http://litellm:4000/v1")
        with patch("agentseal.config.get_llm_config", return_value={}):
            judge = _resolve_llm_judge(args)
            assert judge.base_url == "http://litellm:4000/v1"

    def test_litellm_takes_precedence_over_ollama(self):
        args = _make_args(
            model="gpt-4o",
            litellm_url="http://litellm:4000/v1",
            ollama_url="http://ollama:11434",
        )
        with patch("agentseal.config.get_llm_config", return_value={}):
            judge = _resolve_llm_judge(args)
            assert judge.base_url == "http://litellm:4000/v1"

    def test_saved_litellm_url_used_as_fallback(self):
        args = _make_args(model="gpt-4o")
        saved = {"litellm_url": "http://litellm:4000/v1"}
        with patch("agentseal.config.get_llm_config", return_value=saved):
            judge = _resolve_llm_judge(args)
            assert judge.base_url == "http://litellm:4000/v1"
