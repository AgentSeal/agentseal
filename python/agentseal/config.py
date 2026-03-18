# agentseal/config.py
"""
Local configuration management for AgentSeal.

Stores API keys, LLM preferences, and other settings in
~/.agentseal/config.json. Keys are stored in plaintext —
for production use, users should use environment variables instead.

Usage:
    agentseal config set model claude-haiku-4-5-20251001
    agentseal config set api-key sk-ant-...
    agentseal config show
    agentseal config remove api-key
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional


_CONFIG_DIR = Path.home() / ".agentseal"
_CONFIG_FILE = _CONFIG_DIR / "config.json"

# Valid config keys and their descriptions
_VALID_KEYS = {
    "model": "Default LLM model (e.g. claude-haiku-4-5-20251001, gpt-4o, ollama/qwen3.5:cloud)",
    "api-key": "API key for OpenAI/Anthropic/MiniMax/OpenRouter",
    "ollama-url": "Ollama base URL (default: http://localhost:11434)",
    "litellm-url": "LiteLLM proxy URL for custom LLM routing",
    "registry-url": "Custom URL for MCP server registry updates",
    "dashboard-url": "AgentSeal Dashboard API URL",
    "dashboard-key": "AgentSeal Dashboard API key",
}


def get_setup_guide() -> str:
    """Return a formatted guide for setting up LLM providers."""
    return """
  ┌─────────────────────────────────────────────────────────────────┐
  │                  LLM Provider Setup Guide                      │
  └─────────────────────────────────────────────────────────────────┘

  AgentSeal uses LLMs for deep skill analysis (Layer 4 — LLM Judge).
  Choose one provider below. Once configured, guard/shield will
  auto-use it for every scan.

  ── CLOUD PROVIDERS ──────────────────────────────────────────────

  Anthropic (Claude):
    agentseal config set model claude-haiku-4-5-20251001
    agentseal config set api-key sk-ant-api03-xxxxx
    # Or: export ANTHROPIC_API_KEY=sk-ant-api03-xxxxx

  OpenAI (GPT):
    agentseal config set model gpt-4o-mini
    agentseal config set api-key sk-xxxxx
    # Or: export OPENAI_API_KEY=sk-xxxxx

  MiniMax:
    agentseal config set model MiniMax-M2.7
    agentseal config set api-key xxxxx
    # Or: export MINIMAX_API_KEY=xxxxx
    # Models: MiniMax-M2.7, MiniMax-M2.7-highspeed, MiniMax-M2.5, MiniMax-M2.5-highspeed

  OpenRouter (any model, one API key):
    agentseal config set model openrouter/anthropic/claude-haiku-4-5-20251001
    agentseal config set api-key sk-or-xxxxx
    # Or: export OPENAI_API_KEY=sk-or-xxxxx
    # Models: openrouter/meta-llama/llama-3-70b, openrouter/google/gemini-pro, etc.

  ── LOCAL / SELF-HOSTED (FREE, PRIVATE) ──────────────────────────

  Ollama (recommended for local):
    # 1. Install: https://ollama.com/download
    # 2. Pull a model:
    ollama pull qwen3:8b          # 8B params, fast
    ollama pull qwen3.5:35b       # 35B params, more accurate
    # 3. Configure:
    agentseal config set model ollama/qwen3:8b
    # Ollama runs at localhost:11434 by default — no API key needed

  Ollama (cloud models via ollama.com):
    agentseal config set model ollama/qwen3.5:cloud
    # Uses Ollama's cloud routing — no local GPU needed

  LM Studio:
    # 1. Install: https://lmstudio.ai/
    # 2. Load a model and start the local server (port 1234)
    # 3. Configure:
    agentseal config set model local-model
    agentseal config set litellm-url http://localhost:1234/v1
    # LM Studio serves an OpenAI-compatible API

  llama.cpp (server mode):
    # 1. Start llama-server:
    llama-server -m model.gguf --port 8080
    # 2. Configure:
    agentseal config set model local-model
    agentseal config set litellm-url http://localhost:8080/v1

  vLLM:
    # 1. Start vLLM server:
    vllm serve meta-llama/Llama-3-8B --port 8000
    # 2. Configure:
    agentseal config set model meta-llama/Llama-3-8B
    agentseal config set litellm-url http://localhost:8000/v1

  Any OpenAI-compatible server (LocalAI, text-gen-webui, etc.):
    agentseal config set model model-name
    agentseal config set litellm-url http://localhost:PORT/v1

  ── REMOTE ACCESS (expose local model) ───────────────────────────

  ngrok (share local Ollama with remote machines):
    # 1. Install ngrok: https://ngrok.com/download
    # 2. Expose Ollama:
    ngrok http 11434
    # 3. On remote machine, use the ngrok URL:
    agentseal config set model ollama/qwen3:8b
    agentseal config set ollama-url https://xxxx.ngrok.io

  ── VERIFY SETUP ─────────────────────────────────────────────────

  agentseal config show         # Check current configuration
  agentseal guard               # Run a scan — LLM judge activates automatically
"""

# Keys that contain secrets and should be masked in output
_SECRET_KEYS = {"api-key", "api_key", "dashboard-key", "dashboard_key"}


def _load() -> dict[str, Any]:
    """Load config from disk."""
    if not _CONFIG_FILE.is_file():
        return {}
    try:
        return json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save(config: dict[str, Any]) -> None:
    """Save config to disk."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _CONFIG_FILE.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    # Set restrictive permissions (owner-only read/write) since it may contain keys
    try:
        _CONFIG_FILE.chmod(0o600)
    except OSError:
        pass


def config_set(key: str, value: str) -> str:
    """Set a config value. Returns confirmation message."""
    if key not in _VALID_KEYS:
        valid = ", ".join(sorted(_VALID_KEYS.keys()))
        return f"Unknown key '{key}'. Valid keys: {valid}"

    config = _load()
    config[key] = value
    _save(config)

    display = _mask(key, value)
    return f"Set {key} = {display}"


def config_get(key: str) -> Optional[str]:
    """Get a config value. Returns None if not set."""
    config = _load()
    return config.get(key)


def config_remove(key: str) -> str:
    """Remove a config value. Returns confirmation message."""
    config = _load()
    if key not in config:
        return f"Key '{key}' is not set"
    del config[key]
    _save(config)
    return f"Removed {key}"


def config_show() -> dict[str, str]:
    """Return all config values (secrets masked)."""
    config = _load()
    return {k: _mask(k, v) for k, v in config.items()}


def config_show_all_keys() -> dict[str, str]:
    """Return all valid keys with descriptions."""
    return dict(_VALID_KEYS)


def get_llm_config() -> dict[str, Optional[str]]:
    """Get LLM-related config for use by guard/scan commands.

    Returns dict with model, api_key, base_url — ready to pass to LLMJudge.
    CLI flags take precedence over config file values.
    """
    config = _load()
    return {
        "model": config.get("model"),
        "api_key": config.get("api-key"),
        "ollama_url": config.get("ollama-url"),
        "litellm_url": config.get("litellm-url"),
    }


def _mask(key: str, value: Any) -> str:
    """Mask secret values for display."""
    if key not in _SECRET_KEYS or not isinstance(value, str):
        return str(value)
    if len(value) <= 8:
        return "****"
    return value[:4] + "..." + value[-4:]
