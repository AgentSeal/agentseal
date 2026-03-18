# agentseal/connectors/__init__.py
"""
Connector subpackage - build async chat functions for various LLM providers.

Layer 3: Individual connector modules (openai.py, anthropic.py, etc.) have
zero agentseal imports - they only use httpx. This __init__.py imports from
them and provides the build_agent_fn() router, which has no agentseal type
imports either (it delegates to the individual builders). If retry logic or
custom exceptions are added later, they would import from Layer 0-1.
"""

from agentseal.connectors.openai import build_openai_chat
from agentseal.connectors.anthropic import build_anthropic_chat
from agentseal.connectors.ollama import build_ollama_chat
from agentseal.connectors.litellm import build_litellm_chat
from agentseal.connectors.http import build_http_chat
from agentseal.connectors.minimax import build_minimax_chat


def build_agent_fn(model: str, system_prompt: str, api_key: str = None,
                   ollama_url: str = None, litellm_url: str = None):
    """Build an async chat function for the specified model.

    Routes to the appropriate connector based on the model string:
      - "ollama/..." → Ollama
      - litellm_url set → LiteLLM proxy
      - "claude"/"anthropic" in name → Anthropic
      - "minimax" in name → MiniMax
      - else → OpenAI-compatible
    """
    if model.startswith("ollama/"):
        model_name = model.replace("ollama/", "")
        return build_ollama_chat(
            model=model_name,
            system_prompt=system_prompt,
            ollama_url=ollama_url or "http://localhost:11434",
        )

    if litellm_url:
        return build_litellm_chat(
            model=model,
            system_prompt=system_prompt,
            litellm_url=litellm_url,
            api_key=api_key,
        )

    if "claude" in model.lower() or "anthropic" in model.lower():
        return build_anthropic_chat(
            model=model,
            system_prompt=system_prompt,
            api_key=api_key,
        )

    if "minimax" in model.lower():
        return build_minimax_chat(
            model=model,
            system_prompt=system_prompt,
            api_key=api_key,
        )

    return build_openai_chat(
        model=model,
        system_prompt=system_prompt,
        api_key=api_key,
    )


__all__ = [
    "build_agent_fn",
    "build_openai_chat",
    "build_anthropic_chat",
    "build_ollama_chat",
    "build_litellm_chat",
    "build_http_chat",
    "build_minimax_chat",
]
