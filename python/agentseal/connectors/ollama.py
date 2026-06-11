# agentseal/connectors/ollama.py
"""
Ollama connector - build a chat function for local Ollama models.

Layer 3: no agentseal imports (uses httpx directly).
"""

import os


def build_ollama_chat(model: str, system_prompt: str, ollama_url: str = "http://localhost:11434"):
    """Build an async chat function for an Ollama model.

    Args:
        model: Model name without "ollama/" prefix (e.g. "llama3.1:8b").
        system_prompt: The system prompt to use.
        ollama_url: Ollama API base URL.
    """
    import httpx

    async def chat(message: str) -> str:
        url = f"{ollama_url}/api/chat"
        async with httpx.AsyncClient(timeout=180) as client:
            resp = await client.post(url, json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": message},
                ],
                "stream": False,
            })
            resp.raise_for_status()
            return resp.json()["message"]["content"]

    return chat
