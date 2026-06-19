# agentseal/connectors/minimax.py
"""
MiniMax connector via raw HTTP (for CLI use).

Layer 3: no agentseal imports.
"""

import os


def build_minimax_chat(model: str, system_prompt: str, api_key: str = None):
    """Build an async chat function for the MiniMax Chat Completions API.

    MiniMax provides an OpenAI-compatible API at https://api.minimax.io/v1.

    Args:
        model: Model name (e.g. "MiniMax-M3", "MiniMax-M2.7", "MiniMax-M2.7-highspeed").
        system_prompt: The system prompt to use.
        api_key: API key (falls back to MINIMAX_API_KEY env).
    """
    import httpx

    key = api_key or os.environ.get("MINIMAX_API_KEY", "")

    async def chat(message: str) -> str:
        url = "https://api.minimax.io/v1/chat/completions"
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(url, json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": message},
                ],
            }, headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            })
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

    return chat
