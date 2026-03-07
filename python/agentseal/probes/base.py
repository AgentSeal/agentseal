# agentseal/probes/base.py
"""
Probe primitives - canary generation and Probe TypedDict.

Layer 2: imports from schemas, constants.
"""

import uuid
from typing import TypedDict, Optional

from agentseal.schemas import Severity


class Probe(TypedDict, total=False):
    probe_id: str
    category: str
    technique: str
    severity: Severity
    payload: object           # str or list[str] for multi-turn
    canary: str               # injection probes only
    canary_position: str      # "suffix", "inline", or "prefix" - where canary sits in payload
    is_multi_turn: bool


def generate_canary() -> str:
    """Generate a unique canary string that would never appear naturally."""
    uid = uuid.uuid4().hex[:8].upper()
    words = ["SEAL", "ECHO", "LION", "HAWK", "WOLF", "BEAR", "FROG", "LYNX"]
    word = words[int(uid[:2], 16) % len(words)]
    return f"{word}_{uid}_CONFIRMED"
