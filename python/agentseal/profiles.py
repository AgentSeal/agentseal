"""Scan profile presets for AgentValidator."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Optional

_BOOL_FLAGS = ("adaptive", "semantic", "mcp", "rag", "multimodal", "genome", "use_canary_only")
_OPT_FIELDS = ("concurrency", "timeout", "output", "min_score")


@dataclass
class ProfileConfig:
    description: str
    adaptive: bool = False
    semantic: bool = False
    mcp: bool = False
    rag: bool = False
    multimodal: bool = False
    genome: bool = False
    use_canary_only: bool = False
    concurrency: Optional[int] = None
    timeout: Optional[float] = None
    output: Optional[str] = None
    min_score: Optional[int] = None


PROFILES: dict[str, ProfileConfig] = {
    "quick": ProfileConfig(
        description="Fast canary check (5 probes, ~10s)",
        use_canary_only=True, concurrency=5, timeout=15,
    ),
    "default": ProfileConfig(
        description="Standard scan (225 probes)",
    ),
    "code-agent": ProfileConfig(
        description="Coding assistant scan (225+ probes)",
        adaptive=True, mcp=True, semantic=True,
    ),
    "support-bot": ProfileConfig(
        description="Customer-facing chatbot scan",
        adaptive=True, semantic=True,
    ),
    "rag-agent": ProfileConfig(
        description="RAG pipeline agent scan",
        adaptive=True, rag=True, semantic=True,
    ),
    "mcp-heavy": ProfileConfig(
        description="Multi-tool MCP agent scan",
        adaptive=True, mcp=True, semantic=True,
    ),
    "full": ProfileConfig(
        description="Full scan - all probes and analysis",
        adaptive=True, mcp=True, rag=True, multimodal=True, genome=True, semantic=True,
    ),
    "ci": ProfileConfig(
        description="CI/CD pipeline optimized",
        concurrency=5, timeout=15, output="json",
    ),
}


def resolve_profile(name: str) -> ProfileConfig:
    """Return a profile by name, or raise ValueError with valid options."""
    key = name.lower()
    if key in PROFILES:
        return PROFILES[key]
    valid = ", ".join(sorted(PROFILES))
    raise ValueError(f"Unknown profile {name!r}. Valid profiles: {valid}")


def apply_profile(args: argparse.Namespace, profile: ProfileConfig) -> None:
    """Apply profile settings to *args* without overriding explicit user values.

    Boolean flags are only set when the current value is False.
    Optional fields are only set when the current value is None.
    """
    for flag in _BOOL_FLAGS:
        if not getattr(args, flag, False):
            setattr(args, flag, getattr(profile, flag))

    for field in _OPT_FIELDS:
        val = getattr(profile, field)
        if val is not None and getattr(args, field, None) is None:
            setattr(args, field, val)


def list_profiles() -> str:
    """Return a formatted table of available profiles."""
    lines = [f"{'Profile':<14} {'Description':<42} Enables"]
    lines.append("-" * 80)
    for name, cfg in PROFILES.items():
        enabled = [f for f in _BOOL_FLAGS if getattr(cfg, f)]
        extras = []
        for f in _OPT_FIELDS:
            v = getattr(cfg, f)
            if v is not None:
                extras.append(f"{f}={v}")
        parts = enabled + extras
        lines.append(f"{name:<14} {cfg.description:<42} {', '.join(parts) or '-'}")
    return "\n".join(lines)
