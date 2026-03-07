# agentseal/__init__.py
"""
AgentSeal - Security validator for AI agents.

Quick start:
    from agentseal import AgentValidator

    validator = AgentValidator.from_openai(
        client=openai.AsyncOpenAI(),
        model="gpt-4o",
        system_prompt="You are a helpful assistant...",
    )
    report = await validator.run()
    report.print()
"""

from agentseal.validator import AgentValidator
from agentseal.schemas import (
    ScanReport,
    ProbeResult,
    Verdict,
    Severity,
    TrustLevel,
)
from agentseal.remediation import RemediationReport, RemediationItem, AffectedProbe
from agentseal.fingerprint import DefenseProfile
from agentseal.mutations import TRANSFORMS, apply_mutation

__version__ = "0.5.0"
__all__ = [
    "AgentValidator",
    "ScanReport",
    "ProbeResult",
    "Verdict",
    "Severity",
    "TrustLevel",
    "RemediationReport",
    "RemediationItem",
    "AffectedProbe",
    "DefenseProfile",
    "TRANSFORMS",
    "apply_mutation",
]

# Conditional export - only available when semantic deps are installed
try:
    from agentseal.detection.semantic import compute_semantic_similarity
    __all__.append("compute_semantic_similarity")
except ImportError:
    pass
