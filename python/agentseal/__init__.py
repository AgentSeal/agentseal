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
from agentseal.guard import Guard
from agentseal.guard_models import (
    GuardReport,
    GuardVerdict,
    SkillResult,
    MCPServerResult,
    ToxicFlowResult,
    BaselineChangeResult,
)
from agentseal.profiles import ProfileConfig, PROFILES, resolve_profile, apply_profile
from agentseal.chains import AttackChain, ChainStep, detect_chains
from agentseal.fix import quarantine_skill, restore_skill, list_quarantine
from agentseal.deobfuscate import deobfuscate
from agentseal.probes.loader import load_custom_probes, load_all_custom_probes

# Shield is only available when watchdog is installed
try:
    from agentseal.shield import Shield
except (ImportError, NameError):
    Shield = None  # type: ignore[assignment,misc]

# LLM judge is only available when optional deps are installed
try:
    from agentseal.llm_judge import LLMJudge, LLMJudgeResult
except ImportError:
    LLMJudge = None  # type: ignore[assignment,misc]
    LLMJudgeResult = None  # type: ignore[assignment,misc]

__version__ = "0.8.1"
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
    "Guard",
    "GuardReport",
    "GuardVerdict",
    "SkillResult",
    "MCPServerResult",
    "ToxicFlowResult",
    "BaselineChangeResult",
    "Shield",
    "ProfileConfig",
    "PROFILES",
    "resolve_profile",
    "apply_profile",
    "AttackChain",
    "ChainStep",
    "detect_chains",
    "quarantine_skill",
    "restore_skill",
    "list_quarantine",
    "deobfuscate",
    "load_custom_probes",
    "load_all_custom_probes",
    "LLMJudge",
    "LLMJudgeResult",
]

# Conditional export - only available when semantic deps are installed
try:
    from agentseal.detection.semantic import compute_semantic_similarity
    __all__.append("compute_semantic_similarity")
except ImportError:
    pass
