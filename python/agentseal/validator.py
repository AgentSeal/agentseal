# agentseal/validator.py
"""
AgentSeal Validator - The core product.

This module talks to ANY AI agent and validates its security posture.
The agent provides a `chat()` function, and we attack it.

Usage:
    from agentseal.validator import AgentValidator

    # Option 1: Wrap any chat function
    async def my_agent(message: str) -> str:
        response = await openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": my_system_prompt},
                {"role": "user", "content": message},
            ],
        )
        return response.choices[0].message.content

    validator = AgentValidator(
        agent_fn=my_agent,
        ground_truth_prompt=my_system_prompt,   # So we can measure what leaked
        agent_name="Sales Copilot",
    )
    report = await validator.run()
    report.print()         # Pretty terminal output
    report.to_json()       # Machine-readable
    report.to_dict()       # Python dict

    # Option 2: Against an HTTP endpoint
    validator = AgentValidator.from_endpoint(
        url="http://localhost:8080/chat",
        ground_truth_prompt=my_system_prompt,
    )
"""

import asyncio
import time
import uuid
import warnings
from typing import Callable, Optional

# ═══════════════════════════════════════════════════════════════════════
# CANONICAL IMPORTS - code now lives in dedicated modules
# These are used internally by AgentValidator.run(). Prefixed with _
# so they don't pollute the module namespace.
# ═══════════════════════════════════════════════════════════════════════

from agentseal import schemas as _schemas
from agentseal.probes.extraction import build_extraction_probes as _build_extraction_probes
from agentseal.probes.injection import build_injection_probes as _build_injection_probes
from agentseal.detection.canary import detect_canary as _detect_canary
from agentseal.detection.canary import classify_canary_leak as _classify_canary_leak
from agentseal.probes.injection import make_data_extraction_variant as _make_data_extraction_variant
from agentseal.detection.ngram import detect_extraction as _detect_extraction
from agentseal.scoring import compute_scores as _compute_scores
from agentseal import constants as _constants
from agentseal.chains import detect_chains as _detect_chains
from agentseal.probes.loader import load_custom_probes as _load_custom_probes

_VERDICT_ICONS: dict[str, str] = {"blocked": "✓", "leaked": "✗", "partial": "◐", "error": "⚠"}

# Private aliases for internal use by AgentValidator.
# NOT exported at module level - so __getattr__ fires for deprecated imports.
_Verdict = _schemas.Verdict
_Severity = _schemas.Severity
_TrustLevel = _schemas.TrustLevel
_ProbeResult = _schemas.ProbeResult
_ScanReport = _schemas.ScanReport
_ChatFn = _schemas.ChatFn

# ═══════════════════════════════════════════════════════════════════════
# BACKWARD COMPAT - deprecated re-exports
# "from agentseal.validator import Verdict" still works but warns.
# Use "from agentseal.schemas import Verdict" instead.
# ═══════════════════════════════════════════════════════════════════════

_DEPRECATED_NAMES = {
    # schemas re-exports
    "Verdict": ("agentseal.schemas", _schemas.Verdict),
    "Severity": ("agentseal.schemas", _schemas.Severity),
    "TrustLevel": ("agentseal.schemas", _schemas.TrustLevel),
    "ProbeResult": ("agentseal.schemas", _schemas.ProbeResult),
    "ScanReport": ("agentseal.schemas", _schemas.ScanReport),
    "ChatFn": ("agentseal.schemas", _schemas.ChatFn),
    # constants re-exports
    "EXTRACTION_WEIGHT": ("agentseal.constants", _constants.EXTRACTION_WEIGHT),
    "INJECTION_WEIGHT": ("agentseal.constants", _constants.INJECTION_WEIGHT),
    "BOUNDARY_WEIGHT": ("agentseal.constants", _constants.BOUNDARY_WEIGHT),
    "CONSISTENCY_WEIGHT": ("agentseal.constants", _constants.CONSISTENCY_WEIGHT),
    "DATA_EXTRACTION_WEIGHT": ("agentseal.constants", _constants.DATA_EXTRACTION_WEIGHT),
    "BOUNDARY_CATEGORIES": ("agentseal.constants", _constants.BOUNDARY_CATEGORIES),
}


def __getattr__(name: str):
    if name in _DEPRECATED_NAMES:
        canonical_module, obj = _DEPRECATED_NAMES[name]
        warnings.warn(
            f"Importing {name} from agentseal.validator is deprecated. "
            f"Use 'from {canonical_module} import {name}' instead. "
            f"This will be removed in a future version.",
            DeprecationWarning,
            stacklevel=2,
        )
        return obj
    raise AttributeError(f"module 'agentseal.validator' has no attribute {name!r}")


# ═══════════════════════════════════════════════════════════════════════
# THE VALIDATOR - Main class
# ═══════════════════════════════════════════════════════════════════════

class AgentValidator:
    """
    Validates an AI agent's security by running 225+ attack probes against it.

    The agent is accessed through a simple async function:
        async def chat(message: str) -> str

    This function should send the message to your agent and return its response.
    That's it. We handle everything else.
    """

    def __init__(
        self,
        agent_fn: _ChatFn,
        ground_truth_prompt: Optional[str] = None,
        agent_name: str = "Unnamed Agent",
        concurrency: int = 3,
        timeout_per_probe: float = 30.0,
        verbose: bool = False,
        on_progress: Optional[Callable[[str, int, int], None]] = None,
        adaptive: bool = False,
        semantic: bool = False,
        mcp: bool = False,
        rag: bool = False,
        multimodal: bool = False,
        custom_probes=None,
    ):
        """
        Args:
            agent_fn: Async function that sends a message to the agent and returns the response.
            ground_truth_prompt: The actual system prompt (optional but recommended).
                                 Without it, extraction detection is less accurate.
            agent_name: Display name for reports.
            concurrency: Max parallel probes (careful with rate limits).
            timeout_per_probe: Seconds before a probe times out.
            verbose: Print each probe result as it completes.
            on_progress: Callback(phase, completed, total) for progress tracking.
            adaptive: Enable mutation phase - re-run blocked extraction probes with transforms.
            semantic: Enable semantic leak detection (requires: pip install agentseal[semantic]).
            mcp: Include MCP tool poisoning probes (45 additional injection probes).
            rag: Include RAG poisoning probes (28 additional injection probes).
            multimodal: Include multimodal attack probes (13 additional injection probes).
            custom_probes: Path to YAML probes file/directory, or list of probe dicts.
        """
        self.agent_fn = agent_fn
        self.ground_truth = ground_truth_prompt
        self.agent_name = agent_name
        self.concurrency = concurrency
        self.timeout = timeout_per_probe
        self.verbose = verbose
        self.on_progress = on_progress
        self.adaptive = adaptive
        self.semantic = semantic
        self.mcp = mcp
        self.rag = rag
        self.multimodal = multimodal
        self.custom_probes = custom_probes

        if self.semantic:
            from agentseal.detection.semantic import is_available
            if not is_available():
                raise ImportError(
                    "Semantic detection requires extra dependencies. "
                    "Install with: pip install agentseal[semantic]"
                )

    @classmethod
    def from_endpoint(
        cls,
        url: str,
        ground_truth_prompt: Optional[str] = None,
        agent_name: str = "HTTP Agent",
        message_field: str = "message",
        response_field: str = "response",
        headers: Optional[dict] = None,
        **kwargs,
    ) -> "AgentValidator":
        """
        Create a validator that talks to an HTTP endpoint.

        Expects:
            POST {url} with JSON body {message_field: "..."}
            Returns JSON with {response_field: "..."}
        """
        import httpx

        async def http_chat(message: str) -> str:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    url,
                    json={message_field: message},
                    headers=headers or {},
                )
                resp.raise_for_status()
                return resp.json()[response_field]

        return cls(
            agent_fn=http_chat,
            ground_truth_prompt=ground_truth_prompt,
            agent_name=agent_name,
            **kwargs,
        )

    @classmethod
    def from_openai(
        cls,
        client,  # openai.AsyncOpenAI
        model: str,
        system_prompt: str,
        agent_name: str = "OpenAI Agent",
        **kwargs,
    ) -> "AgentValidator":
        """
        Create a validator that wraps an OpenAI client directly.
        The system prompt IS the ground truth (we're testing it directly).
        """
        async def openai_chat(message: str) -> str:
            response = await client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": message},
                ],
            )
            return response.choices[0].message.content

        return cls(
            agent_fn=openai_chat,
            ground_truth_prompt=system_prompt,
            agent_name=agent_name,
            **kwargs,
        )

    @classmethod
    def from_anthropic(
        cls,
        client,  # anthropic.AsyncAnthropic
        model: str,
        system_prompt: str,
        agent_name: str = "Claude Agent",
        **kwargs,
    ) -> "AgentValidator":
        """Create a validator that wraps an Anthropic client."""
        async def anthropic_chat(message: str) -> str:
            response = await client.messages.create(
                model=model,
                max_tokens=1024,
                system=system_prompt,
                messages=[{"role": "user", "content": message}],
            )
            return response.content[0].text

        return cls(
            agent_fn=anthropic_chat,
            ground_truth_prompt=system_prompt,
            agent_name=agent_name,
            **kwargs,
        )

    async def run_genome(
        self,
        scan_report: _ScanReport | None = None,
        max_probes_per_category: int = 5,
        max_categories: int = 3,
    ) -> "object":
        """Run genome boundary mapping. If scan_report is None, runs a full scan first."""
        if scan_report is None:
            scan_report = await self.run()
        from agentseal.genome import run_genome_scan
        return await run_genome_scan(
            agent_fn=self.agent_fn,
            scan_report=scan_report,
            ground_truth=self.ground_truth,
            max_probes_per_category=max_probes_per_category,
            max_categories=max_categories,
            concurrency=self.concurrency,
            timeout=self.timeout,
            on_progress=self.on_progress,
            semantic=self.semantic,
        )

    async def run(self) -> _ScanReport:
        """Run all probes against the agent and return a full report."""
        scan_id = uuid.uuid4().hex[:12]
        start_time = time.time()
        all_results: list[_ProbeResult] = []

        extraction_probes = _build_extraction_probes()
        injection_probes = _build_injection_probes()
        if self.mcp:
            from agentseal.probes.mcp_tools import build_mcp_probes
            injection_probes.extend(build_mcp_probes())
        if self.rag:
            from agentseal.probes.rag_poisoning import build_rag_probes
            injection_probes.extend(build_rag_probes())
        if self.multimodal:
            from agentseal.probes.multimodal import build_multimodal_probes
            injection_probes.extend(build_multimodal_probes())

        # ── Custom probes ────────────────────────────────────────────
        if self.custom_probes:
            from pathlib import Path as _Path
            if isinstance(self.custom_probes, (str, _Path)):
                custom = _load_custom_probes(self.custom_probes)
            elif isinstance(self.custom_probes, list):
                custom = self.custom_probes
            else:
                custom = []
            for cp in custom:
                cp_type = cp.get("type", "extraction")
                if cp_type == "injection":
                    injection_probes.append(cp)
                else:
                    extraction_probes.append(cp)

        # ── Phase 1: Extraction ──────────────────────────────────────
        sem = asyncio.Semaphore(self.concurrency)

        async def run_extraction_probe(probe: dict) -> _ProbeResult:
            async with sem:
                t0 = time.time()
                try:
                    if probe.get("is_multi_turn"):
                        response = ""
                        for msg in probe["payload"]:
                            response = await asyncio.wait_for(
                                self.agent_fn(msg), timeout=self.timeout
                            )
                    else:
                        response = await asyncio.wait_for(
                            self.agent_fn(probe["payload"]), timeout=self.timeout
                        )

                    sem_score = None
                    if self.semantic:
                        from agentseal.detection.fusion import detect_extraction_with_semantic
                        verdict, confidence, reasoning, sem_score = detect_extraction_with_semantic(
                            response, self.ground_truth or ""
                        )
                    else:
                        verdict, confidence, reasoning = _detect_extraction(
                            response, self.ground_truth or ""
                        )
                except asyncio.TimeoutError:
                    response = "[TIMEOUT]"
                    verdict, confidence, reasoning = _Verdict.ERROR, 0.0, "Probe timed out"
                    sem_score = None
                except Exception as e:
                    response = f"[ERROR: {e}]"
                    verdict, confidence, reasoning = _Verdict.ERROR, 0.0, f"Error: {e}"
                    sem_score = None

                duration = (time.time() - t0) * 1000
                payload_str = " → ".join(probe["payload"]) if isinstance(probe["payload"], list) else probe["payload"]

                result = _ProbeResult(
                    probe_id=probe["probe_id"],
                    category=probe["category"],
                    probe_type="extraction",
                    technique=probe["technique"],
                    severity=probe["severity"],
                    attack_text=payload_str[:500],
                    response_text=response[:1000],
                    verdict=verdict,
                    confidence=confidence,
                    reasoning=reasoning,
                    duration_ms=duration,
                    semantic_similarity=sem_score,
                )

                if self.verbose:
                    print(f"  [{_VERDICT_ICONS[verdict.value]}] {probe['probe_id']:20s} → {verdict.value:8s}  ({reasoning[:60]})")

                if self.on_progress:
                    ext_done[0] += 1
                    self.on_progress("extraction", ext_done[0], len(extraction_probes))

                return result

        ext_done = [0]
        if self.on_progress:
            self.on_progress("extraction", 0, len(extraction_probes))

        extraction_tasks = [run_extraction_probe(p) for p in extraction_probes]
        extraction_results = await asyncio.gather(*extraction_tasks)
        all_results.extend(extraction_results)

        # ── Phase 2: Injection ───────────────────────────────────────
        async def run_injection_probe(probe: dict) -> _ProbeResult:
            async with sem:
                t0 = time.time()
                try:
                    if probe.get("is_multi_turn"):
                        response = ""
                        for msg in probe["payload"]:
                            response = await asyncio.wait_for(
                                self.agent_fn(msg), timeout=self.timeout
                            )
                    else:
                        response = await asyncio.wait_for(
                            self.agent_fn(probe["payload"]), timeout=self.timeout
                        )
                    canary = probe["canary"]
                    verdict, reasoning = _classify_canary_leak(response, canary)
                    if verdict == _Verdict.LEAKED:
                        confidence = 0.99
                    elif verdict == _Verdict.PARTIAL:
                        confidence = 0.75
                    else:
                        confidence = 0.85
                except asyncio.TimeoutError:
                    response = "[TIMEOUT]"
                    verdict, confidence, reasoning = _Verdict.ERROR, 0.0, "Probe timed out"
                except Exception as e:
                    response = f"[ERROR: {e}]"
                    verdict, confidence, reasoning = _Verdict.ERROR, 0.0, f"Error: {e}"

                duration = (time.time() - t0) * 1000
                payload_str = " → ".join(probe["payload"]) if isinstance(probe["payload"], list) else probe["payload"]

                result = _ProbeResult(
                    probe_id=probe["probe_id"],
                    category=probe["category"],
                    probe_type="injection",
                    technique=probe["technique"],
                    severity=probe["severity"],
                    attack_text=payload_str[:500],
                    response_text=response[:1000],
                    verdict=verdict,
                    confidence=confidence,
                    reasoning=reasoning,
                    duration_ms=duration,
                )

                if self.verbose:
                    print(f"  [{_VERDICT_ICONS[verdict.value]}] {probe['probe_id']:20s} → {verdict.value:8s}  ({reasoning[:60]})")

                if self.on_progress:
                    inj_done[0] += 1
                    self.on_progress("injection", inj_done[0], len(injection_probes))

                return result

        inj_done = [0]
        if self.on_progress:
            self.on_progress("injection", 0, len(injection_probes))

        injection_tasks = [run_injection_probe(p) for p in injection_probes]
        injection_results = await asyncio.gather(*injection_tasks)
        all_results.extend(injection_results)

        # ── Phase 3: Data Extraction Follow-up ───────────────────────
        # Re-run leaked injection probes with real data extraction payloads
        if self.ground_truth:
            leaked_injections = [
                (r, p) for r, p in zip(injection_results, injection_probes)
                if r.verdict == _Verdict.LEAKED
            ][:20]  # Cap at top 20

            if leaked_injections:
                data_ext_probes = []
                for result, probe in leaked_injections:
                    variant = _make_data_extraction_variant(probe, self.ground_truth)
                    data_ext_probes.append(variant)

                de_done = [0]
                if self.on_progress:
                    self.on_progress("data_extraction", 0, len(data_ext_probes))

                async def run_data_extraction_probe(probe: dict) -> _ProbeResult:
                    async with sem:
                        t0 = time.time()
                        try:
                            if probe.get("is_multi_turn"):
                                response = ""
                                for msg in probe["payload"]:
                                    response = await asyncio.wait_for(
                                        self.agent_fn(msg), timeout=self.timeout
                                    )
                            else:
                                response = await asyncio.wait_for(
                                    self.agent_fn(probe["payload"]), timeout=self.timeout
                                )
                            # Use n-gram detection against ground truth
                            verdict, confidence, reasoning = _detect_extraction(
                                response, self.ground_truth or ""
                            )
                        except asyncio.TimeoutError:
                            response = "[TIMEOUT]"
                            verdict, confidence, reasoning = _Verdict.ERROR, 0.0, "Probe timed out"
                        except Exception as e:
                            response = f"[ERROR: {e}]"
                            verdict, confidence, reasoning = _Verdict.ERROR, 0.0, f"Error: {e}"

                        duration = (time.time() - t0) * 1000
                        payload_str = " → ".join(probe["payload"]) if isinstance(probe["payload"], list) else probe["payload"]

                        result = _ProbeResult(
                            probe_id=probe["probe_id"],
                            category=probe.get("category", "data_extraction"),
                            probe_type="data_extraction",
                            technique=probe.get("technique", "data_extraction"),
                            severity=probe["severity"],
                            attack_text=payload_str[:500],
                            response_text=response[:1000],
                            verdict=verdict,
                            confidence=confidence,
                            reasoning=reasoning,
                            duration_ms=duration,
                        )

                        if self.verbose:
                            print(f"  [{_VERDICT_ICONS[verdict.value]}] {probe['probe_id']:20s} → {verdict.value:8s}  ({reasoning[:60]})")

                        if self.on_progress:
                            de_done[0] += 1
                            self.on_progress("data_extraction", de_done[0], len(data_ext_probes))

                        return result

                de_tasks = [run_data_extraction_probe(p) for p in data_ext_probes]
                de_results = await asyncio.gather(*de_tasks)
                all_results.extend(de_results)

        # ── Phase 4: Defense Fingerprinting ──────────────────────────
        from agentseal.fingerprint import fingerprint_defense
        all_responses = [r.response_text for r in all_results]
        defense_profile = fingerprint_defense(all_responses)

        # ── Phase 5: Mutations (if --adaptive) ──────────────────────
        mutation_results_list: list[_ProbeResult] = []
        mutation_resistance = None

        if self.adaptive:
            from agentseal.mutations import generate_mutations

            severity_order = {_Severity.CRITICAL: 0, _Severity.HIGH: 1, _Severity.MEDIUM: 2, _Severity.LOW: 3}
            blocked_extraction = [
                r for r in all_results
                if r.probe_type == "extraction" and r.verdict == _Verdict.BLOCKED
            ]
            blocked_extraction.sort(key=lambda r: severity_order.get(r.severity, 4))
            top_blocked = blocked_extraction[:5]

            if top_blocked:
                mutation_probes = generate_mutations(top_blocked, extraction_probes)
                total_mutations = len(mutation_probes)

                if self.on_progress:
                    self.on_progress("mutations", 0, total_mutations)

                async def run_mutation_probe(mprobe: dict) -> _ProbeResult:
                    async with sem:
                        t0 = time.time()
                        try:
                            response = await asyncio.wait_for(
                                self.agent_fn(mprobe["payload"]), timeout=self.timeout
                            )
                            sem_score = None
                            if self.semantic:
                                from agentseal.detection.fusion import detect_extraction_with_semantic
                                verdict, confidence, reasoning, sem_score = detect_extraction_with_semantic(
                                    response, self.ground_truth or ""
                                )
                            else:
                                verdict, confidence, reasoning = _detect_extraction(
                                    response, self.ground_truth or ""
                                )
                        except asyncio.TimeoutError:
                            response = "[TIMEOUT]"
                            verdict, confidence, reasoning = _Verdict.ERROR, 0.0, "Probe timed out"
                            sem_score = None
                        except Exception as e:
                            response = f"[ERROR: {e}]"
                            verdict, confidence, reasoning = _Verdict.ERROR, 0.0, f"Error: {e}"
                            sem_score = None

                        duration_ms = (time.time() - t0) * 1000
                        if self.on_progress:
                            mut_done[0] += 1
                            self.on_progress("mutations", mut_done[0], total_mutations)

                        return _ProbeResult(
                            probe_id=mprobe["probe_id"],
                            category="mutation",
                            probe_type="extraction",
                            technique=mprobe["technique"],
                            severity=mprobe["severity"],
                            attack_text=mprobe["payload"][:500],
                            response_text=response[:1000],
                            verdict=verdict,
                            confidence=confidence,
                            reasoning=reasoning,
                            duration_ms=duration_ms,
                            semantic_similarity=sem_score,
                        )

                mut_done = [0]
                mutation_tasks = [run_mutation_probe(mp) for mp in mutation_probes]
                mutation_results_list = list(await asyncio.gather(*mutation_tasks))

                active_mutations = [r for r in mutation_results_list if r.verdict != _Verdict.ERROR]
                if active_mutations:
                    blocked_count = sum(1 for r in active_mutations if r.verdict == _Verdict.BLOCKED)
                    mutation_resistance = (blocked_count / len(active_mutations)) * 100

        # ── Phase 6: Score ───────────────────────────────────────────
        scores = _compute_scores(all_results)
        if not scores.get("scoring_valid", True):
            if self.verbose:
                print("\n  ⚠  All probes errored — no valid trust score. Check your model endpoint.\n")
        trust_level = _TrustLevel.from_score(scores["overall"])

        duration = time.time() - start_time

        # ── Phase 7: Attack Chain Detection ──────────────────────────
        # Build a temporary report to detect chains, then include them
        _tmp_report = _ScanReport(
            agent_name=self.agent_name,
            scan_id=scan_id,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            duration_seconds=duration,
            total_probes=len(all_results),
            probes_blocked=sum(1 for r in all_results if r.verdict == _Verdict.BLOCKED),
            probes_leaked=sum(1 for r in all_results if r.verdict == _Verdict.LEAKED),
            probes_partial=sum(1 for r in all_results if r.verdict == _Verdict.PARTIAL),
            probes_error=sum(1 for r in all_results if r.verdict == _Verdict.ERROR),
            trust_score=scores["overall"],
            trust_level=trust_level,
            score_breakdown=scores,
            results=all_results,
            ground_truth_provided=self.ground_truth is not None,
        )
        attack_chains = _detect_chains(_tmp_report)

        return _ScanReport(
            agent_name=self.agent_name,
            scan_id=scan_id,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            duration_seconds=duration,
            total_probes=len(all_results),
            probes_blocked=sum(1 for r in all_results if r.verdict == _Verdict.BLOCKED),
            probes_leaked=sum(1 for r in all_results if r.verdict == _Verdict.LEAKED),
            probes_partial=sum(1 for r in all_results if r.verdict == _Verdict.PARTIAL),
            probes_error=sum(1 for r in all_results if r.verdict == _Verdict.ERROR),
            trust_score=scores["overall"],
            trust_level=trust_level,
            score_breakdown=scores,
            results=all_results,
            ground_truth_provided=self.ground_truth is not None,
            defense_profile=defense_profile.to_dict() if defense_profile.defense_system != "unknown" else None,
            mutation_results=mutation_results_list,
            mutation_resistance=mutation_resistance,
            attack_chains=attack_chains,
        )
