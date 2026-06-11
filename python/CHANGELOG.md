# Changelog

## 0.10.0 — Dynamic agent testing (opt-in)

### Added
- `agentseal scan --smart`: after the static scan, run a bounded **adaptive (PAIR)** attacker that escalates against the target across turns and reports findings. BYOK, and **not scored** — the deterministic Trust Score stays the static suite.
- `--attacker-model`: drive the adaptive attacker on a separate (e.g. less-aligned) model while still testing the real target.
- Tool-calling test path: action-based detection — flags an agent that invokes a forbidden tool or smuggles data through tool arguments.
- Multi-turn conversation state: multi-turn probes now thread history so gradual-escalation attacks actually work.

### Fixed
- Report-save failures warn instead of being silently swallowed.
- Ollama connector read timeout 60s -> 180s (local "thinking" models).
