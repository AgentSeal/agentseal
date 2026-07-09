# Guarded Local Agent Execution Pattern

A security pattern for running local coding agents (MCP-driven or otherwise) with
narrow, auditable authority instead of a general-purpose shell. This document
describes the pattern itself and how a detection tool such as AgentSeal can
verify that a project follows it.

The pattern is implementation-agnostic. Any executor that enforces the pillars
below satisfies it; AgentSeal's role is detection and verification, not
enforcement.

---

## Why this pattern exists

Local coding agents increasingly receive broad capabilities: filesystem access,
shell execution, and MCP tool calls. When that authority is unbounded, a single
poisoned skill file, malicious MCP tool description, or an upstream model
mistake can escalate into:

- Secret exfiltration (`.env`, SSH keys, tokens, cookies read from disk).
- Execution of commands the operator never authorized (`npm publish`, `git push`,
  destructive shell).
- Writes outside the intended project directory.
- Changes the operator cannot reconstruct after the fact.

The guarded execution pattern narrows the agent's authority to a declarative,
reviewable surface so that detection tools have a stable policy baseline to
compare behavior against.

---

## The five pillars

### 1. Workspace confinement

All file reads and writes are bounded to a single configured workspace root.
Paths are rejected when they:

- Resolve outside the workspace via `..` traversal.
- Are absolute and point outside the root.
- Target sensitive locations by default (home directory, disk root, desktop,
  downloads, documents).

Confinement must be path-normalization-aware. On case-insensitive filesystems
(macOS APFS default), path-based controls can be bypassed by changing case
(e.g., `/Users` -> `/users`). AgentSeal's `fs_safety` detection already warns
on this; executors should normalize and compare case-insensitively where the
filesystem requires it.

### 2. Command allowlists with exact matching

The agent may only run commands that appear verbatim in a trusted allowlist.
There is no shell passthrough and no fuzzy matching. A verification command
`npm test` is not satisfied by `npm test --`, `npm  test`, or `npm run test`
unless each is listed separately.

High-risk commands (`publish`, `push`, `tag`, `release create`, `deploy`) are
excluded from automatic execution regardless of the allowlist. Repo-specific
commands extend the global allowlist only from local trusted configuration,
never from a file the target repository itself can modify.

### 3. Pre-registered agents

The command used to launch the executing agent comes from local, trusted
configuration. It is never derived from model input, tool output, or repository
content. Each registered agent entry is a fixed command and argument template;
placeholders (such as a repo path or prompt) are interpolated by the executor,
not concatenated as raw shell.

This maps directly to AgentSeal's `.agentseal.yaml` `allowed_agents` list: an
agent not present in the allowlist produces a `GUARD-001` finding, so the
detection side and the execution side share one source of truth for "which
agents may run here".

### 4. Sensitive file blocking

A default-deny list blocks reads and writes to credential-bearing paths
regardless of what a policy otherwise permits. Typical entries:

- `.env`, `.env.*`
- SSH keys and known hosts (`.ssh/`, `id_rsa`, `id_ed25519`)
- API token / cookie stores (`cookies.db`, `.npmrc`, `.pypirc`)
- Per-tool credential caches

If a policy were to permit reading such a path, the executor must still refuse;
the policy is invalid and should be corrected, not silently relaxed. Detectors
(see below) read the **names and patterns** in a policy file, never the
contents of the files those patterns refer to.

### 5. Auditable task evidence

Each task produces structured, bounded evidence so a human (or a detection
tool) can reconstruct what happened without re-running it:

- A structured result record with paths touched and warnings.
- A full diff of changes.
- Per-command verification records (command, exit status, bounded log tail).
- Scope-violation markers when changes appear outside declared paths.
- Redaction of suspected secret values in all artifacts.

Evidence is the contract between the executor and the detector: the detector
compares declared policy against recorded behavior, and the redaction record
proves no secret value was carried into the audit trail.

---

## Detection-side guidance (AgentSeal)

AgentSeal detects and verifies; it does not enforce. The pattern above gives
AgentSeal a concrete baseline to check a project against using its existing
mechanisms.

### Project policy as the shared baseline

`.agentseal.yaml` already encodes two pillars directly:

```yaml
# .agentseal.yaml
fail_on: danger

# Pillar 3: pre-registered agents only
allowed_agents:
  - opencode
  - codex

# Pillar 1+3: pre-registered MCP servers only (workspace-bounded)
allowed_mcp_servers:
  - filesystem@claude-code

ignore_paths:
  - node_modules
  - .git
  - .patchwarden      # task evidence / local runtime state
```

Unlisted agents surface as `GUARD-001`; unlisted MCP servers as `GUARD-002`.
A project that follows the guarded pattern should have a non-empty, reviewed
allowlist rather than leaving these blank (blank disables the check).

### Custom rules for the remaining pillars

The custom YAML rule engine can flag configurations that violate pillars 1, 2,
and 4. Rules match against `mcp`, `skill`, or `agent` entities with glob
patterns. Example rules encoding the pattern:

```yaml
rules:
  - id: GUARD-EXEC-001
    title: MCP server grants unrestricted shell
    description: >
      An MCP server exposes a generic shell/exec tool. The guarded execution
      pattern requires command allowlists with exact matching, not arbitrary
      shell passthrough.
    severity: high
    verdict: danger
    match:
      type: mcp
      name:
        - "*shell*"
        - "*exec*"
        - "*terminal*"
    remediation: >
      Replace the shell tool with a confined executor that enforces a command
      allowlist, or remove the server from allowed_mcp_servers.
    tests:
      - name: matches shell server
        input: { name: "local-shell" }
        expect: match
      - name: does not match confined server
        input: { name: "filesystem" }
        expect: no_match

  - id: GUARD-EXEC-002
    title: Skill file references credential paths
    description: >
      A skill file names .env, SSH keys, or token stores. Under the guarded
      pattern these paths are default-deny; their presence in a skill is a
      strong indicator of an exfiltration attempt.
    severity: critical
    verdict: danger
    match:
      type: skill
      content:
        - "*.env*"
        - "*id_rsa*"
        - "*cookies.db*"
        - "*.pem"
    remediation: >
      Review the skill file for prompt injection or data exfiltration. Do not
      run the skill until the reference is explained.
    tests:
      - name: matches env reference
        input: { content: "read the .env file" }
        expect: match
      - name: does not match benign content
        input: { content: "run the tests" }
        expect: no_match
```

Validate rules with `agentseal guard test` before relying on them.

### Detector hygiene: never read secret contents

A detector verifying this pattern must observe **policy metadata and recorded
behavior**, not secret values:

- Read allowlist entries, path patterns, and finding codes.
- Read the **names** of evidence files (e.g., a `verify.json` exists, a
  `redactions.json` exists), not the contents of credential files those
  artifacts reference.
- Treat the presence of a project policy file (for example a
  `project-policy.json` declaring `allowed_commands` and `blocked_files`) as a
  signal that the pattern is in use. Parse only the declarative fields
  (`allowed_commands`, `protected_paths`, `blocked_files`). Do not read the
  files those fields point at.
- If a policy file itself appears to contain a secret value (a literal token,
  key, or cookie), flag it as a finding rather than echoing the value.

This keeps the detector non-exfiltrating by construction: it can confirm that
secrets are protected without ever holding them.

---

## Mapping pillars to detections

| Pillar | Executor responsibility | AgentSeal detection |
|---|---|---|
| Workspace confinement | Reject out-of-workspace paths | `GUARD-002` for unlisted filesystem MCP; `fs_safety` case-sensitivity warning |
| Command allowlists (exact) | Match verify commands verbatim | Custom rule `GUARD-EXEC-001` flags generic shell tools |
| Pre-registered agents | Launch from local config only | `GUARD-001` for unlisted agents |
| Sensitive file blocking | Default-deny credential paths | Custom rule `GUARD-EXEC-002` flags credential references in skills |
| Auditable task evidence | Emit structured, redacted artifacts | Baseline tracking detects missing/changed evidence files |

---

## What the pattern does and does not mitigate

**Mitigates:**

- Accidental broad-shell exposure from a misconfigured MCP server.
- An upstream model running commands the operator did not intend.
- Silent writes outside the project directory.
- Credential files leaking into agent context or audit trails.
- Undetectable post-hoc changes (evidence is reconstructable).

**Does not mitigate:**

- A compromised executor binary itself (the executor is the trusted root).
- Social-engineering the operator into widening the allowlist.
- Vulnerabilities in a registered agent's own tooling.
- A policy that intentionally permits a dangerous path; detectors can flag it,
  but enforcement still depends on the executor refusing.

The pattern reduces blast radius and makes violations observable. It is not a
substitute for human review of the diff and evidence before accepting any task
result.

---

## Relationship to existing executors

This pattern is derived from the security contract used by local-first agent
bridges that confine execution rather than expose a remote shell. PatchWarden is
one such executor; its `.patchwarden/project-policy.json`
(`allowed_commands`, `protected_paths`, `high_risk_commands`) and
`.patchwarden/config.json` are a concrete instance of the declarative policy
described above. The pattern itself does not depend on any specific executor:
any tool that enforces the five pillars and emits bounded evidence satisfies it,
and any detection tool that reads only policy metadata can verify it.

When integrating a guarded executor with AgentSeal, point
`allowed_agents` / `allowed_mcp_servers` at the executor's registered agents
and add the custom rules above so AgentSeal's `guard` verifies the confinement
contract on every scan.
