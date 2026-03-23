import { describe, it, expect } from "vitest";
import { buildInjectionProbes } from "../../src/probes/injection.js";

describe("buildInjectionProbes", () => {
  const probes = buildInjectionProbes();

  it("generates 145 injection probes", () => {
    expect(probes).toHaveLength(145);
  });

  it("all probes have required fields", () => {
    for (const probe of probes) {
      expect(probe.probe_id).toBeTruthy();
      expect(probe.category).toBeTruthy();
      expect(probe.technique).toBeTruthy();
      expect(probe.severity).toBeTruthy();
      expect(probe.payload).toBeTruthy();
    }
  });

  it("all probe_ids are unique", () => {
    const ids = probes.map((p) => p.probe_id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("all probes have unique canary strings", () => {
    const canaries = probes.map((p) => p.canary).filter(Boolean);
    expect(canaries.length).toBe(probes.length);
    expect(new Set(canaries).size).toBe(canaries.length);
  });

  it("canary strings appear in payloads", () => {
    for (const probe of probes) {
      const payload = Array.isArray(probe.payload) ? probe.payload.join(" ") : probe.payload;
      expect(payload).toContain(probe.canary);
    }
  });

  it("includes expected categories", () => {
    const categories = new Set(probes.map((p) => p.category));
    expect(categories.has("instruction_override")).toBe(true);
    expect(categories.has("delimiter_attack")).toBe(true);
    expect(categories.has("persona_hijack")).toBe(true);
    expect(categories.has("a2a_injection")).toBe(true);
    expect(categories.has("tag_char_injection")).toBe(true);
    expect(categories.has("codechameleon")).toBe(true);
    expect(categories.has("tool_desc_injection")).toBe(true);
    expect(categories.has("memory_poison_injection")).toBe(true);
    expect(categories.has("logic_trap_injection")).toBe(true);
    expect(categories.has("cot_hijacking")).toBe(true);
    expect(categories.has("role_confusion")).toBe(true);
    expect(categories.has("tool_invocation_hijacking")).toBe(true);
    expect(categories.has("conditional_trigger")).toBe(true);
    expect(categories.has("likert_judge")).toBe(true);
  });
});
