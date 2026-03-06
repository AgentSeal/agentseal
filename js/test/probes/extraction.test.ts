import { describe, it, expect } from "vitest";
import { buildExtractionProbes } from "../../src/probes/extraction.js";

describe("buildExtractionProbes", () => {
  const probes = buildExtractionProbes();

  it("generates 72 extraction probes", () => {
    expect(probes).toHaveLength(72);
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

  it("includes expected categories", () => {
    const categories = new Set(probes.map((p) => p.category));
    expect(categories.has("direct_ask")).toBe(true);
    expect(categories.has("roleplay_override")).toBe(true);
    expect(categories.has("encoding_tricks")).toBe(true);
    expect(categories.has("output_format")).toBe(true);
  });

  it("has no canary strings (extraction probes don't use canaries)", () => {
    for (const probe of probes) {
      expect(probe.canary).toBeUndefined();
    }
  });
});
