import { describe, it, expect } from "vitest";
import { selectCanaryProbes, checkRegression } from "../src/watch.js";

describe("watch", () => {
  it("selects 5 canary probes by default", () => {
    const probes = selectCanaryProbes();
    expect(probes).toHaveLength(5);
  });

  it("detects regression when score drops", () => {
    const result = checkRegression(70, 80, 5);
    expect(result.regression).toBe(true);
    expect(result.delta).toBe(10);
  });

  it("no regression when score is stable", () => {
    const result = checkRegression(78, 80, 5);
    expect(result.regression).toBe(false);
  });
});
