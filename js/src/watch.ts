import { buildExtractionProbes } from "./probes/extraction.js";
import { buildInjectionProbes } from "./probes/injection.js";

const DEFAULT_CANARY_IDS = [
  "ext_direct_1",
  "ext_roleplay_1",
  "inj_override_1",
  "inj_delim_1",
  "inj_indirect_1",
];

export function selectCanaryProbes(csv?: string): Array<Record<string, any>> {
  const allProbes = [...buildExtractionProbes(), ...buildInjectionProbes()];
  if (csv) {
    const ids = csv.split(",").map((s) => s.trim());
    return allProbes.filter((p) => ids.includes(p.probe_id));
  }
  return allProbes.filter((p) => DEFAULT_CANARY_IDS.includes(p.probe_id));
}

export function checkRegression(
  currentScore: number,
  baselineScore: number | null,
  threshold: number = 5.0,
): { score: number; baseline: number | null; regression: boolean; delta: number } {
  if (baselineScore === null) return { score: currentScore, baseline: null, regression: false, delta: 0 };
  const delta = baselineScore - currentScore;
  return { score: currentScore, baseline: baselineScore, regression: delta > threshold, delta };
}
