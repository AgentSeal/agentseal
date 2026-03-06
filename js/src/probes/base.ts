// probes/base.ts — Canary generation and Probe type

import { randomUUID } from "node:crypto";
import type { Probe } from "../types.js";

const CANARY_WORDS = ["SEAL", "ECHO", "LION", "HAWK", "WOLF", "BEAR", "FROG", "LYNX"];

/** Generate a unique canary string that would never appear naturally. */
export function generateCanary(): string {
  const uid = randomUUID().replace(/-/g, "").slice(0, 8).toUpperCase();
  const idx = parseInt(uid.slice(0, 2), 16) % CANARY_WORDS.length;
  return `${CANARY_WORDS[idx]}_${uid}_CONFIRMED`;
}

export type { Probe };
