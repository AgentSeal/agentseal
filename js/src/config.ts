import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";

export const CONFIG_DIR = join(homedir(), ".agentseal");
export const DEFAULT_CONFIG_PATH = join(CONFIG_DIR, "config.json");

export const CONFIG_KEYS = [
  "model", "api-key", "ollama-url", "litellm-url", "dashboard-url", "dashboard-key",
] as const;

export type ConfigKey = (typeof CONFIG_KEYS)[number];

export function loadConfig(path: string = DEFAULT_CONFIG_PATH): Record<string, string> {
  if (!existsSync(path)) return {};
  return JSON.parse(readFileSync(path, "utf-8"));
}

export function saveConfigKey(key: string, value: string, path: string = DEFAULT_CONFIG_PATH): void {
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  const cfg = loadConfig(path);
  cfg[key] = value;
  writeFileSync(path, JSON.stringify(cfg, null, 2), { mode: 0o600 });
  chmodSync(path, 0o600);
}

export function removeConfigKey(key: string, path: string = DEFAULT_CONFIG_PATH): void {
  const cfg = loadConfig(path);
  delete cfg[key];
  writeFileSync(path, JSON.stringify(cfg, null, 2), { mode: 0o600 });
  chmodSync(path, 0o600);
}

export function showConfig(path: string = DEFAULT_CONFIG_PATH): string {
  const cfg = loadConfig(path);
  if (Object.keys(cfg).length === 0) return "No configuration set.";
  return Object.entries(cfg)
    .map(([k, v]) => {
      const display = k.includes("key") ? v.slice(0, 8) + "..." : v;
      return `  ${k}: ${display}`;
    })
    .join("\n");
}
