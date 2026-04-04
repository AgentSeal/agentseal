import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { saveConfigKey, loadConfig, DEFAULT_CONFIG_PATH } from "./config.js";

const CONFIG_DIR = join(homedir(), ".agentseal");

export interface Credentials {
  apiUrl: string;
  apiKey: string;
}

export function saveCredentials(apiUrl: string, apiKey: string, path?: string): void {
  saveConfigKey("dashboard-url", apiUrl, path ?? DEFAULT_CONFIG_PATH);
  saveConfigKey("dashboard-key", apiKey, path ?? DEFAULT_CONFIG_PATH);
}

export function loadCredentials(path?: string): Credentials | null {
  const cfg = loadConfig(path ?? DEFAULT_CONFIG_PATH);
  if (!cfg["dashboard-url"] || !cfg["dashboard-key"]) return null;
  return { apiUrl: cfg["dashboard-url"], apiKey: cfg["dashboard-key"] };
}

export function saveLicense(key: string, path: string = join(CONFIG_DIR, "license.json")): void {
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(path, JSON.stringify({ key, activated: new Date().toISOString() }, null, 2), { mode: 0o600 });
  chmodSync(path, 0o600);
}

export function loadLicense(path: string = join(CONFIG_DIR, "license.json")): string | null {
  if (!existsSync(path)) return null;
  const data = JSON.parse(readFileSync(path, "utf-8"));
  return data.key ?? null;
}
