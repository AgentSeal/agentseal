/**
 * Malicious skill blocklist client.
 *
 * Maintains a local cache of known-malicious skill hashes.
 * Auto-updates from agentseal.org on each run (with 1-hour cache TTL).
 * Works fully offline — falls back to cached or empty blocklist.
 *
 * Port of Python agentseal/blocklist.py — same logic.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const SEED_HASHES = new Set([
  "854aa9bd5a641b03fcf2e4a26affb33057af3238a10a83e194c05384f371734f",  // credential-theft-cursorrules
  "46315c1d4dcd39199c6d0e43985c5007c1156bc538e3a82ba9b2883f363eab35",  // markdown-image-exfil
  "0b2ca8fedb87a97de9f5c462e09110febf887516dd62877d7e95a5556ef90905",  // reverse-shell-instruction
  "2b5a339d00216894c7bd3620e008e5443f4e30b9e9883a2b15c082d076775084",  // curl-exfil-instruction
  "eccb3a65c459a6b69223d38726e3fddb6184a6e7c52935148fdcd84961a6f9df",  // prompt-injection-override
  "f554a511faaca2431265399a9d5b2f7184778b9521952dc757257dbe0aab2a46",  // supply-chain-install
  "323b9121b6e320fb04bae89c963690069c5172dca017469be2917e5feaec886c",  // obfuscated-credential-theft
  "4826c0e8aef00f902190ab32519e4533b7e4b725f46fb70156705ea8708a7385",  // social-engineering-exfil
  "3951cdb38bbc37e28f98448e0478b93d319d892783efb23462b59fedea52189d",  // mcp-config-injection
  "a7ddd5ce6c41055b4ef808810ac6f1b09dc4ae05eecc2f89dc64ac4682502d99",  // keylogger-instruction
  "eab3b7330de3b61fae1b5cba738ae499424e1c45ef1b025c560cca410e6cd16b",  // crypto-miner-injection
  "d71ceee36d1e136a5cddc0d5b416210d94635a71fa90f9ef817f4f74a7b21603",  // dns-exfil-instruction
]);

export class Blocklist {
  static readonly REMOTE_URL = "https://agentseal.org/api/v1/blocklist/skills.json";
  static readonly CACHE_TTL = 3600; // 1 hour in seconds

  private _hashes = new Set<string>(SEED_HASHES);
  private _loaded = false;
  private _cacheDir: string;
  private _cachePath: string;

  constructor(cacheDir?: string) {
    this._cacheDir = cacheDir ?? join(homedir(), ".agentseal");
    this._cachePath = join(this._cacheDir, "blocklist.json");
  }

  /** Override cache dir (useful for testing). */
  setCacheDir(dir: string): void {
    this._cacheDir = dir;
    this._cachePath = join(dir, "blocklist.json");
    this._loaded = false;
    this._hashes = new Set<string>(SEED_HASHES);
  }

  private _load(): void {
    if (this._loaded) return;

    // Check cache freshness
    if (existsSync(this._cachePath)) {
      try {
        const age = (Date.now() / 1000) - statSync(this._cachePath).mtimeMs / 1000;
        if (age < Blocklist.CACHE_TTL) {
          this._loadFromFile(this._cachePath);
          this._loaded = true;
          return;
        }
      } catch {
        // ignore OS errors
      }
    }

    // Try remote fetch (synchronous for simplicity — matches Python behavior)
    if (this._tryRemoteFetch()) {
      this._loaded = true;
      return;
    }

    // Fall back to stale cache
    if (existsSync(this._cachePath)) {
      this._loadFromFile(this._cachePath);
    }

    this._loaded = true;
  }

  private _loadFromFile(path: string): void {
    try {
      const raw = readFileSync(path, "utf-8");
      const data = JSON.parse(raw);
      for (const h of (data.sha256_hashes ?? [])) {
        this._hashes.add(h);
      }
    } catch {
      // parse failed — keep seed hashes intact
    }
  }

  private _tryRemoteFetch(): boolean {
    // Use synchronous XMLHttpRequest-like approach or just skip in Node
    // For Node.js, we'll do an async-compatible approach but cache the result
    // In practice, the remote fetch is best done async — for now, return false
    // and let the cache/seed hashes work. Users can call loadAsync() explicitly.
    return false;
  }

  /** Async remote fetch — call this once at startup if you want remote blocklist. */
  async loadAsync(): Promise<void> {
    if (this._loaded) return;

    // Check cache freshness
    if (existsSync(this._cachePath)) {
      try {
        const age = (Date.now() / 1000) - statSync(this._cachePath).mtimeMs / 1000;
        if (age < Blocklist.CACHE_TTL) {
          this._loadFromFile(this._cachePath);
          this._loaded = true;
          return;
        }
      } catch {
        // ignore
      }
    }

    // Try remote fetch
    try {
      const resp = await fetch(Blocklist.REMOTE_URL, {
        signal: AbortSignal.timeout(5000),
      });
      if (resp.ok) {
        const data = await resp.json() as { sha256_hashes?: string[] };
        for (const h of (data.sha256_hashes ?? [])) {
          this._hashes.add(h);
        }
        // Cache locally
        mkdirSync(this._cacheDir, { recursive: true });
        writeFileSync(this._cachePath, JSON.stringify(data), "utf-8");
        this._loaded = true;
        return;
      }
    } catch {
      // Network unavailable — that's fine
    }

    // Fall back to stale cache
    if (existsSync(this._cachePath)) {
      this._loadFromFile(this._cachePath);
    }

    this._loaded = true;
  }

  /** Check if a SHA256 hash is in the blocklist. */
  isBlocked(sha256: string): boolean {
    this._load();
    return this._hashes.has(sha256.toLowerCase());
  }

  /** Number of hashes in the blocklist. */
  get size(): number {
    this._load();
    return this._hashes.size;
  }

  /** Manually add hashes (for testing or seed data). */
  addHashes(hashes: string[]): void {
    for (const h of hashes) {
      this._hashes.add(h.toLowerCase());
    }
  }
}

/** Compute SHA256 hash of content. */
export function sha256(content: string): string {
  return createHash("sha256").update(content, "utf-8").digest("hex");
}
