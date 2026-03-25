# agentseal/blocklist.py
"""
Malicious skill blocklist client.

Maintains a local cache of known-malicious skill hashes.
Auto-updates from agentseal.org on each run (with 1-hour cache TTL).
Works fully offline — falls back to cached or empty blocklist.
"""

import json
import time
from pathlib import Path


class Blocklist:
    """Client for the AgentSeal malicious skill blocklist."""

    REMOTE_URL = "https://agentseal.org/api/v1/blocklist/skills.json"
    CACHE_TTL = 3600  # 1 hour

    # Seed hashes — canonical malicious skill patterns (guard works offline from day 1).
    # SHA256 hashes of documented attack patterns that circulate in the wild.
    # Updated on each release; remote fetch adds any new hashes between releases.
    _SEED_HASHES: set[str] = {
        "854aa9bd5a641b03fcf2e4a26affb33057af3238a10a83e194c05384f371734f",  # credential-theft-cursorrules
        "46315c1d4dcd39199c6d0e43985c5007c1156bc538e3a82ba9b2883f363eab35",  # markdown-image-exfil
        "0b2ca8fedb87a97de9f5c462e09110febf887516dd62877d7e95a5556ef90905",  # reverse-shell-instruction
        "2b5a339d00216894c7bd3620e008e5443f4e30b9e9883a2b15c082d076775084",  # curl-exfil-instruction
        "eccb3a65c459a6b69223d38726e3fddb6184a6e7c52935148fdcd84961a6f9df",  # prompt-injection-override
        "f554a511faaca2431265399a9d5b2f7184778b9521952dc757257dbe0aab2a46",  # supply-chain-install
        "323b9121b6e320fb04bae89c963690069c5172dca017469be2917e5feaec886c",  # obfuscated-credential-theft
        "4826c0e8aef00f902190ab32519e4533b7e4b725f46fb70156705ea8708a7385",  # social-engineering-exfil
        "3951cdb38bbc37e28f98448e0478b93d319d892783efb23462b59fedea52189d",  # mcp-config-injection
        "a7ddd5ce6c41055b4ef808810ac6f1b09dc4ae05eecc2f89dc64ac4682502d99",  # keylogger-instruction
        "eab3b7330de3b61fae1b5cba738ae499424e1c45ef1b025c560cca410e6cd16b",  # crypto-miner-injection
        "d71ceee36d1e136a5cddc0d5b416210d94635a71fa90f9ef817f4f74a7b21603",  # dns-exfil-instruction
    }

    def __init__(self):
        self._hashes: set[str] = set(self._SEED_HASHES)
        self._loaded = False
        # Lazy compute paths to avoid calling Path.home() at import time
        self._cache_dir: Path | None = None
        self._cache_path: Path | None = None

    @property
    def CACHE_DIR(self) -> Path:
        if self._cache_dir is None:
            self._cache_dir = Path.home() / ".agentseal"
        return self._cache_dir

    @CACHE_DIR.setter
    def CACHE_DIR(self, value: Path):
        self._cache_dir = value

    @property
    def CACHE_PATH(self) -> Path:
        if self._cache_path is None:
            self._cache_path = self.CACHE_DIR / "blocklist.json"
        return self._cache_path

    @CACHE_PATH.setter
    def CACHE_PATH(self, value: Path):
        self._cache_path = value

    def _load(self):
        """Load blocklist: try cache first, refresh from remote if stale."""
        if self._loaded:
            return

        # Check cache freshness
        if self.CACHE_PATH.is_file():
            try:
                age = time.time() - self.CACHE_PATH.stat().st_mtime
                if age < self.CACHE_TTL:
                    self._load_from_file(self.CACHE_PATH)
                    self._loaded = True
                    return
            except OSError:
                pass

        # Try remote fetch (non-blocking, short timeout)
        if self._try_remote_fetch():
            self._loaded = True
            return

        # Fall back to stale cache
        if self.CACHE_PATH.is_file():
            self._load_from_file(self.CACHE_PATH)

        self._loaded = True

    def _load_from_file(self, path: Path):
        """Load hashes from a local JSON file."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self._hashes = set(data.get("sha256_hashes", []))
        except (json.JSONDecodeError, OSError, KeyError):
            self._hashes = set()

    def _try_remote_fetch(self) -> bool:
        """Try to fetch blocklist from remote. Returns True on success."""
        try:
            import httpx
            resp = httpx.get(self.REMOTE_URL, timeout=5.0, follow_redirects=True)
            if resp.status_code == 200:
                data = resp.json()
                self._hashes = set(data.get("sha256_hashes", []))
                # Cache locally
                self.CACHE_DIR.mkdir(parents=True, exist_ok=True)
                self.CACHE_PATH.write_text(resp.text, encoding="utf-8")
                return True
        except Exception:
            pass  # Network unavailable — that's fine
        return False

    def is_blocked(self, sha256: str) -> bool:
        """Check if a SHA256 hash is in the blocklist."""
        self._load()
        return sha256.lower() in self._hashes

    @property
    def size(self) -> int:
        """Number of hashes in the blocklist."""
        self._load()
        return len(self._hashes)
