"""Client for AgentSeal MCP registry trust score enrichment."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Optional

BULK_CHECK_URL = "https://agentseal.org/api/v1/mcp/intel/bulk-check"
TIMEOUT = 8


def slugify(name: str) -> str:
    """Derive registry slug from an MCP server name.
    Lowercase, strip @scope/ prefix to scope-name, replace non-alnum with dash.
    """
    if not name:
        return ""
    name = name.lower()
    name = re.sub(r"^@([^/]+)/", r"\1-", name)
    name = re.sub(r"[^a-z0-9-]", "-", name)
    return name


def extract_package_slug(command: str) -> Optional[str]:
    """Extract package name from command string and slugify it.
    Handles: npx @scope/pkg, npx pkg, uvx pkg, docker run img.
    Returns None for bare binaries or empty commands.
    """
    if not command:
        return None
    parts = command.strip().split()
    if len(parts) < 2:
        return None
    runner = parts[0].rsplit("/", 1)[-1]  # basename
    if runner in ("npx", "bunx", "uvx", "pip", "pipx"):
        # Skip flags like -y, --yes, -p, etc. to find the package name
        pkg = None
        for p in parts[1:]:
            if not p.startswith("-"):
                pkg = p
                break
        if not pkg:
            return None
        pkg = re.sub(r"@[\d.]+$", "", pkg)  # strip @version
        return slugify(pkg)
    if runner == "docker" and len(parts) >= 3 and parts[1] == "run":
        img = parts[2]
        img = img.split(":")[0]  # strip :tag
        return slugify(img)
    return None


def bulk_check(slugs: list[str], *, api_key: str | None = None) -> dict[str, dict]:
    """Call bulk-check endpoint. Returns {slug: {trust_score, trust_level, ...}}.
    Returns empty dict on any error. Skips API call if slugs list is empty.
    """
    if not slugs:
        return {}

    body = json.dumps({"slugs": list(set(slugs))}).encode()
    req = urllib.request.Request(
        BULK_CHECK_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "agentseal-guard/0.8",
        },
        method="POST",
    )
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read())
            if isinstance(data, dict):
                return data
            return {}
    except (TimeoutError, urllib.error.URLError, urllib.error.HTTPError,
            json.JSONDecodeError, OSError):
        return {}


def enrich_mcp_results(
    results: list,  # list[MCPServerResult] -- avoid circular import
    *,
    api_key: str | None = None,
) -> None:
    """Enrich MCPServerResult objects in-place with registry trust data.
    Tries matching by both server name slug and command package slug.
    """
    if not results:
        return

    slug_map: dict[str, list] = {}
    all_slugs: set[str] = set()
    for r in results:
        name_slug = slugify(r.name)
        cmd_slug = extract_package_slug(r.command)
        for s in (name_slug, cmd_slug):
            if s:
                all_slugs.add(s)
                slug_map.setdefault(s, []).append(r)

    if not all_slugs:
        return

    registry = bulk_check(list(all_slugs), api_key=api_key)

    for slug, data in registry.items():
        for r in slug_map.get(slug, []):
            if r.registry_score is None:
                r.registry_score = data.get("trust_score")
                r.registry_level = data.get("trust_level")
                r.registry_findings_count = data.get("findings_count")
                r.registry_tools = data.get("tools", [])
