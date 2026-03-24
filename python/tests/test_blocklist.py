# tests/test_blocklist.py
"""Tests for blocklist client."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from agentseal.blocklist import Blocklist


class TestBlocklist:
    def test_empty_blocklist(self, tmp_path):
        """Blocklist with no cache and cleared seeds reports nothing blocked."""
        bl = Blocklist()
        bl.CACHE_PATH = tmp_path / "nonexistent.json"
        bl._loaded = True  # Skip loading
        bl._hashes = set()  # Clear seed hashes to test empty state
        assert bl.is_blocked("abc123") is False
        assert bl.size == 0

    def test_seed_hashes_present(self):
        """Blocklist ships with seed hashes for offline protection."""
        bl = Blocklist()
        assert len(bl._SEED_HASHES) >= 10, "Should have at least 10 seed hashes"
        assert len(bl._hashes) == len(bl._SEED_HASHES), "Initial hashes should equal seeds"

    def test_known_hash_blocked(self):
        bl = Blocklist()
        bl._hashes = {"abc123", "def456"}
        bl._loaded = True
        assert bl.is_blocked("abc123") is True
        assert bl.is_blocked("def456") is True
        assert bl.is_blocked("xyz789") is False

    def test_case_insensitive(self):
        bl = Blocklist()
        bl._hashes = {"abc123"}
        bl._loaded = True
        assert bl.is_blocked("ABC123") is True

    def test_loads_from_cache(self, tmp_path):
        cache = tmp_path / "blocklist.json"
        cache.write_text(json.dumps({"sha256_hashes": ["hash1", "hash2"]}))

        bl = Blocklist()
        bl.CACHE_PATH = cache
        bl.CACHE_DIR = tmp_path
        bl.CACHE_TTL = 99999  # Don't expire

        assert bl.is_blocked("hash1") is True
        assert bl.is_blocked("hash2") is True
        assert bl.size == 2

    def test_fallback_on_corrupt_cache(self, tmp_path):
        cache = tmp_path / "blocklist.json"
        cache.write_text("not valid json")

        bl = Blocklist()
        bl.CACHE_PATH = cache
        bl.CACHE_DIR = tmp_path
        bl.CACHE_TTL = 99999

        # Should not raise
        assert bl.is_blocked("anything") is False
        assert bl.size == 0
