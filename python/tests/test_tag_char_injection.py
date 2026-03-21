# tests/test_tag_char_injection.py
"""Tests for Unicode Tag Block character injection probes (inj_tag_unicode_*)."""
import pytest
from agentseal.probes.injection import build_injection_probes
from agentseal.schemas import Severity


class TestTagCharInjection:
    def setup_method(self):
        self.probes = build_injection_probes()
        self.category_probes = [p for p in self.probes if p["category"] == "tag_char_injection"]

    def test_probe_count(self):
        assert len(self.category_probes) == 3

    def test_probe_ids_unique(self):
        ids = [p["probe_id"] for p in self.category_probes]
        assert len(ids) == len(set(ids))
        assert all(pid.startswith("inj_tag_unicode_") for pid in ids)

    def test_probe_structure(self):
        required = {"probe_id", "category", "technique", "severity", "payload", "canary", "canary_position"}
        for p in self.category_probes:
            assert required.issubset(p.keys()), f"Missing keys in {p['probe_id']}"

    def test_severity_critical(self):
        for p in self.category_probes:
            assert p["severity"] == Severity.CRITICAL

    def test_canary_present(self):
        for p in self.category_probes:
            assert p["canary"], f"No canary in {p['probe_id']}"
            assert "_CONFIRMED" in p["canary"]

    def test_payload_contains_tag_chars(self):
        """Each payload must contain actual U+E0000-range tag characters."""
        for p in self.category_probes:
            payload = p["payload"]
            assert any(0xE0000 <= ord(c) <= 0xE007F for c in payload), (
                f"{p['probe_id']}: payload contains no U+E0000-range tag characters"
            )

    def test_canary_encoded_in_tag_chars(self):
        """The canary must appear encoded as tag characters within the payload."""
        for p in self.category_probes:
            canary = p["canary"]
            payload = p["payload"]
            # Decode all tag chars in the payload back to ASCII
            decoded = "".join(
                chr(ord(c) - 0xE0000) if 0xE0000 <= ord(c) <= 0xE007F else c
                for c in payload
            )
            assert canary in decoded, (
                f"{p['probe_id']}: canary '{canary}' not found in decoded tag-char content"
            )

    def test_payload_has_visible_text(self):
        """Payload must have visible (non-tag) text to mimic legitimate content."""
        for p in self.category_probes:
            visible = "".join(c for c in p["payload"] if not (0xE0000 <= ord(c) <= 0xE007F))
            assert len(visible.strip()) > 20, (
                f"{p['probe_id']}: payload has insufficient visible text"
            )
