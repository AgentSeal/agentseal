"""Tests for agentseal.deobfuscate module."""

from __future__ import annotations

import time

import pytest

from agentseal.deobfuscate import (
    decode_base64_blocks,
    deobfuscate,
    expand_string_concat,
    normalize_unicode,
    strip_zero_width,
    unescape_sequences,
)


# --- strip_zero_width ---


def test_strip_zero_width_chars():
    # U+200B between letters should be removed.
    text = "he\u200bll\u200co\u200d"
    assert strip_zero_width(text) == "hello"


def test_strip_zero_width_preserves_normal_text():
    text = "normal text with spaces and punctuation!"
    assert strip_zero_width(text) == text


# --- normalize_unicode ---


def test_normalize_unicode_homoglyphs():
    # Cyrillic \u0430 (а) looks like Latin 'a'; NFKC may or may not map it.
    # Fullwidth is the reliable NFKC case; we test Cyrillic separately.
    cyrillic_a = "\u0430"  # Cyrillic Small Letter A
    result = normalize_unicode(cyrillic_a)
    # TR39 confusable mapping now remaps Cyrillic lookalikes to Latin.
    assert result == "a"


def test_normalize_unicode_fullwidth():
    # Fullwidth letters are reliably normalized by NFKC.
    fullwidth = "\uff46\uff49\uff4c\uff45"  # ｆｉｌｅ
    assert normalize_unicode(fullwidth) == "file"


# --- decode_base64_blocks ---


def test_decode_base64_block():
    # "hello world" in base64
    text = "aGVsbG8gd29ybGQ="
    assert decode_base64_blocks(text) == "hello world"


def test_decode_base64_preserves_non_base64():
    text = "this is normal text without encoding"
    assert decode_base64_blocks(text) == text


def test_decode_base64_skips_short_strings():
    # Tokens < 8 chars should not be decoded even if valid base64.
    text = "YWJj"  # "abc" in base64, only 4 chars
    assert decode_base64_blocks(text) == "YWJj"


def test_decode_base64_skips_binary_result():
    # A valid base64 string that decodes to non-printable binary.
    # \x00\x01\x02\x03\x04\x05\x06\x07 in base64:
    text = "AAECAwQFBgc="
    assert decode_base64_blocks(text) == "AAECAwQFBgc="


def test_decode_base64_in_context():
    # Base64 embedded in a larger expression with quotes.
    # "curl" in base64 is Y3VybA== (8 chars with padding).
    text = "run eval(atob('Y3VybA=='))"
    result = decode_base64_blocks(text)
    assert "curl" in result


# --- unescape_sequences ---


def test_unescape_hex_sequences():
    text = r"\x41\x42\x43"
    assert unescape_sequences(text) == "ABC"


def test_unescape_unicode_sequences():
    text = r"\u0041\u0042\u0043"
    assert unescape_sequences(text) == "ABC"


# --- expand_string_concat ---


def test_expand_string_concat_double_quotes():
    text = '"abc" + "def"'
    assert expand_string_concat(text) == '"abcdef"'


def test_expand_string_concat_single_quotes():
    text = "'abc' + 'def'"
    assert expand_string_concat(text) == "'abcdef'"


def test_expand_no_variable_expansion():
    # Concatenation with a variable should NOT be expanded.
    text = '"abc" + var'
    assert expand_string_concat(text) == '"abc" + var'


# --- deobfuscate (full pipeline) ---


def test_deobfuscate_full_pipeline():
    # Combine multiple obfuscation techniques.
    # Zero-width chars + string concat + hex escapes.
    text = '"he\u200bllo" + " wo\\x72ld"'
    result = deobfuscate(text)
    assert "hello world" in result


def test_deobfuscate_idempotent():
    text = '"he\u200bllo" + " wo\\x72ld"'
    once = deobfuscate(text)
    twice = deobfuscate(once)
    assert once == twice


def test_deobfuscate_empty_string():
    assert deobfuscate("") == ""


def test_deobfuscate_pure_ascii_passthrough():
    text = "import os\nprint('hello world')\n"
    assert deobfuscate(text) == text


def test_deobfuscate_large_text_performance():
    # Must process 100KB in under 50ms.
    large_text = "import os; print('hello')\n" * 4000  # ~100KB
    start = time.perf_counter()
    deobfuscate(large_text)
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert elapsed_ms < 50, f"Took {elapsed_ms:.1f}ms, expected < 50ms"
