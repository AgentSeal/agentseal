"""Text deobfuscation transforms for skill file content.

Applied BEFORE regex pattern matching to make obfuscated payloads
visible to existing detection patterns. Stdlib only: re, base64, unicodedata.
"""

from __future__ import annotations

import base64
import html as _html_mod
import re
import unicodedata

__all__ = [
    "deobfuscate",
    "strip_zero_width",
    "strip_tag_chars",
    "strip_variation_selectors",
    "strip_bidi_controls",
    "strip_html_comments",
    "has_invisible_chars",
    "normalize_unicode",
    "decode_base64_blocks",
    "unescape_sequences",
    "expand_string_concat",
    "decode_html_entities",
]

# Zero-width and invisible characters to strip.
_ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\ufeff\u00ad\u2060]")

# Unicode Tag Characters (ASCII smuggling) — U+E0001 to U+E007F
_TAG_CHARS = re.compile("[\U000e0001-\U000e007f]")

# Variation Selectors — U+FE00-FE0F + U+E0100-E01EF
_VARIATION_SELECTORS = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]")

# BiDi Control Characters
_BIDI_CONTROLS = re.compile("[\u202a-\u202e\u2066-\u2069\u200e\u200f]")

# HTML comments with hidden instructions
_HTML_COMMENTS = re.compile(r"<!--[\s\S]*?-->")

# Combined invisible character detection pattern (for pre-strip detection)
_INVISIBLE_CHARS = re.compile(
    "[\u200b\u200c\u200d\ufeff\u00ad\u2060"
    "\U000e0001-\U000e007f"
    "\ufe00-\ufe0f\U000e0100-\U000e01ef"
    "\u202a-\u202e\u2066-\u2069\u200e\u200f]"
)

# Base64 block: standalone token of 8+ base64 chars (including padding).
# We use a non-capturing group approach instead of variable-width lookbehind.
_BASE64_BLOCK = re.compile(
    r"(?:(?<=[\"\'\s(])|(?<=^))([A-Za-z0-9+/=]{8,})(?=[\"'\s)]|$)",
    re.MULTILINE,
)

# Hex escape: \xHH
_HEX_ESCAPE = re.compile(r"\\x([0-9A-Fa-f]{2})")

# Unicode escape: \uHHHH
_UNICODE_ESCAPE = re.compile(r"\\u([0-9A-Fa-f]{4})")

# Common backslash escapes.
_SIMPLE_ESCAPES = {"\\n": "\n", "\\t": "\t", "\\r": "\r", "\\\\": "\\"}

# Adjacent string concatenation: "..." + "..." or '...' + '...'
_CONCAT_DOUBLE = re.compile(r'"([^"]*?)"\s*\+\s*"([^"]*?)"')
_CONCAT_SINGLE = re.compile(r"'([^']*?)'\s*\+\s*'([^']*?)'")


def strip_zero_width(text: str) -> str:
    """Remove zero-width characters: U+200B, U+200C, U+200D, U+FEFF, U+00AD, U+2060."""
    return _ZERO_WIDTH.sub("", text)


def strip_tag_chars(text: str) -> str:
    """Remove Unicode Tag Characters (U+E0001–U+E007F) used in ASCII smuggling."""
    return _TAG_CHARS.sub("", text)


def strip_variation_selectors(text: str) -> str:
    """Remove Variation Selectors (U+FE00–FE0F, U+E0100–E01EF)."""
    return _VARIATION_SELECTORS.sub("", text)


def strip_bidi_controls(text: str) -> str:
    """Remove BiDi control characters that can hide text direction."""
    return _BIDI_CONTROLS.sub("", text)


def strip_html_comments(text: str) -> str:
    """Remove HTML comments that may contain hidden instructions."""
    return _HTML_COMMENTS.sub("", text)


def has_invisible_chars(text: str) -> bool:
    """Check if text contains any invisible/obfuscation characters (before stripping)."""
    return bool(_INVISIBLE_CHARS.search(text))


# Unicode confusable mapping (TR39 skeleton subset).
# Maps visually similar characters from Cyrillic, Greek, Cherokee, etc.
# to their Latin equivalents. NFKC does NOT handle these.
_CONFUSABLES: dict[str, str] = {
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",  # Cyrillic uppercase
    "\u041d": "H", "\u0406": "I", "\u0408": "J", "\u041a": "K",
    "\u041c": "M", "\u041e": "O", "\u0420": "P", "\u0405": "S",
    "\u0422": "T", "\u0425": "X", "\u0423": "Y", "\u0417": "Z",
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u04bb": "h",  # Cyrillic lowercase
    "\u0456": "i", "\u0458": "j", "\u043e": "o", "\u0440": "p",
    "\u0455": "s", "\u0445": "x", "\u0443": "y",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",  # Greek uppercase
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N",
    "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
    "\u03a5": "Y", "\u0396": "Z",
    "\u03bf": "o", "\u03b1": "a",                                  # Greek lowercase
    "\u13a0": "D", "\u13a1": "R", "\u13a2": "T", "\u13aa": "G",  # Cherokee
    "\u13b3": "W", "\u13d2": "S", "\u13da": "S",
    "\uab4e": "s", "\uab4f": "s", "\uaba3": "s", "\uabaa": "s",    # Cherokee lowercase
    "\u0131": "i",                                                  # Turkish dotless i
    "\u1d00": "A", "\u0299": "B", "\u1d04": "C",                  # Small caps
    "\uff21": "A", "\uff22": "B", "\uff23": "C", "\uff24": "D",  # Fullwidth Latin
    "\uff25": "E", "\uff26": "F", "\uff27": "G", "\uff28": "H",
    "\uff29": "I", "\uff2a": "J", "\uff2b": "K", "\uff2c": "L",
    "\uff2d": "M", "\uff2e": "N", "\uff2f": "O", "\uff30": "P",
    "\uff31": "Q", "\uff32": "R", "\uff33": "S", "\uff34": "T",
    "\uff35": "U", "\uff36": "V", "\uff37": "W", "\uff38": "X",
    "\uff39": "Y", "\uff3a": "Z",
    "\uff41": "a", "\uff42": "b", "\uff43": "c", "\uff44": "d",  # Fullwidth lowercase
    "\uff45": "e", "\uff46": "f", "\uff47": "g", "\uff48": "h",
    "\uff49": "i", "\uff4a": "j", "\uff4b": "k", "\uff4c": "l",
    "\uff4d": "m", "\uff4e": "n", "\uff4f": "o", "\uff50": "p",
    "\uff51": "q", "\uff52": "r", "\uff53": "s", "\uff54": "t",
    "\uff55": "u", "\uff56": "v", "\uff57": "w", "\uff58": "x",
    "\uff59": "y", "\uff5a": "z",
}

_CONFUSABLES_TABLE = str.maketrans(_CONFUSABLES)


def normalize_unicode(text: str) -> str:
    """Apply NFKC normalization + TR39 confusable mapping.

    NFKC handles compatibility characters but misses Cyrillic/Greek/Cherokee
    lookalikes. The confusable table catches ~/.ꮪꮪh -> ~/.ssh, etc.
    """
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_CONFUSABLES_TABLE)
    return text


def _is_printable_text(data: bytes) -> bool:
    """Check if bytes are valid printable UTF-8 text."""
    try:
        s = data.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return False
    # Reject if more than 10% non-printable (excluding whitespace).
    non_printable = sum(1 for c in s if not c.isprintable() and c not in "\n\r\t ")
    return non_printable <= len(s) * 0.1


def decode_base64_blocks(text: str) -> str:
    """Find and decode inline base64 strings.

    Only decodes standalone tokens >= 8 chars that produce valid printable UTF-8.
    Single pass (no recursive decoding).
    """

    def _replace(m: re.Match) -> str:
        token = m.group(1)
        # Skip tokens that look like normal words (all lowercase alpha, no
        # digits, no uppercase mix that suggests encoding).
        if token.isalpha() and token.islower():
            return m.group(0)
        try:
            decoded = base64.b64decode(token, validate=True)
        except Exception:
            return m.group(0)
        if _is_printable_text(decoded):
            # Preserve surrounding delimiters from the original match.
            prefix = m.group(0)[: m.start(1) - m.start(0)]
            suffix = m.group(0)[m.end(1) - m.start(0) :]
            return prefix + decoded.decode("utf-8") + suffix
        return m.group(0)

    return _BASE64_BLOCK.sub(_replace, text)


def unescape_sequences(text: str) -> str:
    r"""Convert common escape sequences to actual characters.

    Handles: \xHH, \uHHHH, \\n, \\t, \\r, \\\\.
    Does NOT eval() anything.
    """
    # Protect literal \\ (double-backslash) from being partially consumed
    # by \xHH / \uHHHH regex subs.  Use a placeholder that cannot appear
    # in valid input, then restore after all other processing.
    _BKSL_PLACEHOLDER = "\x00BKSL\x00"
    text = text.replace("\\\\", _BKSL_PLACEHOLDER)

    # Hex / unicode escapes.
    text = _HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
    text = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)

    # Simple escapes (\n, \t, \r) — skip \\\\ which is already handled.
    for seq, char in _SIMPLE_ESCAPES.items():
        if seq == "\\\\":
            continue
        text = text.replace(seq, char)

    # Restore literal backslashes.
    text = text.replace(_BKSL_PLACEHOLDER, "\\")
    return text


def expand_string_concat(text: str) -> str:
    """Join adjacent string literal concatenations.

    "abc" + "def" -> "abcdef"
    'abc' + 'def' -> 'abcdef'

    Iterates until no more concatenations remain (handles chains like "a"+"b"+"c").
    Does NOT expand variables or function calls.
    """
    prev = None
    while prev != text:
        prev = text
        text = _CONCAT_DOUBLE.sub(r'"\1\2"', text)
        text = _CONCAT_SINGLE.sub(r"'\1\2'", text)
    return text


def decode_html_entities(text: str) -> str:
    """Decode HTML entities: &#99;&#117;&#114;&#108; -> curl.

    Catches both numeric (&#99;, &#x63;) and named (&amp;, &lt;) entities.
    """
    return _html_mod.unescape(text)


def _deobfuscate_pass(text: str) -> str:
    """Single pass of deobfuscation transforms."""
    text = strip_zero_width(text)
    text = strip_tag_chars(text)
    text = strip_variation_selectors(text)
    text = strip_bidi_controls(text)
    text = strip_html_comments(text)
    text = decode_html_entities(text)
    text = normalize_unicode(text)
    text = decode_base64_blocks(text)
    text = unescape_sequences(text)
    text = expand_string_concat(text)
    return text


def deobfuscate(text: str) -> str:
    """Apply all deobfuscation transforms to text (2-pass).

    Two passes catch layered obfuscation: e.g. base64-encoded content that
    itself contains zero-width chars or escape sequences. The first pass
    decodes base64, the second pass strips the revealed hidden content.

    Returns cleaned text for regex pattern matching.
    """
    text = _deobfuscate_pass(text)
    text = _deobfuscate_pass(text)
    return text
