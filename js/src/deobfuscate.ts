/**
 * Text deobfuscation transforms for skill file content.
 *
 * Applied BEFORE regex pattern matching to make obfuscated payloads
 * visible to existing detection patterns. Zero dependencies.
 *
 * Port of Python agentseal/deobfuscate.py — same transforms, same order.
 */

// ═══════════════════════════════════════════════════════════════════════
// CHARACTER CLASS PATTERNS
// ═══════════════════════════════════════════════════════════════════════

/** Zero-width and invisible characters: U+200B, U+200C, U+200D, U+FEFF, U+00AD, U+2060 */
const ZERO_WIDTH = /[\u200B\u200C\u200D\uFEFF\u00AD\u2060]/g;

/** Unicode Tag Characters (ASCII smuggling) — U+E0001 to U+E007F */
// JS regex: \u{E0001}-\u{E007F} requires 'u' flag for astral planes
const TAG_CHARS = /[\u{E0001}-\u{E007F}]/gu;

/** Variation Selectors — U+FE00-FE0F + U+E0100-E01EF */
const VARIATION_SELECTORS = /[\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/gu;

/** BiDi Control Characters */
const BIDI_CONTROLS = /[\u202A-\u202E\u2066-\u2069\u200E\u200F]/g;

/** HTML comments with hidden instructions */
const HTML_COMMENTS = /<!--[\s\S]*?-->/g;

/** Combined invisible character detection (for has_invisible_chars) */
const INVISIBLE_CHARS = /[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u{E0001}-\u{E007F}\uFE00-\uFE0F\u{E0100}-\u{E01EF}\u202A-\u202E\u2066-\u2069\u200E\u200F]/gu;

/** Base64 block: standalone token of 8+ base64 chars */
const BASE64_BLOCK = /(?<=["'\s(]|^)([A-Za-z0-9+/=]{8,})(?=["'\s)]|$)/gm;

/** Hex escape: \xHH */
const HEX_ESCAPE = /\\x([0-9A-Fa-f]{2})/g;

/** Unicode escape: \uHHHH */
const UNICODE_ESCAPE = /\\u([0-9A-Fa-f]{4})/g;

/** Adjacent string concatenation */
const CONCAT_DOUBLE = /"([^"]*?)"\s*\+\s*"([^"]*?)"/g;
const CONCAT_SINGLE = /'([^']*?)'\s*\+\s*'([^']*?)'/g;

// Simple escape sequences
const SIMPLE_ESCAPES: Record<string, string> = {
  "\\n": "\n",
  "\\t": "\t",
  "\\r": "\r",
};

// ═══════════════════════════════════════════════════════════════════════
// STRIP FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

/** Remove zero-width characters: U+200B, U+200C, U+200D, U+FEFF, U+00AD, U+2060. */
export function stripZeroWidth(text: string): string {
  return text.replace(ZERO_WIDTH, "");
}

/** Remove Unicode Tag Characters (U+E0001–U+E007F) used in ASCII smuggling. */
export function stripTagChars(text: string): string {
  return text.replace(TAG_CHARS, "");
}

/** Remove Variation Selectors (U+FE00–FE0F, U+E0100–E01EF). */
export function stripVariationSelectors(text: string): string {
  return text.replace(VARIATION_SELECTORS, "");
}

/** Remove BiDi control characters that can hide text direction. */
export function stripBidiControls(text: string): string {
  return text.replace(BIDI_CONTROLS, "");
}

/** Remove HTML comments that may contain hidden instructions. */
export function stripHtmlComments(text: string): string {
  return text.replace(HTML_COMMENTS, "");
}

/** Check if text contains any invisible/obfuscation characters. */
export function hasInvisibleChars(text: string): boolean {
  // Reset lastIndex since regex has 'g' flag
  INVISIBLE_CHARS.lastIndex = 0;
  return INVISIBLE_CHARS.test(text);
}

// ═══════════════════════════════════════════════════════════════════════
// TRANSFORM FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

/**
 * TR39 confusable character mappings.
 * Characters from other scripts that visually resemble ASCII but have
 * different codepoints.  Applied AFTER NFKC to catch what normalization misses.
 */
const CONFUSABLES: Map<string, string> = new Map([
  // — Cyrillic uppercase —
  ["\u0410", "A"], ["\u0412", "B"], ["\u0421", "C"], ["\u0415", "E"],
  ["\u041D", "H"], ["\u0406", "I"], ["\u0408", "J"], ["\u041A", "K"],
  ["\u041C", "M"], ["\u041E", "O"], ["\u0420", "P"], ["\u0405", "S"],
  ["\u0422", "T"], ["\u0425", "X"], ["\u0423", "Y"], ["\u0417", "Z"],
  // — Cyrillic lowercase —
  ["\u0430", "a"], ["\u0441", "c"], ["\u0435", "e"], ["\u04BB", "h"],
  ["\u0456", "i"], ["\u0458", "j"], ["\u043E", "o"], ["\u0440", "p"],
  ["\u0455", "s"], ["\u0445", "x"], ["\u0443", "y"],
  // — Greek uppercase —
  ["\u0391", "A"], ["\u0392", "B"], ["\u0395", "E"], ["\u0397", "H"],
  ["\u0399", "I"], ["\u039A", "K"], ["\u039C", "M"], ["\u039D", "N"],
  ["\u039F", "O"], ["\u03A1", "P"], ["\u03A4", "T"], ["\u03A7", "X"],
  ["\u03A5", "Y"], ["\u0396", "Z"],
  // — Greek lowercase —
  ["\u03BF", "o"], ["\u03B1", "a"],
  // — Cherokee —
  ["\u13A0", "D"], ["\u13A1", "R"], ["\u13A2", "T"], ["\u13AA", "G"],
  ["\u13B3", "W"], ["\u13D2", "S"], ["\u13DA", "S"],
  ["\uAB4E", "s"], ["\uAB4F", "s"], ["\uABA3", "s"], ["\uABAA", "s"],
  // — Turkish dotless i —
  ["\u0131", "i"],
  // — Small caps —
  ["\u1D00", "A"], ["\u0299", "B"], ["\u1D04", "C"],
  // — Fullwidth Latin uppercase A–Z (U+FF21–U+FF3A) —
  ...Array.from({ length: 26 }, (_, i): [string, string] => [
    String.fromCharCode(0xFF21 + i),
    String.fromCharCode(0x41 + i),
  ]),
  // — Fullwidth Latin lowercase a–z (U+FF41–U+FF5A) —
  ...Array.from({ length: 26 }, (_, i): [string, string] => [
    String.fromCharCode(0xFF41 + i),
    String.fromCharCode(0x61 + i),
  ]),
]);

/**
 * Apply NFKC unicode normalization then TR39 confusable mapping.
 * NFKC handles compatibility decompositions (fullwidth, ligatures).
 * The confusable map catches cross-script homoglyphs that NFKC misses
 * (Cyrillic, Greek, Cherokee, etc.).
 */
export function normalizeUnicode(text: string): string {
  let result = text.normalize("NFKC");
  let out = "";
  for (const ch of result) {
    out += CONFUSABLES.get(ch) ?? ch;
  }
  return out;
}

/** Check if decoded bytes are valid printable text. */
function isPrintableText(decoded: string): boolean {
  let nonPrintable = 0;
  for (const ch of decoded) {
    const code = ch.codePointAt(0)!;
    // Allow whitespace
    if (ch === "\n" || ch === "\r" || ch === "\t" || ch === " ") continue;
    // Reject control characters and other non-printable
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) {
      nonPrintable++;
    }
  }
  return nonPrintable <= decoded.length * 0.1;
}

/**
 * Find and decode inline base64 strings.
 * Only decodes standalone tokens >= 8 chars that produce valid printable UTF-8.
 */
export function decodeBase64Blocks(text: string): string {
  BASE64_BLOCK.lastIndex = 0;
  return text.replace(BASE64_BLOCK, (fullMatch, token: string) => {
    // Skip tokens that look like normal words (all lowercase alpha)
    if (/^[a-z]+$/.test(token)) return fullMatch;
    try {
      const decoded = Buffer.from(token, "base64").toString("utf-8");
      // Verify it's valid base64 by re-encoding
      if (Buffer.from(decoded, "utf-8").toString("base64").replace(/=+$/, "") !==
          token.replace(/=+$/, "")) {
        return fullMatch;
      }
      if (!isPrintableText(decoded)) return fullMatch;
      // Preserve surrounding context
      const tokenStart = fullMatch.indexOf(token);
      const prefix = fullMatch.slice(0, tokenStart);
      const suffix = fullMatch.slice(tokenStart + token.length);
      return prefix + decoded + suffix;
    } catch {
      return fullMatch;
    }
  });
}

/**
 * Convert common escape sequences to actual characters.
 * Handles: \xHH, \uHHHH, \n, \t, \r, \\.
 * Does NOT eval() anything.
 */
export function unescapeSequences(text: string): string {
  const PLACEHOLDER = "\x00BKSL\x00";
  // Protect literal \\ from being consumed by \x/\u replacements
  text = text.replaceAll("\\\\", PLACEHOLDER);

  // Hex / unicode escapes
  HEX_ESCAPE.lastIndex = 0;
  text = text.replace(HEX_ESCAPE, (_m, hex: string) =>
    String.fromCharCode(parseInt(hex, 16))
  );
  UNICODE_ESCAPE.lastIndex = 0;
  text = text.replace(UNICODE_ESCAPE, (_m, hex: string) =>
    String.fromCharCode(parseInt(hex, 16))
  );

  // Simple escapes
  for (const [seq, char] of Object.entries(SIMPLE_ESCAPES)) {
    text = text.replaceAll(seq, char);
  }

  // Restore literal backslashes
  text = text.replaceAll(PLACEHOLDER, "\\");
  return text;
}

/**
 * Join adjacent string literal concatenations.
 * "abc" + "def" → "abcdef"
 * 'abc' + 'def' → 'abcdef'
 * Iterates until no more concatenations remain (handles chains).
 */
export function expandStringConcat(text: string): string {
  let prev: string | undefined;
  while (prev !== text) {
    prev = text;
    CONCAT_DOUBLE.lastIndex = 0;
    text = text.replace(CONCAT_DOUBLE, '"$1$2"');
    CONCAT_SINGLE.lastIndex = 0;
    text = text.replace(CONCAT_SINGLE, "'$1$2'");
  }
  return text;
}

// ═══════════════════════════════════════════════════════════════════════
// HTML ENTITY DECODING
// ═══════════════════════════════════════════════════════════════════════

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'",
  nbsp: "\u00A0", copy: "\u00A9", reg: "\u00AE",
};

/**
 * Decode HTML character references (numeric, hex, and named).
 * Handles &#99; (decimal), &#x63; (hex), and &amp; (named) forms.
 */
export function decodeHtmlEntities(text: string): string {
  return text
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(parseInt(dec, 10)))
    .replace(/&([a-zA-Z]+);/g, (match, name) => NAMED_ENTITIES[name.toLowerCase()] ?? match);
}

// ═══════════════════════════════════════════════════════════════════════
// MAIN PIPELINE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Single deobfuscation pass — all transforms in order.
 *
 * 1. stripZeroWidth
 * 2. stripTagChars
 * 3. stripVariationSelectors
 * 4. stripBidiControls
 * 5. stripHtmlComments
 * 6. decodeHtmlEntities
 * 7. normalizeUnicode (NFKC + TR39 confusables)
 * 8. decodeBase64Blocks
 * 9. unescapeSequences
 * 10. expandStringConcat
 */
function _deobfuscatePass(text: string): string {
  text = stripZeroWidth(text);
  text = stripTagChars(text);
  text = stripVariationSelectors(text);
  text = stripBidiControls(text);
  text = stripHtmlComments(text);
  text = decodeHtmlEntities(text);
  text = normalizeUnicode(text);
  text = decodeBase64Blocks(text);
  text = unescapeSequences(text);
  text = expandStringConcat(text);
  return text;
}

/**
 * Apply all deobfuscation transforms to text (2-pass pipeline).
 *
 * Two passes catch nested obfuscation where the first pass reveals
 * content that a second pass can further decode (e.g. base64 hidden
 * inside zero-width splits, or escape sequences inside HTML entities).
 */
export function deobfuscate(text: string): string {
  text = _deobfuscatePass(text);
  text = _deobfuscatePass(text);
  return text;
}
