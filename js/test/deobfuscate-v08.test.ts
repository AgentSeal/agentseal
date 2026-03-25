import { describe, it, expect } from "vitest";
import {
  deobfuscate,
  normalizeUnicode,
  decodeHtmlEntities,
} from "../src/deobfuscate.js";

// ═══════════════════════════════════════════════════════════════════════
// TR39 CONFUSABLE CHARACTER MAPPINGS
// ═══════════════════════════════════════════════════════════════════════

describe("TR39 confusables (normalizeUnicode)", () => {
  it("maps Cyrillic lowercase а to Latin a", () => {
    expect(normalizeUnicode("\u0430")).toBe("a");
  });

  it("maps Cyrillic uppercase С to Latin C", () => {
    expect(normalizeUnicode("\u0421")).toBe("C");
  });

  it("maps Fullwidth A to Latin A", () => {
    expect(normalizeUnicode("\uFF21")).toBe("A");
  });

  it("maps Greek lowercase ο to Latin o", () => {
    expect(normalizeUnicode("\u03BF")).toBe("o");
  });

  it("maps Turkish dotless ı to Latin i", () => {
    expect(normalizeUnicode("\u0131")).toBe("i");
  });

  it("normalizes mixed Cyrillic/Latin word to pure Latin", () => {
    // "сurl" with Cyrillic с (U+0441) → "curl"
    expect(normalizeUnicode("\u0441url")).toBe("curl");
  });

  it("normalizes Cyrillic uppercase lookalikes", () => {
    // А→A, В→B, Е→E, Н→H, О→O, Р→P, Т→T
    expect(normalizeUnicode("\u0410\u0412\u0415\u041D\u041E\u0420\u0422")).toBe("ABEHOPT");
  });

  it("normalizes Greek uppercase lookalikes", () => {
    // Α→A, Β→B, Ε→E, Η→H, Ι→I
    expect(normalizeUnicode("\u0391\u0392\u0395\u0397\u0399")).toBe("ABEHI");
  });

  it("normalizes fullwidth lowercase range", () => {
    // ａｂｃ → abc
    expect(normalizeUnicode("\uFF41\uFF42\uFF43")).toBe("abc");
  });

  it("preserves normal ASCII unchanged", () => {
    expect(normalizeUnicode("hello world")).toBe("hello world");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// HTML ENTITY DECODING
// ═══════════════════════════════════════════════════════════════════════

describe("decodeHtmlEntities", () => {
  it("decodes numeric (decimal) entities", () => {
    // &#99;&#117;&#114;&#108; → curl
    expect(decodeHtmlEntities("&#99;&#117;&#114;&#108;")).toBe("curl");
  });

  it("decodes hex entities", () => {
    // &#x63;&#x75;&#x72;&#x6c; → curl
    expect(decodeHtmlEntities("&#x63;&#x75;&#x72;&#x6c;")).toBe("curl");
  });

  it("decodes named entities", () => {
    expect(decodeHtmlEntities("&amp; &lt; &gt;")).toBe("& < >");
  });

  it("decodes mixed entities", () => {
    expect(decodeHtmlEntities("&#99;url &amp; stuff")).toBe("curl & stuff");
  });

  it("decodes quot and apos", () => {
    expect(decodeHtmlEntities("&quot;hello&apos;")).toBe('"hello\'');
  });

  it("leaves unknown named entities untouched", () => {
    expect(decodeHtmlEntities("&unknown;")).toBe("&unknown;");
  });

  it("preserves plain text", () => {
    expect(decodeHtmlEntities("no entities here")).toBe("no entities here");
  });

  it("handles empty string", () => {
    expect(decodeHtmlEntities("")).toBe("");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 2-PASS DEOBFUSCATION PIPELINE
// ═══════════════════════════════════════════════════════════════════════

describe("2-pass deobfuscate pipeline", () => {
  it("catches nested obfuscation (base64 inside zero-width split)", () => {
    // "aGVsbG8=" split with zero-width chars — pass 1 strips zero-width,
    // pass 2 decodes the now-continuous base64
    const encoded = "a\u200BGV\u200Bsb\u200BG8=";
    const result = deobfuscate(encoded);
    expect(result).toContain("hello");
  });

  it("decodes HTML entities then processes the result", () => {
    // HTML-encoded hex escape: &#92;x48 → \x48 → H
    const text = "&#92;x48ello";
    const result = deobfuscate(text);
    expect(result).toContain("Hello");
  });

  it("normalizes confusables in HTML-decoded content", () => {
    // HTML entity for Cyrillic а (U+0430 = decimal 1072) followed by "bc"
    const text = "&#1072;bc";
    const result = deobfuscate(text);
    expect(result).toBe("abc");
  });

  it("still passes through pure ASCII unchanged", () => {
    const text = "Just normal text with no tricks.";
    expect(deobfuscate(text)).toBe(text);
  });

  it("is idempotent on already-clean text", () => {
    const text = "hello world";
    expect(deobfuscate(text)).toBe(text);
  });
});
