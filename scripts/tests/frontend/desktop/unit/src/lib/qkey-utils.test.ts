import { describe, expect, test } from "vitest";
import {
  extractQKey,
  normalizeUtf8,
} from "../../../../../../../apps/svelte-desktop/src/lib/qkey-utils";

describe("extractQKey", () => {
  test("extracts a well-formed QKey token from clean input", () => {
    expect(extractQKey("QKey-abc123")).toBe("QKey-abc123");
  });

  test("extracts QKey from surrounding prose", () => {
    expect(extractQKey("Your token is QKey-xYz_456= and it expires soon")).toBe(
      "QKey-xYz_456=",
    );
  });

  test("normalizes lowercase qkey prefix to QKey", () => {
    expect(extractQKey("qkey-lowerCaseToken")).toBe("QKey-lowerCaseToken");
  });

  test("returns null for mixed-case prefix that is not QKey or qkey", () => {
    // The regex only matches exact "QKey" or "qkey" prefixes
    expect(extractQKey("qKey-MixedCase")).toBeNull();
    expect(extractQKey("QKEY-AllCaps")).toBeNull();
  });

  test("handles base64 characters including +, /, and =", () => {
    expect(extractQKey("QKey-abc+def/ghi=")).toBe("QKey-abc+def/ghi=");
  });

  test("handles URL-safe base64 characters with _ and -", () => {
    expect(extractQKey("QKey-abc_def-ghi")).toBe("QKey-abc_def-ghi");
  });

  test("returns null for empty string", () => {
    expect(extractQKey("")).toBeNull();
  });

  test("returns null when no QKey pattern is present", () => {
    expect(extractQKey("just some random text without a token")).toBeNull();
  });

  test("returns null for partial prefix without hyphen", () => {
    expect(extractQKey("QKey without hyphen")).toBeNull();
  });

  test("extracts only the first QKey when multiple are present", () => {
    const result = extractQKey("first QKey-aaa then QKey-bbb");
    expect(result).toBe("QKey-aaa");
  });

  test("extracts QKey at the very start of input", () => {
    expect(extractQKey("QKey-startToken rest")).toBe("QKey-startToken");
  });

  test("extracts QKey at the very end of input", () => {
    expect(extractQKey("prefix QKey-endToken")).toBe("QKey-endToken");
  });

  test("handles QKey with only alphanumeric characters after hyphen", () => {
    expect(extractQKey("QKey-ABC123def456")).toBe("QKey-ABC123def456");
  });
});

describe("normalizeUtf8", () => {
  test("strips BOM character", () => {
    expect(normalizeUtf8("\uFEFFhello")).toBe("hello");
  });

  test("strips multiple BOM characters", () => {
    expect(normalizeUtf8("\uFEFF\uFEFFtext")).toBe("text");
  });

  test("strips zero-width space (U+200B)", () => {
    expect(normalizeUtf8("he\u200Bllo")).toBe("hello");
  });

  test("strips zero-width non-joiner (U+200C)", () => {
    expect(normalizeUtf8("he\u200Cllo")).toBe("hello");
  });

  test("strips zero-width joiner (U+200D)", () => {
    expect(normalizeUtf8("he\u200Dllo")).toBe("hello");
  });

  test("strips word joiner (U+2060)", () => {
    expect(normalizeUtf8("he\u2060llo")).toBe("hello");
  });

  test("normalizes CRLF to LF", () => {
    expect(normalizeUtf8("line1\r\nline2")).toBe("line1\nline2");
  });

  test("normalizes bare CR to LF", () => {
    expect(normalizeUtf8("line1\rline2")).toBe("line1\nline2");
  });

  test("preserves existing LF", () => {
    expect(normalizeUtf8("line1\nline2")).toBe("line1\nline2");
  });

  test("normalizes to NFC form", () => {
    // e + combining acute accent (NFD) should become e-acute (NFC)
    const nfd = "e\u0301";
    const nfc = "\u00E9";
    expect(normalizeUtf8(nfd)).toBe(nfc);
  });

  test("handles all transformations combined", () => {
    const messy = "\uFEFFhe\u200Bllo\r\nwo\u2060rld\r";
    expect(normalizeUtf8(messy)).toBe("hello\nworld\n");
  });

  test("returns empty string for empty input", () => {
    expect(normalizeUtf8("")).toBe("");
  });

  test("returns clean string unchanged", () => {
    expect(normalizeUtf8("already clean")).toBe("already clean");
  });

  test("handles string that is only BOM and zero-width chars", () => {
    expect(normalizeUtf8("\uFEFF\u200B\u200C\u200D\u2060")).toBe("");
  });
});
