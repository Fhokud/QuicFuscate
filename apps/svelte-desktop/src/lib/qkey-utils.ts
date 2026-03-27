/** Extract a QKey token from freeform text input. */
export function extractQKey(text: string): string | null {
  const m = text.match(/(?:QKey|qkey)-[A-Za-z0-9+/=_-]+/);
  if (!m) return null;
  return m[0].replace(/^[Qq][Kk]ey-/, "QKey-");
}

/** Strip BOM, zero-width characters, normalize line endings and Unicode form. */
export function normalizeUtf8(value: string): string {
  return value.replace(/\uFEFF/g, "").replace(/[\u200B-\u200D\u2060]/g, "").replace(/\r\n?/g, "\n").normalize("NFC");
}
