import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

/**
 * clipboard.ts uses `await import("@tauri-apps/api/core")` as a dynamic import.
 * In the jsdom test environment, that module is not resolvable, so
 * readClipboardFromTauriInvoke() always catches and returns null.
 * The Tauri-runtime tests therefore verify the navigator.clipboard fallback
 * path that executes after the native invoke silently fails.
 */

import { readClipboardTextDirect } from "../../../../../../../apps/svelte-desktop/src/lib/clipboard";

function setTauriRuntime(active: boolean): void {
  if (active) {
    (window as typeof window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ = {};
  } else {
    delete (window as typeof window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__;
  }
}

function setNavigatorClipboard(readText: () => Promise<string>): void {
  Object.defineProperty(window.navigator, "clipboard", {
    configurable: true,
    value: { readText, writeText: vi.fn(async () => undefined) },
  });
}

describe("readClipboardTextDirect", () => {
  beforeEach(() => {
    setTauriRuntime(false);
  });

  afterEach(() => {
    setTauriRuntime(false);
    vi.restoreAllMocks();
  });

  describe("Tauri runtime path (invoke silently unavailable in jsdom)", () => {
    test("falls back to navigator.clipboard when Tauri invoke is unavailable", async () => {
      setTauriRuntime(true);
      setNavigatorClipboard(async () => "navigator fallback");

      const result = await readClipboardTextDirect();

      // Tauri invoke fails silently in test env; navigator provides the value
      expect(result).toBe("navigator fallback");
    });

    test("returns empty string when both Tauri invoke and navigator.clipboard fail", async () => {
      setTauriRuntime(true);
      setNavigatorClipboard(async () => { throw new Error("permission denied"); });

      const result = await readClipboardTextDirect();

      expect(result).toBe("");
    });

    test("returns empty string when navigator.clipboard returns empty string", async () => {
      setTauriRuntime(true);
      setNavigatorClipboard(async () => "");

      const result = await readClipboardTextDirect();

      expect(result).toBe("");
    });
  });

  describe("browser / non-Tauri path", () => {
    test("returns text from navigator.clipboard in non-Tauri, non-WebKit browser", async () => {
      setTauriRuntime(false);
      Object.defineProperty(navigator, "userAgent", {
        configurable: true,
        value: "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0",
      });
      setNavigatorClipboard(async () => "browser clipboard text");

      const result = await readClipboardTextDirect();

      expect(result).toBe("browser clipboard text");
    });

    test("returns empty string when navigator.clipboard throws in non-Tauri path", async () => {
      setTauriRuntime(false);
      Object.defineProperty(navigator, "userAgent", {
        configurable: true,
        value: "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0",
      });
      setNavigatorClipboard(async () => { throw new Error("clipboard access denied"); });

      const result = await readClipboardTextDirect();

      expect(result).toBe("");
    });

    test("returns empty string in non-Tauri WebKit browser (no clipboard API access)", async () => {
      setTauriRuntime(false);
      Object.defineProperty(navigator, "userAgent", {
        configurable: true,
        value: "Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/537.36",
      });

      const result = await readClipboardTextDirect();

      expect(result).toBe("");
    });
  });
});
