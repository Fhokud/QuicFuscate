function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && Boolean((window as any).__TAURI_INTERNALS__);
}

function isWebKitBrowser(): boolean {
  if (typeof navigator === "undefined") return false;
  const ua = navigator.userAgent;
  return ua.includes("AppleWebKit");
}

async function readClipboardFromTauriInvoke(): Promise<string | null> {
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    const value = await invoke<string>("clipboard_read_text");
    return typeof value === "string" ? value : null;
  } catch {
    return null;
  }
}

async function readClipboardFromNavigatorDirect(): Promise<string | null> {
  if (typeof navigator === "undefined" || !navigator.clipboard?.readText) {
    return null;
  }

  try {
    return await navigator.clipboard.readText();
  } catch {
    return null;
  }
}

async function readClipboardFromDevBridge(): Promise<string | null> {
  if (!import.meta.env.DEV) return null;
  if (typeof fetch === "undefined") return null;

  try {
    const response = await fetch("/__dev_clipboard/read", {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "x-dev-clipboard": "1" },
    });
    if (!response.ok) return null;
    const data = (await response.json()) as { text?: unknown };
    if (typeof data?.text !== "string") return null;
    return data.text;
  } catch {
    return null;
  }
}

export async function readClipboardTextDirect(): Promise<string> {
  if (isTauriRuntime()) {
    const nativeText = await readClipboardFromTauriInvoke();
    if (typeof nativeText === "string" && nativeText.length > 0) {
      return nativeText;
    }

    const browserFallbackInTauri = await readClipboardFromNavigatorDirect();
    if (typeof browserFallbackInTauri === "string" && browserFallbackInTauri.length > 0) {
      return browserFallbackInTauri;
    }
    return "";
  }

  // Browser/dev mode: use local dev bridge first to avoid WebKit paste popovers.
  const bridgeText = await readClipboardFromDevBridge();
  if (typeof bridgeText === "string" && bridgeText.length > 0) {
    return bridgeText;
  }

  // Safari/WebKit often enforces a native paste confirmation UI.
  // If bridge is unavailable, skip API call to avoid surfacing that context popup.
  if (isWebKitBrowser()) {
    return "";
  }

  const browserText = await readClipboardFromNavigatorDirect();
  if (typeof browserText === "string" && browserText.length > 0) {
    return browserText;
  }

  return "";
}
