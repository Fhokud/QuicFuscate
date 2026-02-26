import { useRef, useState } from "react";
import { useSetAtom } from "jotai";
import { tunnelsAtom, selectedTunnelIdAtom } from "@/stores/atoms";
import type { TunnelConfig } from "@/stores/types";
import { cn } from "@/lib/utils";
import { isValidSniHost, normalizeRemoteForStorage, parseRemote } from "@/lib/tunnel-validators";
import { readClipboardTextDirect } from "@/lib/clipboard";
import { useStageModalPortal, withStageModalClassNames } from "@/lib/stage-modal";
import { Modal, ModalContent, ModalHeader, ModalBody, ModalFooter } from "@heroui/react";
import { Button } from "@/components/ui/button";
import { CountrySelect } from "@/components/ui/country-select";

const LABEL_CLASS = cn(
  "block",
  "text-[11px] font-semibold text-black dashboard-heading-sans",
  "leading-[1.2]",
);
const INPUT_CLASS = cn(
  "h-8 w-full px-3 rounded-md",
  "glass-nav-pill glass-select-edge",
  "text-[11px] text-black",
  "placeholder:text-black/40",
  "outline-none focus:outline-none",
  "focus:border-edge-accent",
  "transition-colors",
);
const TEXTAREA_CLASS = cn(
  "w-full px-3 py-2.5 rounded-md resize-none",
  "glass-nav-pill glass-select-edge",
  "text-[11px] text-black leading-relaxed dashboard-heading-sans qkey-text-input",
  "placeholder:text-black/30",
  "outline-none focus:outline-none",
  "focus:border-edge-accent",
  "transition-colors",
);
const MAX_NAME_CHARS = 96;
const MAX_REMOTE_CHARS = 320;
const MAX_QKEY_TEXT_CHARS = 16384;
const DEFAULT_SHELL_SNI = "cdn.cloudflare.com";
const RIPPLE_ACTION_DELAY_MS = 88;

function extractQKey(text: string): string | null {
  const m = text.match(/(?:QKey|qkey)-[A-Za-z0-9+/=_-]+/);
  if (!m) return null;
  return m[0].replace(/^[Qq][Kk]ey-/, "QKey-");
}

function normalizeUtf8TextInput(value: string): string {
  return value
    .replace(/\uFEFF/g, "")
    .replace(/[\u200B-\u200D\u2060]/g, "")
    .replace(/\r\n?/g, "\n")
    .normalize("NFC");
}

function deriveTunnelNameFromRemote(remote: string): string {
  const trimmed = remote.trim();
  if (!trimmed) return "Imported";

  if (trimmed.startsWith("[")) {
    const end = trimmed.indexOf("]");
    if (end > 1) return trimmed.slice(1, end);
    return "Imported";
  }

  const colonCount = (trimmed.match(/:/g) || []).length;
  if (colonCount === 1) {
    const host = trimmed.split(":")[0];
    return host?.trim() || "Imported";
  }

  // Unbracketed IPv6 or unexpected shape: keep raw remote as best-effort label.
  return trimmed;
}

function isIpv4Host(host: string): boolean {
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) return false;
  return host.split(".").every((part) => {
    const n = Number.parseInt(part, 10);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

function deriveTunnelSni(remoteHost: string): string {
  const host = remoteHost.trim().toLowerCase();
  if (!host) return DEFAULT_SHELL_SNI;
  const isIpv6 = host.includes(":");
  if (isIpv6 || isIpv4Host(host)) return DEFAULT_SHELL_SNI;
  return host;
}

// Create Tunnel Dialog

interface CreateTunnelDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function CreateTunnelDialog({ open, onOpenChange }: CreateTunnelDialogProps) {
  const setTunnels = useSetAtom(tunnelsAtom);
  const setSelectedId = useSetAtom(selectedTunnelIdAtom);
  const portalContainer = useStageModalPortal();

  const [name, setName] = useState("");
  const [remote, setRemote] = useState("");
  const [countryCode, setCountryCode] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);

  function reset() {
    setName(""); setRemote(""); setCountryCode(""); setParseError(null);
  }

  function addTunnel(config: TunnelConfig) {
    setTunnels((prev) => [...prev, config]);
    setSelectedId(config.id);
    reset();
    onOpenChange(false);
  }

  async function handleCreate() {
    const nameTrimmed = name.trim();
    const remoteTrimmed = remote.trim();
    if (!nameTrimmed || !remoteTrimmed) return;
    if (nameTrimmed.length > MAX_NAME_CHARS) {
      setParseError(`Name too long [max ${MAX_NAME_CHARS} chars].`);
      return;
    }
    if (remoteTrimmed.length > MAX_REMOTE_CHARS) {
      setParseError(`Remote too long [max ${MAX_REMOTE_CHARS} chars].`);
      return;
    }

    const r = parseRemote(remoteTrimmed);
    if (!r) {
      setParseError("Invalid remote. Use IP-Address:Port or [IPv6]:Port [no spaces].");
      return;
    }

    const sniTrimmed = deriveTunnelSni(r.server);
    if (!isValidSniHost(sniTrimmed)) {
      setParseError("Unable to derive a valid SNI from this remote endpoint.");
      return;
    }

    const normalizedRemoteHost = r.server.includes(":") ? `[${r.server}]` : r.server;

    const cc = countryCode.trim().toUpperCase();
    if (cc && !/^[A-Z]{2}$/.test(cc)) {
      setParseError("Invalid country code. Use 2 letters [e.g. DE].");
      return;
    }

    // Manual creation creates a "shell" tunnel without a QKey.
    // The user can paste/import a server-issued QKey later.
    addTunnel({
      id: crypto.randomUUID(),
      name: nameTrimmed,
      remote: `${normalizedRemoteHost}:${r.port}`,
      sni: sniTrimmed,
      qkey: "",
      createdAt: Date.now(),
      hasToken: false,
      countryCode: cc || undefined,
    });
  }

  const canCreate = name.trim().length > 0 && remote.trim().length > 0 && !parseError;

  return (
    <Modal
      isOpen={open}
      onOpenChange={(v) => { if (!v) reset(); onOpenChange(v); }}
      backdrop="blur"
      hideCloseButton
      size="lg"
      placement="center"
      scrollBehavior="inside"
      portalContainer={portalContainer}
      classNames={withStageModalClassNames({ wrapper: "items-center justify-center p-4" })}
    >
      <ModalContent className="w-[min(92vw,720px)] max-h-[calc(100vh-2rem)] overflow-hidden glass border border-edge shadow-xl rounded-[18px] dialog-typography dialog-surface">
        {(onClose) => (
          <>
            <ModalHeader className="dialog-header-pad flex flex-col gap-1">
              <div className="text-[13px] font-semibold text-black dashboard-heading-sans">Create Tunnel</div>
              <div className="text-[11px] text-black">Enter the tunnel configuration manually</div>
            </ModalHeader>

            <ModalBody className="dialog-body-pad overflow-y-auto">
              <div className="space-y-5">
                <div className="grid grid-cols-[minmax(0,1fr)_max-content] gap-2 items-start">
                  <div className="flex-1 flex flex-col gap-2">
                    <label htmlFor="create-tunnel-name" className={LABEL_CLASS}>Name of the Connection</label>
                    <input
                      id="create-tunnel-name"
                      value={name}
                      onChange={(e) => { setName(e.target.value.slice(0, MAX_NAME_CHARS)); setParseError(null); }}
                      autoFocus
                      maxLength={MAX_NAME_CHARS}
                      className={INPUT_CLASS}
                    />
                  </div>
                  <div className="flex flex-col gap-2">
                    <div className={LABEL_CLASS}>Country</div>
                    <CountrySelect
                      value={countryCode}
                      onChange={(code) => {
                        setCountryCode(code);
                        setParseError(null);
                      }}
                    />
                  </div>
                </div>
                <div className="flex flex-col gap-2 pt-1">
                  <label htmlFor="create-tunnel-remote" className={LABEL_CLASS}>Remote [IP-Address:Port]</label>
                  <input
                    id="create-tunnel-remote"
                    value={remote}
                    onChange={(e) => { setRemote(e.target.value.slice(0, MAX_REMOTE_CHARS)); setParseError(null); }}
                    maxLength={MAX_REMOTE_CHARS}
                    className={INPUT_CLASS}
                  />
                </div>
                <div className="rounded-lg border border-edge bg-white/72 px-3 py-2.5 shadow-[inset_0_1px_0_rgba(255,255,255,0.8),0_1px_3px_rgba(0,0,0,0.04)]">
                  <p className="text-[10px] font-semibold text-black/80 dashboard-heading-sans">
                    SNI shown here is local placeholder metadata
                  </p>
                  <p className="mt-1 text-[10px] leading-relaxed text-black/65">
                    Authoritative Domain Fronting [SNI] policy is embedded in server-issued QKeys.
                    Manual shell entries become connect-ready only after importing a QKey.
                  </p>
                </div>
              </div>
            </ModalBody>

            <ModalFooter className="dialog-footer-pad">
              <Button
                type="button"
                onClick={() => {
                  window.setTimeout(() => {
                    reset();
                    onClose();
                  }, RIPPLE_ACTION_DELAY_MS);
                }}
                className="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-refresh-btn h-auto min-w-0"
                size="sm"
              >
                Cancel
              </Button>
              <Button
                type="button"
                onClick={handleCreate}
                disabled={!canCreate}
                className="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-save-btn disabled:opacity-55 disabled:cursor-not-allowed h-auto min-w-0"
                size="sm"
              >
                Create Tunnel
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}

// Import QKey Dialog

interface ImportQKeyDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ImportQKeyDialog({ open, onOpenChange }: ImportQKeyDialogProps) {
  const setTunnels = useSetAtom(tunnelsAtom);
  const setSelectedId = useSetAtom(selectedTunnelIdAtom);
  const portalContainer = useStageModalPortal();

  const [qkeyText, setQkeyText] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);
  const pasteTriggeredFromPointerRef = useRef(false);

  const runtimeReady = Boolean((window as any).__TAURI_INTERNALS__);
  const extracted = extractQKey(qkeyText.trim());
  function reset() {
    setQkeyText(""); setParseError(null);
  }

  function addTunnel(config: TunnelConfig) {
    setTunnels((prev) => [...prev, config]);
    setSelectedId(config.id);
    reset();
    onOpenChange(false);
  }

  async function handleImport() {
    const raw = qkeyText.trim();
    if (!raw) return;
    if (!runtimeReady) return;
    if (raw.length > MAX_QKEY_TEXT_CHARS) {
      setParseError(`Input too long [max ${MAX_QKEY_TEXT_CHARS} chars].`);
      return;
    }

    try {
      const { invoke } = await import("@tauri-apps/api/core");
      if (!extracted) return;
      const parsed = await invoke<{ remote: string; sni: string; hasToken: boolean }>("qkey_parse", {
        qkey_data: extracted,
      });
      const normalizedRemote = normalizeRemoteForStorage(parsed.remote ?? "");
      if (!normalizedRemote) {
        setParseError("QKey contains invalid remote endpoint");
        return;
      }
      const normalizedSni = String(parsed.sni ?? "").trim();
      if (!isValidSniHost(normalizedSni)) {
        setParseError("QKey contains invalid SNI");
        return;
      }
      addTunnel({
        id: crypto.randomUUID(),
        name: deriveTunnelNameFromRemote(normalizedRemote),
        remote: normalizedRemote,
        sni: normalizedSni,
        qkey: extracted,
        createdAt: Date.now(),
        hasToken: Boolean(parsed.hasToken),
      });
    } catch (e: any) {
      setParseError(String(e ?? "Invalid QKey or missing token"));
    }
  }

  const canImport = runtimeReady && Boolean(extracted);

  async function handlePasteFromClipboard() {
    const pasted = await readClipboardTextDirect();
    if (!pasted) return;
    setQkeyText(normalizeUtf8TextInput(pasted).slice(0, MAX_QKEY_TEXT_CHARS));
    setParseError(null);
  }

  function handlePastePointerDown(e: React.PointerEvent<HTMLButtonElement>) {
    // Run paste as early as possible in the same trusted user gesture.
    e.preventDefault();
    pasteTriggeredFromPointerRef.current = true;
    void handlePasteFromClipboard();
  }

  function handlePasteClick() {
    // Pointer path already handled on pointerdown; keep click for keyboard activation.
    if (pasteTriggeredFromPointerRef.current) {
      pasteTriggeredFromPointerRef.current = false;
      return;
    }
    void handlePasteFromClipboard();
  }

  return (
    <Modal
      isOpen={open}
      onOpenChange={(v) => { if (!v) reset(); onOpenChange(v); }}
      backdrop="blur"
      hideCloseButton
      placement="center"
      scrollBehavior="inside"
      portalContainer={portalContainer}
      classNames={withStageModalClassNames({ wrapper: "items-center justify-center p-4" })}
    >
      <ModalContent className="w-[min(92vw,720px)] max-h-[calc(100vh-2rem)] overflow-hidden glass border border-edge shadow-xl rounded-[18px] dialog-typography dialog-surface">
        {(onClose) => (
          <>
            <ModalHeader className="dialog-header-pad flex flex-col gap-1">
              <div className="text-[13px] font-semibold text-black dashboard-heading-sans">Import QKey</div>
            </ModalHeader>

            <ModalBody className="dialog-body-pad overflow-y-auto">
              <div className="space-y-4">
                <div className="flex flex-col gap-2">
                  <div className="flex items-center justify-between">
                    <label htmlFor="import-qkey-text" className={LABEL_CLASS}>QKey String</label>
                    <Button
                      type="button"
                      onPointerDown={handlePastePointerDown}
                      onClick={handlePasteClick}
                      className="inline-flex items-center rounded-lg border transition-all action-copy-btn"
                      size="sm"
                    >
                      Paste
                    </Button>
                  </div>
                  <textarea
                    id="import-qkey-text"
                    value={qkeyText}
                    onChange={(e) => {
                      setQkeyText(normalizeUtf8TextInput(e.target.value).slice(0, MAX_QKEY_TEXT_CHARS));
                      setParseError(null);
                    }}
                    rows={8}
                    maxLength={MAX_QKEY_TEXT_CHARS}
                    className={TEXTAREA_CLASS}
                    autoFocus
                    autoComplete="off"
                    autoCorrect="off"
                    autoCapitalize="off"
                    spellCheck={false}
                    aria-label="QKey String"
                    aria-invalid={Boolean(parseError)}
                  />
                </div>
                <p className="text-[10px] text-black px-1 leading-relaxed">
                  QKeys are bearer credentials.<br />Treat them like passwords.
                </p>
              </div>
            </ModalBody>

            <ModalFooter className="dialog-footer-pad">
              <Button
                type="button"
                onClick={() => {
                  window.setTimeout(() => {
                    reset();
                    onClose();
                  }, RIPPLE_ACTION_DELAY_MS);
                }}
                className="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-refresh-btn h-auto min-w-0"
                size="sm"
              >
                Cancel
              </Button>
              <Button
                type="button"
                onClick={handleImport}
                disabled={!canImport}
                className="relative isolate overflow-hidden inline-flex items-center justify-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-save-btn disabled:opacity-55 disabled:cursor-not-allowed h-auto min-w-0"
                size="sm"
              >
                Import
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}
