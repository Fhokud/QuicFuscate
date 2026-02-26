import { useMemo, useRef, useState } from "react";
import { useSetAtom } from "jotai";
import { Modal, ModalContent, ModalHeader, ModalBody, ModalFooter } from "@heroui/react";
import { Textarea } from "@heroui/react";
import { tunnelsAtom } from "@/stores/atoms";
import { cn } from "@/lib/utils";
import { isValidSniHost, normalizeRemoteForStorage } from "@/lib/tunnel-validators";
import { readClipboardTextDirect } from "@/lib/clipboard";
import { useStageModalPortal, withStageModalClassNames } from "@/lib/stage-modal";
import { Button } from "@/components/ui/button";

const LABEL_CLASS = "text-[11px] font-semibold text-black dashboard-heading-sans static";
const MAX_QKEY_TEXT_CHARS = 16384;
const RIPPLE_ACTION_DELAY_MS = 88;

const TEXTAREA_CLASSNAMES = {
  base: "w-full",
  label: LABEL_CLASS,
  inputWrapper: cn(
    "px-3 py-2.5 rounded-md",
    "glass-nav-pill glass-select-edge",
    "group-data-[focus=true]:border-accent",
    "!shadow-none !outline-none",
  ),
  input: cn(
    "text-[11px] text-black leading-relaxed dashboard-heading-sans qkey-text-input",
    "placeholder:text-black/30",
    "!outline-none !ring-0",
  ),
} as const;

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

export function EditQKeyDialog({
  open,
  onOpenChange,
  tunnelId,
  mode,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  tunnelId: string;
  mode: "set" | "replace";
}) {
  const setTunnels = useSetAtom(tunnelsAtom);
  const portalContainer = useStageModalPortal();

  const [qkeyText, setQkeyText] = useState("");
  const [busy, setBusy] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);
  const pasteTriggeredFromPointerRef = useRef(false);

  const runtimeReady = Boolean((window as any).__TAURI_INTERNALS__);
  const extracted = useMemo(() => extractQKey(qkeyText.trim()), [qkeyText]);

  const canSubmit = runtimeReady && Boolean(extracted) && !busy && !parseError;

  function reset() {
    setQkeyText("");
    setParseError(null);
    setBusy(false);
  }

  async function submit() {
    if (!canSubmit) return;
    if (!extracted) return;
    setBusy(true);
    setParseError(null);
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const parsed = await invoke<{ remote: string; sni: string; hasToken: boolean }>("qkey_parse", {
        qkey_data: extracted,
      });
      const normalizedRemoteRaw = String(parsed.remote ?? "").trim();
      const normalizedSniRaw = String(parsed.sni ?? "").trim();
      if (normalizedRemoteRaw && !normalizeRemoteForStorage(normalizedRemoteRaw)) {
        setParseError("QKey contains invalid remote endpoint");
        return;
      }
      if (normalizedSniRaw && !isValidSniHost(normalizedSniRaw)) {
        setParseError("QKey contains invalid SNI");
        return;
      }
      const parsedRemote = normalizedRemoteRaw ? normalizeRemoteForStorage(normalizedRemoteRaw)! : "";
      const parsedSni = normalizedSniRaw || "";
      setTunnels((prev) =>
        prev.map((t) => {
          if (t.id !== tunnelId) return t;
          const next = {
            ...t,
            remote: parsedRemote || t.remote,
            sni: parsedSni || t.sni,
            qkey: extracted,
            hasToken: Boolean(parsed.hasToken),
          };
          delete (next as { debugSniOverride?: string }).debugSniOverride;
          return next;
        }),
      );
      reset();
      onOpenChange(false);
    } catch (e: any) {
      setParseError(String(e ?? "Invalid QKey"));
    } finally {
      setBusy(false);
    }
  }

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
      onOpenChange={(v) => {
        if (!v) reset();
        onOpenChange(v);
      }}
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
              <div className="text-[13px] font-semibold text-black dashboard-heading-sans">
                {mode === "replace" ? "Replace QKey" : "Set QKey"}
              </div>
              <div className="text-[11px] text-black">
                Paste a server-issued QKey to enable connecting this tunnel.
              </div>
            </ModalHeader>

            <ModalBody className="dialog-body-pad overflow-y-auto">
              <div className="space-y-4">
                <div className="flex items-center justify-end">
                  <Button
                    type="button"
                    onPointerDown={handlePastePointerDown}
                    onClick={handlePasteClick}
                    className="inline-flex items-center rounded-lg border transition-all action-refresh-btn"
                    size="sm"
                  >
                    Paste
                  </Button>
                </div>
                <Textarea
                  id="edit-qkey-text"
                  label="QKey String"
                  labelPlacement="outside"
                  value={qkeyText}
                  onValueChange={(v) => {
                    setQkeyText(normalizeUtf8TextInput(v).slice(0, MAX_QKEY_TEXT_CHARS));
                    setParseError(null);
                  }}
                  minRows={8}
                  maxRows={8}
                  maxLength={MAX_QKEY_TEXT_CHARS}
                  disableAutosize
                  autoFocus
                  autoComplete="off"
                  classNames={TEXTAREA_CLASSNAMES as any}
                />
                {mode === "replace" && (
                  <p className="text-[10px] text-black px-1 leading-relaxed">
                    Replacing a QKey overwrites the stored credential. Treat QKeys like passwords.
                  </p>
                )}
                {mode === "set" && (
                  <p className="text-[10px] text-black px-1 leading-relaxed">
                    QKeys are bearer credentials. Treat them like passwords.
                  </p>
                )}
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
                onClick={submit}
                disabled={!canSubmit}
                className="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-save-btn disabled:opacity-55 disabled:cursor-not-allowed h-auto min-w-0"
                size="sm"
              >
                {busy ? "..." : "Save"}
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}
