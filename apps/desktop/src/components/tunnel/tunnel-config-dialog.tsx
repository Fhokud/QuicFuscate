import { useState, useEffect, useCallback } from "react";
import { useAtomValue, useSetAtom } from "jotai";
import { tunnelsAtom, selectedTunnelIdAtom } from "@/stores/atoms";
import { addToastAtom } from "@/stores/toastAtom";
import type { TunnelConfig } from "@/stores/types";
import { cn, countryCodeToFlag } from "@/lib/utils";
import { parseRemote } from "@/lib/tunnel-validators";
import { useStageModalPortal, withStageModalClassNames } from "@/lib/stage-modal";
import { Modal, ModalContent, ModalHeader, ModalBody, ModalFooter } from "@heroui/react";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { CountrySelect } from "@/components/ui/country-select";
import { Lock } from "lucide-react";

const LABEL_CLASS = cn(
  "block",
  "text-[11px] font-semibold text-black dashboard-heading-sans",
  "leading-[1.2]",
);

const HINT_CLASS = "text-[9px] text-black mt-0.5 leading-tight";

const INPUT_CLASS = cn(
  "h-8 w-full px-3 rounded-md",
  "glass-nav-pill glass-select-edge",
  "text-[11px] text-black",
  "placeholder:text-black/40",
  "outline-none focus:outline-none",
  "focus:border-edge-accent",
  "transition-colors",
);

const MAX_NAME_CHARS = 96;
const MAX_REMOTE_CHARS = 320;
const RIPPLE_ACTION_DELAY_MS = 88;

interface TunnelConfigDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  tunnel: TunnelConfig;
}

export function TunnelConfigDialog({ open, onOpenChange, tunnel }: TunnelConfigDialogProps) {
  const tunnels = useAtomValue(tunnelsAtom);
  const setTunnels = useSetAtom(tunnelsAtom);
  const setSelectedId = useSetAtom(selectedTunnelIdAtom);
  const addToast = useSetAtom(addToastAtom);

  const [name, setName] = useState("");
  const [remote, setRemote] = useState("");
  const [countryCode, setCountryCode] = useState("");
  const [parseError, setParseError] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const [confirmDeleteOpen, setConfirmDeleteOpen] = useState(false);
  const portalContainer = useStageModalPortal();

  useEffect(() => {
    if (open && tunnel) {
      setName(tunnel.name || "");
      setRemote(tunnel.remote || "");
      setCountryCode((tunnel.countryCode || "").toUpperCase());
      setParseError(null);
      setDirty(false);
      setConfirmDeleteOpen(false);
    }
  }, [open, tunnel]);

  const markDirty = useCallback(() => {
    if (!dirty) setDirty(true);
  }, [dirty]);

  const handleSave = useCallback(() => {
    const tunnelExists = tunnels.some((t) => t.id === tunnel.id);

    if (!tunnelExists) {
      addToast({ type: "warning", message: "Tunnel no longer exists. Refresh the list and try again." });
      onOpenChange(false);
      return;
    }

    const nameTrimmed = name.trim();
    const remoteTrimmed = remote.trim();
    if (!nameTrimmed) {
      setParseError("Name is required.");
      return;
    }
    if (nameTrimmed.length > MAX_NAME_CHARS) {
      setParseError(`Name too long [max ${MAX_NAME_CHARS} chars].`);
      return;
    }
    if (!remoteTrimmed) {
      setParseError("Remote is required.");
      return;
    }
    if (remoteTrimmed.length > MAX_REMOTE_CHARS) {
      setParseError(`Remote too long [max ${MAX_REMOTE_CHARS} chars].`);
      return;
    }

    const r = parseRemote(remoteTrimmed);
    if (!r) {
      setParseError("Invalid remote. Use IP-Address:Port or [IPv6]:Port.");
      return;
    }

    const cc = countryCode.trim().toUpperCase();
    if (cc && !/^[A-Z]{2}$/.test(cc)) {
      setParseError("Invalid country code. Use 2 letters [e.g. DE].");
      return;
    }

    const normalizedRemoteHost = r.server.includes(":") ? `[${r.server}]` : r.server;
    const normalizedRemote = `${normalizedRemoteHost}:${r.port}`;

    setTunnels((prev) =>
      prev.map((t) =>
        t.id === tunnel.id
          ? {
              ...t,
              name: nameTrimmed,
              remote: normalizedRemote,
              countryCode: cc || undefined,
            }
          : t
      )
    );

    setDirty(false);
    addToast({ type: "success", message: "Tunnel configuration saved" });
    onOpenChange(false);
  }, [
    name,
    remote,
    countryCode,
    tunnel.id,
    tunnels,
    setTunnels,
    onOpenChange,
    addToast,
  ]);

  const handleDelete = useCallback(() => {
    setTunnels((prev) => prev.filter((t) => t.id !== tunnel.id));
    setSelectedId((prev) => (prev === tunnel.id ? null : prev));
    addToast({ type: "success", message: `Tunnel "${tunnel.name}" deleted` });
    setConfirmDeleteOpen(false);
    onOpenChange(false);
  }, [tunnel.id, tunnel.name, setTunnels, setSelectedId, addToast, onOpenChange]);

  const handleClose = useCallback(() => {
    onOpenChange(false);
  }, [onOpenChange]);

  const flag = countryCodeToFlag(countryCode.trim().toUpperCase() || undefined);
  const canSave = dirty && tunnels.some((t) => t.id === tunnel.id) && !parseError;

  return (
    <>
      <ConfirmDialog
        open={confirmDeleteOpen}
        title="Delete Tunnel"
        message={`Permanently delete "${tunnel.name}"? This cannot be undone.`}
        confirmLabel="Delete"
        cancelLabel="Cancel"
        variant="danger"
        onConfirm={handleDelete}
        onCancel={() => setConfirmDeleteOpen(false)}
      />
      <Modal
        isOpen={open && !confirmDeleteOpen}
        onOpenChange={onOpenChange}
        backdrop="blur"
        hideCloseButton
        size="lg"
        placement="center"
        scrollBehavior="inside"
        portalContainer={portalContainer}
        classNames={withStageModalClassNames({ wrapper: "items-center justify-center p-4" })}
      >
        <ModalContent className="w-[min(92vw,520px)] max-h-[calc(100vh-2rem)] overflow-hidden glass border border-edge shadow-xl rounded-[18px] dialog-typography dialog-surface">
          {() => (
            <>
              <ModalHeader className="dialog-header-pad flex items-center justify-between gap-3">
                <div className="flex flex-col gap-0.5">
                  <div className="flex items-center gap-2">
                    <span className="text-[13px] font-semibold text-black dashboard-heading-sans">Tunnel Configuration</span>
                    {flag && <span className="text-[13px] leading-none">{flag}</span>}
                  </div>
                  <div className="text-[10px] text-black">{tunnel.name} &middot; {tunnel.remote}</div>
                </div>
                <Button
                  type="button"
                  onClick={() => {
                    window.setTimeout(handleSave, RIPPLE_ACTION_DELAY_MS);
                  }}
                  disabled={!canSave}
                  className="inline-flex h-8 items-center rounded-lg px-3 border text-[11px] font-semibold transition-all action-save-btn disabled:opacity-55 disabled:cursor-not-allowed h-auto min-w-0"
                  size="sm"
                >
                  Save
                </Button>
              </ModalHeader>

              <ModalBody className="dialog-body-pad overflow-y-auto">
                <div className="space-y-4">
                  <div className="grid grid-cols-[minmax(0,1fr)_max-content] gap-3 items-start">
                    <div className="flex flex-col gap-1.5">
                      <label htmlFor="tunnel-config-name" className={LABEL_CLASS}>Name of the Connection</label>
                      <input
                        id="tunnel-config-name"
                        value={name}
                        onChange={(e) => { setName(e.target.value.slice(0, MAX_NAME_CHARS)); markDirty(); setParseError(null); }}
                        maxLength={MAX_NAME_CHARS}
                        className={INPUT_CLASS}
                      />
                    </div>
                    <div className="flex flex-col items-start gap-1.5">
                      <label htmlFor="tunnel-config-cc" className={LABEL_CLASS}>Country</label>
                      <CountrySelect
                        value={countryCode}
                        onChange={(code) => {
                          setCountryCode(code);
                          markDirty();
                          setParseError(null);
                        }}
                      />
                    </div>
                  </div>

                  <div className="flex flex-col gap-1.5">
                    <label htmlFor="tunnel-config-remote" className={LABEL_CLASS}>Remote [IP-Address:Port]</label>
                    <input
                      id="tunnel-config-remote"
                      value={remote}
                      onChange={(e) => { setRemote(e.target.value.slice(0, MAX_REMOTE_CHARS)); markDirty(); setParseError(null); }}
                      maxLength={MAX_REMOTE_CHARS}
                      className={INPUT_CLASS}
                    />
                    <p className={HINT_CLASS}>IPv4 or IPv6 with port</p>
                  </div>

                    <div className="rounded-[10px] border border-edge/60 bg-black/[0.02] px-3 py-2.5">
                      <div className="flex items-center gap-1.5 mb-2">
                      <Lock className="h-[10px] w-[10px] text-black" />
                      <span className="text-[10px] font-semibold text-black tracking-[0.03em]">Server policy [read-only]</span>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="flex flex-col gap-1">
                        <span className={cn(LABEL_CLASS, "text-black")}>Stealth</span>
                        <div className={cn(INPUT_CLASS, "flex items-center !bg-black/[0.03] !text-black cursor-not-allowed select-none")}>
                          Policy Enforced
                        </div>
                      </div>
                      <div className="flex flex-col gap-1">
                        <span className={cn(LABEL_CLASS, "text-black")}>FEC</span>
                        <div className={cn(INPUT_CLASS, "flex items-center !bg-black/[0.03] !text-black cursor-not-allowed select-none")}>
                          Policy Enforced
                        </div>
                      </div>
                    </div>
                    <div className="flex flex-col gap-1 mt-2.5">
                      <span className={cn(LABEL_CLASS, "text-black")}>SNI [Server Name Indication]</span>
                      <div className={cn(INPUT_CLASS, "flex items-center !bg-black/[0.03] !text-black cursor-not-allowed select-none")}>
                        Policy Enforced
                      </div>
                    </div>
                    <p className="text-[9px] text-black mt-2 leading-tight">
                      Stealth, FEC and SNI modes are controlled by server policy embedded in QKeys. Configure these in the Web Admin panel.
                    </p>
                  </div>

                </div>
              </ModalBody>

              <ModalFooter className="dialog-footer-pad">
                <div className="w-full flex items-center justify-end gap-2">
                  <Button
                    type="button"
                    onClick={() => {
                      window.setTimeout(handleClose, RIPPLE_ACTION_DELAY_MS);
                    }}
                    className="inline-flex h-8 items-center rounded-lg px-3 border text-[11px] font-semibold transition-all action-refresh-btn h-auto min-w-0"
                    size="sm"
                  >
                    Cancel
                  </Button>
                  <Button
                    type="button"
                    onClick={() => {
                      window.setTimeout(() => setConfirmDeleteOpen(true), RIPPLE_ACTION_DELAY_MS);
                    }}
                    className="inline-flex h-8 items-center rounded-lg px-3 border text-[11px] font-semibold transition-all action-disconnect-btn h-auto min-w-0"
                    size="sm"
                  >
                    Delete
                  </Button>
                </div>
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </Modal>
    </>
  );
}
