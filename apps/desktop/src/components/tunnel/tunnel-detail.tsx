import { useState, useCallback, useMemo, useEffect, useRef } from "react";
import { useAtomValue, useSetAtom } from "jotai";
import { motion, AnimatePresence } from "framer-motion";
import {
  selectedTunnelAtom,
  selectedTunnelStateAtom,
  selectedTunnelStatsAtom,
  settingsAtom,
  tunnelStatesAtom,
  errorAtom,
} from "@/stores/atoms";
import { addToastAtom } from "@/stores/toastAtom";
import { cn, countryCodeToFlag, formatBytes, formatDuration } from "@/lib/utils";
import { displayFecMode, displayStealthMode } from "@/lib/policy-display";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { ErrorBanner } from "@/components/ui/error-banner";
import { EditQKeyDialog } from "@/components/tunnel/edit-qkey-dialog";
import { ConnectButton } from "@/components/ui/connect-button";
import { Button } from "@/components/ui/button";

const BUTTON_RIPPLE_VISIBILITY_DELAY_MS = 88;

export function TunnelDetail() {
  // ALL hooks must be called unconditionally - before any early return
  const tunnel = useAtomValue(selectedTunnelAtom);
  const tunnelState = useAtomValue(selectedTunnelStateAtom);
  const stats = useAtomValue(selectedTunnelStatsAtom);
  const error = useAtomValue(errorAtom);
  const settings = useAtomValue(settingsAtom);
  const setTunnelStates = useSetAtom(tunnelStatesAtom);
  const setError = useSetAtom(errorAtom);
  const addToast = useSetAtom(addToastAtom);

  const isActive = tunnelState === "active";
  const isBusy = tunnelState === "activating" || tunnelState === "deactivating";

  const [qkeyModes, setQkeyModes] = useState<{ stealth: string | null; fec: string | null } | null>(null);
  const [showDisconnectConfirm, setShowDisconnectConfirm] = useState(false);
  const [showQKeyDialog, setShowQKeyDialog] = useState(false);
  const rippleDelayTimersRef = useRef<number[]>([]);

  useEffect(() => {
    let cancelled = false;
    setQkeyModes(null);
    if (!tunnel?.qkey?.trim()) return;
    if (!window.__TAURI_INTERNALS__) return;

    (async () => {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const parsed = await invoke<{ stealth?: string | null; fec?: string | null }>("qkey_parse", {
          qkey_data: tunnel.qkey,
        });
        if (cancelled) return;
        setQkeyModes({
          stealth: typeof parsed?.stealth === "string" && parsed.stealth.trim() ? parsed.stealth : null,
          fec: typeof parsed?.fec === "string" && parsed.fec.trim() ? parsed.fec : null,
        });
      } catch {
        // ignore: invalid qkey or runtime not available
      }
    })();

    return () => { cancelled = true; };
  }, [tunnel?.qkey]);

  const effectiveModes = useMemo(() => {
    const stealth = qkeyModes?.stealth
      ? { value: displayStealthMode(qkeyModes.stealth), source: "qkey" as const }
      : { value: displayStealthMode("auto"), source: "default" as const };

    const fec = qkeyModes?.fec
      ? { value: displayFecMode(qkeyModes.fec), source: "qkey" as const }
      : { value: displayFecMode("auto"), source: "default" as const };

    return { stealth, fec };
  }, [qkeyModes?.fec, qkeyModes?.stealth]);

  const runAfterRipple = useCallback((action: () => void) => {
    const timerId = window.setTimeout(() => {
      rippleDelayTimersRef.current = rippleDelayTimersRef.current.filter((id) => id !== timerId);
      action();
    }, BUTTON_RIPPLE_VISIBILITY_DELAY_MS);
    rippleDelayTimersRef.current.push(timerId);
  }, []);

  useEffect(() => {
    return () => {
      for (const timerId of rippleDelayTimersRef.current) window.clearTimeout(timerId);
      rippleDelayTimersRef.current = [];
    };
  }, []);

  const performDisconnect = useCallback(async () => {
    if (!tunnel) return;
    setShowDisconnectConfirm(false);
    setTunnelStates((prev) => ({ ...prev, [tunnel.id]: "deactivating" }));
    setError(null);
    if (!window.__TAURI_INTERNALS__) {
      setTunnelStates((prev) => ({ ...prev, [tunnel.id]: "inactive" }));
      return;
    }
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("engine_disconnect");
      addToast({ type: "success", message: "Disconnected from tunnel" });
    } catch (e: any) {
      setError(String(e ?? "Disconnect failed"));
      addToast({ type: "error", message: "Disconnect failed" });
    } finally {
      setTunnelStates((prev) => ({ ...prev, [tunnel.id]: "inactive" }));
    }
  }, [tunnel, setTunnelStates, setError, addToast]);

  const handleActivate = useCallback(async () => {
    if (!tunnel || isBusy) return;
    if (isActive) {
      setShowDisconnectConfirm(true);
      return;
    } else {
      setTunnelStates((prev) => ({ ...prev, [tunnel.id]: "activating" }));
      setError(null);
      if (!window.__TAURI_INTERNALS__) {
        setTunnelStates((prev) => ({ ...prev, [tunnel.id]: "inactive" }));
        setError("Connect requires the desktop app runtime");
        addToast({ type: "error", message: "Connect requires the desktop app runtime" });
        return;
      }
      if (!tunnel.qkey.trim()) {
        setTunnelStates((prev) => ({ ...prev, [tunnel.id]: "inactive" }));
        setError("Missing QKey for this tunnel");
        addToast({ type: "error", message: "Missing QKey for this tunnel" });
        return;
      }
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        await invoke("engine_connect", {
          tunnel_id: tunnel.id,
          qkey_data: tunnel.qkey,
          settings,
        });
        setTunnelStates((prev) => ({ ...prev, [tunnel.id]: "active" }));
        addToast({ type: "success", message: "Connected to tunnel" });
      } catch (e: any) {
        setTunnelStates((prev) => ({ ...prev, [tunnel.id]: "inactive" }));
        setError(String(e ?? "Connect failed"));
        addToast({ type: "error", message: String(e ?? "Connect failed") });
      }
    }
  }, [tunnel, isBusy, isActive, settings, setTunnelStates, setError, addToast]);

  // Empty state - no tunnel selected
  if (!tunnel) {
    return (
      <div className="flex-1 min-h-0 px-6 py-5 flex items-center justify-center">
        <div className="w-full max-w-[560px] rounded-[16px] border border-edge glass-pane-pill shadow-[0_14px_36px_rgba(0,0,0,0.08),0_2px_6px_rgba(0,0,0,0.05)] px-6 py-10">
          <div className="flex flex-col items-center justify-center gap-3">
            <div className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-black/30" />
              <span className="w-1.5 h-1.5 rounded-full bg-black/20" />
              <span className="w-1.5 h-1.5 rounded-full bg-black/12" />
            </div>
            <p className="text-[12px] font-semibold text-black dashboard-heading-sans">No tunnel selected</p>
            <p className="text-[11px] text-black/70 text-center">
              Select a tunnel from the list to view status, metrics and controls.
            </p>
          </div>
        </div>
      </div>
    );
  }

  const flag = countryCodeToFlag(tunnel.countryCode);
  const hasQKey = Boolean(tunnel.qkey?.trim());
  const statusView = (() => {
    if (isActive) {
      return {
        key: "active",
        label: "Connected",
        textClass: "text-positive",
        dotColor: "#22c55e",
      } as const;
    }
    if (tunnelState === "activating") {
      return {
        key: "activating",
        label: "Connecting",
        textClass: "text-warning",
        dotColor: "#f59e0b",
      } as const;
    }
    if (tunnelState === "deactivating") {
      return {
        key: "deactivating",
        label: "Disconnecting",
        textClass: "text-warning",
        dotColor: "#f59e0b",
      } as const;
    }
    return {
      key: "inactive",
      label: "Disconnected",
      textClass: "text-black/60",
      dotColor: "rgba(0,0,0,0.28)",
    } as const;
  })();

  return (
    <div className="flex-1 flex flex-col min-h-0 overflow-y-auto">
      <ConfirmDialog
        open={showDisconnectConfirm}
        title="Disconnect Tunnel"
        message="Are you sure you want to disconnect from this tunnel? Your traffic will no longer be routed through the VPN."
        confirmLabel="Disconnect"
        cancelLabel="Cancel"
        variant="danger"
        onConfirm={performDisconnect}
        onCancel={() => setShowDisconnectConfirm(false)}
      />
      <EditQKeyDialog
        open={showQKeyDialog}
        onOpenChange={setShowQKeyDialog}
        tunnelId={tunnel.id}
        mode={hasQKey ? "replace" : "set"}
      />
      <div className="px-6 py-5 space-y-6">
        {/* Interface Section */}
        <section className="space-y-2.5">
          <div className="flex items-center justify-between">
            <h2 className="text-[11px] font-semibold text-text-primary dashboard-heading-sans">
              Tunnel
            </h2>
            {flag && <span className="text-[14px]">{flag}</span>}
          </div>

          <div className="space-y-0">
            <InfoRow label="Name" value={tunnel.name} />
            <InfoRow label="Remote" value={tunnel.remote} mono />
            <InfoRow label="SNI" value={tunnel.sni} mono />
            <InfoRow label="Token" value={tunnel.hasToken ? "Present" : "None"} />
            <InfoRow label="Stealth">
              <span className="flex items-center justify-end gap-2 min-w-0">
                <span className="text-[12px] text-text-primary truncate min-w-0">
                  {effectiveModes.stealth.value}
                </span>
                <span className="px-1.5 py-0.5 rounded-md text-[10px] text-text-ghost border border-edge bg-white/3 shrink-0">
                  {effectiveModes.stealth.source === "qkey" ? "QKey" : "Default"}
                </span>
              </span>
            </InfoRow>
            <InfoRow label="FEC">
              <span className="flex items-center justify-end gap-2 min-w-0">
                <span className="text-[12px] text-text-primary truncate min-w-0">
                  {effectiveModes.fec.value}
                </span>
                <span className="px-1.5 py-0.5 rounded-md text-[10px] text-text-ghost border border-edge bg-white/3 shrink-0">
                  {effectiveModes.fec.source === "qkey" ? "QKey" : "Default"}
                </span>
              </span>
            </InfoRow>
          </div>

          <div className="rounded-xl border border-edge glass-pane-pill px-3 py-3 shadow-[0_8px_18px_rgba(0,0,0,0.08),0_1px_2px_rgba(0,0,0,0.05)]">
            <div className="flex items-center justify-between gap-4">
              <span className="text-[10px] font-semibold text-black/72 tracking-[0.06em] dashboard-heading-sans">
                Connection Status
              </span>
              <span className="inline-flex items-center justify-end gap-2 min-w-[150px]">
                <motion.span
                  key={statusView.key}
                  className="w-[8px] h-[8px] rounded-full shadow-[0_0_0_2px_rgba(255,255,255,0.65)]"
                  animate={{
                    backgroundColor: statusView.dotColor,
                    scale: statusView.key === "active" ? [1, 1.14, 1] : statusView.key === "inactive" ? 1 : [1, 1.08, 1],
                  }}
                  transition={{
                    backgroundColor: { duration: 0.22, ease: "easeOut" },
                    scale: {
                      duration: statusView.key === "inactive" ? 0.18 : 0.9,
                      repeat: statusView.key === "inactive" ? 0 : Infinity,
                      repeatDelay: statusView.key === "active" ? 1.2 : 0.45,
                      ease: "easeInOut",
                    },
                  }}
                />
                <span className={cn("text-[12px] w-[98px] text-left tabular-nums", statusView.textClass)}>
                  {statusView.label}
                </span>
              </span>
            </div>

            <div className="mt-3 flex items-center justify-end gap-2">
                <Button
                  type="button"
                  onClick={() => runAfterRipple(() => setShowQKeyDialog(true))}
                  className={cn(
                    "inline-flex items-center justify-center rounded-lg border transition-all",
                    tunnel.qkey
                      ? "action-refresh-btn"
                      : "action-save-btn text-white",
                  )}
                size="sm"
              >
                {tunnel.qkey ? "Change QKey" : "Set QKey"}
              </Button>
              <ConnectButton
                state={isActive ? "connected" : isBusy ? (tunnelState === "activating" ? "connecting" : "disconnecting") : "idle"}
                onClick={() => {
                  if (!hasQKey && !isActive) {
                    runAfterRipple(() => setShowQKeyDialog(true));
                    return;
                  }
                  handleActivate();
                }}
                disabled={!hasQKey && !isActive}
                hasQKey={hasQKey}
                hint={!hasQKey && !isActive ? "QKey required for connection" : undefined}
              />
            </div>
          </div>
        </section>

        {/* Error */}
        <ErrorBanner error={error} onDismiss={() => setError(null)} />

        {/* Transfer stats (when active) */}
        <AnimatePresence>
          {isActive && stats && (
            <motion.section
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="space-y-3"
            >
              <h2 className="text-[11px] font-semibold text-text-primary dashboard-heading-sans">
                Transfer
              </h2>
              <div className="space-y-0">
                <InfoRow label="Received" value={formatBytes(stats.rxBytes)} mono />
                <InfoRow label="Sent" value={formatBytes(stats.txBytes)} mono />
                <InfoRow label="Latency" value={`${stats.latencyMs.toFixed(1)} ms`} mono />
                <InfoRow label="Loss" value={`${stats.lossPercent.toFixed(2)}%`} mono warn={stats.lossPercent > 3} />
                <InfoRow label="Uptime" value={formatDuration(stats.uptimeSecs)} mono />
                <InfoRow label="Stealth [live]" value={displayStealthMode(stats.stealthMode)} />
                <InfoRow label="FEC [live]" value={displayFecMode(stats.fecMode)} />
              </div>
            </motion.section>
          )}
        </AnimatePresence>

      </div>
    </div>
  );
}

function InfoRow({
  label,
  value,
  mono,
  warn,
  children,
}: {
  label: string;
  value?: string;
  mono?: boolean;
  warn?: boolean;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex items-baseline justify-between py-1.5 gap-4">
      <span className="text-[12px] text-text-tertiary shrink-0">{label}</span>
      {children ?? (
        <span className={cn(
          "text-[12px] text-right truncate min-w-0",
          mono ? "tabular-nums" : "",
          warn ? "text-warning" : "text-text-primary",
        )}>
          {value}
        </span>
      )}
    </div>
  );
}

// Intentionally no key rendering here. QKeys are managed in import/export flows.
