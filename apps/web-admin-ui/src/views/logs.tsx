import { useCallback, useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useDisclosure } from "@heroui/react";
import { Shield, ShieldCheck, AlertTriangle, Eye, EyeOff, Check } from "lucide-react";
import { ApiError, getJson, postJson, sanitizeErrorMessage } from "@/api";
import { cn } from "@/lib/cn";
import { SkeletonText } from "@/components/ui/skeleton";
import { Btn } from "@/components/ui/controls";
import { useConfirmDialog } from "@/lib/use-confirm-dialog";
import { useTopStatusAnchor } from "@/lib/use-top-status-anchor";
import { useNotify } from "@/lib/use-notify";
import { notifyErrorOverlay } from "@/lib/notify-error";
import { buildUnsavedConfirm } from "@/lib/unsaved-guard";
import { AppDialog, AppDialogBody, AppDialogContent, AppDialogFooter, AppDialogHeader } from "@/components/ui/app-dialog";
import { useSetAtom } from "jotai";
import { authErrorAtom, authRequiredAtom, logsDirtyAtom } from "@/stores/atoms";

type LogMode = "verbose" | "normal" | "minimal" | "no-log";
const MAX_PERSIST_ATTEMPTS = 2;

interface LogEntry {
  ts: number;
  level: string;
  msg: string;
}

type LogsPayload = { lines: LogEntry[]; cursor: number };

function parseLogsResponse(resp: unknown): LogsPayload {
  const asObj = resp as any;
  if (typeof asObj?.success === "boolean") {
    if (!asObj.success) {
      throw new Error(
        typeof asObj?.message === "string" && asObj.message.trim()
          ? asObj.message.trim()
          : "Failed to load logs",
      );
    }
  }
  const data = asObj?.data ?? resp;
  const lines = Array.isArray(data?.lines) ? data.lines as LogEntry[] : [];
  const cursor = typeof data?.cursor === "number" ? data.cursor : 0;
  return { lines, cursor };
}

const MODE_DESCRIPTIONS: Record<LogMode, { title: string; desc: string; icon: React.ElementType; color: string }> = {
  verbose: {
    title: "Verbose",
    desc: "Full debug logging with all metadata. Best for development and troubleshooting.",
    icon: Eye,
    color: "text-amber-600",
  },
  normal: {
    title: "Normal",
    desc: "Info-level logging. Standard operation mode with reasonable detail.",
    icon: Eye,
    color: "text-text-secondary",
  },
  minimal: {
    title: "Minimal",
    desc: "Warnings and errors only. Client metadata [IPs, session IDs] stripped from entries.",
    icon: EyeOff,
    color: "text-text-tertiary",
  },
  "no-log": {
    title: "No-Log",
    desc: "Strict zero-log privacy mode.",
    icon: ShieldCheck,
    color: "text-emerald-600",
  },
};

const NO_LOG_FEATURES = [
  { label: "In-Memory Buffer", desc: "Server log buffer is a capped ring in RAM. No log files are written by the app." },
  { label: "Logs Endpoint Empty", desc: "Admin logs API returns an empty result and resets the cursor." },
  { label: "Buffer Cleared", desc: "Switching to No-Log clears the in-memory ring buffer immediately." },
  { label: "App Logging Disabled", desc: "Application logging is set to Off [best-effort]. It does not guarantee OS-level suppression." },
];
const RIPPLE_ACTION_DELAY_MS = 88;

export function LogsView() {
  const [mode, setMode] = useState<LogMode>("normal");
  const [savedMode, setSavedMode] = useState<LogMode>("normal");
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [saving, setSaving] = useState(false);
  const [loadingLogs, setLoadingLogs] = useState(true);
  const [logsReady, setLogsReady] = useState(false);
  const [backendOnline, setBackendOnline] = useState(false);
  const logsFetchInFlightRef = useRef(false);
  const logsEpochRef = useRef(0);
  const cursorRef = useRef(0);
  const bottomRef = useRef<HTMLDivElement>(null);
  const actionsRef = useRef<HTMLDivElement | null>(null);
  const copyFeedbackTimeoutRef = useRef<number | null>(null);
  const [copyFeedback, setCopyFeedback] = useState(false);
  const entryCountLabel = logs.length === 1 ? "1 entry" : `${logs.length} entries`;
  const clearLogsDialog = useDisclosure();
  const notify = useNotify();
  const setAuthRequired = useSetAtom(authRequiredAtom);
  const setAuthError = useSetAtom(authErrorAtom);
  const setLogsDirty = useSetAtom(logsDirtyAtom);
  const confirmDialog = useConfirmDialog();
  useTopStatusAnchor(actionsRef);

  const handleCopyAll = useCallback(async () => {
    if (logs.length === 0) return;
    const text = logs.map(l => `[${new Date(l.ts).toISOString()}] [${l.level.toUpperCase()}] ${l.msg}`).join('\n');
    try {
      await navigator.clipboard.writeText(text);
      setCopyFeedback(true);
      if (copyFeedbackTimeoutRef.current !== null) {
        window.clearTimeout(copyFeedbackTimeoutRef.current);
      }
      copyFeedbackTimeoutRef.current = window.setTimeout(() => {
        setCopyFeedback(false);
        copyFeedbackTimeoutRef.current = null;
      }, 1100);
    } catch {
      setCopyFeedback(false);
    }
  }, [logs]);

  const isAuthError = useCallback(
    (e: unknown): boolean => e instanceof ApiError && e.status === 401,
    [],
  );

  const isRetriablePersistenceError = useCallback((e: unknown): boolean => {
    if (e instanceof ApiError) {
      const status = e.status;
      return status == null || status >= 500;
    }
    return true;
  }, []);

  const fetchMode = useCallback(async (): Promise<LogMode> => {
    let nextMode = savedMode;
    try {
      const resp = await getJson<{ success: boolean; message?: string; data?: { mode?: string } }>("/api/config/logging");
      if (!resp.success) throw new Error(resp.message ?? "Failed to load logging mode");
      if (resp.data?.mode) {
        const m = resp.data.mode as LogMode;
        setMode(m);
        setSavedMode(m);
        nextMode = m;
      }
    } catch (e: unknown) {
      if (isAuthError(e)) {
        setAuthError(null);
        setAuthRequired(true);
      }
    }
    return nextMode;
  }, [isAuthError, savedMode, setAuthError, setAuthRequired]);

  const fetchLogsOnce = useCallback(async (modeOverride?: LogMode, reset = false) => {
    if (logsFetchInFlightRef.current) return;
    logsFetchInFlightRef.current = true;
    const epochAtStart = logsEpochRef.current;
    const effectiveMode = modeOverride ?? mode;
    if (reset) {
      cursorRef.current = 0;
    }
    if (effectiveMode === "no-log") {
      if (epochAtStart !== logsEpochRef.current) {
        logsFetchInFlightRef.current = false;
        return;
      }
      cursorRef.current = 0;
      setLogs([]);
      setLoadingLogs(false);
      setLogsReady(true);
      logsFetchInFlightRef.current = false;
      return;
    }
    try {
      const resp = await getJson<LogsPayload | { success?: boolean; data?: LogsPayload }>(`/api/logs?cursor=${cursorRef.current}`);
      const next = parseLogsResponse(resp);
      if (epochAtStart !== logsEpochRef.current) return;
      if (next.lines.length) {
        cursorRef.current = next.cursor;
        if (reset) {
          setLogs(next.lines.length > 500 ? next.lines.slice(-500) : next.lines);
        } else {
          setLogs((prev) => {
            const merged = [...prev, ...next.lines];
            return merged.length > 500 ? merged.slice(-500) : merged;
          });
        }
      } else if (next.cursor >= 0) {
        cursorRef.current = next.cursor;
        if (reset) setLogs([]);
      }
    } catch (e: unknown) {
      if (epochAtStart !== logsEpochRef.current) return;
      if (isAuthError(e)) {
        setAuthError(null);
        setAuthRequired(true);
        return;
      }
      const message = sanitizeErrorMessage(String((e as any)?.message ?? e), "Failed to load logs");
      notifyErrorOverlay(notify, message, "logs:load");
    } finally {
      if (epochAtStart === logsEpochRef.current) {
        setLoadingLogs(false);
        setLogsReady(true);
      }
      logsFetchInFlightRef.current = false;
    }
  }, [isAuthError, mode, notify, setAuthError, setAuthRequired]);

  const fetchOnlineStatus = useCallback(async () => {
    try {
      const resp = await getJson<{ success: boolean; data?: unknown; message?: string }>("/api/status");
      setBackendOnline(Boolean(resp?.success && resp?.data));
    } catch (e: unknown) {
      if (isAuthError(e)) {
        setAuthError(null);
        setAuthRequired(true);
      }
      setBackendOnline(false);
    }
  }, [isAuthError, setAuthError, setAuthRequired]);

  const refreshAll = useCallback(async () => {
    setLoadingLogs(true);
    const latestMode = await fetchMode();
    await Promise.allSettled([fetchOnlineStatus(), fetchLogsOnce(latestMode, true)]);
  }, [fetchLogsOnce, fetchMode, fetchOnlineStatus]);

  // Fetch current mode from server
  useEffect(() => {
    fetchMode();
  }, [fetchMode]);

  // Poll logs (only when not in no-log mode)
  useEffect(() => {
    let stopped = false;
    const poll = async () => {
      if (stopped) return;
      await fetchLogsOnce();
    };
    const id = setInterval(poll, 1200);
    poll();
    return () => {
      stopped = true;
      clearInterval(id);
    };
  }, [fetchLogsOnce]);

  // Keep top status indicator synced.
  useEffect(() => {
    fetchOnlineStatus();
    const id = setInterval(fetchOnlineStatus, 5000);
    return () => clearInterval(id);
  }, [fetchOnlineStatus]);

  useEffect(() => {
    setLogsDirty(mode !== savedMode);
  }, [mode, savedMode, setLogsDirty]);

  useEffect(() => {
    return () => setLogsDirty(false);
  }, [setLogsDirty]);

  useEffect(() => {
    return () => {
      if (copyFeedbackTimeoutRef.current !== null) {
        window.clearTimeout(copyFeedbackTimeoutRef.current);
      }
    };
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const handleRefresh = useCallback(async () => {
    if (mode !== savedMode) {
      const discard = await confirmDialog(buildUnsavedConfirm("logging", "refresh"));
      if (!discard) return;
    }
    notify.info("Refreshed");
    void refreshAll();
  }, [confirmDialog, mode, notify, refreshAll, savedMode]);

  const applyMode = useCallback(async (newMode: LogMode) => {
    setSaving(true);
    try {
      let persistedMode: LogMode | null = null;
      for (let attempt = 1; attempt <= MAX_PERSIST_ATTEMPTS; attempt++) {
        try {
          const resp = await postJson<{ success: boolean; message?: string }, { mode: LogMode }>("/api/config/logging", { mode: newMode });
          if (!resp.success) throw new Error(resp.message ?? "Failed to save logging mode");

          const verifyResp = await getJson<{ success: boolean; message?: string; data?: { mode?: string } }>("/api/config/logging");
          if (!verifyResp.success) throw new Error(verifyResp.message ?? "Failed to verify logging mode");
          const modeFromServer = verifyResp.data?.mode as LogMode | undefined;
          if (!modeFromServer || modeFromServer !== newMode) {
            throw new Error("Failed to verify logging mode");
          }
          persistedMode = modeFromServer;
          break;
        } catch (e) {
          if (attempt >= MAX_PERSIST_ATTEMPTS || !isRetriablePersistenceError(e)) {
            throw e;
          }
        }
      }
      const nextSavedMode = persistedMode ?? newMode;
      setMode(nextSavedMode);
      setSavedMode(nextSavedMode);
      notify.success("Changes saved");
    } catch (e: unknown) {
      if (isAuthError(e)) {
        setAuthError(null);
        setAuthRequired(true);
        return;
      }
      const message = sanitizeErrorMessage(String((e as any)?.message ?? e), "");
      notifyErrorOverlay(
        notify,
        message || "Failed to save logging mode. Backend unreachable or API unavailable.",
        "logs:save-mode",
      );
    } finally {
      setSaving(false);
    }
  }, [isAuthError, isRetriablePersistenceError, notify, setAuthError, setAuthRequired]);

  const confirmClearLogs = useCallback(async () => {
    const previousLogs = logs;
    logsEpochRef.current += 1;
    // Immediate UX feedback: close dialog and clear visible panel first.
    clearLogsDialog.onClose();
    logsFetchInFlightRef.current = false;
    cursorRef.current = 0;
    setLogs([]);
    try {
      const resp = await postJson<{ success: boolean; message?: string }, Record<string, never>>("/api/logs/clear", {});
      if (!resp.success) {
        throw new Error(resp.message ?? "Failed to clear logs");
      }
      // Re-sync with backend cursor state after clear.
      await fetchLogsOnce(mode, true);
    } catch (e: unknown) {
      if (isAuthError(e)) {
        setAuthError(null);
        setAuthRequired(true);
        return;
      }
      // Restore prior lines on hard failure so the action is never "silent no-op".
      setLogs(previousLogs);
      const message = sanitizeErrorMessage(String((e as any)?.message ?? e), "Failed to clear logs");
      notifyErrorOverlay(notify, message, "logs:clear");
    }
  }, [clearLogsDialog, fetchLogsOnce, isAuthError, logs, mode, notify, setAuthError, setAuthRequired, setLogs]);

  return (
    <div className="flex flex-1 min-h-0 overflow-hidden dashboard-heading-sans">
      <div className="w-full h-full min-h-0 px-6 pt-6 pb-0 flex flex-col gap-5">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="text-[14px] font-bold text-text-primary">Logs</div>
          <div ref={actionsRef} className="flex items-center gap-2.5">
            <Btn
              type="button"
              loading={saving}
              disabled={saving || mode === savedMode}
              onClick={() => {
                void applyMode(mode);
              }}
              variant="accent"
            >
              Save
            </Btn>
            <Btn
              type="button"
              onClick={() => {
                void handleRefresh();
              }}
              variant="secondary"
            >
              Refresh
            </Btn>
            <div
              className={cn(
                "status-chip dashboard-heading-sans",
                backendOnline ? "border-positive/35 text-positive" : "border-negative/35 text-negative",
              )}
            >
              <span className={cn("h-2 w-2 rounded-full", backendOnline ? "bg-positive shadow-[0_0_10px_rgba(22,163,74,0.55)]" : "bg-negative shadow-[0_0_10px_rgba(220,38,38,0.55)]")} />
              {backendOnline ? "Online" : "Offline"}
            </div>
          </div>
        </div>
        {/* Logging Mode */}
        <section className="rounded-xl glass border border-edge/70">
          <div className="pane-header border-b border-edge">
            <div className="text-[11px] text-black font-semibold dashboard-heading-sans">Logging Mode</div>
          </div>
          <div className="pane-body pane-first-item-offset space-y-1.5">
            <div role="radiogroup" aria-label="Logging mode selection">
              {(["verbose", "normal", "minimal", "no-log"] as LogMode[]).map((m) => {
                const info = MODE_DESCRIPTIONS[m];
                const Icon = info.icon;
                const isSelected = mode === m;
                return (
                  <label
                    key={m}
                    data-ripple="off"
                    className="block"
                    onClick={() => setMode(m)}
                  >
                    <input
                      type="radio"
                      name="logging-mode"
                      value={m}
                      checked={isSelected}
                      onChange={() => setMode(m)}
                      className="sr-only"
                    />
                    <div
                    className={cn(
                        "relative w-full flex items-center gap-3 px-4 py-3 rounded-lg text-left cursor-pointer border select-none",
                        isSelected
                          ? "border-edge/70"
                          : "border-transparent transition-colors",
                    )}
                  >
                    {isSelected && (
                      <motion.div
                        layoutId="log-mode-pill"
                        className="absolute inset-0 rounded-lg pointer-events-none"
                        style={{
                          background: "rgba(255,255,255,0.65)",
                          backdropFilter: "blur(24px) saturate(200%)",
                          WebkitBackdropFilter: "blur(24px) saturate(200%)",
                          border: "1px solid rgba(255,255,255,0.60)",
                          boxShadow: "inset 0 1px 0.5px rgba(255,255,255,0.55), 0 3px 10px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.03)",
                          willChange: "transform, opacity",
                          transform: "translateZ(0)",
                        }}
                        transition={{ type: "spring", stiffness: 220, damping: 28, mass: 0.95 }}
                      />
                    )}
                    <Icon className={cn("relative z-10 h-4 w-4 shrink-0", isSelected ? info.color : "text-text-ghost")} strokeWidth={2} />
                    <div className="relative z-10 flex-1 min-w-0">
                      <div className={cn("text-[12px] font-medium dashboard-heading-sans", isSelected ? "text-text-primary" : "text-text-secondary")}>{info.title}</div>
                      <div className="text-[10px] text-text-tertiary leading-snug">{info.desc}</div>
                    </div>
                    </div>
                  </label>
                );
              })}
            </div>
          </div>
        </section>

        <AnimatePresence mode="wait" initial={false}>
          {mode === "no-log" ? (
            <motion.div
              key="no-log-state"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
              className="space-y-5"
            >
              <section className="rounded-xl glass border border-edge/70">
                <div className="px-5 pt-4 pb-4 flex items-start gap-3.5">
                  <div className="mt-0.5 p-2 rounded-lg bg-emerald-500/10 shrink-0">
                    <Shield className="h-5 w-5 text-emerald-600" strokeWidth={2} />
                  </div>
                  <div className="flex-1 min-w-0 space-y-3">
                    <div className="text-[13px] font-semibold text-text-primary">Zero-Log Privacy Modus</div>
                    <div className="text-[11px] text-text-secondary leading-relaxed">
                      When enabled, the admin logs endpoint is disabled and the in-memory log buffer is cleared.
                      The server also sets application logging to Off. This is best-effort and does not guarantee
                      suppression of OS-level logging outside the application.
                    </div>
                    <div className="grid grid-cols-2 gap-x-5 gap-y-2.5">
                      {NO_LOG_FEATURES.map((f) => (
                        <div key={f.label} className="flex items-start gap-2">
                          <ShieldCheck className="h-3 w-3 text-emerald-500 mt-0.5 shrink-0" strokeWidth={2.5} />
                          <div>
                            <div className="text-[11px] font-medium text-text-primary">{f.label}</div>
                            <div className="text-[10px] text-text-tertiary leading-snug">{f.desc}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="px-5 py-3 border-t border-edge/70 flex items-start gap-2">
                  <AlertTriangle className="h-3 w-3 text-amber-500 shrink-0 mt-[2px]" strokeWidth={2.5} />
                  <div className="text-[11px] text-text-tertiary leading-relaxed">
                    No-Log mode disables all diagnostic output. Server issues will not produce visible logs.
                    Use only when privacy is the absolute priority.
                  </div>
                </div>
              </section>

              <section className="rounded-xl glass border border-edge/70">
                <div className="pane-body pt-4 text-center">
                  <div className="text-[11px] text-text-tertiary dashboard-heading-sans">
                    Log output is disabled in No-Log mode. Switch to Normal or Verbose to view server logs.
                  </div>
                </div>
              </section>
            </motion.div>
          ) : (
            <motion.section
              key="live-output-state"
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
              className="rounded-xl glass border border-edge/70 flex flex-col flex-1 min-h-0"
            >
              <div className="pane-header border-b border-edge flex items-center justify-between">
                <div className="text-[11px] text-black font-semibold dashboard-heading-sans">Live Output</div>
                <div className="flex items-center gap-3">
                  <div className="text-[10px] text-text-ghost dashboard-heading-sans">{entryCountLabel}</div>
                  <Btn
                    variant="copy"
                    onClick={handleCopyAll}
                    disabled={logs.length === 0}
                  >
                    <span className="relative z-10 inline-grid place-items-center">
                      <span className="invisible">Copy</span>
                      <AnimatePresence initial={false} mode="wait">
                        {copyFeedback ? (
                          <motion.span
                            key="copied"
                            initial={{ opacity: 0, y: 4, scale: 0.96 }}
                            animate={{ opacity: 1, y: 0, scale: 1 }}
                            exit={{ opacity: 0, y: -4, scale: 0.96 }}
                            transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
                            className="absolute inset-0 inline-flex items-center justify-center"
                          >
                            <Check className="h-3.5 w-3.5" />
                          </motion.span>
                        ) : (
                          <motion.span
                            key="copy"
                            initial={{ opacity: 0, y: 4, scale: 0.96 }}
                            animate={{ opacity: 1, y: 0, scale: 1 }}
                            exit={{ opacity: 0, y: -4, scale: 0.96 }}
                            transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
                            className="absolute inset-0 inline-flex items-center justify-center"
                          >
                            Copy
                          </motion.span>
                        )}
                      </AnimatePresence>
                    </span>
                  </Btn>
                  <Btn
                    type="button"
                    onClick={() => {
                      window.setTimeout(clearLogsDialog.onOpen, RIPPLE_ACTION_DELAY_MS);
                    }}
                    disabled={logs.length === 0}
                    variant="neutral"
                  >
                    Clear
                  </Btn>
                </div>
              </div>
              <div className="pane-body pane-first-item-offset flex-1 min-h-0">
                <div
                  className="rounded-xl glass-pane-pill px-3 py-2 h-full min-h-0"
                  style={{ willChange: "transform, opacity", transform: "translateZ(0)" }}
                >
                  <div className="h-full min-h-0 overflow-y-auto">
                    {logs.length === 0 && loadingLogs && !logsReady ? (
                      <div className="px-2 py-2">
                        <SkeletonText lines={8} />
                      </div>
                    ) : logs.length === 0 ? (
                      <div className="text-[12px] text-text-tertiary py-8 text-center dashboard-heading-sans">
                        {mode === "minimal" ? "Only warnings and errors will appear here." : "Waiting for log entries..."}
                      </div>
                    ) : (
                      <div className="space-y-0">
                        {logs.map((entry, i) => (
                          <div
                            key={`${entry.ts}-${i}`}
                            className={cn(
                              "flex items-start gap-3 px-2 py-[3px] rounded text-[11px]",
                              entry.level === "error" && "bg-negative-muted/30",
                              entry.level === "warn" && "bg-warning-muted/30",
                            )}
                          >
                            <span className="text-text-ghost/60 shrink-0 tabular-nums w-[64px] dashboard-heading-sans">
                              {new Date(entry.ts).toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                            </span>
                            <span className={cn(
                              "w-[40px] text-center text-[9px] font-medium py-0.5 rounded shrink-0 dashboard-heading-sans",
                              entry.level === "error" ? "text-negative" :
                              entry.level === "warn" ? "text-warning" :
                              entry.level === "debug" ? "text-text-ghost" : "text-text-tertiary",
                            )}>
                              {entry.level}
                            </span>
                            <span className="text-text-secondary flex-1 break-words dashboard-heading-sans">{entry.msg}</span>
                          </div>
                        ))}
                        <div ref={bottomRef} />
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        <AppDialog
          isOpen={clearLogsDialog.isOpen}
          onOpenChange={clearLogsDialog.onOpenChange}
        >
          <AppDialogContent>
            <AppDialogHeader>Clear Live Output</AppDialogHeader>
            <AppDialogBody className="space-y-2">
              <div className="text-[12px] text-black">
                This removes all currently visible log entries from the live output panel.
              </div>
              <div className="text-[11px] text-black">Do you want to continue?</div>
            </AppDialogBody>
            <AppDialogFooter>
              <Btn
                variant="ghost"
                onClick={() => {
                  window.setTimeout(clearLogsDialog.onClose, RIPPLE_ACTION_DELAY_MS);
                }}
              >
                Cancel
              </Btn>
              <Btn
                type="button"
                variant="neutral"
                onClick={() => {
                  window.setTimeout(confirmClearLogs, RIPPLE_ACTION_DELAY_MS);
                }}
              >
                Clear
              </Btn>
            </AppDialogFooter>
          </AppDialogContent>
        </AppDialog>

      </div>
    </div>
  );
}
