import { useRef, useEffect, useState, useCallback } from "react";
import { useAtom } from "jotai";
import { motion, AnimatePresence } from "framer-motion";
import { logsAtom } from "@/stores/atoms";
import { cn } from "@/lib/utils";
import { SkeletonText } from "@/components/ui/skeleton";
import { Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Modal, ModalContent, ModalHeader, ModalBody, ModalFooter } from "@heroui/react";
import { useStageModalPortal, withStageModalClassNames } from "@/lib/stage-modal";

const levelStyles: Record<string, string> = {
  error: "text-negative",
  warn: "text-warning",
  info: "text-text-secondary",
  debug: "text-text-tertiary",
  trace: "text-text-ghost",
};

const levelBadgeStyles: Record<string, string> = {
  error: "bg-negative-muted text-negative",
  warn: "bg-warning-muted text-warning",
  info: "bg-surface-3 border border-edge text-text-secondary",
  debug: "bg-surface-3 border border-edge text-text-tertiary",
  trace: "bg-surface-3 border border-edge text-text-ghost",
};

function formatTimestamp(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function LogsView() {
  const [logs, setLogs] = useAtom(logsAtom);
  const portalContainer = useStageModalPortal();
  const scrollRef = useRef<HTMLDivElement>(null);
  const [copyFeedback, setCopyFeedback] = useState(false);
  const [clearDialogOpen, setClearDialogOpen] = useState(false);
  const copyFeedbackTimeoutRef = useRef<number | null>(null);
  const RIPPLE_ACTION_DELAY_MS = 88;
  const entryCountLabel = logs.length === 1 ? "1 entry" : `${logs.length} entries`;

  const handleCopyAll = useCallback(async () => {
    const text = logs.map(l => `[${formatTimestamp(l.timestamp)}] [${l.level.toUpperCase()}] ${l.message}`).join('\n');
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

  const handleClearAll = useCallback(async () => {
    setLogs([]);
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("engine_logs_clear");
    } catch {
      // no-op
    }
  }, [setLogs]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs.length]);

  useEffect(() => {
    return () => {
      if (copyFeedbackTimeoutRef.current !== null) {
        window.clearTimeout(copyFeedbackTimeoutRef.current);
        copyFeedbackTimeoutRef.current = null;
      }
    };
  }, []);

  return (
    <div className="flex-1 h-full min-h-0 overflow-hidden">
      <div className="h-[calc(100%-13px)] w-full px-6 pt-5 pb-0 flex flex-col self-start">
        <div className="flex items-center justify-between">
          <div className="text-[14px] font-bold text-text-primary">Logs</div>
        </div>
        <section className="mt-3 rounded-xl glass border border-edge/70 flex flex-col flex-1 min-h-0">
          <div className="pane-header border-b border-edge flex items-center justify-between">
            <div className="text-[11px] font-semibold text-black dashboard-heading-sans">Live Output</div>
            <div className="flex items-center gap-3">
              <div className="text-[10px] text-text-ghost dashboard-heading-sans [font-family:var(--font-sans)]">{entryCountLabel}</div>
              <Button
                type="button"
                onClick={handleCopyAll}
                disabled={logs.length === 0}
                className="relative isolate overflow-hidden inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold action-copy-btn h-auto min-w-0"
                title="Copy all logs"
                size="sm"
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
              </Button>
              <Button
                type="button"
                variant="neutral"
                onClick={() => {
                  window.setTimeout(() => setClearDialogOpen(true), RIPPLE_ACTION_DELAY_MS);
                }}
                disabled={logs.length === 0}
                className="relative isolate overflow-hidden inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold action-neutral-btn h-auto min-w-0"
                size="sm"
              >
                <span className="relative z-10">Clear</span>
              </Button>
            </div>
          </div>
          <div className="pane-body pane-first-item-offset flex-1 min-h-0">
            <div className="rounded-xl glass-pane-pill px-3 py-2 h-full min-h-0" style={{ willChange: "transform, opacity", transform: "translateZ(0)" }}>
              <div ref={scrollRef} className="h-full min-h-0 overflow-y-auto">
                {logs.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full gap-4">
                    <div className="text-center space-y-1">
                      <p className="text-[12px] font-medium text-text-secondary dashboard-heading-sans">Waiting for engine output...</p>
                      <p className="text-[11px] text-text-ghost dashboard-heading-sans">Connect a tunnel to see logs</p>
                    </div>
                    <div className="w-full max-w-[320px] px-6">
                      <SkeletonText lines={4} />
                    </div>
                  </div>
                ) : (
                  <div className="py-0.5">
                    {logs.map((entry, i) => (
                      <motion.div
                        key={`${entry.timestamp}-${i}`}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: 0.1 }}
                        className={cn(
                          "flex items-start gap-3 px-2 py-[3px] rounded text-[11px]",
                          entry.level === "error" && "bg-negative/[0.03]",
                          entry.level === "warn" && "bg-warning/[0.02]",
                        )}
                      >
                        <span className="text-text-ghost/60 shrink-0 tabular-nums w-[64px] dashboard-heading-sans">
                          {formatTimestamp(entry.timestamp)}
                        </span>
                        <span
                          className={cn(
                            "w-[40px] text-center text-[9px] font-medium py-0.5 rounded shrink-0 dashboard-heading-sans",
                            levelBadgeStyles[entry.level] ?? levelBadgeStyles.info,
                          )}
                        >
                          {entry.level}
                        </span>
                        <span
                          className={cn(
                            "leading-relaxed break-all select-text dashboard-heading-sans",
                            levelStyles[entry.level] ?? levelStyles.info,
                          )}
                        >
                          {entry.message}
                        </span>
                      </motion.div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>
      </div>

      <Modal
        isOpen={clearDialogOpen}
        onOpenChange={setClearDialogOpen}
        backdrop="blur"
        hideCloseButton
        size="sm"
        placement="center"
        scrollBehavior="inside"
        portalContainer={portalContainer}
        classNames={withStageModalClassNames({ wrapper: "items-center justify-center p-4" })}
      >
        <ModalContent className="w-[min(92vw,420px)] overflow-hidden glass border border-edge shadow-xl rounded-[18px] dialog-typography dialog-surface">
          {(onClose) => (
            <>
              <ModalHeader className="dialog-header-pad flex flex-col gap-1">
                <div className="text-[13px] font-semibold text-black dashboard-heading-sans">Clear Live Output</div>
              </ModalHeader>
              <ModalBody className="dialog-body-pad">
                <p className="text-[12px] text-black leading-relaxed">
                  This removes all currently visible log entries from the live output panel.
                </p>
                <p className="text-[11px] text-black">Do you want to continue?</p>
              </ModalBody>
              <ModalFooter className="dialog-footer-pad">
                <Button
                  type="button"
                  onClick={() => {
                    window.setTimeout(onClose, RIPPLE_ACTION_DELAY_MS);
                  }}
                  className="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-refresh-btn h-auto min-w-0"
                  size="sm"
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="neutral"
                  onClick={() => {
                    window.setTimeout(() => {
                      onClose();
                      void handleClearAll();
                    }, RIPPLE_ACTION_DELAY_MS);
                  }}
                  className="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-neutral-btn h-auto min-w-0"
                  size="sm"
                >
                  Clear
                </Button>
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </Modal>
    </div>
  );
}
