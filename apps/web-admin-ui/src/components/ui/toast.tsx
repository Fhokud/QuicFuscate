import { useAtomValue } from "jotai";
import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useState } from "react";
import type { CSSProperties } from "react";
import { toastAnchorAtom, toastsAtom, type ToastAnchor } from "@/stores/toastAtom";

type Tone = {
  color: string;
  border: string;
  background: string;
  shadow: string;
  edge: string;
  sheen: string;
};

const TONES: Record<"info" | "success" | "error" | "warning", Tone> = {
  info: {
    color: "rgba(63, 82, 214, 1)",
    border: "rgba(98, 118, 252, 0.44)",
    background: "linear-gradient(180deg, rgba(149, 176, 255, 0.18) 0%, rgba(149, 176, 255, 0.09) 100%)",
    shadow: "0 12px 24px rgba(86, 109, 241, 0.18), inset 0 1px 0 rgba(255,255,255,0.36)",
    edge: "linear-gradient(90deg, rgba(86, 109, 241, 0.00) 0%, rgba(86, 109, 241, 0.30) 45%, rgba(86, 109, 241, 0.00) 100%)",
    sheen: "linear-gradient(104deg, rgba(255,255,255,0.00) 22%, rgba(255,255,255,0.34) 48%, rgba(255,255,255,0.00) 72%)",
  },
  success: {
    color: "rgba(18, 145, 90, 1)",
    border: "rgba(35, 181, 118, 0.46)",
    background: "linear-gradient(180deg, rgba(108, 231, 170, 0.18) 0%, rgba(108, 231, 170, 0.09) 100%)",
    shadow: "0 12px 24px rgba(34, 166, 111, 0.17), inset 0 1px 0 rgba(255,255,255,0.36)",
    edge: "linear-gradient(90deg, rgba(34, 166, 111, 0.00) 0%, rgba(34, 166, 111, 0.28) 45%, rgba(34, 166, 111, 0.00) 100%)",
    sheen: "linear-gradient(104deg, rgba(255,255,255,0.00) 22%, rgba(255,255,255,0.30) 48%, rgba(255,255,255,0.00) 72%)",
  },
  error: {
    color: "rgba(205, 42, 78, 1)",
    border: "rgba(233, 78, 115, 0.50)",
    background: "linear-gradient(180deg, rgba(255, 133, 160, 0.20) 0%, rgba(255, 133, 160, 0.10) 100%)",
    shadow: "0 12px 24px rgba(225, 51, 92, 0.20), inset 0 1px 0 rgba(255,255,255,0.32)",
    edge: "linear-gradient(90deg, rgba(225, 51, 92, 0.00) 0%, rgba(225, 51, 92, 0.30) 45%, rgba(225, 51, 92, 0.00) 100%)",
    sheen: "linear-gradient(104deg, rgba(255,255,255,0.00) 20%, rgba(255,255,255,0.32) 46%, rgba(255,255,255,0.00) 72%)",
  },
  warning: {
    color: "rgba(205, 42, 78, 1)",
    border: "rgba(233, 78, 115, 0.50)",
    background: "linear-gradient(180deg, rgba(255, 133, 160, 0.20) 0%, rgba(255, 133, 160, 0.10) 100%)",
    shadow: "0 12px 24px rgba(225, 51, 92, 0.20), inset 0 1px 0 rgba(255,255,255,0.32)",
    edge: "linear-gradient(90deg, rgba(225, 51, 92, 0.00) 0%, rgba(225, 51, 92, 0.30) 45%, rgba(225, 51, 92, 0.00) 100%)",
    sheen: "linear-gradient(104deg, rgba(255,255,255,0.00) 20%, rgba(255,255,255,0.32) 46%, rgba(255,255,255,0.00) 72%)",
  },
};
const TOAST_FADE_EASE = [0.22, 1, 0.36, 1] as const;
const TOAST_FADE_DURATION = 0.42;
const TOAST_SCALE_DURATION = 0.42;
const TOAST_REST_STATE = { scale: 1, filter: "blur(0px)" } as const;
const TOAST_TRANSITION_STATE = { scale: 0.993, filter: "blur(0.35px)" } as const;

export function ToastContainer() {
  const toasts = useAtomValue(toastsAtom);
  const anchor = useAtomValue(toastAnchorAtom);
  const activeToast = toasts.length > 0 ? toasts[toasts.length - 1] : null;
  const [lockedToast, setLockedToast] = useState<{ id: string; anchor: ToastAnchor | null } | null>(null);

  useEffect(() => {
    if (!activeToast) {
      setLockedToast(null);
      return;
    }
    setLockedToast((prev) => {
      if (prev?.id === activeToast.id) {
        return prev;
      }
      return { id: activeToast.id, anchor: anchor ?? null };
    });
  }, [activeToast, anchor]);

  const effectiveAnchor = lockedToast?.anchor ?? anchor;
  const role: "alert" | "status" = activeToast?.type === "error" ? "alert" : "status";
  const tone = activeToast ? TONES[activeToast.type] : TONES.info;

  const overlayStyle: CSSProperties = effectiveAnchor
    ? {
        left: `${effectiveAnchor.x}px`,
        top: `${effectiveAnchor.y}px`,
        transform: "translate(-50%, -50%)",
      }
    : {
        left: "50%",
        top: "42px",
        transform: "translate(-50%, 0)",
      };

  return (
    <div
      data-testid="toast-container"
      role="region"
      aria-label="Notifications"
      aria-live="polite"
      aria-atomic="true"
      className="qf-notify-host fixed z-[120] pointer-events-none"
      style={overlayStyle}
    >
      <AnimatePresence mode="wait">
        {activeToast ? (
          <motion.div
            key={activeToast.id}
            data-testid="toast"
            role={role}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1, transition: { duration: TOAST_FADE_DURATION, ease: TOAST_FADE_EASE } }}
            exit={{ opacity: 0, transition: { duration: TOAST_FADE_DURATION, ease: TOAST_FADE_EASE } }}
          >
            <motion.div
              className="qf-notify-card relative isolate overflow-hidden inline-flex items-center h-[32px] min-h-[32px] rounded-[11px] px-3.5 dashboard-heading-sans"
              initial={TOAST_TRANSITION_STATE}
              animate={{
                ...TOAST_REST_STATE,
                transition: { duration: TOAST_SCALE_DURATION, ease: TOAST_FADE_EASE },
              }}
              exit={{
                ...TOAST_TRANSITION_STATE,
                transition: { duration: TOAST_SCALE_DURATION, ease: TOAST_FADE_EASE },
              }}
              style={{
                border: `1px solid ${tone.border}`,
                background: tone.background,
                boxShadow: tone.shadow,
              }}
            >
              <span
                aria-hidden="true"
                className="pointer-events-none absolute inset-x-[9px] top-0 h-px"
                style={{ background: tone.edge }}
              />
              <motion.span
                aria-hidden="true"
                className="pointer-events-none absolute inset-0"
                style={{ background: tone.sheen }}
                initial={{ x: "-132%", opacity: 0 }}
                animate={{ x: "132%", opacity: [0, 0.42, 0] }}
                transition={{ duration: 0.64, ease: [0.18, 1, 0.28, 1], delay: 0.04 }}
              />
              <span
                data-testid="toast-message"
                className="qf-notify-text relative z-[1] whitespace-nowrap text-[11px] font-semibold tracking-[-0.01em] leading-none"
                style={{ ["--qf-notify-color" as any]: tone.color }}
              >
                {activeToast.message}
              </span>
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
}
