import React from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Check } from "lucide-react";
import { Btn } from "@/components/ui/controls";

type Props = {
  children: React.ReactNode;
};

type State = {
  hasError: boolean;
  message?: string;
  details?: string;
  copied?: boolean;
};

export class ErrorBoundary extends React.Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(err: unknown): State {
    return { hasError: true, message: err instanceof Error ? err.message : String(err) };
  }

  componentDidCatch(err: unknown, info: React.ErrorInfo) {
    // Keep this minimal: logging is useful, but we do not want noisy telemetry here.
    console.error("Web Admin UI crashed:", err);
    const e = err instanceof Error ? err : new Error(String(err));
    const details = [
      `message: ${e.message}`,
      e.stack ? `stack:\n${e.stack}` : null,
      info.componentStack ? `componentStack:\n${info.componentStack}` : null,
    ]
      .filter(Boolean)
      .join("\n\n");
    this.setState({ details });
  }

  render() {
    if (!this.state.hasError) return this.props.children;

    return (
      <div className="min-h-screen w-full flex items-center justify-center bg-transparent px-6">
        <div className="w-full max-w-md rounded-2xl glass p-6">
          <div className="text-[14px] font-semibold text-text-primary">Something went wrong</div>
          <div className="mt-2 text-[11px] text-text-secondary leading-relaxed">
            The UI crashed unexpectedly. Reload the page. If this keeps happening, check server logs.
          </div>
          {(this.state.details || this.state.message) && (
            <pre className="mt-4 text-[10px] text-text-tertiary whitespace-pre-wrap break-words rounded-lg glass-subtle p-3 mono">
              {this.state.details ?? this.state.message}
            </pre>
          )}
          <div className="mt-4 flex items-center justify-between gap-3">
            <div className="text-[10px] text-text-ghost">
              {this.state.copied ? "Copied" : null}
            </div>
            <div className="flex items-center gap-2">
              <Btn
                variant="copy"
                onClick={async () => {
                  const text = this.state.details ?? this.state.message ?? "unknown error";
                  try {
                    await navigator.clipboard.writeText(text);
                    this.setState({ copied: true });
                    window.setTimeout(() => this.setState({ copied: false }), 1100);
                  } catch {
                    // Best-effort.
                  }
                }}
              >
                <span className="relative z-10 inline-grid place-items-center">
                  <span className="invisible">Copy details</span>
                  <AnimatePresence initial={false} mode="wait">
                    {this.state.copied ? (
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
                        Copy details
                      </motion.span>
                    )}
                  </AnimatePresence>
                </span>
              </Btn>
              <Btn
                type="button"
                variant="neutral"
                onClick={() => window.location.reload()}
              >
                Reload
              </Btn>
            </div>
          </div>
        </div>
      </div>
    );
  }
}
