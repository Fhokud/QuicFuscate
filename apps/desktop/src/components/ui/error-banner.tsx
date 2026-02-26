import { motion, AnimatePresence } from "framer-motion";
import { AlertCircle, X } from "lucide-react";
import { Button } from "@/components/ui/button";

interface ErrorBannerProps {
  error: string | Error | null;
  onDismiss: () => void;
}

export function ErrorBanner({ error, onDismiss }: ErrorBannerProps) {
  if (!error) return null;

  return (
    <AnimatePresence>
      <div className="flex justify-center w-full px-6 mb-4">
        <div className="w-full max-w-[500px]">
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.15 }}
            role="alert"
            aria-live="assertive"
            className="relative isolate overflow-hidden flex items-start gap-3 rounded-xl border border-negative/30 bg-negative/5 px-4 py-3 shadow-[0_4px_12px_rgba(220,38,38,0.08)] backdrop-blur-md"
          >
            <AlertCircle className="h-4 w-4 text-negative shrink-0" strokeWidth={2} />
            <span className="text-[12px] text-negative flex-1 break-words">{error.toString()}</span>
            <Button
              type="button"
              aria-label="Dismiss error"
              onClick={onDismiss}
              className="shrink-0 p-1 rounded-md text-negative/60 hover:text-negative hover:bg-negative/10 transition-colors min-w-0 h-auto bg-transparent"
              size="sm"
              isIconOnly
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          </motion.div>
        </div>
      </div>
    </AnimatePresence>
  );
}
