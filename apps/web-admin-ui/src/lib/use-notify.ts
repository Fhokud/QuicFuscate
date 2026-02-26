import { useCallback, useMemo } from "react";
import { useSetAtom } from "jotai";
import { addToastAtom } from "@/stores/toastAtom";

type NotifyType = "success" | "error" | "warning" | "info";

export function useNotify() {
  const addToast = useSetAtom(addToastAtom);

  const push = useCallback((type: NotifyType, message: string, duration?: number) => {
    addToast({ type, message, duration });
  }, [addToast]);

  const info = useCallback((message: string, duration?: number) => {
    push("info", message, duration);
  }, [push]);

  const success = useCallback((message: string, duration?: number) => {
    push("success", message, duration);
  }, [push]);

  const warning = useCallback((message: string, duration?: number) => {
    push("warning", message, duration);
  }, [push]);

  const error = useCallback((message: string, duration?: number) => {
    push("error", message, duration);
  }, [push]);

  return useMemo(() => ({
    push,
    info,
    success,
    warning,
    error,
  }), [error, info, push, success, warning]);
}
