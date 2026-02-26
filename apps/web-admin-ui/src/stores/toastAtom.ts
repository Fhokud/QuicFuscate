import { atom } from "jotai";

export type ToastType = "success" | "error" | "warning" | "info";

export interface Toast {
  id: string;
  type: ToastType;
  message: string;
  duration?: number;
}

export interface ToastAnchor {
  x: number;
  y: number;
}

export const toastsAtom = atom<Toast[]>([]);
export const toastAnchorAtom = atom<ToastAnchor | null>(null);

export const addToastAtom = atom(null, (_get, set, toast: Omit<Toast, "id">) => {
  const id = crypto.randomUUID();
  const duration = toast.duration ?? 1500;
  set(toastsAtom, [{ ...toast, id }]);
  setTimeout(() => {
    set(toastsAtom, (prev) => (prev.length === 1 && prev[0]?.id === id ? [] : prev.filter((t) => t.id !== id)));
  }, duration);
});

export const removeToastAtom = atom(null, (get, set, id: string) => {
  set(toastsAtom, get(toastsAtom).filter((t) => t.id !== id));
});

export const setToastAnchorAtom = atom(null, (_get, set, anchor: ToastAnchor | null) => {
  set(toastAnchorAtom, anchor);
});
