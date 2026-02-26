import { atom } from "jotai";

export interface ConfirmDialogRequest {
  title?: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
}

interface ConfirmDialogState {
  open: boolean;
  title: string;
  message: string;
  confirmLabel: string;
  cancelLabel: string;
}

const DEFAULT_STATE: ConfirmDialogState = {
  open: false,
  title: "Please Confirm",
  message: "",
  confirmLabel: "Confirm",
  cancelLabel: "Cancel",
};

let pendingResolver: ((value: boolean) => void) | null = null;

export const confirmDialogAtom = atom<ConfirmDialogState>(DEFAULT_STATE);

export const requestConfirmAtom = atom(null, (_get, set, req: ConfirmDialogRequest) => {
  return new Promise<boolean>((resolve) => {
    if (pendingResolver) {
      pendingResolver(false);
      pendingResolver = null;
    }
    pendingResolver = resolve;
    set(confirmDialogAtom, {
      open: true,
      title: req.title?.trim() ? req.title.trim() : "Please Confirm",
      message: req.message,
      confirmLabel: req.confirmLabel?.trim() ? req.confirmLabel.trim() : "Confirm",
      cancelLabel: req.cancelLabel?.trim() ? req.cancelLabel.trim() : "Cancel",
    });
  });
});

export const resolveConfirmAtom = atom(null, (_get, set, accepted: boolean) => {
  if (pendingResolver) {
    pendingResolver(accepted);
    pendingResolver = null;
  }
  set(confirmDialogAtom, DEFAULT_STATE);
});
