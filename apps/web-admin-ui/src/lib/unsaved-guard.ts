import type { ConfirmDialogRequest } from "@/stores/confirmDialogAtom";

export type UnsavedScope = "configuration" | "logging" | "configuration and logging";
export type UnsavedAction = "refresh" | "leave" | "reload" | "close";

export function detectUnsavedScope(configDirty: boolean, logsDirty: boolean): UnsavedScope | null {
  if (configDirty && logsDirty) return "configuration and logging";
  if (configDirty) return "configuration";
  if (logsDirty) return "logging";
  return null;
}

export function buildUnsavedConfirm(scope: UnsavedScope, action: UnsavedAction): ConfirmDialogRequest {
  const actionText = action === "refresh"
    ? "Refresh and discard them?"
    : action === "leave"
      ? "Leave without saving?"
      : action === "reload"
        ? "Reload and discard them?"
        : "Close and discard them?";
  const confirmLabel = action === "refresh"
    ? "Discard"
    : action === "leave"
      ? "Leave"
      : action === "reload"
        ? "Reload"
        : "Close";

  return {
    title: "Unsaved Changes",
    message: `You have unsaved ${scope} changes. ${actionText}`,
    confirmLabel,
    cancelLabel: "Cancel",
  };
}
