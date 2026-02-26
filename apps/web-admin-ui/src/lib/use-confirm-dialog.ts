import { useCallback } from "react";
import { useSetAtom } from "jotai";
import { requestConfirmAtom } from "@/stores/confirmDialogAtom";
import type { ConfirmDialogRequest } from "@/stores/confirmDialogAtom";

export function useConfirmDialog() {
  const requestConfirm = useSetAtom(requestConfirmAtom);
  return useCallback((request: ConfirmDialogRequest) => requestConfirm(request), [requestConfirm]);
}
