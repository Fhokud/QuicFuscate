import { useAtomValue, useSetAtom } from "jotai";
import { Btn } from "@/components/ui/controls";
import { AppDialog, AppDialogBody, AppDialogContent, AppDialogFooter, AppDialogHeader } from "@/components/ui/app-dialog";
import { confirmDialogAtom, resolveConfirmAtom } from "@/stores/confirmDialogAtom";
const RIPPLE_ACTION_DELAY_MS = 88;

export function ConfirmDialogHost() {
  const dialog = useAtomValue(confirmDialogAtom);
  const resolveConfirm = useSetAtom(resolveConfirmAtom);

  return (
    <AppDialog
      isOpen={dialog.open}
      onOpenChange={(open) => {
        if (!open) resolveConfirm(false);
      }}
    >
      <AppDialogContent>
        <AppDialogHeader>
          {dialog.title}
        </AppDialogHeader>
        <AppDialogBody>
          <div className="text-[12px] text-black">{dialog.message}</div>
        </AppDialogBody>
        <AppDialogFooter>
          <Btn
            type="button"
            variant="ghost"
            onClick={() => {
              window.setTimeout(() => resolveConfirm(false), RIPPLE_ACTION_DELAY_MS);
            }}
          >
            {dialog.cancelLabel}
          </Btn>
          <Btn
            type="button"
            variant="accent"
            onClick={() => {
              window.setTimeout(() => resolveConfirm(true), RIPPLE_ACTION_DELAY_MS);
            }}
          >
            {dialog.confirmLabel}
          </Btn>
        </AppDialogFooter>
      </AppDialogContent>
    </AppDialog>
  );
}
