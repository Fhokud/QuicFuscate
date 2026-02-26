import { Modal, ModalContent, ModalHeader, ModalBody, ModalFooter } from "@heroui/react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useStageModalPortal, withStageModalClassNames } from "@/lib/stage-modal";
const RIPPLE_ACTION_DELAY_MS = 88;

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: "default" | "danger";
  onConfirm: () => void;
  onCancel: () => void;
  loading?: boolean;
}

export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  variant = "default",
  onConfirm,
  onCancel,
  loading = false,
}: ConfirmDialogProps) {
  const portalContainer = useStageModalPortal();

  return (
    <Modal
      isOpen={open}
      onClose={onCancel}
      backdrop="blur"
      hideCloseButton
      size="sm"
      portalContainer={portalContainer}
      classNames={withStageModalClassNames()}
    >
      <ModalContent className="glass border border-edge shadow-xl rounded-[18px] dialog-typography dialog-surface">
        {() => (
          <>
            <ModalHeader className="dialog-header-pad flex flex-col gap-1">
              <div className="text-[13px] font-semibold text-black dashboard-heading-sans">{title}</div>
            </ModalHeader>
            <ModalBody className="dialog-body-pad">
              <p className="text-[12px] text-black leading-relaxed">{message}</p>
            </ModalBody>
            <ModalFooter className="dialog-footer-pad">
              <Button
                type="button"
                onClick={() => {
                  window.setTimeout(onCancel, RIPPLE_ACTION_DELAY_MS);
                }}
                disabled={loading}
                className="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-refresh-btn disabled:opacity-55"
              >
                {cancelLabel}
              </Button>
              <Button
                type="button"
                onClick={() => {
                  window.setTimeout(onConfirm, RIPPLE_ACTION_DELAY_MS);
                }}
                disabled={loading}
                className={cn(
                  "inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all disabled:opacity-55",
                  variant === "danger" ? "action-disconnect-btn" : "action-save-btn",
                )}
              >
                {loading ? "..." : confirmLabel}
              </Button>
            </ModalFooter>
          </>
        )}
      </ModalContent>
    </Modal>
  );
}
