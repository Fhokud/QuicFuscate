import type { ReactNode } from "react";
import type { ComponentProps } from "react";
import { Modal, ModalBody, ModalContent, ModalFooter, ModalHeader } from "@heroui/react";
import { cn } from "@/lib/cn";
import { useStageModalPortal } from "@/lib/use-stage-modal-portal";

type ModalProps = ComponentProps<typeof Modal>;
type ModalContentProps = ComponentProps<typeof ModalContent>;
type ModalHeaderProps = ComponentProps<typeof ModalHeader>;
type ModalBodyProps = ComponentProps<typeof ModalBody>;
type ModalFooterProps = ComponentProps<typeof ModalFooter>;

const APP_DIALOG_CONTENT = "glass border border-edge shadow-xl rounded-[18px] dialog-typography dialog-surface dashboard-heading-sans";
const APP_DIALOG_HEADER = "dialog-header-pad text-[13px] font-semibold text-black dashboard-heading-sans";
const APP_DIALOG_BODY = "dialog-body-pad overflow-y-auto";
const APP_DIALOG_FOOTER = "dialog-footer-pad";
const APP_DIALOG_WRAPPER = "qf-stage-modal-wrapper";
const APP_DIALOG_BACKDROP = "qf-stage-modal-backdrop";

export function AppDialog({
  placement = "center",
  size = "md",
  backdrop = "blur",
  hideCloseButton = true,
  scrollBehavior = "inside",
  classNames,
  children,
  ...rest
}: ModalProps & { children: ReactNode }) {
  const portalContainer = useStageModalPortal();

  return (
    <Modal
      placement={placement}
      size={size}
      backdrop={backdrop}
      hideCloseButton={hideCloseButton}
      scrollBehavior={scrollBehavior}
      portalContainer={portalContainer}
      classNames={{
        ...classNames,
        wrapper: cn(APP_DIALOG_WRAPPER, classNames?.wrapper),
        backdrop: cn(APP_DIALOG_BACKDROP, classNames?.backdrop),
      }}
      {...rest}
    >
      {children}
    </Modal>
  );
}

export function AppDialogContent({ className, ...props }: ModalContentProps) {
  return <ModalContent className={cn(APP_DIALOG_CONTENT, className)} {...props} />;
}

export function AppDialogHeader({ className, ...props }: ModalHeaderProps) {
  return <ModalHeader className={cn(APP_DIALOG_HEADER, className)} {...props} />;
}

export function AppDialogBody({ className, ...props }: ModalBodyProps) {
  return <ModalBody className={cn(APP_DIALOG_BODY, className)} {...props} />;
}

export function AppDialogFooter({ className, ...props }: ModalFooterProps) {
  return <ModalFooter className={cn(APP_DIALOG_FOOTER, className)} {...props} />;
}
