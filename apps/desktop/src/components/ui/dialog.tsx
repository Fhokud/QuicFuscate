import * as React from "react";
import { Modal, ModalContent, type ModalProps } from "@heroui/react";
import { cn } from "@/lib/utils";
import { useStageModalPortal, withStageModalClassNames } from "@/lib/stage-modal";

type DialogContextValue = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
};

const DialogContext = React.createContext<DialogContextValue | null>(null);
const DialogCloseContext = React.createContext<(() => void) | null>(null);

type DialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: React.ReactNode;
} & Omit<ModalProps, "isOpen" | "onOpenChange" | "children">;

function Dialog({ open, onOpenChange, children, classNames, ...props }: DialogProps) {
  const portalContainer = useStageModalPortal();
  const mergedClassNames = withStageModalClassNames(classNames);

  return (
    <DialogContext.Provider value={{ open, onOpenChange }}>
      <Modal
        isOpen={open}
        onOpenChange={onOpenChange}
        backdrop="blur"
        hideCloseButton
        portalContainer={portalContainer}
        classNames={mergedClassNames}
        {...props}
      >
        {children}
      </Modal>
    </DialogContext.Provider>
  );
}

type DialogTriggerProps = {
  asChild?: boolean;
  children: React.ReactElement<any>;
};

function DialogTrigger({ asChild = false, children }: DialogTriggerProps) {
  const ctx = React.useContext(DialogContext);
  if (!ctx) return children;

  const onClick = (e: any) => {
    (children.props as any)?.onClick?.(e);
    ctx.onOpenChange(true);
  };

  if (asChild) {
    return React.cloneElement(children, { onClick } as any);
  }

  return (
    <button type="button" onClick={onClick}>
      {children}
    </button>
  );
}

type DialogContentProps = React.ComponentPropsWithoutRef<typeof ModalContent> & {
  children: React.ReactNode;
};

const DialogContent = React.forwardRef<HTMLDivElement, DialogContentProps>(
  ({ className, children, ...props }, _ref) => (
    <ModalContent
      className={cn(
        "w-full max-w-[420px] glass border border-edge shadow-xl rounded-[18px] dialog-typography dialog-surface",
        className,
      )}
      {...props}
    >
      {(onClose) => (
        <DialogCloseContext.Provider value={onClose}>
          <div>{children}</div>
        </DialogCloseContext.Provider>
      )}
    </ModalContent>
  ),
);
DialogContent.displayName = "DialogContent";

const DialogHeader = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn("dialog-header-pad", className)} {...props} />
);

const DialogTitle = React.forwardRef<HTMLHeadingElement, React.HTMLAttributes<HTMLHeadingElement>>(
  ({ className, ...props }, ref) => (
    <h2
      ref={ref}
      className={cn("text-[13px] font-semibold text-black dashboard-heading-sans", className)}
      {...props}
    />
  ),
);
DialogTitle.displayName = "DialogTitle";

const DialogDescription = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLParagraphElement>>(
  ({ className, ...props }, ref) => (
    <p
      ref={ref}
      className={cn("text-[12px] text-black mt-1", className)}
      {...props}
    />
  ),
);
DialogDescription.displayName = "DialogDescription";

const DialogFooter = ({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
  <div className={cn("dialog-footer-pad flex justify-end", className)} {...props} />
);

type DialogCloseProps = {
  asChild?: boolean;
  children: React.ReactElement<any>;
};

function DialogClose({ asChild = false, children }: DialogCloseProps) {
  const onClose = React.useContext(DialogCloseContext);
  if (!onClose) return children;

  const onClick = (e: any) => {
    (children.props as any)?.onClick?.(e);
    onClose();
  };

  if (asChild) {
    return React.cloneElement(children, { onClick } as any);
  }

  return (
    <button type="button" onClick={onClick}>
      {children}
    </button>
  );
}

// HeroUI handles portal and overlay internally. Kept for compatibility.
const DialogPortal = ({ children }: { children: React.ReactNode }) => <>{children}</>;
const DialogOverlay = () => null;

export {
  Dialog,
  DialogTrigger,
  DialogContent,
  DialogHeader,
  DialogFooter,
  DialogTitle,
  DialogDescription,
  DialogClose,
  DialogPortal,
  DialogOverlay,
};
