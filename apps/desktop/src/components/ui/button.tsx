import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Button as HeroButton } from "@heroui/react";
import type { ButtonProps as HeroButtonProps } from "@heroui/react";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "qf-ripple-lock relative isolate overflow-hidden inline-flex items-center justify-center gap-2 whitespace-nowrap border text-[11px] font-semibold cursor-pointer disabled:pointer-events-none disabled:opacity-55 focus-visible:outline-none",
  {
    variants: {
      variant: {
        default: "action-save-btn",
        secondary: "action-refresh-btn",
        neutral: "action-neutral-btn",
        ghost: "glass-pane-pill border-edge text-text-primary",
        danger: "action-revoke-btn",
        outline: "glass-pane-pill border-edge text-text-primary",
      },
      size: {
        default: "h-8 px-3",
        sm: "h-7 px-2.5",
        lg: "h-10 px-5 text-[14px]",
        icon: "h-8 w-8",
        "icon-sm": "h-7 w-7",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

export interface ButtonProps
  extends Omit<HeroButtonProps, "variant" | "size" | "isDisabled">,
    VariantProps<typeof buttonVariants> {
  disabled?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, disabled, ...props }, ref) => (
    <HeroButton
      {...props}
      className={cn(buttonVariants({ variant, size, className }))}
      isDisabled={disabled}
      disableAnimation={false}
      disableRipple={false}
      ref={ref}
    />
  ),
);
Button.displayName = "Button";

export { Button, buttonVariants };
