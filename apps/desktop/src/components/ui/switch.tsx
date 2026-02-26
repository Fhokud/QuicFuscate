import * as React from "react";
import { cn } from "@/lib/utils";

interface SwitchProps {
  checked?: boolean;
  onCheckedChange?: (checked: boolean) => void;
  disabled?: boolean;
  className?: string;
}

const Switch = React.forwardRef<HTMLButtonElement, SwitchProps>(
  ({ className, checked, onCheckedChange, disabled, ...props }, ref) => (
    <button
      ref={ref}
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => !disabled && onCheckedChange?.(!checked)}
      className={cn(
        "relative inline-flex h-[18px] w-[32px] shrink-0 rounded-full transition-[box-shadow] duration-200 ease-[cubic-bezier(0.34,1.56,0.64,1)] cursor-pointer overflow-hidden",
        "bg-surface-4",
        checked ? "shadow-none" : "shadow-[inset_0_1px_2px_rgba(0,0,0,0.08)]",
        disabled && "opacity-35 cursor-not-allowed",
        className,
      )}
      {...props}
    >
      <span
        className={cn(
          "pointer-events-none absolute inset-0 rounded-full bg-accent origin-left transition-transform duration-200 ease-[cubic-bezier(0.34,1.56,0.64,1)] will-change-transform",
          checked ? "scale-x-100" : "scale-x-0",
        )}
      />
      <span
        className={cn(
          "absolute top-[2px] h-[14px] w-[14px] rounded-full bg-white transition-transform duration-200 ease-[cubic-bezier(0.34,1.56,0.64,1)] will-change-transform",
          checked ? "translate-x-[16px]" : "translate-x-[2px]",
        )}
        style={{ boxShadow: "0 1px 3px rgba(0,0,0,0.15)" }}
      />
    </button>
  ),
);
Switch.displayName = "Switch";

export { Switch };
