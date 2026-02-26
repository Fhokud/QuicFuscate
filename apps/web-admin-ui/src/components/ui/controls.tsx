import { useId } from "react";
import { motion } from "framer-motion";
import { Button as HeroButton } from "@heroui/react";
import type { ButtonProps as HeroButtonProps } from "@heroui/react";
import { cn } from "@/lib/cn";

const glassIndicator = {
  background: "rgba(255,255,255,0.65)",
  backdropFilter: "blur(24px) saturate(200%)",
  WebkitBackdropFilter: "blur(24px) saturate(200%)",
  border: "1px solid rgba(255,255,255,0.60)",
  boxShadow: "inset 0 1px 0.5px rgba(255,255,255,0.55), 0 3px 10px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.03)",
};
const glassSpring = { type: "spring" as const, stiffness: 420, damping: 34 };

/* Segmented Control */
interface SegmentedProps<T extends string> {
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
  className?: string;
  name?: string;
}

export function Segmented<T extends string>({ value, options, onChange, className, name = "seg" }: SegmentedProps<T>) {
  return (
    <div className={cn("inline-flex rounded-lg bg-surface-3 p-[3px] gap-[2px]", className)}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => onChange(o.value)}
          className={cn(
            "relative px-3 py-1 rounded-md text-[11px] font-medium transition-colors duration-150 cursor-pointer",
            value === o.value ? "text-text-primary" : "text-text-tertiary",
          )}
        >
          {value === o.value && (
            <motion.div
              layoutId={`seg-glass-${name}`}
              className="absolute inset-0 rounded-md"
              style={glassIndicator}
              transition={glassSpring}
            />
          )}
          <span className="relative z-10">{o.label}</span>
        </button>
      ))}
    </div>
  );
}

/* Pill Toggle (binary) */
interface PillToggleProps {
  value: string;
  options: [string, string];
  labels: [string, string];
  onChange: (v: string) => void;
  name?: string;
}

export function PillToggle({ value, options, labels, onChange, name = "pill" }: PillToggleProps) {
  return (
    <div className="inline-flex rounded-lg bg-surface-3 p-[3px] gap-[2px]">
      {options.map((o, i) => (
        <button
          key={o}
          type="button"
          onClick={() => onChange(o)}
          className={cn(
            "relative px-3 py-1 rounded-md text-[11px] font-medium transition-colors duration-150 cursor-pointer",
            value === o ? "text-text-primary" : "text-text-tertiary",
          )}
        >
          {value === o && (
            <motion.div
              layoutId={`pill-glass-${name}`}
              className="absolute inset-0 rounded-md"
              style={glassIndicator}
              transition={glassSpring}
            />
          )}
          <span className="relative z-10">{labels[i]}</span>
        </button>
      ))}
    </div>
  );
}

/* Toggle Switch */
interface ToggleProps {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: string;
  disabled?: boolean;
}

export function Toggle({ checked, onChange, label, disabled }: ToggleProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        "relative inline-flex h-[18px] w-[32px] shrink-0 rounded-full transition-[background-color,box-shadow] duration-260 ease-[cubic-bezier(0.22,1,0.36,1)] cursor-pointer overflow-hidden",
        checked
          ? "bg-accent shadow-[inset_0_1px_0_rgba(255,255,255,0.22),0_0_0_1px_rgba(99,102,241,0.28)]"
          : "bg-surface-4 shadow-[inset_0_1px_2px_rgba(0,0,0,0.08)]",
        disabled && "opacity-35 cursor-not-allowed",
      )}
    >
      <span
        className={cn(
          "absolute top-[2px] h-[14px] w-[14px] rounded-full bg-white transition-transform duration-260 ease-[cubic-bezier(0.22,1,0.36,1)] will-change-transform",
          checked ? "translate-x-[16px]" : "translate-x-[2px]",
        )}
        style={{ boxShadow: "0 1px 3px rgba(0,0,0,0.16), inset 0 1px 0 rgba(255,255,255,0.58)" }}
      />
    </button>
  );
}

/* Btn */
interface BtnProps extends Omit<HeroButtonProps, "variant" | "size" | "isDisabled"> {
  variant?: "accent" | "secondary" | "neutral" | "danger" | "copy" | "ghost";
  size?: "sm" | "md";
  loading?: boolean;
  disabled?: boolean;
}

export function Btn({ variant = "secondary", size = "sm", loading, disabled, className, children, ...props }: BtnProps) {
  const base = "qf-ripple-lock action-btn-base inline-flex items-center justify-center font-medium";
  const interaction = disabled ? "opacity-35 cursor-not-allowed" : loading ? "cursor-wait" : "cursor-pointer";
  const sz = size === "sm" ? "h-7 px-3 text-[11px] gap-1.5" : "h-8 px-4 text-[12px] gap-2";
  const variants = {
    accent: "action-save-btn",
    secondary: "action-refresh-btn",
    neutral: "action-neutral-btn",
    danger: "action-revoke-btn",
    copy: "action-copy-btn",
    ghost: "action-refresh-btn",
  };
  return (
    <HeroButton
      {...props}
      isDisabled={disabled || loading}
      disableAnimation={false}
      disableRipple={false}
      className={cn(base, interaction, sz, variants[variant], className)}
    >
      {loading && <span className="h-3 w-3 border-2 border-current border-t-transparent rounded-full animate-spin" />}
      {children}
    </HeroButton>
  );
}

/* TextInput */
interface TextInputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "onChange"> {
  label?: string;
  onChange?: (v: string) => void;
  error?: string | null;
  labelClassName?: string;
}

export function TextInput({ label, onChange, className, error, labelClassName, ...props }: TextInputProps) {
  const generatedId = useId();
  const id = props.id ?? generatedId;
  void error;
  return (
    <div className={cn("flex flex-col gap-1", className)}>
      {label && (
        <label
          htmlFor={id}
          className={cn(
            "text-[10px] tracking-wider text-text-ghost font-medium",
            labelClassName,
          )}
        >
          {label}
        </label>
      )}
      <input
        {...props}
        id={id}
        onChange={(e) => onChange?.(e.target.value)}
        className={cn(
          // Inputs need stronger edge contrast, especially inside translucent modals.
          "h-8 px-3 rounded-md text-[12px] bg-surface-2 border border-edge-hover text-text-primary",
          "shadow-[inset_0_1px_0_rgba(255,255,255,0.45),0_1px_2px_rgba(0,0,0,0.05)]",
          "placeholder:text-text-ghost/70",
          "focus:border-accent focus:outline-none",
          "transition-all duration-120",
        )}
      />
    </div>
  );
}
