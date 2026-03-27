<script lang="ts">
  import { cn } from "./cn";

  interface Props {
    checked?: boolean;
    disabled?: boolean;
    onchange?: (checked: boolean) => void;
    class?: string;
    label?: string;
  }

  let { checked = false, disabled = false, onchange, class: className, label }: Props = $props();
</script>

<button
  type="button"
  role="switch"
  aria-checked={checked}
  aria-label={label ?? "Toggle"}
  {disabled}
  onclick={() => { if (!disabled) onchange?.(!checked); }}
  class={cn(
    "relative inline-flex h-[18px] w-[32px] shrink-0 rounded-full transition-[background-color,box-shadow] duration-260 ease-[cubic-bezier(0.22,1,0.36,1)] cursor-pointer overflow-hidden",
    checked
      ? "bg-accent shadow-[inset_0_1px_0_rgba(255,255,255,0.22),0_0_0_1px_rgba(99,102,241,0.28)]"
      : "bg-surface-4 shadow-[inset_0_1px_2px_rgba(0,0,0,0.08)]",
    disabled && "opacity-35 cursor-not-allowed",
    className,
  )}
>
  <span
    class={cn(
      "absolute top-[2px] h-[14px] w-[14px] rounded-full bg-white transition-transform duration-260 ease-[cubic-bezier(0.22,1,0.36,1)] will-change-transform",
      checked ? "translate-x-[16px]" : "translate-x-[2px]",
    )}
    style="box-shadow: 0 1px 3px rgba(0,0,0,0.16), inset 0 1px 0 rgba(255,255,255,0.58);"
  ></span>
</button>
