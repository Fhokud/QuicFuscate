<script lang="ts">
  import { cn } from "@quicfuscate/ui";

  interface Props {
    id?: string;
    label?: string;
    value?: string;
    type?: string;
    name?: string;
    maxLength?: number;
    autoComplete?: HTMLInputElement["autocomplete"];
    autoFocus?: boolean;
    error?: string | null;
    ariaInvalid?: boolean;
    labelClassName?: string;
    className?: string;
    inputMode?: "search" | "text" | "none" | "tel" | "url" | "email" | "numeric" | "decimal";
    disabled?: boolean;
    onchange?: (v: string) => void;
    onkeydown?: (e: KeyboardEvent) => void;
  }

  let {
    id,
    label,
    value = "",
    type = "text",
    name,
    maxLength,
    autoComplete,
    autoFocus = false,
    error,
    ariaInvalid,
    labelClassName,
    className,
    inputMode,
    disabled = false,
    onchange,
    onkeydown,
  }: Props = $props();
  let inputEl: HTMLInputElement | null = null;

  function slugifyInputId(value: string): string {
    return value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
  }

  const inputId = $derived.by(() => {
    if (id?.trim()) return id.trim();
    const base = name ?? label ?? "input";
    const slug = slugifyInputId(base);
    return slug ? `input-${slug}` : "input-field";
  });

  $effect(() => {
    if (!autoFocus || disabled || !inputEl) return;
    const frame = window.requestAnimationFrame(() => {
      inputEl?.focus();
      inputEl?.select();
    });
    return () => {
      window.cancelAnimationFrame(frame);
    };
  });
</script>

<div class={cn("flex flex-col gap-1", className)}>
  {#if label}
    <label
      for={inputId}
      class={cn(
        "text-[10px] tracking-wider text-text-ghost font-medium",
        labelClassName,
      )}
    >
      {label}
    </label>
  {/if}
  <input
    bind:this={inputEl}
    id={inputId}
    {type}
    {name}
    {value}
    {disabled}
    maxlength={maxLength}
    autocomplete={autoComplete}
    inputmode={inputMode}
    aria-invalid={ariaInvalid || undefined}
    class={cn(
      "h-8 px-3 rounded-md text-[12px] bg-surface-2 border border-edge-hover text-text-primary",
      "shadow-[inset_0_1px_0_rgba(255,255,255,0.45),0_1px_2px_rgba(0,0,0,0.05)]",
      "placeholder:text-text-ghost/70",
      "focus:border-accent focus:outline-none",
      "transition-all duration-120",
    )}
    oninput={(e) => onchange?.((e.target as HTMLInputElement).value)}
    onkeydown={(e) => onkeydown?.(e)}
  />
</div>
