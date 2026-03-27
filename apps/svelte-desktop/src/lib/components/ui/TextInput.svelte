<script lang="ts">
  import { cn } from "@quicfuscate/ui";

  interface Props {
    value: string;
    oninput: (value: string) => void;
    id?: string;
    maxlength?: number;
    placeholder?: string;
    class?: string;
    element?: HTMLInputElement | null;
  }

  let {
    value,
    oninput,
    id,
    maxlength,
    placeholder,
    class: className,
    element = $bindable(null),
  }: Props = $props();
</script>

<input
  bind:this={element}
  type="text"
  {id}
  {value}
  {maxlength}
  {placeholder}
  oninput={(e) => {
    const v = (e.target as HTMLInputElement).value;
    oninput(maxlength ? v.slice(0, maxlength) : v);
  }}
  class={cn(
    "h-8 w-full px-3 rounded-md",
    "glass-nav-pill glass-select-edge",
    "text-[11px] text-black",
    "placeholder:text-black/40",
    "outline-none focus:outline-none",
    "focus:border-edge-accent",
    "transition-colors",
    className,
  )}
/>
