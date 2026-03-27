<script lang="ts">
  import { cn } from "./cn";
  import type { Snippet } from "svelte";

  interface Props {
    class?: string;
    variant?: "default" | "subtle" | "strong";
    children: Snippet;
  }

  let { class: className = "", variant = "default", children }: Props = $props();

  const variantClass = $derived(
    variant === "subtle" ? "glass-subtle" : variant === "strong" ? "glass" : "glass"
  );
</script>

<div class={cn(variantClass, "rounded-xl", className)}>
  {@render children()}
</div>
