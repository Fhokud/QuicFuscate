<script lang="ts">
  import type { Snippet } from "svelte";

  interface Props {
    label: string;
    description?: string;
    children: Snippet;
  }

  let { label, description, children }: Props = $props();
</script>

<div class="flex items-center justify-between gap-4 py-2.5">
  <div class="flex-1 min-w-0">
    <div class="text-[13px] font-medium text-text-primary">{label}</div>
    {#if description}
      <div class="text-[11px] text-text-tertiary mt-0.5">{description}</div>
    {/if}
  </div>
  <div class="flex-shrink-0">
    {@render children()}
  </div>
</div>
