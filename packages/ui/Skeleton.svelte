<script lang="ts">
  import { cn } from "./cn";

  interface Props {
    class?: string;
    width?: string;
    height?: string;
  }

  let { class: className = "", width, height }: Props = $props();
</script>

<div
  class={cn("animate-pulse rounded-md bg-surface-3", className)}
  style:width
  style:height
  role="status"
  aria-label="Loading"
></div>
