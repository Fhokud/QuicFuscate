<script lang="ts">
  import type { Snippet } from "svelte";

  interface Props {
    children: Snippet;
    fallback?: Snippet<[error: unknown, reset: () => void]>;
  }

  let { children, fallback }: Props = $props();
</script>

<svelte:boundary failed={fallback}>
  {@render children()}
</svelte:boundary>
