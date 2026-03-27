<script lang="ts">
  import ErrorBoundary from "../../../../../../../../packages/ui/ErrorBoundary.svelte";
  import ThrowingChild from "./throwing-child.svelte";
</script>

{#snippet fallback(error: unknown, reset: () => void)}
  <div>
    <p>caught:{String(error)}</p>
    <button type="button" onclick={reset}>Reset</button>
  </div>
{/snippet}

<ErrorBoundary fallback={fallback}>
  <ThrowingChild />
</ErrorBoundary>
