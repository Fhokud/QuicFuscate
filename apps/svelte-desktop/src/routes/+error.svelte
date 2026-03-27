<script lang="ts">
  import FatalErrorScreen from "$lib/components/ui/FatalErrorScreen.svelte";

  interface Props {
    error: unknown;
    status: number;
  }

  let { error, status }: Props = $props();

  function stringifyError(value: unknown): string {
    if (value instanceof Error) {
      return [value.name, value.message].filter(Boolean).join(": ");
    }
    if (typeof value === "string") return value;
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }

  const details = $derived(`Route error (HTTP ${status}): ${stringifyError(error)}`);
</script>

<FatalErrorScreen
  error={details}
  onretry={() => { window.location.hash = ""; window.location.reload(); }}
/>
