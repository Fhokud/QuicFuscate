<script lang="ts">
  import { goto } from "$app/navigation";
  import FatalErrorScreen from "$lib/components/ui/FatalErrorScreen.svelte";

  interface Props {
    error: unknown;
    status: number;
  }

  let { error, status }: Props = $props();

  function stringifyError(value: unknown): string {
    if (value instanceof Error) {
      return [value.name, value.message, value.stack].filter(Boolean).join("\n\n");
    }
    if (typeof value === "string") return value;
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }

  const details = $derived.by(() => {
    const lines = [
      `Admin UI crashed with HTTP ${status}.`,
      stringifyError(error),
    ];
    return lines.filter(Boolean).join("\n\n");
  });
</script>

<FatalErrorScreen
  title="Something went wrong"
  description="An unexpected admin UI error occurred. Retry the page, copy the details, or reload the app."
  details={details}
  onretry={() => { void goto("/"); }}
  onreload={() => { window.location.reload(); }}
/>
