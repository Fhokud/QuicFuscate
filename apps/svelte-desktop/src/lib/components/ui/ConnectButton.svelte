<script lang="ts">
  import { ripple } from "@quicfuscate/ui";
  import { cn } from "@quicfuscate/ui";

  type ConnectButtonState = "idle" | "connecting" | "connected" | "disconnecting";

  interface Props {
    state: ConnectButtonState;
    onclick: () => void;
    disabled?: boolean;
    hasQKey?: boolean;
    class?: string;
    buttonClass?: string;
    hint?: string;
  }

  let {
    state,
    onclick,
    disabled = false,
    hasQKey = false,
    class: className,
    buttonClass,
    hint,
  }: Props = $props();

  const isBusy = $derived(state === "connecting" || state === "disconnecting");
  const isConnected = $derived(state === "connected");

  const buttonText = $derived(
    state === "connecting" ? "Connecting"
    : state === "disconnecting" ? "Stopping"
    : state === "connected" ? "Disconnect"
    : "Connect"
  );

  const buttonStyle = $derived(isConnected ? "action-disconnect-btn" : "action-save-btn");

  function handleClick() {
    if (isBusy || disabled) return;
    onclick();
  }
</script>

<div class={cn("relative inline-flex flex-col items-center", className)}>
  <button
    type="button"
    use:ripple
    onclick={handleClick}
    disabled={isBusy || disabled}
    class={cn(
      "connect-action-btn relative inline-flex items-center justify-center rounded-lg overflow-hidden",
      "border disabled:opacity-40 disabled:cursor-not-allowed overflow-hidden",
      "text-[11px] font-semibold",
      buttonStyle,
      buttonClass,
    )}
    aria-label={isConnected ? "Disconnect" : hasQKey ? "Connect" : "Set QKey"}
  >
    <span>{buttonText}</span>
  </button>

  {#if hint}
    <p class="mt-2 text-[10px] text-text-tertiary text-center max-w-[180px]">
      {hint}
    </p>
  {/if}
</div>
