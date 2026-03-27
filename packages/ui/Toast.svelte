<script lang="ts">
  import { getToasts, getAnchor, getToneStyle } from "./toast-store.svelte";
  import { fade } from "svelte/transition";
  import { cubicOut } from "svelte/easing";

  const toasts = $derived(getToasts());
  const anchor = $derived(getAnchor());
  const activeToast = $derived(toasts.length > 0 ? toasts[toasts.length - 1] : null);

  // Lock anchor at the moment a toast appears (prevents jumping if anchor moves)
  let lockedToast = $state<{ id: string; anchor: { x: number; y: number } | null } | null>(null);

  $effect(() => {
    if (!activeToast) { lockedToast = null; return; }
    if (lockedToast?.id === activeToast.id) return;
    lockedToast = { id: activeToast.id, anchor: anchor ?? null };
  });

  const effectiveAnchor = $derived(lockedToast?.anchor ?? anchor);

  const overlayStyle = $derived.by(() => {
    if (effectiveAnchor) {
      return `left:${effectiveAnchor.x}px;top:${effectiveAnchor.y}px;transform:translate(-50%,-50%);`;
    }
    return "left:50%;top:42px;transform:translate(-50%,0);";
  });

  // Sheen animation key - changes on each new toast to re-trigger
  let sheenKey = $state(0);
  let lastToastId = $state("");

  $effect(() => {
    if (activeToast && activeToast.id !== lastToastId) {
      lastToastId = activeToast.id;
      sheenKey += 1;
    }
  });
</script>

<style>
  @keyframes qf-toast-scale-in {
    from { transform: scale(0.993); filter: blur(0.35px); }
    to { transform: scale(1); filter: blur(0px); }
  }
  @keyframes qf-toast-scale-out {
    from { transform: scale(1); filter: blur(0px); }
    to { transform: scale(0.993); filter: blur(0.35px); }
  }
  @keyframes qf-sheen-sweep {
    0% { transform: translateX(-132%); opacity: 0; }
    25% { opacity: 0.42; }
    75% { opacity: 0.42; }
    100% { transform: translateX(132%); opacity: 0; }
  }
  .qf-toast-card-enter {
    animation: qf-toast-scale-in 0.42s cubic-bezier(0.22, 1, 0.36, 1) both;
  }
  .qf-sheen {
    animation: qf-sheen-sweep 0.64s cubic-bezier(0.18, 1, 0.28, 1) 0.04s both;
  }
</style>

<div
  role="region"
  aria-label="Notifications"
  aria-live="polite"
  aria-atomic="true"
  data-testid="toast-container"
  class="qf-notify-host fixed z-[120] pointer-events-none"
  style={overlayStyle}
>
  {#if activeToast}
    {@const tone = getToneStyle(activeToast.tone)}
    <div
      transition:fade={{ duration: 420, easing: cubicOut }}
    >
      <div
        data-testid="toast"
        class="qf-notify-card qf-toast-card-enter relative isolate overflow-hidden inline-flex items-center h-[32px] min-h-[32px] rounded-[11px] px-3.5 dashboard-heading-sans"
        style="
          border: 1px solid {tone.border};
          background: {tone.background};
          box-shadow: {tone.shadow};
        "
      >
        <!-- Top edge line -->
        <span
          aria-hidden="true"
          class="pointer-events-none absolute inset-x-[9px] top-0 h-px"
          style="background: {tone.edge};"
        ></span>
        <!-- Sheen sweep -->
        {#key sheenKey}
          <span
            aria-hidden="true"
            class="pointer-events-none absolute inset-0 qf-sheen"
            style="background: {tone.sheen};"
          ></span>
        {/key}
        <span
          data-testid="toast-message"
          class="qf-notify-text relative z-[1] whitespace-nowrap text-[11px] font-semibold tracking-[-0.01em] leading-none"
          style="--qf-notify-color: {tone.color}; color: {tone.color};"
        >
          {activeToast.message}
        </span>
      </div>
    </div>
  {/if}
</div>
