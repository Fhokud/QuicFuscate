<script lang="ts">
  import { fade, fly } from "svelte/transition";
  import { Check } from "@lucide/svelte";
  import { ConfirmDialog, ripple, createCopyFeedback } from "@quicfuscate/ui";
  import { Skeleton } from "@quicfuscate/ui";
  import { cn } from "@quicfuscate/ui";
  import { formatTimestamp } from "$lib/format";
  import { getLogs, setLogs } from "$lib/stores/app.svelte";
  import { engineLogsClear } from "$lib/stores/tauri-bridge.svelte";

  let scrollRef = $state<HTMLDivElement | null>(null);
  const copyFb = createCopyFeedback(1100);
  let clearDialogOpen = $state(false);

  const logs = $derived(getLogs());
  const entryCountLabel = $derived(logs.length === 1 ? "1 entry" : `${logs.length} entries`);

  const levelBadgeStyles: Record<string, string> = {
    error: "bg-negative-muted text-negative",
    warn: "bg-warning-muted text-warning",
    info: "bg-surface-3 border border-edge text-text-secondary",
    debug: "bg-surface-3 border border-edge text-text-tertiary",
    trace: "bg-surface-3 border border-edge text-text-ghost",
  };
  const levelStyles: Record<string, string> = {
    error: "text-negative",
    warn: "text-warning",
    info: "text-text-secondary",
    debug: "text-text-tertiary",
    trace: "text-text-ghost",
  };

  $effect(() => {
    void logs.length;
    if (scrollRef) scrollRef.scrollTop = scrollRef.scrollHeight;
  });

  $effect(() => {
    return () => { copyFb.destroy(); };
  });

  async function handleCopyAll() {
    const text = logs.map((l) => `[${formatTimestamp(l.timestamp)}] [${l.level.toUpperCase()}] ${l.message}`).join("\n");
    await copyFb.trigger(text);
  }

  async function handleClearAll() {
    setLogs([]);
    try { await engineLogsClear(); } catch { /* Best-effort clear on backend. */ }
  }
</script>

{#if clearDialogOpen}
  <ConfirmDialog
    open={true}
    title="Clear Live Output"
    message="This removes all currently visible log entries from the live output panel. Do you want to continue?"
    confirmLabel="Clear"
    cancelLabel="Cancel"
    onconfirm={() => { clearDialogOpen = false; void handleClearAll(); }}
    oncancel={() => { clearDialogOpen = false; }}
  />
{/if}

<div class="flex-1 h-full min-h-0 overflow-hidden">
  <div class="h-[calc(100%-13px)] w-full px-6 pt-5 pb-0 flex flex-col self-start">
    <div class="flex items-center justify-between">
      <div class="text-[14px] font-bold text-text-primary">Logs</div>
    </div>
    <section class="mt-3 rounded-xl glass border border-edge/70 flex flex-col flex-1 min-h-0">
      <div class="pane-header border-b border-edge flex items-center justify-between">
        <div class="text-[11px] font-semibold text-black dashboard-heading-sans">Live Output</div>
        <div class="flex items-center gap-3">
          <div class="text-[10px] text-text-ghost dashboard-heading-sans">{entryCountLabel}</div>
          <button
            type="button"
            use:ripple
            onclick={handleCopyAll}
            disabled={logs.length === 0}
            class="relative isolate overflow-hidden inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold action-copy-btn h-auto min-w-0 disabled:opacity-55 disabled:cursor-not-allowed"
            title="Copy all logs"
          >
            <span class="inline-grid [&>*]:[grid-area:1/1]">
              {#key copyFb.copied}
                <span class="inline-flex items-center justify-center" in:fly={{ y: 4, duration: 240 }}>
                  {#if copyFb.copied}
                    <Check class="h-3.5 w-3.5" />
                  {:else}
                    Copy
                  {/if}
                </span>
              {/key}
              <span class="invisible" aria-hidden="true">Copy</span>
            </span>
          </button>
          <button
            type="button"
            use:ripple
            onclick={() => { clearDialogOpen = true; }}
            disabled={logs.length === 0}
            class="relative isolate overflow-hidden inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold action-neutral-btn h-auto min-w-0 disabled:opacity-55 disabled:cursor-not-allowed"
          >Clear</button>
        </div>
      </div>
      <div class="pane-body pane-first-item-offset flex-1 min-h-0">
        <div class="rounded-xl glass-pane-pill px-3 py-2 h-full min-h-0" style="will-change: transform, opacity; transform: translateZ(0);">
          <div bind:this={scrollRef} class="h-full min-h-0 overflow-y-auto">
            {#if logs.length === 0}
              <div class="flex flex-col gap-4 p-3">
                <div class="text-center space-y-1 mb-2">
                  <p class="text-[12px] font-medium text-text-secondary dashboard-heading-sans">Waiting for engine output...</p>
                  <p class="text-[11px] text-text-ghost dashboard-heading-sans">Connect a tunnel to see logs</p>
                </div>
                <div class="space-y-2.5">
                  <Skeleton class="h-3 w-full" />
                  <Skeleton class="h-3 w-[90%]" />
                  <Skeleton class="h-3 w-[75%]" />
                  <Skeleton class="h-3 w-[85%]" />
                </div>
              </div>
            {:else}
              <div class="py-0.5">
                {#each logs as entry, i (`${entry.timestamp}-${i}`)}
                  <div
                    in:fade={{ duration: 100 }}
                    class={cn(
                      "flex items-start gap-3 px-2 py-[3px] rounded text-[11px]",
                      entry.level === "error" && "bg-negative/[0.03]",
                      entry.level === "warn" && "bg-warning/[0.02]",
                    )}
                  >
                    <span class="text-text-ghost/60 shrink-0 tabular-nums w-[64px] dashboard-heading-sans">
                      {formatTimestamp(entry.timestamp)}
                    </span>
                    <span
                      class={cn(
                        "w-[40px] text-center text-[9px] font-medium py-0.5 rounded shrink-0 dashboard-heading-sans",
                        levelBadgeStyles[entry.level] ?? levelBadgeStyles.info,
                      )}
                    >{entry.level}</span>
                    <span
                      class={cn(
                        "leading-relaxed break-all select-text dashboard-heading-sans",
                        levelStyles[entry.level] ?? levelStyles.info,
                      )}
                    >{entry.message}</span>
                  </div>
                {/each}
              </div>
            {/if}
          </div>
        </div>
      </div>
    </section>
  </div>
</div>
