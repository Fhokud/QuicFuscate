<script lang="ts">
  import { cn } from "@quicfuscate/ui";
  import { Skeleton } from "@quicfuscate/ui";
  import Sparkline from "$lib/components/ui/Sparkline.svelte";
  import SmoothTrafficValue from "$lib/components/views/SmoothTrafficValue.svelte";

  interface Props {
    label: string;
    value: string;
    accent?: boolean;
    color?: string;
    loading?: boolean;
    sparkline?: number[];
    trafficBitsPerSecond?: number;
  }

  let {
    label,
    value,
    accent = false,
    color,
    loading = false,
    sparkline,
    trafficBitsPerSecond,
  }: Props = $props();

  const showTrafficDash = $derived(typeof trafficBitsPerSecond === "number" && trafficBitsPerSecond <= 0);
  const valueClassName = $derived(cn(
    "text-[11px] font-semibold truncate text-center dashboard-heading-sans",
    color ? undefined : (accent ? "text-accent" : "!text-[#6366f1]"),
  ));
</script>

<div class="relative h-[68px] rounded-[10px] border border-[rgba(255,255,255,0.82)] bg-white/72 px-3 py-2.5 shadow-[inset_0_1px_0_rgba(255,255,255,0.88),0_1px_3px_rgba(18,26,44,0.08)]">
  <div class="flex h-full flex-col min-w-0">
    <div class="h-[12px] leading-[12px] text-[10px] font-semibold text-black/54 tracking-[0.03em] truncate dashboard-heading-sans">
      {label}
    </div>
    {#if loading}
      <div class="mt-[12px] h-[15px] flex items-center justify-center">
        <Skeleton class="h-[10px] w-[64px] rounded" />
      </div>
    {:else if showTrafficDash}
      <div class="mt-[11px] h-[16px] leading-[16px] text-[11px] font-semibold truncate text-center !text-[#6366f1] dashboard-heading-sans">
        -
      </div>
    {:else}
      <div class="relative mt-[11px] h-[16px] leading-[16px]">
        <div class={valueClassName} style={color ? `color:${color}` : ""}>
          {#if typeof trafficBitsPerSecond === "number"}
            <SmoothTrafficValue bitsPerSecond={trafficBitsPerSecond} />
          {:else}
            {value}
          {/if}
        </div>
        {#if typeof trafficBitsPerSecond !== "number" && sparkline && sparkline.length > 0}
          <div class="absolute right-0 bottom-0">
            <Sparkline data={sparkline} width={48} height={20} color={color || "var(--color-accent)"} />
          </div>
        {/if}
      </div>
    {/if}
    <div class="mt-auto h-[11px] leading-[11px] text-[9px] text-transparent" aria-hidden="true">
      &nbsp;
    </div>
  </div>
</div>
