<script lang="ts">
  import { formatBitsPerSecond } from "$lib/format";

  interface Props {
    bitsPerSecond: number;
  }

  let { bitsPerSecond }: Props = $props();

  let displayBits = $state(0);
  let rafId: number | null = null;
  let initialized = false;

  function easeOutCubic(t: number): number {
    return 1 - (1 - t) * (1 - t) * (1 - t);
  }

  $effect(() => {
    const target = Math.max(0, bitsPerSecond);
    if (!initialized) {
      displayBits = target;
      initialized = true;
      return;
    }
    const start = displayBits;
    const delta = target - start;
    if (Math.abs(delta) < 0.5) {
      displayBits = target;
      return;
    }
    if (rafId !== null) {
      window.cancelAnimationFrame(rafId);
      rafId = null;
    }
    const durationMs = 560;
    const startedAt = performance.now();
    const step = (now: number) => {
      const t = Math.min(1, (now - startedAt) / durationMs);
      displayBits = start + delta * easeOutCubic(t);
      if (t < 1) {
        rafId = window.requestAnimationFrame(step);
      } else {
        rafId = null;
      }
    };
    rafId = window.requestAnimationFrame(step);
    return () => {
      if (rafId !== null) {
        window.cancelAnimationFrame(rafId);
        rafId = null;
      }
    };
  });
</script>

{formatBitsPerSecond(displayBits)}
