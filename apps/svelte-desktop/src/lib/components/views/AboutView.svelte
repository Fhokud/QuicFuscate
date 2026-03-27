<script lang="ts">
  import { AboutContent } from "@quicfuscate/ui";
  import { detectCpuFeatures } from "$lib/stores/tauri-bridge.svelte";
  import appLogo from "../../../../../../assets/logo/QuicFuscate_clean.png";

  let cpuFeatures = $state<string[]>([]);
  let error = $state<string | null>(null);
  const version = "v0.2.0";

  $effect(() => {
    let cancelled = false;
    (async () => {
      try {
        const features = await detectCpuFeatures();
        if (!cancelled) cpuFeatures = features;
      } catch (e: unknown) {
        if (!cancelled) error = String(e ?? "Failed to detect CPU features");
      }
    })();
    return () => { cancelled = true; };
  });
</script>

<AboutContent {version} {cpuFeatures} {error} logoSrc={appLogo} />
