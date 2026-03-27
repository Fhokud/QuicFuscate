<script lang="ts">
  import { fade } from "svelte/transition";
  import { getActiveTab } from "$lib/stores/app.svelte";
  import TunnelsView from "$lib/components/views/TunnelsView.svelte";
  import SettingsView from "$lib/components/views/SettingsView.svelte";
  import LogsView from "$lib/components/views/LogsView.svelte";
  import AboutView from "$lib/components/views/AboutView.svelte";

  const activeTab = $derived(getActiveTab());
</script>

<div class="relative flex-1 min-h-0">
  {#key activeTab}
    <div in:fade={{ duration: 100 }} out:fade={{ duration: 100 }} class="absolute inset-0 flex flex-col">
      {#if activeTab === "tunnels"}
        <TunnelsView />
      {:else if activeTab === "settings"}
        <SettingsView />
      {:else if activeTab === "logs"}
        <LogsView />
      {:else if activeTab === "about"}
        <AboutView />
      {/if}
    </div>
  {/key}
</div>
