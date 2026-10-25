<script lang="ts">
  import { telemetryStore } from "../stores/telemetryStore.svelte";

  const egress = $derived(telemetryStore.activeEgress);
  const canaryActive = $derived(telemetryStore.canaryAlertActive);
  const canaryIp = $derived(telemetryStore.canaryTargetIp);
</script>

<div class="h-full flex flex-col space-y-3 font-sans select-none">
  
  <!-- Canary Alert Tripwire Pulse Banner -->
  {#if canaryActive}
    <div class="p-3 bg-red-950/80 border border-red-600 rounded-xl flex items-center justify-between animate-pulse">
      <div class="flex items-center space-x-2.5">
        <span class="text-base">🚨</span>
        <div>
          <span class="text-xs font-bold text-red-200 block">CANARY TRIPWIRE TRIGGERED</span>
          <span class="text-[11px] text-red-300 font-mono">Attempted egress to honeypot IP: {canaryIp}</span>
        </div>
      </div>
      <button
        type="button"
        class="px-2.5 py-1 text-[11px] font-medium rounded bg-red-900 border border-red-700 text-white hover:bg-red-800 cursor-pointer"
        onclick={() => telemetryStore.clearCanaryAlert()}
      >
        Acknowledge
      </button>
    </div>
  {/if}

  <!-- Header -->
  <div class="flex items-center justify-between border-b border-zinc-800/80 pb-2">
    <div class="flex items-center space-x-2">
      <span class="text-xs font-semibold text-zinc-200 tracking-wide">
        Active Egress & DNS Mediation
      </span>
      <span class="text-[11px] font-mono px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-300">
        {egress.length} active
      </span>
    </div>
  </div>

  <!-- Egress List / Grid -->
  {#if egress.length === 0}
    <div class="flex-1 flex flex-col items-center justify-center text-center p-6 text-zinc-500 border border-dashed border-zinc-800/80 rounded-xl">
      <span class="text-2xl mb-1.5">🌐</span>
      <span class="text-xs font-medium text-zinc-400">Zero unvetted outbound egress</span>
      <span class="text-[11px] text-zinc-500 mt-1">DNS proxy synthesizing NXDOMAIN for untrusted domains</span>
    </div>
  {:else}
    <div class="space-y-2 overflow-y-auto max-h-[420px] pr-1">
      {#each egress as conn}
        <div class="p-3 rounded-xl border border-zinc-800/90 bg-zinc-900/40 hover:bg-zinc-900/70 transition-colors flex items-center justify-between">
          <div class="space-y-1">
            <div class="flex items-center space-x-2">
              <span class="text-xs font-semibold text-zinc-100 font-mono tracking-tight">
                {conn.destinationDomain}
              </span>
              {#if conn.isPinned}
                <span class="text-[10px] font-semibold px-1.5 py-0.2 rounded bg-emerald-950/70 border border-emerald-700/60 text-emerald-300 uppercase tracking-wider">
                  PINNED
                </span>
              {:else}
                <span class="text-[10px] font-semibold px-1.5 py-0.2 rounded bg-amber-950/70 border border-amber-700/60 text-amber-300 uppercase tracking-wider">
                  MEDIATED
                </span>
              {/if}
            </div>
            <div class="text-[11px] font-mono text-zinc-400">
              {conn.destinationIp}:{conn.destinationPort} &bull; {conn.protocol.toUpperCase()}
            </div>
          </div>

          <div class="text-right text-[11px] font-mono text-zinc-300 space-y-0.5">
            <div class="text-emerald-400/90 font-medium">&uarr; {(conn.bytesSent / 1024).toFixed(1)} KB</div>
            <div class="text-sky-400/90 font-medium">&darr; {(conn.bytesReceived / 1024).toFixed(1)} KB</div>
          </div>
        </div>
      {/each}
    </div>
  {/if}

</div>
