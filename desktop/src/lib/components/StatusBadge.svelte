<script lang="ts">
  interface Props {
    connected?: boolean;
    activeVMs?: number;
    latencyMs?: number;
  }

  let { connected = true, activeVMs = 0, latencyMs = 28 }: Props = $props();
</script>

<div class="flex items-center space-x-2 text-xs font-sans">
  <div class="flex items-center space-x-1.5 px-3 py-1 rounded-full bg-zinc-900/90 border border-zinc-800 text-zinc-200">
    <div class="h-2 w-2 rounded-full {connected ? 'bg-emerald-400 animate-pulse' : 'bg-red-500'}"></div>
    <span class="font-medium">{connected ? 'Daemon Online' : 'Disconnected'}</span>
  </div>

  <div class="px-2.5 py-1 rounded-full bg-zinc-900/90 border border-zinc-800 text-zinc-400">
    VMs: <span class="text-zinc-100 font-semibold font-mono">{activeVMs}</span>
  </div>

  <div class="px-2.5 py-1 rounded-full bg-zinc-900/90 border border-zinc-800 text-zinc-400">
    Boot: <span class="text-zinc-100 font-semibold font-mono">{latencyMs}ms</span>
  </div>
</div>
