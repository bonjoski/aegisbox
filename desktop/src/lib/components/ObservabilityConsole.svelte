<script lang="ts">
  import { telemetryStore, type LogItem } from "../stores/telemetryStore.svelte";
  import LiveNetworkMap from "./LiveNetworkMap.svelte";
  import ToolCallGraph from "./ToolCallGraph.svelte";
  import AuditExportModal from "./AuditExportModal.svelte";

  let activeTab = $state<"network" | "graph">("network");
  let filterCategory = $state<"all" | "stdout" | "stderr" | "mcp" | "egress" | "tripwire">("all");
  let searchQuery = $state<string>("");
  let showAuditExport = $state<boolean>(false);
  let autoScroll = $state<boolean>(true);
  let terminalContainer: HTMLDivElement;

  const allLogs = $derived(telemetryStore.logs);

  const categoryCounts = $derived.by(() => {
    const counts = { all: allLogs.length, mcp: 0, egress: 0, stdout: 0, tripwire: 0 };
    for (const log of allLogs) {
      if (log.category === "mcp") counts.mcp++;
      else if (log.category === "egress") counts.egress++;
      else if (log.category === "stdout" || log.category === "stderr") counts.stdout++;
      else if (log.category === "tripwire") counts.tripwire++;
    }
    return counts;
  });

  const filteredLogs = $derived.by(() => {
    const list = allLogs;
    const cat = filterCategory;
    const q = searchQuery.trim().toLowerCase();

    return list.filter((log) => {
      if (cat !== "all") {
        if (cat === "stdout") {
          if (log.category !== "stdout" && log.category !== "stderr") return false;
        } else if (log.category !== cat) {
          return false;
        }
      }
      if (q !== "") {
        return (
          log.text.toLowerCase().includes(q) ||
          log.category.toLowerCase().includes(q) ||
          log.vmId.toLowerCase().includes(q)
        );
      }
      return true;
    });
  });

  $effect(() => {
    // Auto-scroll to bottom on new logs if enabled
    if (autoScroll && terminalContainer && filteredLogs.length > 0) {
      setTimeout(() => {
        terminalContainer.scrollTop = terminalContainer.scrollHeight;
      }, 20);
    }
  });

  function getCategoryBadge(cat: LogItem["category"]) {
    switch (cat) {
      case "mcp":
        return { label: "MCP", bg: "bg-sky-500/15 text-sky-400 border-sky-500/30" };
      case "egress":
        return { label: "NET", bg: "bg-blue-500/15 text-blue-400 border-blue-500/30" };
      case "tripwire":
        return { label: "TRIPWIRE", bg: "bg-rose-500/20 text-rose-300 border-rose-500/50" };
      case "stderr":
        return { label: "ERR", bg: "bg-amber-500/15 text-amber-300 border-amber-500/30" };
      default:
        return { label: "SYS", bg: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30" };
    }
  }

  function getMessageColor(cat: LogItem["category"]): string {
    switch (cat) {
      case "tripwire":
        return "text-rose-300 font-semibold";
      case "stderr":
        return "text-amber-300";
      case "mcp":
        return "text-sky-300";
      case "egress":
        return "text-blue-300";
      default:
        return "text-emerald-300/90";
    }
  }

  function simulateTripwire() {
    const honeypotIPs = ["169.254.169.254", "10.200.5.42", "192.168.1.100"];
    const targetIP = honeypotIPs[Math.floor(Math.random() * honeypotIPs.length)];
    const agentId = "agent-" + Math.floor(10 + Math.random() * 90);
    
    telemetryStore.addLog({
      id: Date.now(),
      timestampNs: Date.now() * 1e6,
      vmId: agentId,
      category: "tripwire",
      text: `🚨 CANARY TRIPWIRE VIOLATION: Rogue egress attempt to honeypot ${targetIP} intercepted — MicroVM frozen by kernel netgate`,
    });
    
    telemetryStore.triggerCanary(targetIP);
  }

  function formatLocalTime(timestampNs: number): string {
    const d = new Date(timestampNs / 1e6);
    const h = String(d.getHours()).padStart(2, "0");
    const m = String(d.getMinutes()).padStart(2, "0");
    const s = String(d.getSeconds()).padStart(2, "0");
    return `${h}:${m}:${s}`;
  }

  function copyAllLogs() {
    const text = filteredLogs
      .map(
        (l) =>
          `[${formatLocalTime(l.timestampNs)}] [${l.category.toUpperCase()}] ${l.text}`
      )
      .join("\n");
    navigator.clipboard.writeText(text);
  }
</script>

<div class="w-full h-full flex flex-col space-y-3 font-sans select-none">
  
  <!-- Subheader with View Switcher, Filter & Audit Action -->
  <div class="flex items-center justify-between border-b border-zinc-800 pb-2.5">
    
    <!-- Left: Secondary Tabs -->
    <div class="flex items-center space-x-1.5 bg-zinc-900/60 p-1 rounded-lg border border-zinc-800">
      <button
        type="button"
        class="px-3 py-1 text-xs font-medium rounded-md transition-all cursor-pointer
          {activeTab === 'network' ? 'bg-zinc-800 text-white font-semibold shadow-sm' : 'text-zinc-400 hover:text-zinc-200'}"
        onclick={() => (activeTab = "network")}
      >
        Live Egress Map
      </button>

      <button
        type="button"
        class="px-3 py-1 text-xs font-medium rounded-md transition-all cursor-pointer
          {activeTab === 'graph' ? 'bg-zinc-800 text-white font-semibold shadow-sm' : 'text-zinc-400 hover:text-zinc-200'}"
        onclick={() => (activeTab = "graph")}
      >
        Tool-Call DAG
      </button>
    </div>

    <!-- Right: Audit Export Button -->
    <div class="flex items-center space-x-2">
      <button
        type="button"
        class="px-3.5 py-1.5 text-xs font-medium rounded-lg bg-indigo-950/70 border border-indigo-700/80 text-indigo-200 hover:bg-indigo-900/80 transition-all cursor-pointer shadow-sm flex items-center space-x-1.5"
        onclick={() => (showAuditExport = true)}
      >
        <span>📜</span>
        <span>Export Cryptographic Audit</span>
      </button>
    </div>
  </div>

  <!-- Side-by-Side Split View Grid -->
  <div class="grid grid-cols-1 md:grid-cols-2 gap-3.5 flex-1 min-h-[360px]">
    
    <!-- Left Pane: High-Contrast Crisp Terminal Viewport -->
    <div class="bg-zinc-950 border border-zinc-800 rounded-xl p-3 flex flex-col space-y-2.5 shadow-xl overflow-hidden">
      
      <!-- Terminal Controls & Category Filter Bar -->
      <div class="flex items-center justify-between border-b border-zinc-800/80 pb-2">
        <div class="flex items-center space-x-2">
          <div class="flex items-center space-x-1.5">
            <div class="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></div>
            <span class="text-xs font-semibold text-zinc-200 tracking-wide">Live Stream</span>
          </div>
          <span class="text-[11px] text-zinc-500 font-mono">10k lines/s</span>
        </div>

        <div class="flex items-center space-x-2">
          <button
            type="button"
            class="text-[11px] font-medium text-rose-400 hover:text-rose-300 hover:bg-rose-950/70 px-2 py-0.5 rounded bg-rose-950/40 border border-rose-800/60 cursor-pointer flex items-center space-x-1 transition-all"
            onclick={simulateTripwire}
            title="Simulate an egress probe to a honeypot canary IP"
          >
            <span>⚡ Simulate Tripwire</span>
          </button>
          <button
            type="button"
            class="text-[11px] text-zinc-400 hover:text-zinc-200 px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 cursor-pointer"
            onclick={() => telemetryStore.clearLogs()}
          >
            Clear
          </button>
          <button
            type="button"
            class="text-[11px] text-zinc-400 hover:text-zinc-200 px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 cursor-pointer"
            onclick={copyAllLogs}
          >
            Copy
          </button>
          <button
            type="button"
            class="text-[11px] text-zinc-400 hover:text-zinc-200 px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 cursor-pointer"
            onclick={() => (autoScroll = !autoScroll)}
          >
            Auto-scroll: {autoScroll ? "ON" : "OFF"}
          </button>
        </div>
      </div>

      <!-- Filter Pills -->
      <div class="flex items-center space-x-1.5 overflow-x-auto pb-0.5 text-[11px]">
        {#each [
          { id: "all", label: "All", count: categoryCounts.all },
          { id: "mcp", label: "MCP Tools", count: categoryCounts.mcp },
          { id: "egress", label: "Egress", count: categoryCounts.egress },
          { id: "stdout", label: "System", count: categoryCounts.stdout },
          { id: "tripwire", label: "Tripwires", count: categoryCounts.tripwire }
        ] as cat}
          <button
            type="button"
            class="px-2.5 py-0.5 rounded-full transition-all cursor-pointer font-medium flex items-center space-x-1
              {filterCategory === cat.id 
                ? (cat.id === 'tripwire' ? 'bg-rose-900/80 text-rose-200 border border-rose-600 shadow-sm' : 'bg-zinc-800 text-white border border-zinc-600 shadow-sm')
                : 'text-zinc-400 hover:text-zinc-200 border border-transparent hover:bg-zinc-900'}"
            onclick={() => {
              filterCategory = cat.id as any;
            }}
          >
            <span>{cat.label}</span>
            <span class="text-[10px] opacity-75 font-mono">({cat.count})</span>
          </button>
        {/each}
      </div>

      <!-- Crisp Terminal Log Window -->
      <div
        bind:this={terminalContainer}
        class="flex-1 w-full bg-[#09090b] border border-zinc-900 rounded-lg p-2.5 font-mono text-[12px] leading-relaxed overflow-y-auto select-text space-y-1"
        style="font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;"
      >
        {#if filteredLogs.length === 0}
          <div class="h-full flex items-center justify-center text-zinc-600 text-xs">
            No matching log lines
          </div>
        {:else}
          {#each filteredLogs as log (log.id)}
            {@const badge = getCategoryBadge(log.category)}
            <div class="flex items-start space-x-2 py-0.5 hover:bg-zinc-900/50 rounded px-1 -mx-1 transition-colors">
              <!-- Timestamp -->
              <span class="text-zinc-500 shrink-0 text-[11px] select-none">
                {formatLocalTime(log.timestampNs)}
              </span>

              <!-- Category Badge -->
              <span class="text-[9px] font-semibold px-1.5 py-0.2 rounded border uppercase tracking-wider shrink-0 select-none {badge.bg}">
                {badge.label}
              </span>

              <!-- Log Text -->
              <span class="break-all {getMessageColor(log.category)}">
                {log.text}
              </span>
            </div>
          {/each}
        {/if}
      </div>
    </div>

    <!-- Right Pane: Live Network Egress or DAG Tool Graph -->
    <div class="bg-zinc-950 border border-zinc-800 rounded-xl p-3 flex flex-col shadow-xl overflow-hidden">
      {#if activeTab === "network"}
        <LiveNetworkMap />
      {:else}
        <ToolCallGraph />
      {/if}
    </div>

  </div>

  <!-- Cryptographic Audit Export Dialog -->
  {#if showAuditExport}
    <AuditExportModal onClose={() => (showAuditExport = false)} />
  {/if}

</div>
