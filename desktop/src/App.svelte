<script lang="ts">
  import { onMount } from "svelte";
  import ProfileSwitcher from "./lib/components/ProfileSwitcher.svelte";
  import ApprovalModal from "./lib/components/ApprovalModal.svelte";
  import StatusBadge from "./lib/components/StatusBadge.svelte";
  import ObservabilityConsole from "./lib/components/ObservabilityConsole.svelte";
  import { approvalStore } from "./lib/stores/approvalStore.svelte";
  import { profileStore } from "./lib/stores/profileStore.svelte";
  import { telemetryStore } from "./lib/stores/telemetryStore.svelte";
  import type { PendingApproval, SecurityProfileStatus } from "./lib/types/ipc";

  interface LiveLogEvent {
    id: number;
    timestampNs: number;
    vmId: string;
    category: "stdout" | "stderr" | "mcp" | "egress" | "tripwire";
    text: string;
    canaryTriggered?: boolean;
    canaryTargetIp?: string;
  }

  let daemonOnline = $state(true);
  let activeVMCount = $state(0);
  let mainView = $state<"posture" | "observability">("observability");
  let lastEventNs = 0;

  onMount(() => {
    let pollInterval: ReturnType<typeof setInterval> | null = null;

    (async () => {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        
        // Initial profile state
        const status = await invoke<SecurityProfileStatus>("get_active_profile");
        if (status) {
          profileStore.setProfile(status.activeProfile, status.mdmLocked);
        }

        // Initial pending approvals
        const pending = await invoke<PendingApproval[]>("list_pending_approvals");
        if (pending) {
          approvalStore.setPending(pending);
        }

        // Live event subscription polling loop (reads from daemon/events.jsonl)
        pollInterval = setInterval(async () => {
          try {
            const isLive = await invoke<boolean>("check_daemon_status");
            if (typeof isLive === "boolean") {
              daemonOnline = isLive;
            }

            const events = await invoke<LiveLogEvent[]>("get_live_events", {
              since_ns: lastEventNs,
              sinceNs: lastEventNs,
            });
            if (events && events.length > 0) {
              for (const ev of events) {
                if (ev.timestampNs > lastEventNs) {
                  lastEventNs = ev.timestampNs;
                }
                telemetryStore.addLog({
                  id: ev.id,
                  timestampNs: ev.timestampNs,
                  vmId: ev.vmId || "aegisbox",
                  category: ev.category,
                  text: ev.text,
                });
                if (ev.canaryTriggered) {
                  telemetryStore.triggerCanary(ev.canaryTargetIp || "169.254.169.254");
                }
              }
            }
          } catch (pollErr) {
            console.error("[Cockpit Poll Error]:", pollErr);
          }
        }, 300);
      } catch (err) {
        console.warn("Desktop running in standalone or preview mode:", err);
      }
    })();

    return () => {
      if (pollInterval) clearInterval(pollInterval);
    };
  });
</script>

<main class="h-screen w-screen flex flex-col bg-zinc-950 text-zinc-100 select-none overflow-hidden font-sans">
  
  <!-- Titlebar / Header -->
  <header class="h-12 border-b border-zinc-800/80 px-4 flex items-center justify-between bg-zinc-900/40">
    <div class="flex items-center space-x-4">
      <div class="flex items-center space-x-2.5">
        <img src="/icon.png" alt="Aegisbox" class="h-6 w-6 rounded-md shadow-sm object-contain" />
        <h1 class="text-sm font-semibold tracking-wide text-zinc-100">
          Aegisbox <span class="text-xs text-zinc-500 font-mono">Cockpit</span>
        </h1>
      </div>

      <nav class="flex items-center space-x-1 pl-4 border-l border-zinc-800 bg-zinc-900/60 p-1 rounded-lg border">
        <button
          type="button"
          class="px-3 py-1 text-xs font-medium rounded-md transition-all cursor-pointer
            {mainView === 'observability' ? 'bg-zinc-800 text-white font-semibold shadow-sm' : 'text-zinc-400 hover:text-zinc-200'}"
          onclick={() => mainView = 'observability'}
        >
          Observability
        </button>

        <button
          type="button"
          class="px-3 py-1 text-xs font-medium rounded-md transition-all cursor-pointer
            {mainView === 'posture' ? 'bg-zinc-800 text-white font-semibold shadow-sm' : 'text-zinc-400 hover:text-zinc-200'}"
          onclick={() => mainView = 'posture'}
        >
          Containment Posture
        </button>
      </nav>
    </div>

    <StatusBadge connected={daemonOnline} activeVMs={activeVMCount} latencyMs={28} />
  </header>

  <!-- Body Content -->
  <div class="flex-1 p-5 overflow-y-auto">
    {#if mainView === "observability"}
      <ObservabilityConsole />
    {:else}
      <div class="max-w-xl mx-auto space-y-6">
        <!-- Security Profile Matrix -->
        <section>
          <ProfileSwitcher />
        </section>

        <!-- Sister Ecosystem Status Card -->
        <section class="border border-zinc-800/80 rounded-xl p-4 bg-zinc-900/20 space-y-3">
          <h3 class="text-xs font-mono uppercase tracking-wider text-zinc-400">
            Integrated Fabrial Fabric
          </h3>
          <div class="grid grid-cols-2 gap-3 text-xs">
            <div class="p-2.5 rounded-lg bg-zinc-900/50 border border-zinc-800">
              <span class="font-semibold text-emerald-400 block mb-0.5">🔐 Locksmith</span>
              <span class="text-zinc-400">Biometric step-up vault & ephemeral secret broker</span>
            </div>
            <div class="p-2.5 rounded-lg bg-zinc-900/50 border border-zinc-800">
              <span class="font-semibold text-cyan-400 block mb-0.5">👁️ Argus</span>
              <span class="text-zinc-400">Shell AST parsing & slopsquatting pre-flight filter</span>
            </div>
            <div class="p-2.5 rounded-lg bg-zinc-900/50 border border-zinc-800">
              <span class="font-semibold text-yellow-400 block mb-0.5">⚡ Airlock</span>
              <span class="text-zinc-400">Sub-15ms kernel Seatbelt/Landlock sandbox</span>
            </div>
            <div class="p-2.5 rounded-lg bg-zinc-900/50 border border-zinc-800">
              <span class="font-semibold text-indigo-400 block mb-0.5">📦 SBOM Enricher</span>
              <span class="text-zinc-400">CycloneDX supply-chain lockfile verification</span>
            </div>
          </div>
        </section>
      </div>
    {/if}
  </div>

  <!-- Human In The Loop Intercept Sheet -->
  <ApprovalModal />

</main>
