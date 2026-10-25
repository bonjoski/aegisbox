<script lang="ts">
  import { profileStore } from "../stores/profileStore.svelte";
  import type { SecurityProfile } from "../types/ipc";

  const profiles: { id: SecurityProfile; name: string; tier: string; color: string; desc: string }[] = [
    {
      id: "microvm-hardened",
      name: "MicroVM Hardened",
      tier: "Fabrial Tier 2",
      color: "border-emerald-500 bg-emerald-950/20 text-emerald-400",
      desc: "Hardware-isolated microVM (Apple VZ/KVM/HCS) with CoW overlay & CEL firewall",
    },
    {
      id: "standard",
      name: "Standard Local Sandbox",
      tier: "Airlock Tier 1",
      color: "border-yellow-500 bg-yellow-950/20 text-yellow-400",
      desc: "OS kernel Seatbelt/Landlock sandbox with <15ms cold start",
    },
    {
      id: "permissive",
      name: "Permissive",
      tier: "Tier 0 Audit",
      color: "border-zinc-500 bg-zinc-950/20 text-zinc-400",
      desc: "Unrestricted host execution with full telemetry logging",
    },
  ];

  async function switchProfile(profile: SecurityProfile) {
    if (profileStore.isSwitching) return;
    if (profileStore.mdmLocked && profile === "permissive") return;

    profileStore.isSwitching = true;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("set_active_profile", { profile });
      profileStore.setProfile(profile, profileStore.mdmLocked);
    } catch (err) {
      console.error("Failed to set profile:", err);
    } finally {
      profileStore.isSwitching = false;
    }
  }
</script>

<div class="space-y-3 font-sans">
  <div class="flex items-center justify-between">
    <h3 class="text-xs font-mono uppercase tracking-wider text-zinc-400">
      Containment Posture (Fabrial Architecture)
    </h3>
    {#if profileStore.mdmLocked}
      <span class="inline-flex items-center space-x-1 text-xs font-mono text-amber-400 bg-amber-950/40 border border-amber-800/60 px-2 py-0.5 rounded">
        <span>🔒 MDM Enforced</span>
      </span>
    {/if}
  </div>

  <div class="grid grid-cols-1 gap-2.5">
    {#each profiles as p}
      {@const isActive = profileStore.activeProfile === p.id}
      {@const isDisabled = profileStore.mdmLocked && p.id === "permissive"}
      <button
        type="button"
        disabled={isDisabled || profileStore.isSwitching}
        class="w-full text-left p-3.5 rounded-xl border transition-all flex items-start justify-between
          {isActive ? `${p.color} ring-1 ring-offset-1 ring-offset-black` : 'border-zinc-800 bg-zinc-900/50 hover:bg-zinc-900 text-zinc-300'}
          {isDisabled ? 'opacity-40 cursor-not-allowed' : 'cursor-pointer'}"
        onclick={() => switchProfile(p.id)}
      >
        <div class="space-y-1">
          <div class="flex items-center space-x-2">
            <span class="text-sm font-semibold text-zinc-100">{p.name}</span>
            <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700">
              {p.tier}
            </span>
            {#if isDisabled}
              <span class="text-xs text-zinc-500">🔒 Disabled by admin</span>
            {/if}
          </div>
          <p class="text-xs text-zinc-400 leading-snug">{p.desc}</p>
        </div>

        {#if isActive}
          <div class="h-2 w-2 rounded-full bg-emerald-400 shadow-lg shadow-emerald-400/50 mt-1"></div>
        {/if}
      </button>
    {/each}
  </div>
</div>
