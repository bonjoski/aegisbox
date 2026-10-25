<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { approvalStore } from "../stores/approvalStore.svelte";
  import type { ApprovalScope, SecuritySeverity } from "../types/ipc";

  let dwellRemainingMs = $state(800);
  let timerActive = $state(true);
  let countdownSeconds = $state(30);
  let selectedScope = $state<ApprovalScope>("SESSION");
  let intervalId: any = null;
  let dwellIntervalId: any = null;

  const active = $derived(approvalStore.activeApproval);

  // Security Helper 1: Strip Unicode Bidi (Bidirectional) override characters
  // (\u202A-\u202E, \u2066-\u2069) to defeat visual path spoofing
  function sanitizeBidi(input: string): string {
    return input.replace(/[\u202A-\u202E\u2066-\u2069]/g, "");
  }

  // Security Helper 2: Detect mixed-script homoglyphs or Cyrillic lookalikes in domain names
  function detectHomoglyphs(text: string): boolean {
    // Check for mixed Latin and Cyrillic / Greek characters commonly used in domain spoofing
    const hasLatin = /[a-zA-Z]/.test(text);
    const hasCyrillicOrGreek = /[\u0400-\u04FF\u0370-\u03FF]/.test(text);
    return hasLatin && hasCyrillicOrGreek;
  }

  // Formatted tool arguments with Bidi stripped
  const safeArgs = $derived.by(() => {
    if (!active?.toolArgsJson) return "";
    try {
      const parsed = JSON.parse(active.toolArgsJson);
      return sanitizeBidi(JSON.stringify(parsed, null, 2));
    } catch {
      return sanitizeBidi(active.toolArgsJson);
    }
  });

  const hasHomoglyphAlert = $derived.by(() => {
    if (!active) return false;
    return detectHomoglyphs(active.reason) || detectHomoglyphs(active.toolArgsJson);
  });

  // Reset dwell timer whenever a new approval becomes active
  $effect(() => {
    if (active) {
      dwellRemainingMs = 800;
      countdownSeconds = 30;
      startDwellTimer();
      startCountdownTimer();
    } else {
      clearTimers();
    }
  });

  function startDwellTimer() {
    if (dwellIntervalId) clearInterval(dwellIntervalId);
    dwellIntervalId = setInterval(() => {
      dwellRemainingMs = Math.max(0, dwellRemainingMs - 100);
      if (dwellRemainingMs === 0) {
        clearInterval(dwellIntervalId);
      }
    }, 100);
  }

  function startCountdownTimer() {
    if (intervalId) clearInterval(intervalId);
    intervalId = setInterval(() => {
      countdownSeconds = Math.max(0, countdownSeconds - 1);
      if (countdownSeconds === 0) {
        clearInterval(intervalId);
        // Timeout: auto-suspend rather than abrupt kill
        handleDecision(new MouseEvent("click"), "DENY", "ONCE");
      }
    }, 1000);
  }

  function clearTimers() {
    if (intervalId) clearInterval(intervalId);
    if (dwellIntervalId) clearInterval(dwellIntervalId);
  }

  onDestroy(() => {
    clearTimers();
  });

  async function handleDecision(event: MouseEvent, decision: "APPROVE" | "DENY", scope?: ApprovalScope) {
    // Adversarial Defense: Strict synthetic event rejection (anti-clickjacking)
    if (!event.isTrusted) {
      console.warn("[Aegisbox Security] Rejected programmatic / synthetic click event!");
      return;
    }

    // Adversarial Defense: Dwell timer enforcement
    if (decision === "APPROVE" && dwellRemainingMs > 0) {
      console.warn("[Aegisbox Security] Click ignored during dwell timer window!");
      return;
    }

    if (!active) return;
    const finalScope = scope || selectedScope;

    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("submit_approval_decision", {
        interceptId: active.interceptId,
        decision,
        scope: finalScope,
      });
      approvalStore.removeApproval(active.interceptId);
    } catch (err) {
      console.error("Failed to submit approval decision:", err);
    }
  }

  function getSeverityColor(sev: SecuritySeverity): string {
    switch (sev) {
      case "CRITICAL": return "bg-red-900/60 text-red-300 border-red-500/50";
      case "HIGH": return "bg-orange-900/60 text-orange-300 border-orange-500/50";
      case "MEDIUM": return "bg-yellow-900/60 text-yellow-300 border-yellow-500/50";
      default: return "bg-blue-900/60 text-blue-300 border-blue-500/50";
    }
  }
</script>

{#if active}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4">
    <div class="w-full max-w-2xl bg-zinc-950 border border-zinc-800 rounded-xl shadow-2xl overflow-hidden flex flex-col animate-in fade-in zoom-in-95 duration-150">
      
      <!-- Header & Severity -->
      <div class="px-6 py-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/50">
        <div class="flex items-center space-x-3">
          <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border {getSeverityColor(active.severity)}">
            {active.severity}
          </span>
          <h2 class="text-lg font-bold text-zinc-100 font-mono">
            MCP Intercept: {sanitizeBidi(active.toolName)}
          </h2>
        </div>
        <div class="text-xs font-mono text-zinc-400">
          Timeout: <span class="text-zinc-200 font-semibold">{countdownSeconds}s</span>
        </div>
      </div>

      <!-- Timeout Progress Bar -->
      <div class="w-full bg-zinc-900 h-1">
        <div 
          class="bg-indigo-500 h-1 transition-all duration-1000 ease-linear"
          style="width: {(countdownSeconds / 30) * 100}%"
        ></div>
      </div>

      <!-- Content Body -->
      <div class="p-6 space-y-4 max-h-[60vh] overflow-y-auto font-sans">
        
        <!-- Reason Banner -->
        <div class="text-sm text-zinc-300 bg-zinc-900/80 p-3 rounded-lg border border-zinc-800">
          <span class="text-zinc-400 font-semibold block mb-1">Policy Intercept Reason:</span>
          {sanitizeBidi(active.reason)}
        </div>

        <!-- Homoglyph Warning Badge -->
        {#if hasHomoglyphAlert}
          <div class="text-xs bg-red-950/80 border border-red-700 text-red-200 p-2.5 rounded-lg flex items-center space-x-2">
            <span class="text-red-400 font-bold">⚠️ SECURITY WARNING:</span>
            <span>Suspected homoglyph or mixed-script spoofing detected in payload.</span>
          </div>
        {/if}

        <!-- Raw Monospace Arguments (No Markdown injection permitted) -->
        <div>
          <label class="text-xs font-mono text-zinc-400 block mb-1">
            Raw Tool Arguments (Sanitized Plaintext):
          </label>
          <pre class="bg-black border border-zinc-800 rounded-lg p-3 text-xs font-mono text-emerald-400 overflow-x-auto select-all max-h-48 leading-relaxed">
{safeArgs}
          </pre>
        </div>

        <!-- Scope Selection -->
        <div class="space-y-1.5 pt-2">
          <span class="text-xs font-mono text-zinc-400 block">Approval Scope:</span>
          <div class="grid grid-cols-3 gap-2">
            {#each ["ONCE", "SESSION", "WORKSPACE"] as scope}
              <button
                type="button"
                class="px-3 py-2 text-xs font-mono rounded-lg border transition-all text-center
                  {selectedScope === scope 
                    ? 'bg-zinc-800 border-indigo-500 text-white font-semibold' 
                    : 'bg-zinc-900 border-zinc-800 text-zinc-400 hover:text-zinc-200'}"
                onclick={() => selectedScope = scope as ApprovalScope}
              >
                Allow {scope.toLowerCase()}
              </button>
            {/each}
          </div>
        </div>

      </div>

      <!-- Action Footer -->
      <div class="px-6 py-4 border-t border-zinc-800 bg-zinc-900/40 flex items-center justify-between">
        <button
          type="button"
          class="px-4 py-2 text-xs font-semibold rounded-lg bg-red-950/60 border border-red-800 text-red-300 hover:bg-red-900/80 transition-all cursor-pointer"
          onclick={(e) => handleDecision(e, "DENY")}
        >
          Deny Tool Call
        </button>

        <div class="flex items-center space-x-3">
          {#if dwellRemainingMs > 0}
            <span class="text-xs font-mono text-zinc-500 animate-pulse">
              Dwell delay ({(dwellRemainingMs / 1000).toFixed(1)}s)...
            </span>
          {/if}

          <button
            type="button"
            disabled={dwellRemainingMs > 0}
            class="px-5 py-2 text-xs font-semibold rounded-lg transition-all flex items-center space-x-2
              {dwellRemainingMs > 0 
                ? 'bg-zinc-800 text-zinc-600 border border-zinc-700 cursor-not-allowed' 
                : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-900/20 cursor-pointer active:scale-95'}"
            onclick={(e) => handleDecision(e, "APPROVE")}
          >
            {#if active.severity === "CRITICAL"}
              <span>🔐 Approve with Biometric Step-Up</span>
            {:else}
              <span>Approve ({selectedScope.toLowerCase()})</span>
            {/if}
          </button>
        </div>
      </div>

    </div>
  </div>
{/if}
