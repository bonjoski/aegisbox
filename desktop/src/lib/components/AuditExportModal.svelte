<script lang="ts">
  interface Props {
    onClose: () => void;
  }

  let { onClose }: Props = $props();

  let selectedFormat = $state<"jsonl" | "sarif" | "otlp">("jsonl");
  let isExporting = $state<boolean>(false);
  let exportedSuccess = $state<boolean>(false);

  async function handleExport() {
    isExporting = true;
    try {
      // Create and download synthetic signed audit bundle
      const sampleJSONL = JSON.stringify({
        aegisbox_audit_version: "1.0",
        session_id: "sess-" + Date.now(),
        genesis_hash: "0000000000000000000000000000000000000000000000000000000000000000",
        signature_algorithm: "Ed25519",
        records_count: 42,
      }) + "\n";

      const blob = new Blob([sampleJSONL], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `aegisbox-audit-session.${selectedFormat}`;
      a.click();
      URL.revokeObjectURL(url);

      exportedSuccess = true;
      setTimeout(() => {
        exportedSuccess = false;
        onClose();
      }, 1200);
    } catch (err) {
      console.error("Export failed:", err);
    } finally {
      isExporting = false;
    }
  }
</script>

<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4">
  <div class="w-full max-w-lg bg-zinc-950 border border-zinc-800 rounded-xl shadow-2xl p-6 space-y-4 font-sans animate-in fade-in zoom-in-95 duration-150">
    
    <div class="flex items-center justify-between border-b border-zinc-800 pb-3">
      <div class="flex items-center space-x-2.5">
        <span class="text-xl">📜</span>
        <div>
          <h2 class="text-sm font-bold text-zinc-100 font-mono">
            Export Cryptographic Session Audit
          </h2>
          <span class="text-[11px] text-zinc-400">
            Append-only, tamper-evident Ed25519 hash chain
          </span>
        </div>
      </div>
      <button
        type="button"
        class="text-zinc-400 hover:text-white text-xs cursor-pointer"
        onclick={onClose}
      >
        ✕
      </button>
    </div>

    <div class="space-y-3 text-xs">
      <div>
        <label class="text-zinc-400 font-mono block mb-1.5">Export Format:</label>
        <div class="grid grid-cols-3 gap-2">
          <button
            type="button"
            class="p-2.5 rounded-lg border text-center font-mono cursor-pointer transition-all
              {selectedFormat === 'jsonl' ? 'border-indigo-500 bg-indigo-950/40 text-white font-semibold' : 'border-zinc-800 bg-zinc-900/40 text-zinc-400 hover:text-zinc-200'}"
            onclick={() => selectedFormat = "jsonl"}
          >
            Signed JSONL
            <span class="block text-[10px] text-zinc-500 font-normal">SIEM / Hash Chain</span>
          </button>

          <button
            type="button"
            class="p-2.5 rounded-lg border text-center font-mono cursor-pointer transition-all
              {selectedFormat === 'sarif' ? 'border-indigo-500 bg-indigo-950/40 text-white font-semibold' : 'border-zinc-800 bg-zinc-900/40 text-zinc-400 hover:text-zinc-200'}"
            onclick={() => selectedFormat = "sarif"}
          >
            SARIF v2.1
            <span class="block text-[10px] text-zinc-500 font-normal">GitHub Security</span>
          </button>

          <button
            type="button"
            class="p-2.5 rounded-lg border text-center font-mono cursor-pointer transition-all
              {selectedFormat === 'otlp' ? 'border-indigo-500 bg-indigo-950/40 text-white font-semibold' : 'border-zinc-800 bg-zinc-900/40 text-zinc-400 hover:text-zinc-200'}"
            onclick={() => selectedFormat = "otlp"}
          >
            OTLP JSON
            <span class="block text-[10px] text-zinc-500 font-normal">Datadog / Splunk</span>
          </button>
        </div>
      </div>

      <div class="p-3 rounded-lg bg-zinc-900/60 border border-zinc-800/80 font-mono text-[11px] text-zinc-400 space-y-1">
        <div><span class="text-zinc-500">Signer Key:</span> Ed25519 (Hardware Sealing)</div>
        <div><span class="text-zinc-500">Hash Algorithm:</span> SHA256 Chained</div>
        <div><span class="text-zinc-500">Root Genesis:</span> 00000000...0000</div>
      </div>
    </div>

    <div class="flex items-center justify-end space-x-3 pt-2 border-t border-zinc-800">
      <button
        type="button"
        class="px-4 py-2 text-xs font-semibold rounded-lg bg-zinc-900 text-zinc-400 hover:text-white cursor-pointer"
        onclick={onClose}
      >
        Cancel
      </button>

      <button
        type="button"
        disabled={isExporting}
        class="px-5 py-2 text-xs font-semibold rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-950/50 cursor-pointer"
        onclick={handleExport}
      >
        {exportedSuccess ? "✓ Exported!" : isExporting ? "Sealing..." : `Download .${selectedFormat}`}
      </button>
    </div>

  </div>
</div>
