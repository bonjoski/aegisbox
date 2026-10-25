<script lang="ts">
  import { onMount } from "svelte";
  import { DAGLayoutEngine, type DAGNode, type DAGEdge } from "../canvas/GraphLayout";

  let engine = new DAGLayoutEngine();
  let layoutNodes = $state<DAGNode[]>([]);
  let layoutEdges = $state<DAGEdge[]>([]);
  let selectedNode = $state<DAGNode | null>(null);

  onMount(() => {
    // Scaffold initial DAG execution trace: Agent Prompt -> read_file -> vetpkg -> run_command -> commit
    engine.addNode("prompt", "User Prompt", "agent_prompt", "completed");
    engine.addNode("read1", "read_file (package.json)", "read_file", "completed", { path: "package.json" });
    engine.addNode("vet", "argus:vetpkg", "vetpkg", "approved", { ecosystem: "npm", package: "express" });
    engine.addNode("exec", "run_command (npm test)", "run_command", "running", { cmd: "npm test" });
    engine.addNode("commit", "commit_gate", "commit_gate", "pending");

    engine.addEdge("prompt", "read1");
    engine.addEdge("read1", "vet");
    engine.addEdge("vet", "exec");
    engine.addEdge("exec", "commit");

    const layout = engine.computeLayout(550, 240);
    layoutNodes = layout.nodes;
    layoutEdges = layout.edges;
  });

  function getNodeColor(status: DAGNode["status"]): string {
    switch (status) {
      case "completed": return "fill-emerald-950 stroke-emerald-500 text-emerald-300";
      case "approved": return "fill-blue-950 stroke-blue-500 text-blue-300";
      case "running": return "fill-amber-950 stroke-amber-500 text-amber-300";
      case "denied": return "fill-red-950 stroke-red-500 text-red-300";
      default: return "fill-zinc-900 stroke-zinc-700 text-zinc-400";
    }
  }
</script>

<div class="h-full flex flex-col space-y-3 font-sans relative">
  <div class="flex items-center justify-between border-b border-zinc-800 pb-2">
    <span class="text-xs font-mono uppercase tracking-wider text-zinc-400">
      Agent Tool-Call Execution DAG
    </span>
    <span class="text-[10px] font-mono text-zinc-500">Click node to inspect</span>
  </div>

  <div class="flex-1 w-full bg-zinc-950/60 border border-zinc-800/80 rounded-xl overflow-hidden relative">
    <svg class="w-full h-full min-h-[260px]">
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#52525b" />
        </marker>
      </defs>

      <!-- Draw Edges -->
      {#each layoutEdges as edge}
        {@const fromNode = layoutNodes.find(n => n.id === edge.from)}
        {@const toNode = layoutNodes.find(n => n.id === edge.to)}
        {#if fromNode && toNode}
          <line
            x1={fromNode.x}
            y1={fromNode.y}
            x2={toNode.x}
            y2={toNode.y}
            stroke="#3f3f46"
            stroke-width="2"
            marker-end="url(#arrow)"
          />
        {/if}
      {/each}

      <!-- Draw Nodes -->
      {#each layoutNodes as node}
        <g
          class="cursor-pointer transition-transform hover:scale-105"
          onclick={() => selectedNode = node}
        >
          <circle
            cx={node.x}
            cy={node.y}
            r="16"
            class="{getNodeColor(node.status)} stroke-2 transition-all"
          />
          <text
            x={node.x}
            y={node.y + 26}
            text-anchor="middle"
            class="text-[10px] font-mono fill-zinc-300 pointer-events-none"
          >
            {node.label}
          </text>
        </g>
      {/each}
    </svg>
  </div>

  <!-- Click-to-Inspect Modal Dialog -->
  {#if selectedNode}
    <div class="absolute inset-0 z-20 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 rounded-xl">
      <div class="w-full max-w-sm bg-zinc-900 border border-zinc-700 rounded-xl p-4 space-y-3 shadow-xl">
        <div class="flex items-center justify-between border-b border-zinc-800 pb-2">
          <span class="text-xs font-bold font-mono text-zinc-100">{selectedNode.label}</span>
          <button
            type="button"
            class="text-zinc-400 hover:text-white text-xs cursor-pointer"
            onclick={() => selectedNode = null}
          >
            ✕
          </button>
        </div>

        <div class="text-xs font-mono space-y-1 text-zinc-300">
          <div><span class="text-zinc-500">Tool:</span> {selectedNode.toolName}</div>
          <div><span class="text-zinc-500">Status:</span> {selectedNode.status.toUpperCase()}</div>
          {#if selectedNode.args}
            <div class="pt-1">
              <span class="text-zinc-500 block mb-0.5">Arguments:</span>
              <pre class="bg-black/70 p-2 rounded text-[11px] text-emerald-400 overflow-x-auto">
{JSON.stringify(selectedNode.args, null, 2)}
              </pre>
            </div>
          {/if}
        </div>
      </div>
    </div>
  {/if}
</div>
