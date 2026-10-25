export interface DAGNode {
  id: string;
  label: string;
  toolName: string;
  status: "pending" | "running" | "approved" | "denied" | "completed";
  durationMs?: number;
  args?: Record<string, any>;
  x: number;
  y: number;
  layer: number;
}

export interface DAGEdge {
  from: string;
  to: string;
}

export class DAGLayoutEngine {
  private nodes: Map<string, DAGNode> = new Map();
  private edges: DAGEdge[] = [];

  public addNode(id: string, label: string, toolName: string, status: DAGNode["status"], args?: Record<string, any>): DAGNode {
    const existing = this.nodes.get(id);
    if (existing) {
      existing.status = status;
      if (args) existing.args = args;
      return existing;
    }

    const node: DAGNode = {
      id,
      label,
      toolName,
      status,
      args,
      x: 0,
      y: 0,
      layer: 0,
    };
    this.nodes.set(id, node);
    return node;
  }

  public addEdge(from: string, to: string): void {
    if (!this.edges.some((e) => e.from === from && e.to === to)) {
      this.edges.push({ from, to });
    }
  }

  // Compute hierarchical layout coordinates
  public computeLayout(viewportWidth: number, viewportHeight: number): { nodes: DAGNode[]; edges: DAGEdge[] } {
    // 1. Assign layers using topological ordering
    const inDegree: Map<string, number> = new Map();
    for (const node of this.nodes.values()) {
      inDegree.set(node.id, 0);
    }
    for (const edge of this.edges) {
      inDegree.set(edge.to, (inDegree.get(edge.to) || 0) + 1);
    }

    const queue: string[] = [];
    for (const [id, deg] of inDegree.entries()) {
      if (deg === 0) {
        queue.push(id);
        const n = this.nodes.get(id);
        if (n) n.layer = 0;
      }
    }

    while (queue.length > 0) {
      const curr = queue.shift()!;
      const currLayer = this.nodes.get(curr)?.layer || 0;

      for (const edge of this.edges) {
        if (edge.from === curr) {
          const target = this.nodes.get(edge.to);
          if (target) {
            target.layer = Math.max(target.layer, currLayer + 1);
          }
          const nextDeg = (inDegree.get(edge.to) || 1) - 1;
          inDegree.set(edge.to, nextDeg);
          if (nextDeg === 0) {
            queue.push(edge.to);
          }
        }
      }
    }

    // 2. Group by layer
    const layers: Map<number, DAGNode[]> = new Map();
    for (const node of this.nodes.values()) {
      if (!layers.has(node.layer)) {
        layers.set(node.layer, []);
      }
      layers.get(node.layer)!.push(node);
    }

    // 3. Assign x, y positions
    const maxLayer = Math.max(0, ...Array.from(layers.keys()));
    const xSpacing = Math.max(160, viewportWidth / (maxLayer + 2));

    for (const [layerIdx, layerNodes] of layers.entries()) {
      const ySpacing = Math.max(70, viewportHeight / (layerNodes.length + 1));
      const x = 60 + layerIdx * xSpacing;

      layerNodes.forEach((node, i) => {
        node.x = x;
        node.y = 50 + (i + 1) * ySpacing;
      });
    }

    return {
      nodes: Array.from(this.nodes.values()),
      edges: this.edges,
    };
  }

  public clear(): void {
    this.nodes.clear();
    this.edges = [];
  }
}
