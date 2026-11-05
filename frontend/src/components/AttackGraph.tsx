"use client";
import { Background, Controls, MarkerType, MiniMap, ReactFlow, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMemo } from "react";
import type { AttackPath, GraphEdge, GraphNode } from "@/lib/api";

const COLUMN: Record<GraphNode["type"], number> = { actor: 0, trigger: 1, job: 2, capability: 3, impact: 4 };
const STYLE: Record<GraphNode["type"], { bg: string; fg: string }> = {
  actor: { bg: "#b3261e", fg: "#fff" }, trigger: { bg: "#d9480f", fg: "#fff" }, job: { bg: "#2d3a8c", fg: "#fff" },
  capability: { bg: "#805ad5", fg: "#fff" }, impact: { bg: "#1d2433", fg: "#fff" },
};

export default function AttackGraph({ nodes, edges, highlight, pathOnly = false }: { nodes: GraphNode[]; edges: GraphEdge[]; highlight?: AttackPath | null; pathOnly?: boolean }) {
  const { rfNodes, rfEdges } = useMemo(() => {
    const onPath = new Set(highlight?.nodes || []);
    const pathEdges = new Set<string>();
    if (highlight) for (let i = 0; i < highlight.nodes.length - 1; i++) pathEdges.add(`${highlight.nodes[i]}→${highlight.nodes[i + 1]}`);
    if (pathOnly && highlight) {
      // focused view: the selected chain only, laid out left-to-right at readable size
      const byId = new Map(nodes.map((n) => [n.id, n]));
      const rfNodes: Node[] = highlight.nodes.map((id, i) => {
        const n = byId.get(id)!;
        return { id, position: { x: i * 250, y: (i % 2) * 70 }, data: { label: n?.label ?? id },
          style: { background: STYLE[n?.type ?? "job"].bg, color: "#fff", border: "none", borderRadius: 8, fontSize: 13, width: 210, padding: 10 } };
      });
      const rfEdges: Edge[] = edges.filter((e) => pathEdges.has(`${e.source}→${e.target}`)).map((e) => ({
        id: `${e.source}→${e.target}`, source: e.source, target: e.target, label: e.label.slice(0, 60), animated: true,
        markerEnd: { type: MarkerType.ArrowClosed }, style: { stroke: "#b3261e", strokeWidth: 2.5, strokeDasharray: e.gated ? "5 4" : undefined },
        labelStyle: { fontSize: 11 },
      }));
      return { rfNodes, rfEdges };
    }
    const rows: Record<number, number> = {};
    const rfNodes: Node[] = nodes.map((n) => {
      const col = COLUMN[n.type];
      const row = (rows[col] = (rows[col] ?? -1) + 1);
      const dim = highlight ? !onPath.has(n.id) : !n.on_path;
      return {
        id: n.id, position: { x: col * 260, y: row * 90 }, data: { label: n.label },
        style: { background: STYLE[n.type].bg, color: STYLE[n.type].fg, border: "none", borderRadius: 8, fontSize: 11, width: 210, padding: 8, opacity: dim ? 0.35 : 1 },
      };
    });
    const rfEdges: Edge[] = edges.map((e) => {
      const hot = pathEdges.has(`${e.source}→${e.target}`);
      return {
        id: `${e.source}→${e.target}`, source: e.source, target: e.target, label: e.findings.length ? e.label.slice(0, 48) : undefined,
        animated: hot, markerEnd: { type: MarkerType.ArrowClosed },
        style: { stroke: hot ? "#b3261e" : e.findings.length ? "#d9480f" : "#94a3b8", strokeWidth: hot ? 2.5 : 1.2, strokeDasharray: e.gated ? "5 4" : undefined },
        labelStyle: { fontSize: 10 },
      };
    });
    return { rfNodes, rfEdges };
  }, [nodes, edges, highlight, pathOnly]);
  return (
    <div className="graph-wrap" style={pathOnly ? { height: 300 } : undefined}>
      <ReactFlow key={`${pathOnly}-${highlight?.id}`} nodes={rfNodes} edges={rfEdges} fitView minZoom={0.2} nodesConnectable={false} proOptions={{ hideAttribution: true }}>
        <Background /><Controls showInteractive={false} />{!pathOnly && <MiniMap pannable zoomable />}
      </ReactFlow>
    </div>
  );
}
