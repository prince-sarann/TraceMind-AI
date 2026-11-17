import { useMemo, useState } from 'react';
import { ZoomIn, ZoomOut, RotateCcw } from 'lucide-react';
import type { GraphNode, RelationshipGraph } from '../../shared/types';

interface PositionedNode extends GraphNode {
  x: number;
  y: number;
}

const NODE_COLORS: Record<GraphNode['type'], string> = {
  incident: '#EF4444',
  ip: '#F97316',
  user: '#3B82F6',
  host: '#06B6D4',
  event: '#A855F7',
};

export function NetworkGraphCanvas({
  graph,
  selectedNodeId,
  onSelectNode,
  typeFilter,
  suspiciousOnly,
}: {
  graph: RelationshipGraph;
  selectedNodeId: string | null;
  onSelectNode: (node: GraphNode | null) => void;
  typeFilter: 'all' | GraphNode['type'];
  suspiciousOnly: boolean;
}) {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState<{ startX: number; startY: number; origX: number; origY: number } | null>(null);

  const { visibleNodes, visibleEdges } = useMemo(() => {
    const filteredEdges = suspiciousOnly
      ? graph.edges.filter((e) => e.isSuspicious)
      : graph.edges;

    const connectedToSusp = new Set<string>();
    for (const e of filteredEdges) {
      connectedToSusp.add(e.source);
      connectedToSusp.add(e.target);
    }

    let nodes = graph.nodes.filter((n) => {
      if (suspiciousOnly && !connectedToSusp.has(n.id)) return false;
      if (typeFilter !== 'all' && n.type !== typeFilter) return false;
      return true;
    });

    if (nodes.length > 70) {
      nodes = [...nodes].sort((a, b) => b.riskScore - a.riskScore || b.degree - a.degree).slice(0, 70);
    }

    const nodeSet = new Set(nodes.map((n) => n.id));
    const edges = filteredEdges.filter((e) => nodeSet.has(e.source) && nodeSet.has(e.target));

    const height = 520;
    const lanes: Record<GraphNode['type'], number> = {
      ip: 120,
      user: 320,
      incident: 500,
      host: 680,
      event: 820,
    };

    const grouped: Record<GraphNode['type'], GraphNode[]> = {
      ip: [],
      user: [],
      incident: [],
      host: [],
      event: [],
    };
    for (const n of nodes) grouped[n.type].push(n);

    const positioned: PositionedNode[] = [];
    (Object.keys(grouped) as GraphNode['type'][]).forEach((type) => {
      const list = grouped[type].sort((a, b) => b.riskScore - a.riskScore || a.label.localeCompare(b.label));
      const count = list.length;
      list.forEach((n, idx) => {
        const yStep = count > 1 ? (height - 100) / (count - 1) : 0;
        const y = count === 1 ? height / 2 : 50 + idx * yStep;
        const jitterX = (idx % 2 === 0 ? -16 : 16) * (count > 5 ? 1 : 0.4);
        positioned.push({
          ...n,
          x: lanes[type] + jitterX,
          y,
        });
      });
    });

    return { visibleNodes: positioned, visibleEdges: edges };
  }, [graph, typeFilter, suspiciousOnly]);

  const posMap = useMemo(() => {
    const map = new Map<string, PositionedNode>();
    for (const n of visibleNodes) map.set(n.id, n);
    return map;
  }, [visibleNodes]);

  const connectedNeighbors = useMemo(() => {
    const set = new Set<string>();
    if (!selectedNodeId) return set;
    set.add(selectedNodeId);
    for (const e of visibleEdges) {
      if (e.source === selectedNodeId) set.add(e.target);
      if (e.target === selectedNodeId) set.add(e.source);
    }
    return set;
  }, [selectedNodeId, visibleEdges]);

  return (
    <div className="relative bg-[#090D16] border border-slate-800 rounded-lg overflow-hidden min-w-0">
      <div className="flex flex-wrap items-center justify-between gap-3 px-3 sm:px-4 py-2.5 border-b border-slate-800 bg-[#0E1422]">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-slate-400">
          {(
            [
              ['ip', 'Source IP'],
              ['user', 'User Account'],
              ['incident', 'Incident'],
              ['host', 'Target Host'],
              ['event', 'Milestone Event'],
            ] as const
          ).map(([type, label]) => (
            <span key={type} className="inline-flex items-center gap-1.5 whitespace-nowrap">
              <span
                className="w-2.5 h-2.5 rounded-xs"
                style={{ backgroundColor: NODE_COLORS[type] }}
              />
              {label}
            </span>
          ))}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          <button
            type="button"
            onClick={() => setZoom((z) => Math.min(2.2, Number((z + 0.2).toFixed(2))))}
            className="min-w-[36px] min-h-[36px] flex items-center justify-center rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Zoom in"
            aria-label="Zoom in"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            type="button"
            onClick={() => setZoom((z) => Math.max(0.6, Number((z - 0.2).toFixed(2))))}
            className="min-w-[36px] min-h-[36px] flex items-center justify-center rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Zoom out"
            aria-label="Zoom out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            type="button"
            onClick={() => {
              setZoom(1);
              setPan({ x: 0, y: 0 });
            }}
            className="min-w-[36px] min-h-[36px] flex items-center justify-center rounded bg-slate-800/80 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Reset view"
            aria-label="Reset view"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      <svg
        viewBox="0 0 920 520"
        preserveAspectRatio="xMidYMid meet"
        className="w-full h-[280px] sm:h-[380px] lg:h-[480px] select-none cursor-grab active:cursor-grabbing touch-pan-y"
        onMouseDown={(e) =>
          setDragging({ startX: e.clientX, startY: e.clientY, origX: pan.x, origY: pan.y })
        }
        onMouseMove={(e) => {
          if (!dragging) return;
          setPan({
            x: dragging.origX + (e.clientX - dragging.startX),
            y: dragging.origY + (e.clientY - dragging.startY),
          });
        }}
        onMouseUp={() => setDragging(null)}
        onMouseLeave={() => setDragging(null)}
      >
        <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
          {visibleEdges.map((edge) => {
            const s = posMap.get(edge.source);
            const t = posMap.get(edge.target);
            if (!s || !t) return null;
            const highlighted =
              selectedNodeId &&
              (edge.source === selectedNodeId || edge.target === selectedNodeId);
            const dimmed = selectedNodeId && !highlighted;
            return (
              <line
                key={edge.id}
                x1={s.x}
                y1={s.y}
                x2={t.x}
                y2={t.y}
                stroke={edge.isSuspicious ? '#EF4444' : '#334155'}
                strokeOpacity={dimmed ? 0.12 : highlighted ? 0.9 : edge.isSuspicious ? 0.45 : 0.3}
                strokeWidth={highlighted ? 2 : edge.isSuspicious ? 1.4 : 1}
              />
            );
          })}

          {visibleNodes.map((node) => {
            const color = NODE_COLORS[node.type];
            const isSelected = selectedNodeId === node.id;
            const isDimmed = selectedNodeId !== null && !connectedNeighbors.has(node.id);
            const r = node.type === 'incident' ? 14 : Math.min(12, 6 + node.degree * 0.7);
            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                className="cursor-pointer"
                style={{ opacity: isDimmed ? 0.25 : 1 }}
                onClick={(e) => {
                  e.stopPropagation();
                  onSelectNode(isSelected ? null : node);
                }}
              >
                <circle r={r + 4} fill={color} fillOpacity={isSelected ? 0.28 : 0.1} />
                <circle
                  r={r}
                  fill={color}
                  stroke={isSelected ? '#F8FAFC' : '#090D16'}
                  strokeWidth={isSelected ? 2 : 1.5}
                />
                <text
                  y={r + 12}
                  textAnchor="middle"
                  className="fill-slate-200 text-[10px] font-mono pointer-events-none"
                >
                  {node.label.length > 20 ? `${node.label.slice(0, 18)}…` : node.label}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}
