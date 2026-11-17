import { useState } from 'react';
import type { GraphNode, RelationshipGraph } from '../../shared/types';
import { NetworkGraphCanvas } from '../components/NetworkGraphCanvas';
import { SeverityText } from '../components/SeverityText';
import { SocCard } from '../components/SocUi';

export function RelationshipGraphView({ graph }: { graph: RelationshipGraph }) {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [typeFilter, setTypeFilter] = useState<'all' | GraphNode['type']>('all');
  const [suspiciousOnly, setSuspiciousOnly] = useState(true);

  const connectedEdges = selectedNode
    ? graph.edges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
    : [];

  return (
    <div className="space-y-5 min-w-0">
      <SocCard className="p-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex flex-wrap items-center gap-1 p-1 bg-[#090D16] border border-slate-800 rounded-md">
            {(
              [
                ['all', 'All Entities'],
                ['incident', 'Incidents'],
                ['ip', 'Source IPs'],
                ['user', 'Accounts'],
                ['host', 'Target Hosts'],
                ['event', 'Events'],
              ] as const
            ).map(([t, label]) => (
              <button
                key={t}
                type="button"
                onClick={() => setTypeFilter(t)}
                className={`min-h-[34px] px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap ${
                  typeFilter === t ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() => setSuspiciousOnly((v) => !v)}
            className={`min-h-[38px] px-3 py-1.5 text-xs font-medium rounded border transition-colors whitespace-nowrap ${
              suspiciousOnly
                ? 'bg-red-950/30 border-red-800/70 text-red-300'
                : 'bg-[#090D16] border-slate-800 text-slate-300'
            }`}
          >
            {suspiciousOnly ? 'Suspicious Subgraph Only' : 'Full Telemetry Graph'}
          </button>
        </div>

        <div className="text-xs font-mono tabular-nums text-slate-400">
          Nodes {graph.nodes.length} · Edges {graph.edges.length} · Components {graph.componentCount}
        </div>
      </SocCard>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
        <div className="xl:col-span-8 min-w-0">
          <NetworkGraphCanvas
            graph={graph}
            selectedNodeId={selectedNode?.id ?? null}
            onSelectNode={setSelectedNode}
            typeFilter={typeFilter}
            suspiciousOnly={suspiciousOnly}
          />
        </div>

        <div className="xl:col-span-4 space-y-5 min-w-0">
          <SocCard>
            <h2 className="text-sm font-semibold text-slate-100">Entity Inspector</h2>
            {!selectedNode ? (
              <p className="text-xs text-slate-500 mt-2 leading-relaxed">
                Click or tap any node in the graph to inspect degree centrality, risk score, and correlated edges.
              </p>
            ) : (
              <div className="mt-3 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs uppercase font-mono text-cyan-400">
                    {selectedNode.type}
                  </span>
                  <SeverityText severity={selectedNode.severity} />
                </div>
                <div>
                  <div className="text-sm font-mono font-semibold text-slate-100 break-all">
                    {selectedNode.label}
                  </div>
                  <div className="text-xs text-slate-400 mt-0.5">{selectedNode.sublabel}</div>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono tabular-nums bg-[#090D16] border border-slate-800 rounded p-2.5">
                  <div>
                    <span className="text-slate-500 block text-[11px]">Degree</span>
                    <span className="text-slate-100">{selectedNode.degree}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[11px]">Risk Score</span>
                    <span className="text-slate-100">{selectedNode.riskScore}/100</span>
                  </div>
                </div>

                {connectedEdges.length > 0 && (
                  <div>
                    <div className="text-xs font-medium text-slate-300 mb-1.5">
                      Connected Relationships ({connectedEdges.length})
                    </div>
                    <div className="max-h-44 overflow-y-auto divide-y divide-slate-800/60 text-[11px] font-mono">
                      {connectedEdges.slice(0, 12).map((e) => {
                        const peer = e.source === selectedNode.id ? e.target : e.source;
                        return (
                          <div key={e.id} className="py-1.5 flex items-center justify-between gap-2">
                            <span className="text-slate-300 truncate">{peer}</span>
                            <span className={e.isSuspicious ? 'text-red-400 shrink-0' : 'text-slate-500 shrink-0'}>
                              {e.relation} (×{e.weight})
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}
          </SocCard>

          <SocCard>
            <h3 className="text-sm font-semibold text-slate-100 mb-3">
              Top Graph Pivot Nodes
            </h3>
            <div className="divide-y divide-slate-800/70 text-xs">
              {graph.pivotNodes.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => {
                    const match = graph.nodes.find((n) => n.id === p.id);
                    if (match) setSelectedNode(match);
                  }}
                  className="w-full min-h-[44px] py-2 flex items-center justify-between hover:bg-slate-800/35 px-2.5 rounded text-left"
                >
                  <div className="min-w-0 pr-2">
                    <div className="font-mono text-slate-200 truncate">{p.label}</div>
                    <div className="text-[11px] text-slate-500 uppercase">{p.type}</div>
                  </div>
                  <span className="font-mono tabular-nums text-cyan-300 shrink-0">
                    deg {p.degree}
                  </span>
                </button>
              ))}
            </div>
          </SocCard>
        </div>
      </div>
    </div>
  );
}
