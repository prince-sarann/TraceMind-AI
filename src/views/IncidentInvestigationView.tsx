import { useState } from 'react';
import { FileText, Download, MessageSquarePlus, ArrowUpRight } from 'lucide-react';
import type {
  Incident,
  IncidentStatus,
  SecurityLogEvent,
} from '../../shared/types';
import { SeverityText, StatusText } from '../components/SeverityText';
import { SocCard } from '../components/SocUi';
import { exportIncidentPdf, exportIncidentsCsv } from '../lib/api';

const ANALYSTS = [
  'Unassigned',
  'Prince Kumar Saran',
  'Priya Nair',
  'Lucas Meyer',
  'Elena Rostova',
];

export function IncidentInvestigationView({
  incidents,
  events,
  selectedIncidentId,
  onSelectIncidentId,
  onUpdateStatus,
  onAddNote,
  onOpenAiBrief,
  onAuditExport,
}: {
  incidents: Incident[];
  events: SecurityLogEvent[];
  selectedIncidentId: string | null;
  onSelectIncidentId: (id: string) => void;
  onUpdateStatus: (id: string, status: IncidentStatus, assignee: string) => Promise<void>;
  onAddNote: (id: string, content: string) => Promise<void>;
  onOpenAiBrief: (id: string) => void;
  onAuditExport: (format: 'CSV' | 'PDF', target: string) => void;
}) {
  const [statusFilter, setStatusFilter] = useState<'All' | IncidentStatus>('All');
  const [noteInput, setNoteInput] = useState('');
  const [saving, setSaving] = useState(false);

  const visibleIncidents = incidents.filter(
    (i) => statusFilter === 'All' || i.status === statusFilter,
  );
  const selected =
    visibleIncidents.find((i) => i.id === selectedIncidentId) ?? visibleIncidents[0] ?? null;

  const matchedEvents = selected
    ? events.filter((e) => selected.eventIds.includes(e.id))
    : [];

  const handleStatusChange = async (status: IncidentStatus, assignee: string) => {
    if (!selected) return;
    setSaving(true);
    try {
      await onUpdateStatus(selected.id, status, assignee);
    } finally {
      setSaving(false);
    }
  };

  const handleNoteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selected || !noteInput.trim()) return;
    setSaving(true);
    try {
      await onAddNote(selected.id, noteInput.trim());
      setNoteInput('');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start min-w-0">
      {/* Left Incident Queue */}
      <SocCard className="xl:col-span-4 space-y-4">
        <div className="flex items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-slate-100">Security Incidents</h2>
          <button
            type="button"
            onClick={() => {
              exportIncidentsCsv(incidents);
              onAuditExport('CSV', 'all_incidents');
            }}
            className="min-h-[36px] px-2 text-xs text-blue-400 hover:text-blue-300 inline-flex items-center gap-1 whitespace-nowrap"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export All CSV</span>
          </button>
        </div>

        <div className="flex flex-wrap gap-1 p-1 bg-[#090D16] border border-slate-800 rounded-md">
          {(['All', 'Open', 'Investigating', 'Contained', 'Resolved'] as const).map((st) => (
            <button
              key={st}
              type="button"
              onClick={() => setStatusFilter(st)}
              className={`min-h-[34px] px-2.5 py-1 text-[11px] font-medium rounded transition-colors ${
                statusFilter === st ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        <div className="divide-y divide-slate-800/70">
          {visibleIncidents.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-500">
              No incidents match this status filter.
            </div>
          ) : (
            visibleIncidents.map((inc) => {
              const isActive = selected?.id === inc.id;
              return (
                <button
                  key={inc.id}
                  type="button"
                  onClick={() => onSelectIncidentId(inc.id)}
                  className={`w-full text-left py-3 px-2.5 rounded transition-colors min-h-[64px] ${
                    isActive ? 'bg-slate-800/70' : 'hover:bg-slate-800/35'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-slate-400">{inc.id}</span>
                    <span className="font-mono tabular-nums font-semibold text-slate-100">
                      Risk {inc.riskScore}/100
                    </span>
                  </div>
                  <div className="mt-1 text-sm font-medium text-slate-100 line-clamp-2">
                    {inc.title}
                  </div>
                  <div className="mt-1.5 flex items-center justify-between text-xs">
                    <SeverityText severity={inc.severity} />
                    <StatusText status={inc.status} />
                  </div>
                </button>
              );
            })
          )}
        </div>
      </SocCard>

      {/* Right Incident Drill-Down Workbench */}
      <div className="xl:col-span-8 space-y-5 min-w-0">
        {!selected ? (
          <SocCard className="p-10 text-center text-sm text-slate-500">
            Select an incident from the queue to open the investigation workbench.
          </SocCard>
        ) : (
          <>
            <SocCard className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs font-mono text-slate-400">
                    <span>{selected.id}</span>
                    <span aria-hidden="true">·</span>
                    <SeverityText severity={selected.severity} />
                    <span aria-hidden="true">·</span>
                    <span>IP {selected.primaryIp}</span>
                  </div>
                  <h2 className="mt-1.5 text-base sm:text-lg font-semibold text-slate-100 leading-snug">
                    {selected.title}
                  </h2>
                </div>

                <div className="flex flex-wrap items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => onOpenAiBrief(selected.id)}
                    className="min-h-[40px] inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white rounded-md transition-colors whitespace-nowrap"
                  >
                    <span>Investigate with AI</span>
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      exportIncidentPdf(selected, events);
                      onAuditExport('PDF', selected.id);
                    }}
                    className="min-h-[40px] inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md transition-colors whitespace-nowrap"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    <span>Export PDF</span>
                  </button>
                </div>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">{selected.narrative}</p>

              <div className="pt-3 border-t border-slate-800 grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">
                    Investigation Status
                  </label>
                  <select
                    disabled={saving}
                    value={selected.status}
                    onChange={(e) =>
                      handleStatusChange(e.target.value as IncidentStatus, selected.assignedAnalyst)
                    }
                    className="w-full min-h-[40px] bg-[#090D16] border border-slate-800 rounded px-2.5 py-2 text-xs text-slate-100"
                  >
                    <option value="Open">Open</option>
                    <option value="Investigating">Investigating</option>
                    <option value="Contained">Contained</option>
                    <option value="Resolved">Resolved</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">
                    Assigned Analyst
                  </label>
                  <select
                    disabled={saving}
                    value={selected.assignedAnalyst}
                    onChange={(e) => handleStatusChange(selected.status, e.target.value)}
                    className="w-full min-h-[40px] bg-[#090D16] border border-slate-800 rounded px-2.5 py-2 text-xs text-slate-100"
                  >
                    {ANALYSTS.map((name) => (
                      <option key={name} value={name}>
                        {name}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-[11px] text-slate-400 mb-1">
                    Blast Radius
                  </label>
                  <div className="min-h-[40px] flex items-center bg-[#090D16] border border-slate-800 rounded px-2.5 py-2 text-xs font-mono text-slate-300 truncate">
                    {selected.affectedUsers.length} user(s) · {selected.affectedHosts.length} host(s)
                  </div>
                </div>
              </div>
            </SocCard>

            {/* Risk Assessment Breakdown */}
            <SocCard>
              <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
                <div>
                  <h3 className="text-sm font-semibold text-slate-100">
                    Risk Assessment Decomposition
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Transparent weighted contribution explaining why {selected.id} scored {selected.riskScore}/100
                  </p>
                </div>
                <span className="text-2xl font-mono tabular-nums font-bold text-slate-100">
                  {selected.riskScore}
                  <span className="text-xs font-normal text-slate-500">/100</span>
                </span>
              </div>

              <div className="space-y-3">
                {selected.riskFactors.map((f) => (
                  <div key={f.factor} className="space-y-1">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                      <span className="text-slate-200 font-medium">
                        {f.factor}{' '}
                        <span className="text-slate-500 font-mono">({f.weightPct}% weight)</span>
                      </span>
                      <span className="font-mono tabular-nums text-cyan-300">
                        +{f.weightedPoints.toFixed(1)} pts (raw {f.rawScore})
                      </span>
                    </div>
                    <div className="h-1.5 w-full bg-slate-800 rounded overflow-hidden">
                      <div
                        className="h-full bg-blue-500"
                        style={{ width: `${Math.min(100, f.rawScore)}%` }}
                      />
                    </div>
                    <div className="text-[11px] text-slate-400">{f.evidenceSummary}</div>
                  </div>
                ))}
              </div>
            </SocCard>

            {/* Supporting Events Table */}
            <SocCard>
              <h3 className="text-sm font-semibold text-slate-100 mb-3">
                Correlated Evidence Events ({matchedEvents.length})
              </h3>
              <div className="overflow-x-auto max-h-64">
                <table className="w-full text-left text-xs min-w-[600px]">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2 pr-3 font-medium">ID</th>
                      <th className="py-2 pr-3 font-medium">Timestamp</th>
                      <th className="py-2 pr-3 font-medium">Event</th>
                      <th className="py-2 pr-3 font-medium">User</th>
                      <th className="py-2 pr-3 font-medium">Source IP</th>
                      <th className="py-2 font-medium">Host</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {matchedEvents.map((ev) => (
                      <tr key={ev.id}>
                        <td className="py-2 pr-3 font-mono text-slate-300 whitespace-nowrap">{ev.id}</td>
                        <td className="py-2 pr-3 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                          {ev.timestamp.replace('T', ' ').slice(0, 19)}
                        </td>
                        <td className="py-2 pr-3 font-mono text-slate-200 whitespace-nowrap">{ev.eventType}</td>
                        <td className="py-2 pr-3 text-slate-200 whitespace-nowrap">{ev.username}</td>
                        <td className="py-2 pr-3 font-mono text-cyan-300 whitespace-nowrap">{ev.sourceIp}</td>
                        <td className="py-2 font-mono text-slate-300 whitespace-nowrap">{ev.targetHost}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </SocCard>

            {/* Persistent Analyst Notes */}
            <SocCard className="space-y-4">
              <h3 className="text-sm font-semibold text-slate-100">
                Analyst Investigation Notes ({selected.notes.length})
              </h3>

              <form onSubmit={handleNoteSubmit} className="flex flex-col sm:flex-row gap-2">
                <input
                  type="text"
                  value={noteInput}
                  onChange={(e) => setNoteInput(e.target.value)}
                  placeholder="Document triage findings, IOC validation, or containment actions..."
                  className="flex-1 min-h-[40px] bg-[#090D16] border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                />
                <button
                  type="submit"
                  disabled={saving || !noteInput.trim()}
                  className="min-h-[40px] inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-medium bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded whitespace-nowrap"
                >
                  <MessageSquarePlus className="w-3.5 h-3.5" />
                  <span>Add Note</span>
                </button>
              </form>

              {selected.notes.length > 0 && (
                <div className="space-y-2.5">
                  {selected.notes.map((n) => (
                    <div key={n.id} className="bg-[#090D16] border border-slate-800/80 rounded p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-400">
                        <span className="font-medium text-slate-200">
                          {n.author} · {n.role}
                        </span>
                        <span className="font-mono tabular-nums">
                          {n.createdAt.replace('T', ' ').slice(0, 19)} UTC
                        </span>
                      </div>
                      <p className="mt-1.5 text-xs text-slate-300 leading-relaxed">{n.content}</p>
                    </div>
                  ))}
                </div>
              )}
            </SocCard>
          </>
        )}
      </div>
    </div>
  );
}
