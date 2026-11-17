import type { Incident } from '../../shared/types';
import { SeverityText, StatusText } from '../components/SeverityText';
import { SocCard } from '../components/SocUi';

export function AttackTimelineView({
  incidents,
  selectedIncidentId,
  onSelectIncidentId,
  onOpenInvestigation,
}: {
  incidents: Incident[];
  selectedIncidentId: string | null;
  onSelectIncidentId: (id: string) => void;
  onOpenInvestigation: (id: string) => void;
}) {
  const selected =
    incidents.find((i) => i.id === selectedIncidentId) ?? incidents[0] ?? null;

  if (!selected) {
    return (
      <SocCard className="p-12 text-center text-sm text-slate-500">
        No correlated attack timelines have been generated yet.
      </SocCard>
    );
  }

  return (
    <div className="space-y-5 min-w-0">
      <SocCard className="p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-400 mr-1">Attack Story:</span>
          {incidents.map((inc) => (
            <button
              key={inc.id}
              type="button"
              onClick={() => onSelectIncidentId(inc.id)}
              className={`min-h-[38px] px-3 py-1.5 text-xs font-mono rounded transition-colors ${
                selected.id === inc.id
                  ? 'bg-blue-600 text-white'
                  : 'bg-[#090D16] border border-slate-800 text-slate-300 hover:border-slate-700'
              }`}
            >
              {inc.id} ({inc.severity})
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={() => onOpenInvestigation(selected.id)}
          className="min-h-[38px] px-3.5 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded whitespace-nowrap self-start sm:self-auto"
        >
          Open Investigation Case
        </button>
      </SocCard>

      <SocCard className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-slate-400 font-mono">
              <span>{selected.id}</span>
              <span aria-hidden="true">·</span>
              <SeverityText severity={selected.severity} />
              <span aria-hidden="true">·</span>
              <StatusText status={selected.status} />
            </div>
            <h2 className="mt-1 text-base font-semibold text-slate-100 leading-snug">
              {selected.title}
            </h2>
          </div>
          <div className="text-left sm:text-right text-xs font-mono tabular-nums text-slate-400 shrink-0">
            <div>First seen: {selected.firstSeen.replace('T', ' ').slice(0, 19)} UTC</div>
            <div>Last seen: {selected.lastSeen.replace('T', ' ').slice(0, 19)} UTC</div>
          </div>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed bg-[#090D16] border border-slate-800/80 rounded p-3.5">
          {selected.narrative}
        </p>
      </SocCard>

      <SocCard>
        <h3 className="text-sm font-semibold text-slate-100 mb-4">
          Chronological Evidence Sequence ({selected.attackStory.length} milestones)
        </h3>

        <div className="divide-y divide-slate-800/80">
          {selected.attackStory.map((step) => (
            <div
              key={`${step.stepNumber}-${step.eventId}`}
              className="py-4 grid grid-cols-1 md:grid-cols-12 gap-3 items-start"
            >
              <div className="md:col-span-3 flex items-center gap-3">
                <span className="w-7 h-7 rounded bg-slate-800 text-slate-200 font-mono text-xs flex items-center justify-center shrink-0">
                  {step.stepNumber}
                </span>
                <div className="min-w-0">
                  <div className="text-xs font-mono tabular-nums text-cyan-300">
                    {step.timestamp.replace('T', ' ').slice(0, 19)}
                  </div>
                  <div className="text-[11px] font-mono text-slate-500">{step.eventId}</div>
                </div>
              </div>

              <div className="md:col-span-3">
                <div className="text-xs font-semibold text-slate-100">{step.stage}</div>
                <div className="text-xs font-mono text-slate-400 mt-0.5">{step.action}</div>
              </div>

              <div className="md:col-span-6 min-w-0">
                <div className="text-xs font-mono text-slate-300 break-all sm:break-normal">
                  {step.actor} @ {step.sourceIp} → {step.targetHost}
                </div>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">{step.significance}</p>
              </div>
            </div>
          ))}
        </div>
      </SocCard>
    </div>
  );
}
