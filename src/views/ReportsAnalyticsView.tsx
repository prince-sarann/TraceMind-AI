import { Download, FileText } from 'lucide-react';
import type { WorkspaceSnapshot } from '../../shared/types';
import { SeverityText, StatusText } from '../components/SeverityText';
import { SectionHeader, SocCard } from '../components/SocUi';
import { exportEventsCsv, exportIncidentPdf, exportIncidentsCsv } from '../lib/api';

export function ReportsAnalyticsView({
  snapshot,
  onAuditExport,
}: {
  snapshot: WorkspaceSnapshot;
  onAuditExport: (format: 'CSV' | 'PDF', target: string) => void;
}) {
  const { analytics, incidents, events, auditLogs } = snapshot;

  return (
    <div className="space-y-6 min-w-0">
      <SocCard className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">
            Analytics and Reports
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Export normalized telemetry, correlated incident summaries, or formatted PDF case briefings
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => {
              exportEventsCsv(events);
              onAuditExport('CSV', 'normalized_events');
            }}
            className="min-h-[40px] inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded whitespace-nowrap"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Events CSV</span>
          </button>
          <button
            type="button"
            onClick={() => {
              exportIncidentsCsv(incidents);
              onAuditExport('CSV', 'correlated_incidents');
            }}
            className="min-h-[40px] inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded whitespace-nowrap"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Incidents CSV</span>
          </button>
          {incidents[0] && (
            <button
              type="button"
              onClick={() => {
                exportIncidentPdf(incidents[0], events);
                onAuditExport('PDF', incidents[0].id);
              }}
              className="min-h-[40px] inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white rounded whitespace-nowrap"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Export Top Incident PDF</span>
            </button>
          )}
        </div>
      </SocCard>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
        <SocCard className="xl:col-span-5">
          <SectionHeader
            title="Telemetry Event Type Breakdown"
            subtitle="Volume and flagged event ratios per action type"
          />
          <div className="space-y-3">
            {analytics.eventTypeBreakdown.map((item) => {
              const pct = analytics.totalEvents
                ? Math.round((item.count / analytics.totalEvents) * 100)
                : 0;
              return (
                <div key={item.eventType} className="space-y-1 text-xs">
                  <div className="flex flex-wrap justify-between gap-2 font-mono">
                    <span className="text-slate-200">{item.eventType}</span>
                    <span className="tabular-nums text-slate-400">
                      {item.count} ({item.suspiciousCount} flagged)
                    </span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded overflow-hidden">
                    <div className="h-full bg-cyan-500" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </SocCard>

        <SocCard className="xl:col-span-7">
          <SectionHeader
            title="Incident Case Register"
            subtitle="Download per-case forensic PDF reports"
          />
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs min-w-[540px]">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2 pr-3 font-medium">Case ID</th>
                  <th className="py-2 pr-3 font-medium">Severity</th>
                  <th className="py-2 pr-3 font-medium">Status</th>
                  <th className="py-2 pr-3 font-medium">Assignee</th>
                  <th className="py-2 pr-3 font-medium text-right">Risk</th>
                  <th className="py-2 font-medium text-right">Report</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {incidents.map((inc) => (
                  <tr key={inc.id}>
                    <td className="py-2.5 pr-3 font-mono text-slate-200 whitespace-nowrap">{inc.id}</td>
                    <td className="py-2.5 pr-3">
                      <SeverityText severity={inc.severity} />
                    </td>
                    <td className="py-2.5 pr-3">
                      <StatusText status={inc.status} />
                    </td>
                    <td className="py-2.5 pr-3 text-slate-300 whitespace-nowrap">{inc.assignedAnalyst}</td>
                    <td className="py-2.5 pr-3 text-right font-mono tabular-nums text-slate-100">
                      {inc.riskScore}/100
                    </td>
                    <td className="py-2.5 text-right">
                      <button
                        type="button"
                        onClick={() => {
                          exportIncidentPdf(inc, events);
                          onAuditExport('PDF', inc.id);
                        }}
                        className="min-h-[32px] px-2 text-blue-400 hover:text-blue-300 font-medium"
                      >
                        PDF
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SocCard>
      </div>

      <SocCard>
        <SectionHeader
          title={`Platform Security Audit Log (${auditLogs.length} entries)`}
          subtitle="Immutable SQLite trail of log ingestions, case updates, AI queries, and report exports"
        />
        <div className="overflow-x-auto max-h-72">
          <table className="w-full text-left text-xs min-w-[740px]">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2 pr-3 font-medium">Timestamp</th>
                <th className="py-2 pr-3 font-medium">Actor</th>
                <th className="py-2 pr-3 font-medium">Role</th>
                <th className="py-2 pr-3 font-medium">Action</th>
                <th className="py-2 pr-3 font-medium">Target</th>
                <th className="py-2 font-medium">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {auditLogs.map((log) => (
                <tr key={log.id}>
                  <td className="py-2 pr-3 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                    {log.timestamp.replace('T', ' ').slice(0, 19)}
                  </td>
                  <td className="py-2 pr-3 text-slate-200 whitespace-nowrap">{log.actor}</td>
                  <td className="py-2 pr-3 text-slate-400 whitespace-nowrap">{log.role}</td>
                  <td className="py-2 pr-3 font-mono text-cyan-300 whitespace-nowrap">{log.action}</td>
                  <td className="py-2 pr-3 font-mono text-slate-300 whitespace-nowrap">{log.target}</td>
                  <td className="py-2 text-slate-400">{log.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </SocCard>
    </div>
  );
}
