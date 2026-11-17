import { ArrowUpRight } from 'lucide-react';
import type { Incident, WorkspaceSnapshot } from '../../shared/types';
import { ActivityTrendChart, GeoThreatMap } from '../components/Charts';
import { SeverityText, StatusText } from '../components/SeverityText';
import { KpiCard, SectionHeader, SocCard } from '../components/SocUi';

export function OverviewView({
  snapshot,
  analystName,
  onSelectIncident,
  onNavigate,
}: {
  snapshot: WorkspaceSnapshot;
  analystName: string;
  onSelectIncident: (inc: Incident) => void;
  onNavigate: (page: string) => void;
}) {
  const { analytics, incidents, modelEvaluation } = snapshot;

  const totalBySev =
    analytics.severityDistribution.Critical +
    analytics.severityDistribution.High +
    analytics.severityDistribution.Medium +
    analytics.severityDistribution.Low;

  const pct = (n: number) => (totalBySev > 0 ? Math.round((n / totalBySev) * 100) : 0);

  return (
    <div className="space-y-6">
      <div role="note" className="rounded-md border border-amber-900/50 bg-amber-950/20 px-3 py-2 text-xs text-amber-200">
        Demo environment: synthetic security events only. This workspace is not connected to live telemetry.
      </div>
      {/* Section 1: Security Overview */}
      <div>
        <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Security Overview
          </h2>
          <span className="text-xs text-slate-500">
            Active Analyst: <span className="text-slate-300 font-medium">{analystName}</span>
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          <KpiCard
            label="Events Analyzed"
            value={analytics.totalEvents.toLocaleString()}
            subvalue={`${analytics.suspiciousEventsCount} flagged`}
            caption={`Normalized across ${analytics.geoPoints.length} geographic regions`}
          />
          <KpiCard
            label="Critical Incidents"
            value={analytics.criticalIncidentsCount}
            subvalue={`${analytics.openIncidentsCount} open`}
            caption={`Mean risk score ${analytics.meanRiskScore}/100 across ${incidents.length} clusters`}
            valueColor="text-red-400"
          />
          <KpiCard
            label="Rule Detections"
            value={snapshot.ruleHits.length}
            subvalue="6 active rules"
            caption="MITRE Credential Access & Exfiltration coverage"
            valueColor="text-cyan-400"
          />
          <KpiCard
            label="Synthetic Model ROC-AUC"
            value={modelEvaluation.rocAucEstimate.toFixed(2)}
            subvalue={`F1 ${modelEvaluation.f1Score.toFixed(2)}`}
            caption={`Estimated on synthetic labels · ${modelEvaluation.benignAnomaliesIsolated} benign outlier(s) separated`}
            valueColor="text-blue-400"
          />
        </div>
      </div>

      {/* Section 2: Attack Timeline & Risk Assessment */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-stretch">
        <SocCard className="xl:col-span-8 flex flex-col justify-between">
          <SectionHeader
            title="Attack Timeline & Telemetry Velocity"
            subtitle="Two-hour UTC buckets comparing total events, failed logins, and correlated incident activity"
            action={
              <button
                type="button"
                onClick={() => onNavigate('logs')}
                className="min-h-[36px] px-2 text-xs font-medium text-blue-400 hover:text-blue-300 inline-flex items-center gap-1 whitespace-nowrap"
              >
                <span>Explore logs</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            }
          />
          <ActivityTrendChart data={analytics.hourlyTrends} />
        </SocCard>

        <SocCard className="xl:col-span-4 flex flex-col justify-between gap-5">
          <div>
            <SectionHeader
              title="Risk Assessment"
              subtitle="Severity mix across correlated clusters"
            />

            <div className="h-2.5 w-full rounded bg-slate-800 overflow-hidden flex">
              <div
                style={{ width: `${pct(analytics.severityDistribution.Critical)}%` }}
                className="bg-red-500"
              />
              <div
                style={{ width: `${pct(analytics.severityDistribution.High)}%` }}
                className="bg-orange-500"
              />
              <div
                style={{ width: `${pct(analytics.severityDistribution.Medium)}%` }}
                className="bg-amber-400"
              />
              <div
                style={{ width: `${pct(analytics.severityDistribution.Low)}%` }}
                className="bg-emerald-500"
              />
            </div>

            <div className="mt-4 grid grid-cols-2 gap-y-2.5 gap-x-4 text-xs">
              {(
                [
                  ['Critical', analytics.severityDistribution.Critical],
                  ['High', analytics.severityDistribution.High],
                  ['Medium', analytics.severityDistribution.Medium],
                  ['Low', analytics.severityDistribution.Low],
                ] as const
              ).map(([sev, count]) => (
                <div
                  key={sev}
                  className="flex items-center justify-between border-b border-slate-800/70 pb-1.5"
                >
                  <SeverityText severity={sev} />
                  <span className="font-mono tabular-nums text-slate-200">{count}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800">
            <h3 className="text-xs font-semibold text-slate-300 mb-2.5">
              Top High-Risk Source IPs
            </h3>
            <div className="space-y-2">
              {analytics.topSuspiciousIps.slice(0, 4).map((ip) => (
                <div
                  key={ip.ip}
                  className="flex items-center justify-between gap-3 text-xs py-1"
                >
                  <div className="min-w-0">
                    <div className="font-mono text-slate-200 truncate">{ip.ip}</div>
                    <div className="text-[11px] text-slate-500 truncate">
                      {ip.country} · {ip.failedLogins} failed
                    </div>
                  </div>
                  <div className="text-right font-mono tabular-nums shrink-0">
                    <span
                      className={
                        ip.reputationScore >= 80
                          ? 'text-red-400 font-semibold'
                          : ip.reputationScore >= 50
                            ? 'text-orange-400'
                            : 'text-slate-300'
                      }
                    >
                      {ip.reputationScore}/100
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </SocCard>
      </div>

      {/* Section 3: Threat Intelligence & Security Incidents */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start">
        <SocCard className="xl:col-span-7">
          <SectionHeader
            title="Threat Intelligence — Geographic IP Telemetry"
            subtitle="Source origin intelligence mapped by reputation score and suspicious event volume"
            action={
              <button
                type="button"
                onClick={() => onNavigate('graph')}
                className="min-h-[36px] px-2 text-xs font-medium text-blue-400 hover:text-blue-300 inline-flex items-center gap-1 whitespace-nowrap"
              >
                <span>Entity graph</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            }
          />
          <GeoThreatMap points={analytics.geoPoints} />
        </SocCard>

        <SocCard className="xl:col-span-5">
          <SectionHeader
            title="Security Incidents"
            subtitle="Select any incident to open full forensic investigation"
            action={
              <button
                type="button"
                onClick={() => onNavigate('incidents')}
                className="min-h-[36px] px-2 text-xs font-medium text-blue-400 hover:text-blue-300 inline-flex items-center gap-1 whitespace-nowrap"
              >
                <span>All incidents</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            }
          />

          {incidents.length === 0 ? (
            <div className="py-10 text-center text-sm text-slate-500">
              No correlated incidents detected under current thresholds.
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {incidents.map((inc) => (
                <button
                  key={inc.id}
                  type="button"
                  onClick={() => onSelectIncident(inc)}
                  className="w-full text-left py-3 px-2.5 rounded hover:bg-slate-800/40 transition-colors flex items-start justify-between gap-3 min-h-[56px]"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-400 font-mono">
                      <span>{inc.id}</span>
                      <span aria-hidden="true">·</span>
                      <SeverityText severity={inc.severity} />
                      <span aria-hidden="true">·</span>
                      <StatusText status={inc.status} />
                    </div>
                    <div className="mt-1 text-sm font-medium text-slate-100 leading-snug line-clamp-2">
                      {inc.title}
                    </div>
                    <div className="mt-0.5 text-xs text-slate-500 font-mono truncate">
                      {inc.primaryIp} · {inc.affectedUsers.join(', ')} · {inc.eventIds.length} events
                    </div>
                  </div>
                  <div className="text-right shrink-0 pl-2">
                    <div className="text-sm font-mono tabular-nums font-semibold text-slate-100">
                      {inc.riskScore}
                    </div>
                    <div className="text-[11px] text-slate-500">risk</div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </SocCard>
      </div>
    </div>
  );
}
