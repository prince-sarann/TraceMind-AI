import type {
  AuditLogEntry,
  DashboardAnalytics,
  GeoIntelligencePoint,
  HourlyTrendPoint,
  Incident,
  IncidentNote,
  PipelineSettings,
  SecurityLogEvent,
  WorkspaceSnapshot,
} from '../shared/types';
import type { IncidentStateRow } from './db/database';
import { buildRelationshipGraph, correlateEvents } from './engine/correlation';
import { runThreatDetection } from './engine/detection';
import { runIsolationForestDetection } from './engine/isolationForest';
import { scoreIncidentRisk } from './engine/riskScoring';
import { buildAttackStory } from './engine/storyBuilder';

export function runAnalysisPipeline(
  events: SecurityLogEvent[],
  settings: PipelineSettings,
  savedStates: Map<string, IncidentStateRow> = new Map(),
  savedNotes: Map<string, IncidentNote[]> = new Map(),
  auditLogs: AuditLogEntry[] = [],
): WorkspaceSnapshot {
  const ruleHits = runThreatDetection(events, settings);
  const { anomalies, evaluation } = runIsolationForestDetection(events, ruleHits, settings);
  const clusters = correlateEvents(events, ruleHits, anomalies);

  const incidents: Incident[] = clusters
    .map((cluster) => {
      const { riskScore, severity, factors } = scoreIncidentRisk(cluster, settings);
      const { title, steps, narrative } = buildAttackStory(cluster);
      const state = savedStates.get(cluster.clusterId);
      const notes = savedNotes.get(cluster.clusterId) ?? [];

      return {
        id: cluster.clusterId,
        title,
        severity,
        riskScore,
        status: state?.status ?? 'Open',
        assignedAnalyst: state?.assignedAnalyst ?? 'Unassigned',
        primaryIp: cluster.primaryIp,
        affectedUsers: cluster.affectedUsers,
        affectedHosts: cluster.affectedHosts,
        eventIds: cluster.events.map((e) => e.id),
        ruleHits: cluster.ruleHits,
        anomalyScores: cluster.anomalyResults,
        riskFactors: factors,
        attackStory: steps,
        narrative,
        firstSeen: cluster.events[0].timestamp,
        lastSeen: cluster.events[cluster.events.length - 1].timestamp,
        createdAt: cluster.events[0].timestamp,
        updatedAt: state?.updatedAt ?? cluster.events[cluster.events.length - 1].timestamp,
        notes,
      };
    })
    .sort((a, b) => b.riskScore - a.riskScore);

  const graph = buildRelationshipGraph(events, incidents);
  const analytics = computeDashboardAnalytics(events, incidents);

  return {
    events,
    ruleHits,
    anomalies,
    modelEvaluation: evaluation,
    incidents,
    graph,
    analytics,
    settings,
    auditLogs,
  };
}

function computeDashboardAnalytics(
  events: SecurityLogEvent[],
  incidents: Incident[],
): DashboardAnalytics {
  const suspiciousEventIds = new Set<string>();
  const incidentByIp = new Map<string, string>();
  for (const inc of incidents) {
    incidentByIp.set(inc.primaryIp, inc.id);
    for (const id of inc.eventIds) {
      suspiciousEventIds.add(id);
    }
  }

  const severityDistribution: DashboardAnalytics['severityDistribution'] = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  };
  for (const inc of incidents) {
    if (inc.severity === 'Critical') severityDistribution.Critical++;
    else if (inc.severity === 'High') severityDistribution.High++;
    else if (inc.severity === 'Medium') severityDistribution.Medium++;
    else severityDistribution.Low++;
  }

  // Top Suspicious IPs
  const ipMap = new Map<
    string,
    {
      ip: string;
      country: string;
      asn: string;
      eventCount: number;
      failedLogins: number;
      reputationScore: number;
      linkedIncidentId?: string;
    }
  >();

  for (const ev of events) {
    const existing = ipMap.get(ev.sourceIp);
    if (!existing) {
      ipMap.set(ev.sourceIp, {
        ip: ev.sourceIp,
        country: ev.country,
        asn: ev.asn,
        eventCount: 1,
        failedLogins: ev.eventType === 'login_failed' ? 1 : 0,
        reputationScore: ev.ipReputationScore,
        linkedIncidentId: incidentByIp.get(ev.sourceIp),
      });
    } else {
      existing.eventCount++;
      if (ev.eventType === 'login_failed') existing.failedLogins++;
      if (ev.ipReputationScore > existing.reputationScore) {
        existing.reputationScore = ev.ipReputationScore;
      }
    }
  }

  const topSuspiciousIps = Array.from(ipMap.values())
    .filter((i) => i.reputationScore >= 25 || i.failedLogins > 1 || Boolean(i.linkedIncidentId))
    .sort((a, b) => b.reputationScore - a.reputationScore || b.failedLogins - a.failedLogins)
    .slice(0, 6);

  // Hourly Trends (bucketed by 2-hour UTC intervals for clear visualization)
  const bucketMap = new Map<string, HourlyTrendPoint & { sortKey: number }>();
  for (const ev of events) {
    const d = new Date(ev.epochMs);
    const bucketHour = Math.floor(d.getUTCHours() / 2) * 2;
    const dayStr = d.toISOString().slice(5, 10);
    const label = `${dayStr} ${String(bucketHour).padStart(2, '0')}:00`;
    const sortKey = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), bucketHour);

    if (!bucketMap.has(label)) {
      bucketMap.set(label, {
        hourLabel: label,
        totalEvents: 0,
        failedLogins: 0,
        suspiciousEvents: 0,
        sortKey,
      });
    }
    const b = bucketMap.get(label)!;
    b.totalEvents++;
    if (ev.eventType === 'login_failed') b.failedLogins++;
    if (suspiciousEventIds.has(ev.id)) b.suspiciousEvents++;
  }
  const hourlyTrends = Array.from(bucketMap.values())
    .sort((a, b) => a.sortKey - b.sortKey)
    .map(({ hourLabel, totalEvents, failedLogins, suspiciousEvents }) => ({
      hourLabel,
      totalEvents,
      failedLogins,
      suspiciousEvents,
    }));

  // Geo Intelligence aggregation
  const geoMap = new Map<string, GeoIntelligencePoint>();
  for (const ev of events) {
    const key = `${ev.country}|${ev.city}`;
    const isSusp = suspiciousEventIds.has(ev.id);
    if (!geoMap.has(key)) {
      geoMap.set(key, {
        country: ev.country,
        city: ev.city,
        latitude: ev.latitude,
        longitude: ev.longitude,
        eventCount: 1,
        suspiciousCount: isSusp ? 1 : 0,
        maxReputationScore: ev.ipReputationScore,
        topIp: ev.sourceIp,
      });
    } else {
      const g = geoMap.get(key)!;
      g.eventCount++;
      if (isSusp) g.suspiciousCount++;
      if (ev.ipReputationScore > g.maxReputationScore) {
        g.maxReputationScore = ev.ipReputationScore;
        g.topIp = ev.sourceIp;
      }
    }
  }
  const geoPoints = Array.from(geoMap.values()).sort(
    (a, b) => b.suspiciousCount - a.suspiciousCount || b.eventCount - a.eventCount,
  );

  // Event type breakdown
  const typeMap = new Map<string, { count: number; suspiciousCount: number }>();
  for (const ev of events) {
    if (!typeMap.has(ev.eventType)) {
      typeMap.set(ev.eventType, { count: 0, suspiciousCount: 0 });
    }
    const t = typeMap.get(ev.eventType)!;
    t.count++;
    if (suspiciousEventIds.has(ev.id)) t.suspiciousCount++;
  }
  const eventTypeBreakdown = Array.from(typeMap.entries())
    .map(([eventType, stats]) => ({ eventType, ...stats }))
    .sort((a, b) => b.count - a.count);

  const openIncidentsCount = incidents.filter(
    (i) => i.status === 'Open' || i.status === 'Investigating',
  ).length;
  const criticalIncidentsCount = incidents.filter((i) => i.severity === 'Critical').length;
  const meanRiskScore =
    incidents.length > 0
      ? Math.round(incidents.reduce((s, i) => s + i.riskScore, 0) / incidents.length)
      : 0;

  return {
    totalEvents: events.length,
    suspiciousEventsCount: suspiciousEventIds.size,
    openIncidentsCount,
    criticalIncidentsCount,
    meanRiskScore,
    severityDistribution,
    topSuspiciousIps,
    hourlyTrends,
    geoPoints,
    eventTypeBreakdown,
  };
}
