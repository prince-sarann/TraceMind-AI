import type {
  PipelineSettings,
  RiskFactor,
  SeverityLevel,
} from '../../shared/types';
import type { CorrelatedCluster } from './correlation';

const SEVERITY_VALUE: Record<SeverityLevel, number> = {
  Critical: 96,
  High: 78,
  Medium: 54,
  Low: 28,
  Info: 10,
};

export function scoreIncidentRisk(
  cluster: CorrelatedCluster,
  settings: PipelineSettings,
): { riskScore: number; severity: SeverityLevel; factors: RiskFactor[] } {
  const weights = settings.riskWeights;
  const weightSum =
    weights.severity +
    weights.frequency +
    weights.blastRadius +
    weights.sourceReputation +
    weights.correlationAndMl;
  const norm = weightSum > 0 ? 1 / weightSum : 1;

  // 1. Event Severity (max rule severity blended with event base severity)
  const maxRuleSev = cluster.ruleHits.reduce(
    (max, h) => Math.max(max, SEVERITY_VALUE[h.severity]),
    20,
  );
  const hasExfilOrPriv = cluster.events.some(
    (e) => e.eventType === 'privilege_escalation' || e.eventType === 'data_export',
  );
  const rawSeverityScore = Math.min(100, maxRuleSev + (hasExfilOrPriv ? 4 : 0));

  // 2. Frequency & Burst Velocity
  const evCount = cluster.events.length;
  const spanMin = Math.max(
    1,
    (cluster.events[evCount - 1].epochMs - cluster.events[0].epochMs) / 60_000,
  );
  const velocity = evCount / spanMin;
  const rawFrequencyScore = Math.min(100, Math.round(evCount * 5 + velocity * 32));

  // 3. Affected Users & Target Hosts (Blast Radius)
  const userCount = cluster.affectedUsers.length;
  const hostCount = cluster.affectedHosts.length;
  const rawBlastRadiusScore = Math.min(100, userCount * 15 + hostCount * 16);

  // 4. Source IP Reputation & External Risk
  const maxRep = cluster.events.reduce(
    (max, e) => Math.max(max, e.ipReputationScore),
    0,
  );
  const rawReputationScore = Math.min(100, maxRep);

  // 5. Correlated Attack Stages + ML Anomaly Consensus
  const uniqueCategories = new Set(cluster.ruleHits.map((h) => h.category)).size;
  const maxAnomaly = cluster.anomalyResults.reduce(
    (max, a) => Math.max(max, a.anomalyScore),
    0,
  );
  const rawCorrelationMlScore = Math.min(
    100,
    Math.round(uniqueCategories * 22 + maxAnomaly * 48),
  );

  const rawEntries: {
    factor: string;
    weight: number;
    rawScore: number;
    evidenceSummary: string;
  }[] = [
    {
      factor: 'Event & Rule Severity',
      weight: weights.severity * norm,
      rawScore: rawSeverityScore,
      evidenceSummary: `${cluster.ruleHits.length} rule hit(s) peaking at ${
        cluster.ruleHits.sort((a, b) => SEVERITY_VALUE[b.severity] - SEVERITY_VALUE[a.severity])[0]
          ?.severity ?? 'Medium'
      } severity${hasExfilOrPriv ? ' with privilege/exfiltration indicators' : ''}.`,
    },
    {
      factor: 'Frequency & Burst Velocity',
      weight: weights.frequency * norm,
      rawScore: rawFrequencyScore,
      evidenceSummary: `${evCount} correlated events within ${Math.round(spanMin)} minute(s) (${velocity.toFixed(2)} events/min).`,
    },
    {
      factor: 'Affected Accounts & Hosts',
      weight: weights.blastRadius * norm,
      rawScore: rawBlastRadiusScore,
      evidenceSummary: `${userCount} account(s) (${cluster.affectedUsers.slice(0, 3).join(', ')}) across ${hostCount} target host(s).`,
    },
    {
      factor: 'Source IP Reputation',
      weight: weights.sourceReputation * norm,
      rawScore: rawReputationScore,
      evidenceSummary: `Peak threat reputation score ${maxRep}/100 on ${cluster.primaryIp}.`,
    },
    {
      factor: 'Correlation Stages & ML Anomaly',
      weight: weights.correlationAndMl * norm,
      rawScore: rawCorrelationMlScore,
      evidenceSummary: `${uniqueCategories} distinct attack stage(s) corroborated by peak Isolation Forest score ${maxAnomaly.toFixed(2)}.`,
    },
  ];

  const factors: RiskFactor[] = rawEntries.map((entry) => ({
    factor: entry.factor,
    weightPct: Math.round(entry.weight * 100),
    rawScore: Math.round(entry.rawScore),
    weightedPoints: Number((entry.rawScore * entry.weight).toFixed(1)),
    evidenceSummary: entry.evidenceSummary,
  }));

  const riskScore = Math.min(
    100,
    Math.max(1, Math.round(factors.reduce((sum, f) => sum + f.weightedPoints, 0))),
  );

  let severity: SeverityLevel = 'Low';
  if (riskScore >= 80) severity = 'Critical';
  else if (riskScore >= 60) severity = 'High';
  else if (riskScore >= 35) severity = 'Medium';

  return { riskScore, severity, factors };
}
