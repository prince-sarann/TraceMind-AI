export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export type IncidentStatus = 'Open' | 'Investigating' | 'Contained' | 'Resolved';

export type EventType =
  | 'login_failed'
  | 'login_success'
  | 'privilege_escalation'
  | 'api_access'
  | 'data_export'
  | 'firewall_block'
  | 'mfa_challenge'
  | 'account_lockout'
  | 'process_exec';

export type AnalystRole = 'Lead SOC Analyst' | 'Tier-2 Responder' | 'Read-Only Auditor';

export interface SecurityLogEvent {
  id: string;
  timestamp: string; // ISO-8601 UTC
  epochMs: number;
  sourceIp: string;
  username: string;
  eventType: EventType;
  targetHost: string;
  statusCode: number;
  bytesTransferred: number;
  country: string;
  city: string;
  latitude: number;
  longitude: number;
  asn: string;
  ipReputationScore: number; // 0 (trusted internal) to 100 (known malicious / Tor exit)
  userAgent: string;
  rawSource: string;
  fingerprint: string;
  groundTruthLabel?: 'normal' | 'anomalous_benign' | 'malicious';
  baseSeverity: SeverityLevel;
}

export interface RejectedLogRecord {
  lineNumber: number;
  reason: string;
  rawPreview: string;
}

export interface IngestionSummary {
  totalSubmitted: number;
  acceptedCount: number;
  duplicateCount: number;
  rejectedCount: number;
  rejectedRecords: RejectedLogRecord[];
  sourceName: string;
  format: 'csv' | 'json';
  ingestedAt: string;
}

export interface DetectionRuleHit {
  id: string;
  ruleId: string;
  ruleName: string;
  category:
    | 'Brute Force'
    | 'Credential Compromise'
    | 'Password Spray'
    | 'Off-Hours Activity'
    | 'Impossible Travel & IP Risk'
    | 'Privilege & Exfiltration';
  mitreTactic: string;
  mitreTechnique: string;
  severity: SeverityLevel;
  confidence: number; // 0 - 100
  description: string;
  matchedEventIds: string[];
  primaryIp: string;
  affectedUsers: string[];
  firstSeen: string;
  lastSeen: string;
}

export interface EntityFeatureVector {
  entityKey: string;
  entityType: 'user' | 'ip';
  username?: string;
  sourceIp?: string;
  eventCount: number;
  failedLoginRatio: number;
  eventRatePerHour: number;
  distinctTargetUsers: number;
  distinctSourceIps: number;
  offHoursRatio: number;
  sensitiveActionRatio: number;
  avgIpReputation: number;
}

export interface FeatureContribution {
  feature: string;
  label: string;
  value: number;
  baselineMean: number;
  zScore: number;
}

export interface AnomalyEntityResult {
  entityKey: string;
  entityType: 'user' | 'ip';
  label: string;
  anomalyScore: number; // 0.0 - 1.0 (Isolation Forest score)
  classification: 'Normal' | 'Behavioural Anomaly' | 'Confirmed Malicious';
  isAnomalous: boolean;
  hasRuleMatch: boolean;
  matchedRuleIds: string[];
  eventIds: string[];
  features: EntityFeatureVector;
  topContributors: FeatureContribution[];
  explanation: string;
}

export interface ModelEvaluationMetrics {
  algorithm: string;
  nEstimators: number;
  sampleSize: number;
  contaminationThreshold: number;
  precision: number;
  recall: number;
  f1Score: number;
  accuracy: number;
  rocAucEstimate: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  benignAnomaliesIsolated: number;
}

export interface RiskFactor {
  factor: string;
  weightPct: number;
  rawScore: number;
  weightedPoints: number;
  evidenceSummary: string;
}

export interface AttackStoryStep {
  stepNumber: number;
  timestamp: string;
  stage: string;
  eventId: string;
  actor: string;
  sourceIp: string;
  targetHost: string;
  action: string;
  significance: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: SeverityLevel;
  riskScore: number; // 0 - 100
  status: IncidentStatus;
  assignedAnalyst: string;
  primaryIp: string;
  affectedUsers: string[];
  affectedHosts: string[];
  eventIds: string[];
  ruleHits: DetectionRuleHit[];
  anomalyScores: AnomalyEntityResult[];
  riskFactors: RiskFactor[];
  attackStory: AttackStoryStep[];
  narrative: string;
  firstSeen: string;
  lastSeen: string;
  createdAt: string;
  updatedAt: string;
  notes: IncidentNote[];
}

export interface IncidentNote {
  id: string;
  incidentId: string;
  author: string;
  role: AnalystRole;
  content: string;
  createdAt: string;
}

export interface GraphNode {
  id: string;
  type: 'user' | 'ip' | 'host' | 'incident' | 'event';
  label: string;
  sublabel: string;
  riskScore: number;
  severity: SeverityLevel;
  degree: number;
  metadata: Record<string, string | number>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation: string;
  weight: number;
  isSuspicious: boolean;
}

export interface RelationshipGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  componentCount: number;
  pivotNodes: { id: string; label: string; type: string; degree: number }[];
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  actor: string;
  role: AnalystRole;
  action: string;
  target: string;
  details: string;
}

export interface PipelineSettings {
  bruteForceThreshold: number;
  bruteForceWindowMin: number;
  sprayAccountThreshold: number;
  offHoursStartUtc: number;
  offHoursEndUtc: number;
  anomalyScoreThreshold: number;
  nEstimators: number;
  riskWeights: {
    severity: number;
    frequency: number;
    blastRadius: number;
    sourceReputation: number;
    correlationAndMl: number;
  };
}

export interface HourlyTrendPoint {
  hourLabel: string;
  totalEvents: number;
  failedLogins: number;
  suspiciousEvents: number;
}

export interface GeoIntelligencePoint {
  country: string;
  city: string;
  latitude: number;
  longitude: number;
  eventCount: number;
  suspiciousCount: number;
  maxReputationScore: number;
  topIp: string;
}

export interface DashboardAnalytics {
  totalEvents: number;
  suspiciousEventsCount: number;
  openIncidentsCount: number;
  criticalIncidentsCount: number;
  meanRiskScore: number;
  severityDistribution: Record<'Critical' | 'High' | 'Medium' | 'Low', number>;
  topSuspiciousIps: {
    ip: string;
    country: string;
    asn: string;
    eventCount: number;
    failedLogins: number;
    reputationScore: number;
    linkedIncidentId?: string;
  }[];
  hourlyTrends: HourlyTrendPoint[];
  geoPoints: GeoIntelligencePoint[];
  eventTypeBreakdown: { eventType: string; count: number; suspiciousCount: number }[];
}

export interface AiInvestigationResponse {
  incidentId: string;
  summary: string;
  whySuspicious: string[];
  supportingEvidence: { eventId: string; timestamp: string; detail: string }[];
  unverifiedHypotheses: string[];
  recommendedNextSteps: string[];
  containmentActions: string[];
  generatedAt: string;
  model: string;
}

export interface WorkspaceSnapshot {
  events: SecurityLogEvent[];
  ruleHits: DetectionRuleHit[];
  anomalies: AnomalyEntityResult[];
  modelEvaluation: ModelEvaluationMetrics;
  incidents: Incident[];
  graph: RelationshipGraph;
  analytics: DashboardAnalytics;
  settings: PipelineSettings;
  auditLogs: AuditLogEntry[];
  lastIngestion?: IngestionSummary;
}
