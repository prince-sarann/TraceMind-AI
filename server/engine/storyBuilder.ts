import type { AttackStoryStep, SecurityLogEvent } from '../../shared/types';
import type { CorrelatedCluster } from './correlation';

function mapStage(ev: SecurityLogEvent, idx: number, total: number): string {
  if (ev.eventType === 'login_failed') {
    return idx === 0 ? 'Initial Reconnaissance / Auth Probing' : 'Credential Access Attempt';
  }
  if (ev.eventType === 'login_success') {
    return 'Initial Access / Session Established';
  }
  if (ev.eventType === 'privilege_escalation') {
    return 'Privilege Escalation';
  }
  if (ev.eventType === 'data_export') {
    return 'Exfiltration / Collection';
  }
  if (ev.eventType === 'firewall_block') {
    return 'Lateral Movement Blocked';
  }
  if (ev.eventType === 'api_access') {
    return idx === total - 1 ? 'Post-Compromise Resource Access' : 'Discovery & API Access';
  }
  return 'Observed Activity';
}

function describeSignificance(ev: SecurityLogEvent): string {
  if (ev.eventType === 'login_failed') {
    return `Authentication rejected (HTTP ${ev.statusCode}) for ${ev.username} from ${ev.city}, ${ev.country} (${ev.asn}).`;
  }
  if (ev.eventType === 'login_success') {
    return `Authentication succeeded on ${ev.targetHost} from ${ev.sourceIp} (${ev.city}, ${ev.country}) using ${ev.userAgent}.`;
  }
  if (ev.eventType === 'privilege_escalation') {
    return `Elevated administrative permissions requested on ${ev.targetHost} under account ${ev.username}.`;
  }
  if (ev.eventType === 'data_export') {
    const mb = (ev.bytesTransferred / (1024 * 1024)).toFixed(1);
    return `Transferred ${mb} MB outbound from ${ev.targetHost} via ${ev.userAgent}.`;
  }
  if (ev.eventType === 'firewall_block') {
    return `Egress/lateral connection from ${ev.sourceIp} blocked at ${ev.targetHost} (HTTP ${ev.statusCode}).`;
  }
  const kb = Math.round(ev.bytesTransferred / 1024);
  return `Executed ${ev.eventType} against ${ev.targetHost} (${kb} KB transferred, status ${ev.statusCode}).`;
}

export function buildAttackStory(cluster: CorrelatedCluster): {
  title: string;
  steps: AttackStoryStep[];
  narrative: string;
} {
  const events = cluster.events;

  // Compress consecutive identical login_failed bursts from same IP+user while preserving first, peak, and all milestone events
  const selectedEvents: SecurityLogEvent[] = [];
  let consecutiveFailures = 0;

  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    const prev = i > 0 ? events[i - 1] : null;
    const isSameFailureBurst =
      ev.eventType === 'login_failed' &&
      prev?.eventType === 'login_failed' &&
      ev.sourceIp === prev.sourceIp &&
      ev.username === prev.username;

    if (isSameFailureBurst) {
      consecutiveFailures++;
      const next = i + 1 < events.length ? events[i + 1] : null;
      const isLastOfBurst =
        !next ||
        next.eventType !== 'login_failed' ||
        next.sourceIp !== ev.sourceIp ||
        next.username !== ev.username;
      if (isLastOfBurst && consecutiveFailures > 1) {
        selectedEvents.push(ev);
      }
    } else {
      consecutiveFailures = 0;
      selectedEvents.push(ev);
    }
  }

  const steps: AttackStoryStep[] = selectedEvents.map((ev, idx) => ({
    stepNumber: idx + 1,
    timestamp: ev.timestamp,
    stage: mapStage(ev, idx, selectedEvents.length),
    eventId: ev.id,
    actor: ev.username,
    sourceIp: ev.sourceIp,
    targetHost: ev.targetHost,
    action: ev.eventType,
    significance: describeSignificance(ev),
  }));

  const categories = Array.from(new Set(cluster.ruleHits.map((h) => h.category)));
  const primaryTitle =
    categories.includes('Privilege & Exfiltration')
      ? `Account Compromise & Data Exfiltration on ${cluster.affectedUsers[0]}`
      : categories.includes('Password Spray')
        ? `Distributed Password Spray & Service Pivot from ${cluster.primaryIp}`
        : categories.includes('Impossible Travel & IP Risk')
          ? `Impossible Travel Session Anomaly on ${cluster.affectedUsers[0]}`
          : categories.includes('Credential Compromise')
            ? `Brute-Force Credential Compromise on ${cluster.affectedUsers[0]}`
            : `Suspicious Activity Cluster from ${cluster.primaryIp}`;

  const first = events[0];
  const last = events[events.length - 1];
  const failedCount = events.filter((e) => e.eventType === 'login_failed').length;
  const successCount = events.filter((e) => e.eventType === 'login_success').length;
  const privCount = events.filter((e) => e.eventType === 'privilege_escalation').length;
  const exportBytes = events
    .filter((e) => e.eventType === 'data_export')
    .reduce((s, e) => s + e.bytesTransferred, 0);

  const parts: string[] = [
    `Between ${first.timestamp} and ${last.timestamp}, ${events.length} correlated security events were observed involving source IP ${cluster.primaryIp} (${first.city}, ${first.country}, ${first.asn}) and account(s) ${cluster.affectedUsers.join(', ')}.`,
  ];

  if (failedCount > 0) {
    parts.push(
      `The sequence included ${failedCount} failed authentication event(s) targeting ${Array.from(new Set(events.filter((e) => e.eventType === 'login_failed').map((e) => e.targetHost))).join(', ')}.`,
    );
  }
  if (successCount > 0) {
    parts.push(
      `${successCount} successful login event(s) followed on ${Array.from(new Set(events.filter((e) => e.eventType === 'login_success').map((e) => e.targetHost))).join(', ')}.`,
    );
  }
  if (privCount > 0) {
    parts.push(
      `Privilege escalation was recorded ${privCount} time(s) on ${Array.from(new Set(events.filter((e) => e.eventType === 'privilege_escalation').map((e) => e.targetHost))).join(', ')}.`,
    );
  }
  if (exportBytes > 0) {
    parts.push(
      `Outbound data export totaling ${(exportBytes / (1024 * 1024)).toFixed(1)} MB was logged against ${Array.from(new Set(events.filter((e) => e.eventType === 'data_export').map((e) => e.targetHost))).join(', ')}.`,
    );
  }

  parts.push(
    `Matched detection rules: ${cluster.ruleHits.map((h) => `${h.ruleId} (${h.ruleName})`).join('; ')}.`,
  );

  return {
    title: primaryTitle,
    steps,
    narrative: parts.join(' '),
  };
}
