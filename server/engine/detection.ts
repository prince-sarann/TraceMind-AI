import type { DetectionRuleHit, PipelineSettings, SecurityLogEvent } from '../../shared/types';

function haversineKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371;
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function isOffHoursUtc(epochMs: number, startHour: number, endHour: number): boolean {
  const hour = new Date(epochMs).getUTCHours();
  if (startHour <= endHour) {
    return hour >= startHour && hour < endHour;
  }
  return hour >= startHour || hour < endHour;
}

export function runThreatDetection(
  events: SecurityLogEvent[],
  settings: PipelineSettings,
): DetectionRuleHit[] {
  const sorted = [...events].sort((a, b) => a.epochMs - b.epochMs);
  const hits: DetectionRuleHit[] = [];
  let hitSeq = 1;
  const nextHitId = () => `HIT-${String(hitSeq++).padStart(3, '0')}`;

  // Group events by sourceIp
  const byIp = new Map<string, SecurityLogEvent[]>();
  const byUser = new Map<string, SecurityLogEvent[]>();

  for (const ev of sorted) {
    if (!byIp.has(ev.sourceIp)) byIp.set(ev.sourceIp, []);
    byIp.get(ev.sourceIp)!.push(ev);

    if (!byUser.has(ev.username)) byUser.set(ev.username, []);
    byUser.get(ev.username)!.push(ev);
  }

  const windowMs = settings.bruteForceWindowMin * 60_000;

  // R-001: Brute-force login attempts per IP & R-002: Repeated Failures followed by Compromise
  for (const [ip, ipEvents] of byIp.entries()) {
    const failed = ipEvents.filter((e) => e.eventType === 'login_failed');
    if (failed.length >= settings.bruteForceThreshold) {
      // Sliding window check
      let left = 0;
      let maxBurst: SecurityLogEvent[] = [];
      for (let right = 0; right < failed.length; right++) {
        while (failed[right].epochMs - failed[left].epochMs > windowMs) {
          left++;
        }
        if (right - left + 1 > maxBurst.length) {
          maxBurst = failed.slice(left, right + 1);
        }
      }

      if (maxBurst.length >= settings.bruteForceThreshold) {
        const affectedUsers = Array.from(new Set(maxBurst.map((e) => e.username)));
        hits.push({
          id: nextHitId(),
          ruleId: 'R-001',
          ruleName: 'Brute-Force Authentication Burst',
          category: 'Brute Force',
          mitreTactic: 'Credential Access',
          mitreTechnique: 'T1110.001 Password Guessing',
          severity: maxBurst.length >= settings.bruteForceThreshold * 2 ? 'High' : 'Medium',
          confidence: Math.min(98, 72 + maxBurst.length * 2),
          description: `Detected ${maxBurst.length} failed authentication attempts from ${ip} within ${settings.bruteForceWindowMin} minutes targeting ${affectedUsers.join(', ')}.`,
          matchedEventIds: maxBurst.map((e) => e.id),
          primaryIp: ip,
          affectedUsers,
          firstSeen: maxBurst[0].timestamp,
          lastSeen: maxBurst[maxBurst.length - 1].timestamp,
        });

        // Check R-002: Credential Compromise (success after repeated failures from same IP)
        const lastFailEpoch = maxBurst[maxBurst.length - 1].epochMs;
        const successes = ipEvents.filter(
          (e) =>
            e.eventType === 'login_success' &&
            e.epochMs >= maxBurst[0].epochMs &&
            e.epochMs <= lastFailEpoch + 30 * 60_000,
        );
        if (successes.length > 0) {
          const compromisedUsers = Array.from(new Set(successes.map((e) => e.username)));
          const matchedIds = Array.from(
            new Set([...maxBurst.map((e) => e.id), ...successes.map((e) => e.id)]),
          );
          hits.push({
            id: nextHitId(),
            ruleId: 'R-002',
            ruleName: 'Suspected Credential Compromise After Failures',
            category: 'Credential Compromise',
            mitreTactic: 'Initial Access',
            mitreTechnique: 'T1078 Valid Accounts',
            severity: 'Critical',
            confidence: 95,
            description: `Source IP ${ip} achieved successful authentication for ${compromisedUsers.join(', ')} immediately following ${maxBurst.length} failed login attempts.`,
            matchedEventIds: matchedIds,
            primaryIp: ip,
            affectedUsers: compromisedUsers,
            firstSeen: maxBurst[0].timestamp,
            lastSeen: successes[successes.length - 1].timestamp,
          });
        }
      }
    }

    // R-003: Password Spraying (1 IP targeting >= sprayAccountThreshold distinct accounts)
    const distinctFailedUsers = Array.from(new Set(failed.map((e) => e.username)));
    if (distinctFailedUsers.length >= settings.sprayAccountThreshold) {
      hits.push({
        id: nextHitId(),
        ruleId: 'R-003',
        ruleName: 'Multi-Account Password Spraying',
        category: 'Password Spray',
        mitreTactic: 'Credential Access',
        mitreTechnique: 'T1110.003 Password Spraying',
        severity: 'High',
        confidence: 91,
        description: `Single source IP ${ip} attempted authentication across ${distinctFailedUsers.length} distinct accounts (${distinctFailedUsers.slice(0, 4).join(', ')}${distinctFailedUsers.length > 4 ? ', ...' : ''}).`,
        matchedEventIds: failed.map((e) => e.id),
        primaryIp: ip,
        affectedUsers: distinctFailedUsers,
        firstSeen: failed[0].timestamp,
        lastSeen: failed[failed.length - 1].timestamp,
      });
    }
  }

  // R-004: Off-Hours Sensitive Authentication / Privilege Execution (excludes internal zero-failure CI bots unless privilege_escalation/data_export)
  for (const [ip, ipEvents] of byIp.entries()) {
    const sensitiveOffHours = ipEvents.filter(
      (e) =>
        isOffHoursUtc(e.epochMs, settings.offHoursStartUtc, settings.offHoursEndUtc) &&
        (e.eventType === 'privilege_escalation' ||
          e.eventType === 'data_export' ||
          (e.eventType === 'login_success' && e.ipReputationScore >= 50)),
    );

    if (sensitiveOffHours.length > 0) {
      const affectedUsers = Array.from(new Set(sensitiveOffHours.map((e) => e.username)));
      hits.push({
        id: nextHitId(),
        ruleId: 'R-004',
        ruleName: 'Suspicious Off-Hours Privileged or External Login',
        category: 'Off-Hours Activity',
        mitreTactic: 'Persistence',
        mitreTechnique: 'T1078.004 Cloud & Domain Accounts',
        severity: sensitiveOffHours.some((e) => e.eventType === 'privilege_escalation') ? 'High' : 'Medium',
        confidence: 84,
        description: `Observed ${sensitiveOffHours.length} high-risk or privileged event(s) during restricted UTC window (${String(settings.offHoursStartUtc).padStart(2, '0')}:00–${String(settings.offHoursEndUtc).padStart(2, '0')}:00) from ${ip}.`,
        matchedEventIds: sensitiveOffHours.map((e) => e.id),
        primaryIp: ip,
        affectedUsers,
        firstSeen: sensitiveOffHours[0].timestamp,
        lastSeen: sensitiveOffHours[sensitiveOffHours.length - 1].timestamp,
      });
    }
  }

  // R-005: Impossible Travel & High-Risk IP Reputation
  for (const [user, userEvents] of byUser.entries()) {
    const logins = userEvents.filter((e) => e.eventType === 'login_success');
    for (let i = 1; i < logins.length; i++) {
      const prev = logins[i - 1];
      const curr = logins[i];
      if (prev.sourceIp === curr.sourceIp) continue;
      const distKm = haversineKm(prev.latitude, prev.longitude, curr.latitude, curr.longitude);
      const deltaHours = Math.max(0.01, (curr.epochMs - prev.epochMs) / 3_600_000);
      const speedKmh = distKm / deltaHours;
      if (distKm > 1000 && speedKmh > 900) {
        const followOn = userEvents.filter(
          (e) => e.sourceIp === curr.sourceIp && e.epochMs >= curr.epochMs && e.epochMs <= curr.epochMs + 60 * 60_000,
        );
        hits.push({
          id: nextHitId(),
          ruleId: 'R-005',
          ruleName: 'Impossible Travel Geolocation Hop',
          category: 'Impossible Travel & IP Risk',
          mitreTactic: 'Defense Evasion',
          mitreTechnique: 'T1090 Proxy / Multi-Hop Access',
          severity: curr.ipReputationScore >= 65 ? 'High' : 'Medium',
          confidence: 88,
          description: `Account ${user} authenticated from ${prev.city}, ${prev.country} (${prev.sourceIp}) and ${Math.round(distKm)} km away in ${curr.city}, ${curr.country} (${curr.sourceIp}) within ${Math.round(deltaHours * 60)} minutes.`,
          matchedEventIds: Array.from(new Set([prev.id, curr.id, ...followOn.map((e) => e.id)])),
          primaryIp: curr.sourceIp,
          affectedUsers: [user],
          firstSeen: prev.timestamp,
          lastSeen: followOn.length > 0 ? followOn[followOn.length - 1].timestamp : curr.timestamp,
        });
      }
    }
  }

  // R-006: Privilege Escalation + Bulk Data Exfiltration Chain
  for (const [ip, ipEvents] of byIp.entries()) {
    const privEvents = ipEvents.filter((e) => e.eventType === 'privilege_escalation');
    const exportEvents = ipEvents.filter(
      (e) => e.eventType === 'data_export' && e.bytesTransferred >= 10_000_000,
    );
    if (privEvents.length > 0 && exportEvents.length > 0) {
      const combined = [...privEvents, ...exportEvents].sort((a, b) => a.epochMs - b.epochMs);
      const totalMb = Math.round(
        exportEvents.reduce((sum, e) => sum + e.bytesTransferred, 0) / (1024 * 1024),
      );
      hits.push({
        id: nextHitId(),
        ruleId: 'R-006',
        ruleName: 'Privilege Escalation Followed by Bulk Data Export',
        category: 'Privilege & Exfiltration',
        mitreTactic: 'Exfiltration',
        mitreTechnique: 'T1567 / T1048 Bulk Data Transfer',
        severity: 'Critical',
        confidence: 97,
        description: `Elevated privileges observed on ${privEvents.map((e) => e.targetHost).join(', ')} followed by ${totalMb} MB data export from ${exportEvents.map((e) => e.targetHost).join(', ')} via ${ip}.`,
        matchedEventIds: combined.map((e) => e.id),
        primaryIp: ip,
        affectedUsers: Array.from(new Set(combined.map((e) => e.username))),
        firstSeen: combined[0].timestamp,
        lastSeen: combined[combined.length - 1].timestamp,
      });
    }
  }

  return hits;
}
