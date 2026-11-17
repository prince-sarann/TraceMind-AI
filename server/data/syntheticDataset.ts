import crypto from 'node:crypto';
import type { EventType, PipelineSettings, SecurityLogEvent, SeverityLevel } from '../../shared/types';

export const DEFAULT_PIPELINE_SETTINGS: PipelineSettings = {
  bruteForceThreshold: 5,
  bruteForceWindowMin: 15,
  sprayAccountThreshold: 4,
  offHoursStartUtc: 1,
  offHoursEndUtc: 5,
  anomalyScoreThreshold: 0.58,
  nEstimators: 80,
  riskWeights: {
    severity: 0.25,
    frequency: 0.15,
    blastRadius: 0.2,
    sourceReputation: 0.2,
    correlationAndMl: 0.2,
  },
};

function makeFingerprint(
  timestamp: string,
  sourceIp: string,
  username: string,
  eventType: string,
  targetHost: string,
): string {
  return crypto
    .createHash('sha256')
    .update(`${timestamp}|${sourceIp}|${username}|${eventType}|${targetHost}`)
    .digest('hex')
    .slice(0, 16);
}

interface RawSeedSpec {
  id: string;
  offsetMin: number; // offset from base time 2026-11-15T00:00:00Z
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
  ipReputationScore: number;
  userAgent: string;
  groundTruthLabel: 'normal' | 'anomalous_benign' | 'malicious';
  baseSeverity: SeverityLevel;
}

const BASE_UTC = Date.parse('2026-11-15T00:00:00.000Z');

function buildEvent(spec: RawSeedSpec): SecurityLogEvent {
  const epochMs = BASE_UTC + spec.offsetMin * 60_000;
  const timestamp = new Date(epochMs).toISOString();
  return {
    id: spec.id,
    timestamp,
    epochMs,
    sourceIp: spec.sourceIp,
    username: spec.username,
    eventType: spec.eventType,
    targetHost: spec.targetHost,
    statusCode: spec.statusCode,
    bytesTransferred: spec.bytesTransferred,
    country: spec.country,
    city: spec.city,
    latitude: spec.latitude,
    longitude: spec.longitude,
    asn: spec.asn,
    ipReputationScore: spec.ipReputationScore,
    userAgent: spec.userAgent,
    rawSource: 'synthetic-soc-corpus-v1',
    fingerprint: makeFingerprint(timestamp, spec.sourceIp, spec.username, spec.eventType, spec.targetHost),
    groundTruthLabel: spec.groundTruthLabel,
    baseSeverity: spec.baseSeverity,
  };
}

export function generateSyntheticDataset(): SecurityLogEvent[] {
  const specs: RawSeedSpec[] = [];
  let seq = 1001;
  const nextId = () => `EVT-${seq++}`;

  // 1. Normal Baseline Corporate Activity across 40 hours (daytime UTC 08:00 - 18:00)
  const normalUsers = [
    {
      user: 'alice.chen',
      ip: '198.51.100.24',
      country: 'United States',
      city: 'San Francisco',
      lat: 37.7749,
      lon: -122.4194,
      asn: 'AS15169 Corporate-VPN-West',
      host: 'sso-idp-01',
      ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)',
    },
    {
      user: 'sarah.patel',
      ip: '203.0.113.42',
      country: 'United Kingdom',
      city: 'London',
      lat: 51.5074,
      lon: -0.1278,
      asn: 'AS2856 Corporate-VPN-UK',
      host: 'erp-app-02',
      ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    },
    {
      user: 'david.kim',
      ip: '198.51.100.89',
      country: 'United States',
      city: 'Seattle',
      lat: 47.6062,
      lon: -122.3321,
      asn: 'AS16509 Corporate-VPN-PNW',
      host: 'git-runner-01',
      ua: 'OpenSSH_9.6p1',
    },
    {
      user: 'nina.alvarez',
      ip: '192.0.2.61',
      country: 'Canada',
      city: 'Toronto',
      lat: 43.6532,
      lon: -79.3832,
      asn: 'AS577 Corporate-VPN-East',
      host: 'crm-portal-01',
      ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4)',
    },
    {
      user: 'ops-monitor',
      ip: '10.20.4.15',
      country: 'Internal',
      city: 'US-East VPC',
      lat: 39.0438,
      lon: -77.4874,
      asn: 'AS64512 Internal-Mesh',
      host: 'telemetry-gw-01',
      ua: 'Prometheus/2.51.0',
    },
  ];

  // Generate steady daytime corporate traffic across Day 1 (09:00-17:30) and Day 2 (33:00-41:30)
  for (let day = 0; day < 2; day++) {
    const dayOffset = day * 24 * 60;
    for (let slot = 0; slot < 12; slot++) {
      const profile = normalUsers[(slot + day) % normalUsers.length];
      const baseMin = dayOffset + 9 * 60 + slot * 42;

      specs.push({
        id: nextId(),
        offsetMin: baseMin,
        sourceIp: profile.ip,
        username: profile.user,
        eventType: 'login_success',
        targetHost: profile.host,
        statusCode: 200,
        bytesTransferred: 2400 + (slot % 5) * 350,
        country: profile.country,
        city: profile.city,
        latitude: profile.lat,
        longitude: profile.lon,
        asn: profile.asn,
        ipReputationScore: profile.ip.startsWith('10.') ? 2 : 8,
        userAgent: profile.ua,
        groundTruthLabel: 'normal',
        baseSeverity: 'Info',
      });

      specs.push({
        id: nextId(),
        offsetMin: baseMin + 6,
        sourceIp: profile.ip,
        username: profile.user,
        eventType: 'api_access',
        targetHost: profile.host,
        statusCode: 200,
        bytesTransferred: 8400 + (slot % 4) * 1900,
        country: profile.country,
        city: profile.city,
        latitude: profile.lat,
        longitude: profile.lon,
        asn: profile.asn,
        ipReputationScore: profile.ip.startsWith('10.') ? 2 : 8,
        userAgent: profile.ua,
        groundTruthLabel: 'normal',
        baseSeverity: 'Info',
      });

      if (slot % 4 === 1) {
        specs.push({
          id: nextId(),
          offsetMin: baseMin + 12,
          sourceIp: profile.ip,
          username: profile.user,
          eventType: 'mfa_challenge',
          targetHost: 'sso-idp-01',
          statusCode: 200,
          bytesTransferred: 1200,
          country: profile.country,
          city: profile.city,
          latitude: profile.lat,
          longitude: profile.lon,
          asn: profile.asn,
          ipReputationScore: 8,
          userAgent: profile.ua,
          groundTruthLabel: 'normal',
          baseSeverity: 'Info',
        });
      }
    }
  }

  // Occasional normal single typo login failure
  specs.push({
    id: nextId(),
    offsetMin: 11 * 60 + 18,
    sourceIp: '198.51.100.24',
    username: 'alice.chen',
    eventType: 'login_failed',
    targetHost: 'sso-idp-01',
    statusCode: 401,
    bytesTransferred: 680,
    country: 'United States',
    city: 'San Francisco',
    latitude: 37.7749,
    longitude: -122.4194,
    asn: 'AS15169 Corporate-VPN-West',
    ipReputationScore: 8,
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)',
    groundTruthLabel: 'normal',
    baseSeverity: 'Low',
  });
  specs.push({
    id: nextId(),
    offsetMin: 11 * 60 + 19,
    sourceIp: '198.51.100.24',
    username: 'alice.chen',
    eventType: 'login_success',
    targetHost: 'sso-idp-01',
    statusCode: 200,
    bytesTransferred: 2650,
    country: 'United States',
    city: 'San Francisco',
    latitude: 37.7749,
    longitude: -122.4194,
    asn: 'AS15169 Corporate-VPN-West',
    ipReputationScore: 8,
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)',
    groundTruthLabel: 'normal',
    baseSeverity: 'Info',
  });

  // 2. INCIDENT A (CRITICAL): Multi-Stage Brute-Force -> Compromise -> Privilege Escalation -> Exfiltration
  // Day 2 early morning 02:04 - 02:26 UTC (offset 26*60 + 4 = 1564)
  const attackAStart = 26 * 60 + 4;
  for (let i = 0; i < 11; i++) {
    specs.push({
      id: nextId(),
      offsetMin: attackAStart + Math.floor(i * 0.7),
      sourceIp: '185.220.101.47',
      username: 'marcus.reed',
      eventType: 'login_failed',
      targetHost: 'auth-gw-prod-01',
      statusCode: 401,
      bytesTransferred: 540,
      country: 'Germany',
      city: 'Frankfurt',
      latitude: 50.1109,
      longitude: 8.6821,
      asn: 'AS205100 Tor-Exit-Relay',
      ipReputationScore: 94,
      userAgent: 'python-requests/2.31.0',
      groundTruthLabel: 'malicious',
      baseSeverity: 'Medium',
    });
  }
  // Successful compromise
  specs.push({
    id: nextId(),
    offsetMin: attackAStart + 9,
    sourceIp: '185.220.101.47',
    username: 'marcus.reed',
    eventType: 'login_success',
    targetHost: 'auth-gw-prod-01',
    statusCode: 200,
    bytesTransferred: 3420,
    country: 'Germany',
    city: 'Frankfurt',
    latitude: 50.1109,
    longitude: 8.6821,
    asn: 'AS205100 Tor-Exit-Relay',
    ipReputationScore: 94,
    userAgent: 'python-requests/2.31.0',
    groundTruthLabel: 'malicious',
    baseSeverity: 'High',
  });
  // Privilege escalation on production vault
  specs.push({
    id: nextId(),
    offsetMin: attackAStart + 13,
    sourceIp: '185.220.101.47',
    username: 'marcus.reed',
    eventType: 'privilege_escalation',
    targetHost: 'iam-vault-prod',
    statusCode: 200,
    bytesTransferred: 4820,
    country: 'Germany',
    city: 'Frankfurt',
    latitude: 50.1109,
    longitude: 8.6821,
    asn: 'AS205100 Tor-Exit-Relay',
    ipReputationScore: 94,
    userAgent: 'aws-cli/2.15.10',
    groundTruthLabel: 'malicious',
    baseSeverity: 'Critical',
  });
  // Bulk data export
  specs.push({
    id: nextId(),
    offsetMin: attackAStart + 17,
    sourceIp: '185.220.101.47',
    username: 'marcus.reed',
    eventType: 'data_export',
    targetHost: 'ledger-db-primary',
    statusCode: 200,
    bytesTransferred: 438_500_000,
    country: 'Germany',
    city: 'Frankfurt',
    latitude: 50.1109,
    longitude: 8.6821,
    asn: 'AS205100 Tor-Exit-Relay',
    ipReputationScore: 94,
    userAgent: 'curl/8.4.0',
    groundTruthLabel: 'malicious',
    baseSeverity: 'Critical',
  });

  // 3. INCIDENT B (HIGH): Distributed Password Spraying across 6 Accounts & Service Account Pivot
  // Day 1 late evening 21:10 - 21:38 UTC
  const attackBStart = 21 * 60 + 10;
  const sprayTargets = [
    'alice.chen',
    'david.kim',
    'sarah.patel',
    'finance-ap',
    'hr-portal-admin',
    'backup-svc',
  ];
  sprayTargets.forEach((targetUser, idx) => {
    specs.push({
      id: nextId(),
      offsetMin: attackBStart + idx * 2,
      sourceIp: '91.132.147.88',
      username: targetUser,
      eventType: 'login_failed',
      targetHost: 'sso-idp-01',
      statusCode: 401,
      bytesTransferred: 620,
      country: 'Romania',
      city: 'Bucharest',
      latitude: 44.4268,
      longitude: 26.1025,
      asn: 'AS209854 M247-Bulletproof-VPS',
      ipReputationScore: 86,
      userAgent: 'Go-http-client/2.0',
      groundTruthLabel: 'malicious',
      baseSeverity: 'Medium',
    });
  });
  // Secondary spray burst & compromise of backup-svc
  specs.push({
    id: nextId(),
    offsetMin: attackBStart + 15,
    sourceIp: '91.132.147.88',
    username: 'backup-svc',
    eventType: 'login_success',
    targetHost: 'sso-idp-01',
    statusCode: 200,
    bytesTransferred: 3100,
    country: 'Romania',
    city: 'Bucharest',
    latitude: 44.4268,
    longitude: 26.1025,
    asn: 'AS209854 M247-Bulletproof-VPS',
    ipReputationScore: 86,
    userAgent: 'Go-http-client/2.0',
    groundTruthLabel: 'malicious',
    baseSeverity: 'High',
  });
  specs.push({
    id: nextId(),
    offsetMin: attackBStart + 18,
    sourceIp: '91.132.147.88',
    username: 'backup-svc',
    eventType: 'api_access',
    targetHost: 'snapshot-storage-01',
    statusCode: 200,
    bytesTransferred: 28_400_000,
    country: 'Romania',
    city: 'Bucharest',
    latitude: 44.4268,
    longitude: 26.1025,
    asn: 'AS209854 M247-Bulletproof-VPS',
    ipReputationScore: 86,
    userAgent: 'Go-http-client/2.0',
    groundTruthLabel: 'malicious',
    baseSeverity: 'High',
  });
  specs.push({
    id: nextId(),
    offsetMin: attackBStart + 21,
    sourceIp: '91.132.147.88',
    username: 'backup-svc',
    eventType: 'firewall_block',
    targetHost: 'internal-core-fw',
    statusCode: 403,
    bytesTransferred: 410,
    country: 'Romania',
    city: 'Bucharest',
    latitude: 44.4268,
    longitude: 26.1025,
    asn: 'AS209854 M247-Bulletproof-VPS',
    ipReputationScore: 86,
    userAgent: 'Go-http-client/2.0',
    groundTruthLabel: 'malicious',
    baseSeverity: 'Medium',
  });

  // 4. INCIDENT C (MEDIUM): Impossible Travel / Suspicious Geolocation Hop for elena.kovacs
  // Login from New York at Day 2 14:05 UTC, then Kyiv 18 minutes later at 14:23 UTC
  const attackCStart = 38 * 60 + 5;
  specs.push({
    id: nextId(),
    offsetMin: attackCStart,
    sourceIp: '104.28.42.19',
    username: 'elena.kovacs',
    eventType: 'login_success',
    targetHost: 'erp-app-02',
    statusCode: 200,
    bytesTransferred: 2800,
    country: 'United States',
    city: 'New York',
    latitude: 40.7128,
    longitude: -74.006,
    asn: 'AS13335 Cloudflare-Warp',
    ipReputationScore: 22,
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)',
    groundTruthLabel: 'normal',
    baseSeverity: 'Info',
  });
  specs.push({
    id: nextId(),
    offsetMin: attackCStart + 18,
    sourceIp: '193.142.146.35',
    username: 'elena.kovacs',
    eventType: 'login_success',
    targetHost: 'erp-app-02',
    statusCode: 200,
    bytesTransferred: 3150,
    country: 'Ukraine',
    city: 'Kyiv',
    latitude: 50.4501,
    longitude: 30.5234,
    asn: 'AS49505 Datacenter-Proxy',
    ipReputationScore: 71,
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64)',
    groundTruthLabel: 'malicious',
    baseSeverity: 'Medium',
  });
  specs.push({
    id: nextId(),
    offsetMin: attackCStart + 24,
    sourceIp: '193.142.146.35',
    username: 'elena.kovacs',
    eventType: 'api_access',
    targetHost: 'payroll-api-01',
    statusCode: 200,
    bytesTransferred: 1_950_000,
    country: 'Ukraine',
    city: 'Kyiv',
    latitude: 50.4501,
    longitude: 30.5234,
    asn: 'AS49505 Datacenter-Proxy',
    ipReputationScore: 71,
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64)',
    groundTruthLabel: 'malicious',
    baseSeverity: 'Medium',
  });

  // 5. BENIGN BEHAVIOURAL ANOMALY (NOT MALICIOUS):
  // Authorized DevOps release engineer `ci-release-bot` runs high-frequency automated pipeline
  // at 03:20 UTC from internal VPC IP 10.24.8.14 (zero failed logins, low IP risk).
  // Isolation Forest detects unusual burst & off-hours timing, while rule engine sees no malicious compromise.
  const benignAnomStart = 27 * 60 + 20;
  for (let j = 0; j < 14; j++) {
    specs.push({
      id: nextId(),
      offsetMin: benignAnomStart + Math.floor(j * 0.4),
      sourceIp: '10.24.8.14',
      username: 'ci-release-bot',
      eventType: j % 3 === 0 ? 'process_exec' : 'api_access',
      targetHost: 'k8s-deploy-cluster-01',
      statusCode: 200,
      bytesTransferred: 145_000 + j * 12_000,
      country: 'Internal',
      city: 'US-West VPC',
      latitude: 45.5152,
      longitude: -122.6784,
      asn: 'AS64512 Internal-CI-Subnet',
      ipReputationScore: 4,
      userAgent: 'GitHub-Actions-Runner/2.319',
      groundTruthLabel: 'anomalous_benign',
      baseSeverity: 'Info',
    });
  }

  return specs.map(buildEvent).sort((a, b) => a.epochMs - b.epochMs);
}

export const SAMPLE_CSV_PAYLOAD = `timestamp,source_ip,username,event_type,target_host,status_code,bytes_transferred,country,city,asn,ip_reputation_score,user_agent
2026-11-16T04:10:02Z,45.148.10.212,admin-ops,login_failed,ssh-bastion-01,401,512,Netherlands,Amsterdam,AS49870 Hosting-Edge,88,OpenSSH_8.9
2026-11-16T04:10:15Z,45.148.10.212,admin-ops,login_failed,ssh-bastion-01,401,512,Netherlands,Amsterdam,AS49870 Hosting-Edge,88,OpenSSH_8.9
2026-11-16T04:10:29Z,45.148.10.212,admin-ops,login_failed,ssh-bastion-01,401,512,Netherlands,Amsterdam,AS49870 Hosting-Edge,88,OpenSSH_8.9
2026-11-16T04:10:44Z,45.148.10.212,admin-ops,login_failed,ssh-bastion-01,401,512,Netherlands,Amsterdam,AS49870 Hosting-Edge,88,OpenSSH_8.9
2026-11-16T04:11:01Z,45.148.10.212,admin-ops,login_failed,ssh-bastion-01,401,512,Netherlands,Amsterdam,AS49870 Hosting-Edge,88,OpenSSH_8.9
2026-11-16T04:11:20Z,45.148.10.212,admin-ops,login_success,ssh-bastion-01,200,3200,Netherlands,Amsterdam,AS49870 Hosting-Edge,88,OpenSSH_8.9
2026-11-16T04:13:05Z,45.148.10.212,admin-ops,privilege_escalation,k8s-control-01,200,6400,Netherlands,Amsterdam,AS49870 Hosting-Edge,88,kubectl/v1.30
2026-11-16T04:15:40Z,45.148.10.212,admin-ops,data_export,secrets-vault-01,200,92400000,Netherlands,Amsterdam,AS49870 Hosting-Edge,88,curl/8.4.0`;
