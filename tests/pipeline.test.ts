import { describe, expect, it } from 'vitest';
import {
  DEFAULT_PIPELINE_SETTINGS,
  generateSyntheticDataset,
  SAMPLE_CSV_PAYLOAD,
} from '../server/data/syntheticDataset';
import { runThreatDetection } from '../server/engine/detection';
import { parseAndNormalizeLogs } from '../server/engine/ingestion';
import { runIsolationForestDetection } from '../server/engine/isolationForest';
import { runAnalysisPipeline } from '../server/pipeline';

describe('TraceMind AI Backend Pipeline', () => {
  it('validates, normalizes, and deduplicates CSV security logs', () => {
    const csvWithInvalidRow = `${SAMPLE_CSV_PAYLOAD}
bad-timestamp,999.999.999.999,,login_failed,ssh-bastion-01,401,512`;
    const firstPass = parseAndNormalizeLogs(csvWithInvalidRow, 'csv', 'test.csv');
    expect(firstPass.events.length).toBe(8);
    expect(firstPass.summary.rejectedCount).toBe(1);
    expect(firstPass.summary.rejectedRecords[0].reason).toContain('Invalid or missing timestamp');

    const fps = new Set(firstPass.events.map((e) => e.fingerprint));
    const secondPass = parseAndNormalizeLogs(SAMPLE_CSV_PAYLOAD, 'csv', 'dup.csv', fps);
    expect(secondPass.events.length).toBe(0);
    expect(secondPass.summary.duplicateCount).toBe(8);
  });

  it('rejects malformed timestamps, invalid addresses, and unsupported event types', () => {
    const payload = JSON.stringify([
      { timestamp: 'not-a-date', ip: '203.0.113.10', user: 'alice', action: 'login_failed' },
      { timestamp: '2026-11-16T04:01:00Z', ip: '999.1.1.1', user: 'bob', action: 'login_failed' },
      { timestamp: '2026-11-16T04:02:00Z', ip: '203.0.113.11', user: 'carol', action: 'unknown_action' },
    ]);
    const result = parseAndNormalizeLogs(payload, 'json', 'invalid-records.json');
    expect(result.events).toHaveLength(0);
    expect(result.summary.rejectedCount).toBe(3);
  });

  it('normalizes JSON and NDJSON logs and enforces IPv4/IPv6 validation', () => {
    const jsonPayload = JSON.stringify([
      {
        timestamp: 1763265600,
        ip: '203.0.113.10',
        user: 'test.analyst',
        action: 'auth_failure',
        host: 'idp-01',
      },
      {
        timestamp: '2026-11-16T04:01:00Z',
        ip: 'invalid-ip',
        user: 'test.analyst',
        action: 'login_success',
      },
    ]);
    const res = parseAndNormalizeLogs(jsonPayload, 'json', 'sample.json');
    expect(res.events.length).toBe(1);
    expect(res.events[0].eventType).toBe('login_failed');
    expect(res.summary.rejectedCount).toBe(1);
  });

  it('detects brute-force, credential compromise, password spray, impossible travel, and exfiltration', () => {
    const events = generateSyntheticDataset();
    const hits = runThreatDetection(events, DEFAULT_PIPELINE_SETTINGS);
    const ruleIds = new Set(hits.map((h) => h.ruleId));

    expect(ruleIds.has('R-001')).toBe(true); // Brute force
    expect(ruleIds.has('R-002')).toBe(true); // Credential compromise
    expect(ruleIds.has('R-003')).toBe(true); // Password spray
    expect(ruleIds.has('R-005')).toBe(true); // Impossible travel
    expect(ruleIds.has('R-006')).toBe(true); // Priv esc + data export
  });

  it('runs Isolation Forest and separates Behavioural Anomaly from Confirmed Malicious', () => {
    const events = generateSyntheticDataset();
    const hits = runThreatDetection(events, DEFAULT_PIPELINE_SETTINGS);
    const { anomalies, evaluation } = runIsolationForestDetection(
      events,
      hits,
      DEFAULT_PIPELINE_SETTINGS,
    );

    expect(anomalies.length).toBeGreaterThan(5);
    expect(evaluation.nEstimators).toBe(DEFAULT_PIPELINE_SETTINGS.nEstimators);
    expect(evaluation.rocAucEstimate).toBeGreaterThan(0.7);

    const benignBot = anomalies.find((a) => a.entityKey === 'user:ci-release-bot');
    expect(benignBot).toBeDefined();
    expect(benignBot?.hasRuleMatch).toBe(false);
    expect(benignBot?.classification).not.toBe('Confirmed Malicious');

    const attackerIp = anomalies.find((a) => a.entityKey === 'ip:185.220.101.47');
    expect(attackerIp).toBeDefined();
    expect(attackerIp?.classification).toBe('Confirmed Malicious');
  });

  it('correlates incidents, computes explainable risk scores, and constructs chronological attack stories', () => {
    const events = generateSyntheticDataset();
    const snapshot = runAnalysisPipeline(events, DEFAULT_PIPELINE_SETTINGS);

    expect(snapshot.incidents.length).toBeGreaterThanOrEqual(3);
    const topIncident = snapshot.incidents[0];
    expect(topIncident.severity).toBe('Critical');
    expect(topIncident.riskScore).toBeGreaterThanOrEqual(80);
    expect(topIncident.riskFactors.length).toBe(5);
    expect(topIncident.attackStory.length).toBeGreaterThanOrEqual(3);

    // Verify chronological attack story ordering
    for (let i = 1; i < topIncident.attackStory.length; i++) {
      expect(Date.parse(topIncident.attackStory[i].timestamp)).toBeGreaterThanOrEqual(
        Date.parse(topIncident.attackStory[i - 1].timestamp),
      );
    }

    expect(snapshot.graph.nodes.length).toBeGreaterThan(10);
    expect(snapshot.graph.edges.length).toBeGreaterThan(10);
    expect(snapshot.analytics.totalEvents).toBe(events.length);
  });
});
