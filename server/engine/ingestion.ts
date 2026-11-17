import crypto from 'node:crypto';
import type {
  EventType,
  IngestionSummary,
  RejectedLogRecord,
  SecurityLogEvent,
  SeverityLevel,
} from '../../shared/types';

const VALID_EVENT_TYPES = new Set<EventType>([
  'login_failed',
  'login_success',
  'privilege_escalation',
  'api_access',
  'data_export',
  'firewall_block',
  'mfa_challenge',
  'account_lockout',
  'process_exec',
]);

const EVENT_TYPE_ALIASES: Record<string, EventType> = {
  failed_login: 'login_failed',
  auth_failure: 'login_failed',
  auth_failed: 'login_failed',
  signin_failed: 'login_failed',
  login_failure: 'login_failed',
  auth_success: 'login_success',
  signin_success: 'login_success',
  priv_esc: 'privilege_escalation',
  sudo: 'privilege_escalation',
  export: 'data_export',
  download_bulk: 'data_export',
  fw_block: 'firewall_block',
  blocked: 'firewall_block',
  mfa: 'mfa_challenge',
  lockout: 'account_lockout',
  exec: 'process_exec',
  command_exec: 'process_exec',
};

const IPV4_REGEX =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const IPV6_REGEX = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;

export function isValidIpAddress(ip: string): boolean {
  const trimmed = ip.trim();
  return IPV4_REGEX.test(trimmed) || IPV6_REGEX.test(trimmed);
}

export function normalizeTimestamp(raw: unknown): { iso: string; epochMs: number } | null {
  if (typeof raw === 'number' && Number.isFinite(raw)) {
    const ms = raw < 1e12 ? raw * 1000 : raw;
    const d = new Date(ms);
    if (!Number.isNaN(d.getTime())) {
      return { iso: d.toISOString(), epochMs: d.getTime() };
    }
    return null;
  }
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  if (/^\d{10,13}$/.test(trimmed)) {
    const num = Number(trimmed);
    const ms = trimmed.length === 10 ? num * 1000 : num;
    const d = new Date(ms);
    return Number.isNaN(d.getTime()) ? null : { iso: d.toISOString(), epochMs: d.getTime() };
  }
  const normalizedStr = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(trimmed)
    ? `${trimmed.replace(' ', 'T')}Z`
    : trimmed;
  const parsed = Date.parse(normalizedStr);
  if (Number.isNaN(parsed)) return null;
  return { iso: new Date(parsed).toISOString(), epochMs: parsed };
}

export function normalizeEventType(raw: unknown): EventType | null {
  if (typeof raw !== 'string') return null;
  const key = raw.trim().toLowerCase().replace(/[\s-]+/g, '_');
  if (VALID_EVENT_TYPES.has(key as EventType)) {
    return key as EventType;
  }
  return EVENT_TYPE_ALIASES[key] ?? null;
}

function inferSeverity(eventType: EventType, statusCode: number, bytesTransferred: number): SeverityLevel {
  if (eventType === 'privilege_escalation') return 'High';
  if (eventType === 'data_export' && bytesTransferred >= 20_000_000) return 'High';
  if (eventType === 'login_failed' || eventType === 'firewall_block' || eventType === 'account_lockout') {
    return 'Medium';
  }
  if (statusCode >= 500 || statusCode === 403) return 'Medium';
  return 'Info';
}

function inferGeoFallback(ip: string): {
  country: string;
  city: string;
  latitude: number;
  longitude: number;
  asn: string;
  reputation: number;
} {
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.')) {
    return {
      country: 'Internal',
      city: 'Corporate VPC',
      latitude: 39.0438,
      longitude: -77.4874,
      asn: 'AS64512 Internal-Network',
      reputation: 5,
    };
  }
  if (ip.startsWith('185.220.')) {
    return {
      country: 'Germany',
      city: 'Frankfurt',
      latitude: 50.1109,
      longitude: 8.6821,
      asn: 'AS205100 Tor-Exit-Relay',
      reputation: 92,
    };
  }
  if (ip.startsWith('45.148.')) {
    return {
      country: 'Netherlands',
      city: 'Amsterdam',
      latitude: 52.3676,
      longitude: 4.9041,
      asn: 'AS49870 Hosting-Edge',
      reputation: 84,
    };
  }
  return {
    country: 'Unknown',
    city: 'External',
    latitude: 48.8566,
    longitude: 2.3522,
    asn: 'AS-External',
    reputation: 35,
  };
}

function parseCsvLine(line: string): string[] {
  const fields: string[] = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      fields.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  fields.push(current.trim());
  return fields;
}

function sanitizeField(val: unknown, maxLen = 180): string {
  if (val === null || val === undefined) return '';
  return String(val)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .trim()
    .slice(0, maxLen);
}

export function parseAndNormalizeLogs(
  rawContent: string,
  format: 'csv' | 'json',
  sourceName: string,
  existingFingerprints: Set<string> = new Set(),
): { events: SecurityLogEvent[]; summary: IngestionSummary } {
  const MAX_BYTES = 5 * 1024 * 1024;
  if (Buffer.byteLength(rawContent, 'utf8') > MAX_BYTES) {
    throw new Error('Log payload exceeds maximum allowed size of 5 MB.');
  }

  let rawRecords: Record<string, unknown>[] = [];
  const rejectedRecords: RejectedLogRecord[] = [];

  if (format === 'json') {
    const trimmed = rawContent.trim();
    if (!trimmed) {
      throw new Error('Empty JSON payload provided.');
    }
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) {
        rawRecords = parsed;
      } else if (parsed && typeof parsed === 'object' && Array.isArray((parsed as { events?: unknown }).events)) {
        rawRecords = (parsed as { events: Record<string, unknown>[] }).events;
      } else if (parsed && typeof parsed === 'object') {
        rawRecords = [parsed as Record<string, unknown>];
      } else {
        throw new Error('JSON must be an array of event objects or an { events: [...] } envelope.');
      }
    } catch {
      // Attempt NDJSON fallback
      const lines = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0);
      if (lines.length === 0) {
        throw new Error('Invalid JSON log format.');
      }
      lines.forEach((line, idx) => {
        try {
          const obj = JSON.parse(line);
          if (obj && typeof obj === 'object') {
            rawRecords.push(obj as Record<string, unknown>);
          } else {
            rejectedRecords.push({
              lineNumber: idx + 1,
              reason: 'NDJSON line is not an object',
              rawPreview: line.slice(0, 100),
            });
          }
        } catch {
          rejectedRecords.push({
            lineNumber: idx + 1,
            reason: 'Malformed JSON syntax',
            rawPreview: line.slice(0, 100),
          });
        }
      });
    }
  } else {
    const lines = rawContent.split(/\r?\n/).filter((l) => l.trim().length > 0);
    if (lines.length < 2) {
      throw new Error('CSV log must contain a header row and at least one data row.');
    }
    const headers = parseCsvLine(lines[0]).map((h) => h.toLowerCase().replace(/[\s-]+/g, '_'));
    for (let i = 1; i < lines.length; i++) {
      const values = parseCsvLine(lines[i]);
      if (values.length < 3) {
        rejectedRecords.push({
          lineNumber: i + 1,
          reason: 'Insufficient CSV columns (expected timestamp, source_ip, username, event_type)',
          rawPreview: lines[i].slice(0, 100),
        });
        continue;
      }
      const row: Record<string, unknown> = {};
      headers.forEach((header, idx) => {
        row[header] = values[idx] ?? '';
      });
      rawRecords.push(row);
    }
  }

  const accepted: SecurityLogEvent[] = [];
  let duplicateCount = 0;
  const seenFingerprints = new Set(existingFingerprints);

  rawRecords.forEach((rec, idx) => {
    const lineNum = idx + (format === 'csv' ? 2 : 1);
    if (!rec || typeof rec !== 'object') {
      rejectedRecords.push({
        lineNumber: lineNum,
        reason: 'Record is not a valid key-value object',
        rawPreview: String(rec).slice(0, 100),
      });
      return;
    }

    const rawTs = rec.timestamp ?? rec.time ?? rec.ts ?? rec.date ?? rec.created_at;
    const normTs = normalizeTimestamp(rawTs);
    if (!normTs) {
      rejectedRecords.push({
        lineNumber: lineNum,
        reason: `Invalid or missing timestamp (${String(rawTs ?? 'empty')})`,
        rawPreview: JSON.stringify(rec).slice(0, 100),
      });
      return;
    }

    const rawIp = sanitizeField(rec.source_ip ?? rec.ip ?? rec.src_ip ?? rec.client_ip ?? '');
    if (!isValidIpAddress(rawIp)) {
      rejectedRecords.push({
        lineNumber: lineNum,
        reason: `Invalid IP address (${rawIp || 'missing'})`,
        rawPreview: JSON.stringify(rec).slice(0, 100),
      });
      return;
    }

    const username = sanitizeField(rec.username ?? rec.user ?? rec.account ?? rec.actor ?? '');
    if (!username) {
      rejectedRecords.push({
        lineNumber: lineNum,
        reason: 'Missing username / actor identifier',
        rawPreview: JSON.stringify(rec).slice(0, 100),
      });
      return;
    }

    const rawEvt = rec.event_type ?? rec.event ?? rec.action ?? rec.type;
    const eventType = normalizeEventType(rawEvt);
    if (!eventType) {
      rejectedRecords.push({
        lineNumber: lineNum,
        reason: `Unsupported or missing event_type (${String(rawEvt ?? 'empty')})`,
        rawPreview: JSON.stringify(rec).slice(0, 100),
      });
      return;
    }

    const targetHost = sanitizeField(rec.target_host ?? rec.host ?? rec.resource ?? 'unknown-host') || 'unknown-host';
    const statusCodeNum = Number(rec.status_code ?? rec.status ?? (eventType === 'login_failed' ? 401 : 200));
    const statusCode = Number.isFinite(statusCodeNum) ? statusCodeNum : 200;
    const bytesNum = Number(rec.bytes_transferred ?? rec.bytes ?? 1024);
    const bytesTransferred = Number.isFinite(bytesNum) && bytesNum >= 0 ? bytesNum : 0;

    const fingerprint = crypto
      .createHash('sha256')
      .update(`${normTs.iso}|${rawIp}|${username}|${eventType}|${targetHost}`)
      .digest('hex')
      .slice(0, 16);

    if (seenFingerprints.has(fingerprint)) {
      duplicateCount++;
      return;
    }
    seenFingerprints.add(fingerprint);

    const geoFallback = inferGeoFallback(rawIp);
    const repRaw = Number(rec.ip_reputation_score ?? rec.reputation ?? geoFallback.reputation);
    const ipReputationScore = Number.isFinite(repRaw) ? Math.max(0, Math.min(100, repRaw)) : geoFallback.reputation;

    const latRaw = Number(rec.latitude ?? rec.lat ?? geoFallback.latitude);
    const lonRaw = Number(rec.longitude ?? rec.lon ?? geoFallback.longitude);

    const event: SecurityLogEvent = {
      id: sanitizeField(rec.id, 32) || `EVT-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
      timestamp: normTs.iso,
      epochMs: normTs.epochMs,
      sourceIp: rawIp,
      username,
      eventType,
      targetHost,
      statusCode,
      bytesTransferred,
      country: sanitizeField(rec.country, 64) || geoFallback.country,
      city: sanitizeField(rec.city, 64) || geoFallback.city,
      latitude: Number.isFinite(latRaw) ? latRaw : geoFallback.latitude,
      longitude: Number.isFinite(lonRaw) ? lonRaw : geoFallback.longitude,
      asn: sanitizeField(rec.asn, 80) || geoFallback.asn,
      ipReputationScore,
      userAgent: sanitizeField(rec.user_agent, 140) || 'Unknown-Client/1.0',
      rawSource: sanitizeField(sourceName, 80) || 'uploaded-logs',
      fingerprint,
      baseSeverity: inferSeverity(eventType, statusCode, bytesTransferred),
    };

    accepted.push(event);
  });

  const summary: IngestionSummary = {
    totalSubmitted: rawRecords.length + rejectedRecords.length,
    acceptedCount: accepted.length,
    duplicateCount,
    rejectedCount: rejectedRecords.length,
    rejectedRecords: rejectedRecords.slice(0, 50),
    sourceName,
    format,
    ingestedAt: new Date().toISOString(),
  };

  return { events: accepted, summary };
}
