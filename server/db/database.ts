import fs from 'node:fs';
import path from 'node:path';
import initSqlJs, { type Database } from 'sql.js';
import type {
  AnalystRole,
  AuditLogEntry,
  IncidentNote,
  IncidentStatus,
  PipelineSettings,
  SecurityLogEvent,
} from '../../shared/types';
import { DEFAULT_PIPELINE_SETTINGS } from '../data/syntheticDataset';

const DATA_DIR = path.resolve(process.cwd(), '.data');
const DB_FILE = path.join(DATA_DIR, 'tracemind.sqlite');

export interface IncidentStateRow {
  incidentId: string;
  status: IncidentStatus;
  assignedAnalyst: string;
  updatedAt: string;
}

class TraceMindDatabase {
  private db: Database | null = null;
  private initPromise: Promise<void> | null = null;

  async init(): Promise<void> {
    if (this.db) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      const SQL = await initSqlJs();
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      if (fs.existsSync(DB_FILE)) {
        const buffer = fs.readFileSync(DB_FILE);
        this.db = new SQL.Database(buffer);
      } else {
        this.db = new SQL.Database();
      }
      this.createSchema();
      this.persist();
    })();

    return this.initPromise;
  }

  private createSchema(): void {
    if (!this.db) return;
    this.db.run(`
      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        epoch_ms INTEGER NOT NULL,
        source_ip TEXT NOT NULL,
        username TEXT NOT NULL,
        event_type TEXT NOT NULL,
        target_host TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        bytes_transferred INTEGER NOT NULL,
        country TEXT NOT NULL,
        city TEXT NOT NULL,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        asn TEXT NOT NULL,
        ip_reputation_score INTEGER NOT NULL,
        user_agent TEXT NOT NULL,
        raw_source TEXT NOT NULL,
        fingerprint TEXT UNIQUE NOT NULL,
        ground_truth_label TEXT,
        base_severity TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS incident_state (
        incident_id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        assigned_analyst TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS incident_notes (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        author TEXT NOT NULL,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        actor TEXT NOT NULL,
        role TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        details TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
  }

  private persist(): void {
    if (!this.db) return;
    const data = this.db.export();
    fs.writeFileSync(DB_FILE, Buffer.from(data));
  }

  async getEventCount(): Promise<number> {
    await this.init();
    const res = this.db!.exec('SELECT COUNT(*) as cnt FROM events');
    return Number(res[0]?.values[0]?.[0] ?? 0);
  }

  async getAllEvents(): Promise<SecurityLogEvent[]> {
    await this.init();
    const stmt = this.db!.prepare('SELECT * FROM events ORDER BY epoch_ms ASC');
    const rows: SecurityLogEvent[] = [];
    while (stmt.step()) {
      const r = stmt.getAsObject();
      rows.push({
        id: String(r.id),
        timestamp: String(r.timestamp),
        epochMs: Number(r.epoch_ms),
        sourceIp: String(r.source_ip),
        username: String(r.username),
        eventType: String(r.event_type) as SecurityLogEvent['eventType'],
        targetHost: String(r.target_host),
        statusCode: Number(r.status_code),
        bytesTransferred: Number(r.bytes_transferred),
        country: String(r.country),
        city: String(r.city),
        latitude: Number(r.latitude),
        longitude: Number(r.longitude),
        asn: String(r.asn),
        ipReputationScore: Number(r.ip_reputation_score),
        userAgent: String(r.user_agent),
        rawSource: String(r.raw_source),
        fingerprint: String(r.fingerprint),
        groundTruthLabel: r.ground_truth_label
          ? (String(r.ground_truth_label) as SecurityLogEvent['groundTruthLabel'])
          : undefined,
        baseSeverity: String(r.base_severity) as SecurityLogEvent['baseSeverity'],
      });
    }
    stmt.free();
    return rows;
  }

  async getExistingFingerprints(): Promise<Set<string>> {
    await this.init();
    const stmt = this.db!.prepare('SELECT fingerprint FROM events');
    const fps = new Set<string>();
    while (stmt.step()) {
      const r = stmt.getAsObject();
      fps.add(String(r.fingerprint));
    }
    stmt.free();
    return fps;
  }

  async insertEvents(events: SecurityLogEvent[]): Promise<number> {
    await this.init();
    if (events.length === 0) return 0;
    const stmt = this.db!.prepare(`
      INSERT OR IGNORE INTO events (
        id, timestamp, epoch_ms, source_ip, username, event_type, target_host,
        status_code, bytes_transferred, country, city, latitude, longitude,
        asn, ip_reputation_score, user_agent, raw_source, fingerprint,
        ground_truth_label, base_severity
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    let inserted = 0;
    this.db!.run('BEGIN TRANSACTION');
    try {
      for (const ev of events) {
        stmt.run([
          ev.id,
          ev.timestamp,
          ev.epochMs,
          ev.sourceIp,
          ev.username,
          ev.eventType,
          ev.targetHost,
          ev.statusCode,
          ev.bytesTransferred,
          ev.country,
          ev.city,
          ev.latitude,
          ev.longitude,
          ev.asn,
          ev.ipReputationScore,
          ev.userAgent,
          ev.rawSource,
          ev.fingerprint,
          ev.groundTruthLabel ?? null,
          ev.baseSeverity,
        ]);
        inserted++;
      }
      this.db!.run('COMMIT');
    } catch (err) {
      this.db!.run('ROLLBACK');
      throw err;
    } finally {
      stmt.free();
    }
    this.persist();
    return inserted;
  }

  async resetAllEvents(seedEvents: SecurityLogEvent[]): Promise<void> {
    await this.init();
    this.db!.run('DELETE FROM events');
    this.db!.run('DELETE FROM incident_state');
    this.db!.run('DELETE FROM incident_notes');
    this.persist();
    await this.insertEvents(seedEvents);
  }

  async getIncidentStates(): Promise<Map<string, IncidentStateRow>> {
    await this.init();
    const stmt = this.db!.prepare('SELECT * FROM incident_state');
    const map = new Map<string, IncidentStateRow>();
    while (stmt.step()) {
      const r = stmt.getAsObject();
      map.set(String(r.incident_id), {
        incidentId: String(r.incident_id),
        status: String(r.status) as IncidentStatus,
        assignedAnalyst: String(r.assigned_analyst),
        updatedAt: String(r.updated_at),
      });
    }
    stmt.free();
    return map;
  }

  async upsertIncidentState(
    incidentId: string,
    status: IncidentStatus,
    assignedAnalyst: string,
  ): Promise<void> {
    await this.init();
    const stmt = this.db!.prepare(`
      INSERT INTO incident_state (incident_id, status, assigned_analyst, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(incident_id) DO UPDATE SET
        status = excluded.status,
        assigned_analyst = excluded.assigned_analyst,
        updated_at = excluded.updated_at
    `);
    stmt.run([incidentId, status, assignedAnalyst, new Date().toISOString()]);
    stmt.free();
    this.persist();
  }

  async getIncidentNotes(): Promise<Map<string, IncidentNote[]>> {
    await this.init();
    const stmt = this.db!.prepare('SELECT * FROM incident_notes ORDER BY created_at DESC');
    const map = new Map<string, IncidentNote[]>();
    while (stmt.step()) {
      const r = stmt.getAsObject();
      const incId = String(r.incident_id);
      if (!map.has(incId)) map.set(incId, []);
      map.get(incId)!.push({
        id: String(r.id),
        incidentId: incId,
        author: String(r.author),
        role: String(r.role) as AnalystRole,
        content: String(r.content),
        createdAt: String(r.created_at),
      });
    }
    stmt.free();
    return map;
  }

  async addIncidentNote(note: IncidentNote): Promise<void> {
    await this.init();
    const stmt = this.db!.prepare(`
      INSERT INTO incident_notes (id, incident_id, author, role, content, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run([note.id, note.incidentId, note.author, note.role, note.content, note.createdAt]);
    stmt.free();
    this.persist();
  }

  async getSettings(): Promise<PipelineSettings> {
    await this.init();
    const stmt = this.db!.prepare('SELECT value FROM settings WHERE key = ?');
    stmt.bind(['pipeline_settings']);
    let result: PipelineSettings = DEFAULT_PIPELINE_SETTINGS;
    if (stmt.step()) {
      const r = stmt.getAsObject();
      try {
        result = { ...DEFAULT_PIPELINE_SETTINGS, ...JSON.parse(String(r.value)) };
      } catch {
        result = DEFAULT_PIPELINE_SETTINGS;
      }
    }
    stmt.free();
    return result;
  }

  async saveSettings(settings: PipelineSettings): Promise<void> {
    await this.init();
    const stmt = this.db!.prepare(`
      INSERT INTO settings (key, value) VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `);
    stmt.run(['pipeline_settings', JSON.stringify(settings)]);
    stmt.free();
    this.persist();
  }

  async addAuditLog(entry: AuditLogEntry): Promise<void> {
    await this.init();
    const stmt = this.db!.prepare(`
      INSERT INTO audit_logs (id, timestamp, actor, role, action, target, details)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run([
      entry.id,
      entry.timestamp,
      entry.actor,
      entry.role,
      entry.action,
      entry.target,
      entry.details,
    ]);
    stmt.free();
    this.persist();
  }

  async getAuditLogs(limit = 100): Promise<AuditLogEntry[]> {
    await this.init();
    const stmt = this.db!.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?');
    stmt.bind([limit]);
    const rows: AuditLogEntry[] = [];
    while (stmt.step()) {
      const r = stmt.getAsObject();
      rows.push({
        id: String(r.id),
        timestamp: String(r.timestamp),
        actor: String(r.actor),
        role: String(r.role) as AnalystRole,
        action: String(r.action),
        target: String(r.target),
        details: String(r.details),
      });
    }
    stmt.free();
    return rows;
  }
}

export const db = new TraceMindDatabase();
