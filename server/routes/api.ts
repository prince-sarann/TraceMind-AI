import crypto from 'node:crypto';
import express, { type Request, type Response } from 'express';
import type { AnalystRole, IncidentStatus, PipelineSettings, WorkspaceSnapshot } from '../../shared/types';
import { DEFAULT_PIPELINE_SETTINGS, generateSyntheticDataset, SAMPLE_CSV_PAYLOAD } from '../data/syntheticDataset';
import { db } from '../db/database';
import { parseAndNormalizeLogs } from '../engine/ingestion';
import { runAnalysisPipeline } from '../pipeline';
import { askInvestigationCopilot, generateIncidentInvestigationBrief } from './ai';

export const apiRouter = express.Router();

function getActorContext(req: Request): { actor: string; role: AnalystRole } {
  const actor = String(req.header('x-analyst-name') || 'Prince Kumar Saran').slice(0, 64);
  const rawRole = String(req.header('x-analyst-role') || 'Lead SOC Analyst');
  const validRoles: AnalystRole[] = ['Lead SOC Analyst', 'Tier-2 Responder', 'Read-Only Auditor'];
  const role: AnalystRole = validRoles.includes(rawRole as AnalystRole)
    ? (rawRole as AnalystRole)
    : 'Lead SOC Analyst';
  return { actor, role };
}

function requireWritePermission(role: AnalystRole, res: Response): boolean {
  if (role === 'Read-Only Auditor') {
    res.status(403).json({
      error: 'Read-Only Auditor role does not have permission to mutate incidents, ingest logs, or modify settings.',
    });
    return false;
  }
  return true;
}

async function ensureSeeded(): Promise<void> {
  const count = await db.getEventCount();
  if (count === 0) {
    const seed = generateSyntheticDataset();
    await db.insertEvents(seed);
    await db.addAuditLog({
      id: `AUD-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
      timestamp: new Date().toISOString(),
      actor: 'System',
      role: 'Lead SOC Analyst',
      action: 'SEED_SYNTHETIC_CORPUS',
      target: 'events',
      details: `Initialized SQLite store with ${seed.length} synthetic security events.`,
    });
  }
}

async function buildSnapshot(): Promise<WorkspaceSnapshot> {
  await ensureSeeded();
  const [events, settings, states, notes, auditLogs] = await Promise.all([
    db.getAllEvents(),
    db.getSettings(),
    db.getIncidentStates(),
    db.getIncidentNotes(),
    db.getAuditLogs(100),
  ]);
  return runAnalysisPipeline(events, settings, states, notes, auditLogs);
}

apiRouter.get('/workspace', async (_req: Request, res: Response) => {
  try {
    const snapshot = await buildSnapshot();
    res.json(snapshot);
  } catch (err) {
    console.error('Error building workspace snapshot:', err);
    res.status(500).json({ error: 'Failed to load workspace telemetry.' });
  }
});

apiRouter.get('/logs/sample-csv', (_req: Request, res: Response) => {
  res.json({ csv: SAMPLE_CSV_PAYLOAD });
});

apiRouter.post('/logs/ingest', async (req: Request, res: Response) => {
  try {
    const { actor, role } = getActorContext(req);
    if (!requireWritePermission(role, res)) return;

    const { content, format, sourceName } = req.body as {
      content?: string;
      format?: 'csv' | 'json';
      sourceName?: string;
    };

    if (!content || typeof content !== 'string') {
      res.status(400).json({ error: 'Missing raw log content payload.' });
      return;
    }
    if (format !== 'csv' && format !== 'json') {
      res.status(400).json({ error: 'Unsupported log format. Only CSV and JSON are permitted.' });
      return;
    }

    const existingFps = await db.getExistingFingerprints();
    const { events, summary } = parseAndNormalizeLogs(
      content,
      format,
      sourceName || `upload.${format}`,
      existingFps,
    );

    if (events.length > 0) {
      await db.insertEvents(events);
    }

    await db.addAuditLog({
      id: `AUD-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
      timestamp: new Date().toISOString(),
      actor,
      role,
      action: 'INGEST_SECURITY_LOGS',
      target: summary.sourceName,
      details: `Accepted ${summary.acceptedCount}, deduplicated ${summary.duplicateCount}, rejected ${summary.rejectedCount} (${format.toUpperCase()}).`,
    });

    const snapshot = await buildSnapshot();
    snapshot.lastIngestion = summary;
    res.json(snapshot);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to parse log payload.';
    res.status(400).json({ error: message });
  }
});

apiRouter.post('/logs/reset', async (req: Request, res: Response) => {
  try {
    const { actor, role } = getActorContext(req);
    if (!requireWritePermission(role, res)) return;

    const seed = generateSyntheticDataset();
    await db.resetAllEvents(seed);
    await db.saveSettings(DEFAULT_PIPELINE_SETTINGS);
    await db.addAuditLog({
      id: `AUD-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
      timestamp: new Date().toISOString(),
      actor,
      role,
      action: 'RESET_SYNTHETIC_DATASET',
      target: 'workspace',
      details: `Restored ${seed.length} baseline synthetic events and default detection thresholds.`,
    });

    const snapshot = await buildSnapshot();
    res.json(snapshot);
  } catch (err) {
    console.error('Error resetting dataset:', err);
    res.status(500).json({ error: 'Failed to reset synthetic dataset.' });
  }
});

apiRouter.patch('/incidents/:id', async (req: Request, res: Response) => {
  try {
    const { actor, role } = getActorContext(req);
    if (!requireWritePermission(role, res)) return;

    const incidentId = String(req.params.id);
    const { status, assignedAnalyst } = req.body as {
      status?: IncidentStatus;
      assignedAnalyst?: string;
    };

    const validStatuses: IncidentStatus[] = ['Open', 'Investigating', 'Contained', 'Resolved'];
    if (!status || !validStatuses.includes(status)) {
      res.status(400).json({ error: 'Invalid incident status.' });
      return;
    }

    const analyst = String(assignedAnalyst || actor).trim().slice(0, 64) || 'Unassigned';
    await db.upsertIncidentState(incidentId, status, analyst);

    await db.addAuditLog({
      id: `AUD-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
      timestamp: new Date().toISOString(),
      actor,
      role,
      action: 'UPDATE_INCIDENT_STATUS',
      target: incidentId,
      details: `Status updated to "${status}", assignee "${analyst}".`,
    });

    const snapshot = await buildSnapshot();
    res.json(snapshot);
  } catch (err) {
    console.error('Error updating incident:', err);
    res.status(500).json({ error: 'Failed to update incident status.' });
  }
});

apiRouter.post('/incidents/:id/notes', async (req: Request, res: Response) => {
  try {
    const { actor, role } = getActorContext(req);
    if (!requireWritePermission(role, res)) return;

    const incidentId = String(req.params.id);
    const { content } = req.body as { content?: string };
    const cleanContent = String(content || '').trim().slice(0, 2000);
    if (!cleanContent) {
      res.status(400).json({ error: 'Analyst note content cannot be empty.' });
      return;
    }

    await db.addIncidentNote({
      id: `NOTE-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
      incidentId,
      author: actor,
      role,
      content: cleanContent,
      createdAt: new Date().toISOString(),
    });

    await db.addAuditLog({
      id: `AUD-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
      timestamp: new Date().toISOString(),
      actor,
      role,
      action: 'ADD_ANALYST_NOTE',
      target: incidentId,
      details: `Added investigation note (${cleanContent.length} chars).`,
    });

    const snapshot = await buildSnapshot();
    res.json(snapshot);
  } catch (err) {
    console.error('Error adding note:', err);
    res.status(500).json({ error: 'Failed to save analyst note.' });
  }
});

apiRouter.put('/settings', async (req: Request, res: Response) => {
  try {
    const { actor, role } = getActorContext(req);
    if (role !== 'Lead SOC Analyst') {
      res.status(403).json({
        error: 'Only Lead SOC Analyst role may modify detection engine and ML hyperparameters.',
      });
      return;
    }

    const incoming = req.body as Partial<PipelineSettings>;
    const current = await db.getSettings();
    const updated: PipelineSettings = {
      bruteForceThreshold: Math.max(2, Math.min(50, Number(incoming.bruteForceThreshold ?? current.bruteForceThreshold))),
      bruteForceWindowMin: Math.max(1, Math.min(180, Number(incoming.bruteForceWindowMin ?? current.bruteForceWindowMin))),
      sprayAccountThreshold: Math.max(2, Math.min(50, Number(incoming.sprayAccountThreshold ?? current.sprayAccountThreshold))),
      offHoursStartUtc: Math.max(0, Math.min(23, Number(incoming.offHoursStartUtc ?? current.offHoursStartUtc))),
      offHoursEndUtc: Math.max(0, Math.min(23, Number(incoming.offHoursEndUtc ?? current.offHoursEndUtc))),
      anomalyScoreThreshold: Math.max(0.4, Math.min(0.85, Number(incoming.anomalyScoreThreshold ?? current.anomalyScoreThreshold))),
      nEstimators: Math.max(20, Math.min(200, Number(incoming.nEstimators ?? current.nEstimators))),
      riskWeights: {
        severity: Number(incoming.riskWeights?.severity ?? current.riskWeights.severity),
        frequency: Number(incoming.riskWeights?.frequency ?? current.riskWeights.frequency),
        blastRadius: Number(incoming.riskWeights?.blastRadius ?? current.riskWeights.blastRadius),
        sourceReputation: Number(incoming.riskWeights?.sourceReputation ?? current.riskWeights.sourceReputation),
        correlationAndMl: Number(incoming.riskWeights?.correlationAndMl ?? current.riskWeights.correlationAndMl),
      },
    };

    await db.saveSettings(updated);
    await db.addAuditLog({
      id: `AUD-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
      timestamp: new Date().toISOString(),
      actor,
      role,
      action: 'UPDATE_PIPELINE_SETTINGS',
      target: 'detection_ml_engine',
      details: `Updated bruteForceThreshold=${updated.bruteForceThreshold}, anomalyThreshold=${updated.anomalyScoreThreshold}, nEstimators=${updated.nEstimators}.`,
    });

    const snapshot = await buildSnapshot();
    res.json(snapshot);
  } catch (err) {
    console.error('Error saving settings:', err);
    res.status(500).json({ error: 'Failed to update settings.' });
  }
});

apiRouter.post('/audit/export', async (req: Request, res: Response) => {
  try {
    const { actor, role } = getActorContext(req);
    const { format, target } = req.body as { format?: string; target?: string };
    await db.addAuditLog({
      id: `AUD-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
      timestamp: new Date().toISOString(),
      actor,
      role,
      action: 'EXPORT_INVESTIGATION_REPORT',
      target: String(target || 'SOC_Report').slice(0, 64),
      details: `Exported ${String(format || 'CSV').toUpperCase()} investigation report.`,
    });
    const auditLogs = await db.getAuditLogs(100);
    res.json({ auditLogs });
  } catch (err) {
    console.error('Error recording export audit:', err);
    res.status(500).json({ error: 'Failed to log export audit.' });
  }
});

apiRouter.post('/ai/investigate', async (req: Request, res: Response) => {
  try {
    const { actor, role } = getActorContext(req);
    const { incidentId } = req.body as { incidentId?: string };
    if (!incidentId) {
      res.status(400).json({ error: 'incidentId is required.' });
      return;
    }

    const snapshot = await buildSnapshot();
    const incident = snapshot.incidents.find((i) => i.id === incidentId);
    if (!incident) {
      res.status(404).json({ error: `Incident ${incidentId} not found.` });
      return;
    }

    const briefing = await generateIncidentInvestigationBrief(incident, snapshot.events);

    await db.addAuditLog({
      id: `AUD-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
      timestamp: new Date().toISOString(),
      actor,
      role,
      action: 'AI_INVESTIGATION_BRIEF',
      target: incidentId,
      details: `Generated evidence-grounded briefing via ${briefing.model}.`,
    });

    res.json(briefing);
  } catch (err) {
    console.error('AI investigation error:', err);
    const message = err instanceof Error ? err.message : 'AI Investigation request failed.';
    const status = message.includes('GEMINI_API_KEY') ? 503 : 500;
    res.status(status).json({ error: message });
  }
});

apiRouter.post('/ai/ask', async (req: Request, res: Response) => {
  try {
    const { actor, role } = getActorContext(req);
    const { question, incidentId } = req.body as { question?: string; incidentId?: string };
    const cleanQuestion = String(question || '').trim().slice(0, 1000);
    if (!cleanQuestion) {
      res.status(400).json({ error: 'Question cannot be empty.' });
      return;
    }

    const snapshot = await buildSnapshot();
    const incident = incidentId
      ? snapshot.incidents.find((i) => i.id === incidentId) ?? null
      : null;

    const reply = await askInvestigationCopilot(cleanQuestion, incident, snapshot.events);

    await db.addAuditLog({
      id: `AUD-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
      timestamp: new Date().toISOString(),
      actor,
      role,
      action: 'AI_COPILOT_QUERY',
      target: incidentId || 'global_telemetry',
      details: `Analyst queried AI Assistant (${cleanQuestion.slice(0, 60)}...).`,
    });

    res.json(reply);
  } catch (err) {
    console.error('AI copilot error:', err);
    const message = err instanceof Error ? err.message : 'AI Copilot query failed.';
    const status = message.includes('GEMINI_API_KEY') ? 503 : 500;
    res.status(status).json({ error: message });
  }
});
