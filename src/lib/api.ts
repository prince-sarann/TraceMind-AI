import { jsPDF } from 'jspdf';
import type {
  AiInvestigationResponse,
  AnalystRole,
  Incident,
  IncidentStatus,
  PipelineSettings,
  SecurityLogEvent,
  WorkspaceSnapshot,
} from '../../shared/types';

export interface AnalystIdentity {
  name: string;
  role: AnalystRole;
}

function buildHeaders(identity: AnalystIdentity): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    'x-analyst-name': identity.name,
    'x-analyst-role': identity.role,
  };
}

async function handleResponse<T>(res: Response): Promise<T> {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error((data as { error?: string }).error || `Request failed (${res.status})`);
  }
  return data as T;
}

export async function fetchWorkspace(): Promise<WorkspaceSnapshot> {
  const res = await fetch('/api/workspace');
  return handleResponse<WorkspaceSnapshot>(res);
}

export async function fetchSampleCsv(): Promise<string> {
  const res = await fetch('/api/logs/sample-csv');
  const data = await handleResponse<{ csv: string }>(res);
  return data.csv;
}

export async function ingestLogs(
  payload: { content: string; format: 'csv' | 'json'; sourceName: string },
  identity: AnalystIdentity,
): Promise<WorkspaceSnapshot> {
  const res = await fetch('/api/logs/ingest', {
    method: 'POST',
    headers: buildHeaders(identity),
    body: JSON.stringify(payload),
  });
  return handleResponse<WorkspaceSnapshot>(res);
}

export async function resetDataset(identity: AnalystIdentity): Promise<WorkspaceSnapshot> {
  const res = await fetch('/api/logs/reset', {
    method: 'POST',
    headers: buildHeaders(identity),
  });
  return handleResponse<WorkspaceSnapshot>(res);
}

export async function updateIncidentStatus(
  incidentId: string,
  status: IncidentStatus,
  assignedAnalyst: string,
  identity: AnalystIdentity,
): Promise<WorkspaceSnapshot> {
  const res = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}`, {
    method: 'PATCH',
    headers: buildHeaders(identity),
    body: JSON.stringify({ status, assignedAnalyst }),
  });
  return handleResponse<WorkspaceSnapshot>(res);
}

export async function addIncidentNote(
  incidentId: string,
  content: string,
  identity: AnalystIdentity,
): Promise<WorkspaceSnapshot> {
  const res = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}/notes`, {
    method: 'POST',
    headers: buildHeaders(identity),
    body: JSON.stringify({ content }),
  });
  return handleResponse<WorkspaceSnapshot>(res);
}

export async function saveSettings(
  settings: PipelineSettings,
  identity: AnalystIdentity,
): Promise<WorkspaceSnapshot> {
  const res = await fetch('/api/settings', {
    method: 'PUT',
    headers: buildHeaders(identity),
    body: JSON.stringify(settings),
  });
  return handleResponse<WorkspaceSnapshot>(res);
}

export async function requestAiInvestigation(
  incidentId: string,
  identity: AnalystIdentity,
): Promise<AiInvestigationResponse> {
  const res = await fetch('/api/ai/investigate', {
    method: 'POST',
    headers: buildHeaders(identity),
    body: JSON.stringify({ incidentId }),
  });
  return handleResponse<AiInvestigationResponse>(res);
}

export async function askAiCopilot(
  question: string,
  incidentId: string | null,
  identity: AnalystIdentity,
): Promise<{ answer: string; model: string; answeredAt: string }> {
  const res = await fetch('/api/ai/ask', {
    method: 'POST',
    headers: buildHeaders(identity),
    body: JSON.stringify({ question, incidentId }),
  });
  return handleResponse<{ answer: string; model: string; answeredAt: string }>(res);
}

export async function logExportAudit(
  format: 'CSV' | 'PDF',
  target: string,
  identity: AnalystIdentity,
): Promise<void> {
  await fetch('/api/audit/export', {
    method: 'POST',
    headers: buildHeaders(identity),
    body: JSON.stringify({ format, target }),
  }).catch(() => undefined);
}

function downloadBlob(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function csvEscape(val: unknown): string {
  const s = String(val ?? '');
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export function exportEventsCsv(events: SecurityLogEvent[]): void {
  const headers = [
    'id',
    'timestamp',
    'sourceIp',
    'username',
    'eventType',
    'targetHost',
    'statusCode',
    'bytesTransferred',
    'country',
    'city',
    'asn',
    'ipReputationScore',
    'baseSeverity',
  ];
  const rows = events.map((e) =>
    [
      e.id,
      e.timestamp,
      e.sourceIp,
      e.username,
      e.eventType,
      e.targetHost,
      e.statusCode,
      e.bytesTransferred,
      e.country,
      e.city,
      e.asn,
      e.ipReputationScore,
      e.baseSeverity,
    ]
      .map(csvEscape)
      .join(','),
  );
  downloadBlob([headers.join(','), ...rows].join('\n'), 'tracemind-ai-events.csv', 'text/csv');
}

export function exportIncidentsCsv(incidents: Incident[]): void {
  const headers = [
    'id',
    'title',
    'severity',
    'riskScore',
    'status',
    'assignedAnalyst',
    'primaryIp',
    'affectedUsers',
    'affectedHosts',
    'eventCount',
    'firstSeen',
    'lastSeen',
    'narrative',
  ];
  const rows = incidents.map((i) =>
    [
      i.id,
      i.title,
      i.severity,
      i.riskScore,
      i.status,
      i.assignedAnalyst,
      i.primaryIp,
      i.affectedUsers.join('; '),
      i.affectedHosts.join('; '),
      i.eventIds.length,
      i.firstSeen,
      i.lastSeen,
      i.narrative,
    ]
      .map(csvEscape)
      .join(','),
  );
  downloadBlob(
    [headers.join(','), ...rows].join('\n'),
    'tracemind-ai-incidents.csv',
    'text/csv',
  );
}

export function exportIncidentPdf(incident: Incident, events: SecurityLogEvent[]): void {
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const margin = 44;
  const maxWidth = 507;
  let y = 50;

  const ensureSpace = (needed: number) => {
    if (y + needed > 780) {
      doc.addPage();
      y = 50;
    }
  };

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.text(`TraceMind AI — Security Incident Investigation Report`, margin, y);
  y += 22;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.text(
    `Incident ID: ${incident.id}   |   Severity: ${incident.severity} (${incident.riskScore}/100)   |   Status: ${incident.status}`,
    margin,
    y,
  );
  y += 16;
  doc.text(
    `Assigned Analyst: ${incident.assignedAnalyst}   |   Generated: ${new Date().toISOString()}`,
    margin,
    y,
  );
  y += 20;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  const titleLines = doc.splitTextToSize(incident.title, maxWidth);
  doc.text(titleLines, margin, y);
  y += titleLines.length * 16 + 8;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.text('Executive Narrative', margin, y);
  y += 14;
  doc.setFont('helvetica', 'normal');
  const narLines = doc.splitTextToSize(incident.narrative, maxWidth);
  doc.text(narLines, margin, y);
  y += narLines.length * 13 + 14;

  ensureSpace(90);
  doc.setFont('helvetica', 'bold');
  doc.text('Risk Score Factor Breakdown', margin, y);
  y += 14;
  doc.setFont('helvetica', 'normal');
  for (const f of incident.riskFactors) {
    ensureSpace(26);
    const line = `• ${f.factor} (${f.weightPct}%): ${f.weightedPoints} pts — ${f.evidenceSummary}`;
    const wrapped = doc.splitTextToSize(line, maxWidth);
    doc.text(wrapped, margin, y);
    y += wrapped.length * 13 + 3;
  }
  y += 10;

  ensureSpace(70);
  doc.setFont('helvetica', 'bold');
  doc.text('Chronological Attack Story', margin, y);
  y += 14;
  doc.setFont('helvetica', 'normal');
  for (const step of incident.attackStory) {
    ensureSpace(32);
    const line = `${step.stepNumber}. [${step.timestamp}] ${step.stage} — ${step.actor}@${step.sourceIp} -> ${step.targetHost} (${step.action}): ${step.significance}`;
    const wrapped = doc.splitTextToSize(line, maxWidth);
    doc.text(wrapped, margin, y);
    y += wrapped.length * 12 + 4;
  }

  if (incident.notes.length > 0) {
    y += 10;
    ensureSpace(60);
    doc.setFont('helvetica', 'bold');
    doc.text('Analyst Investigation Notes', margin, y);
    y += 14;
    doc.setFont('helvetica', 'normal');
    for (const note of incident.notes) {
      ensureSpace(28);
      const line = `[${note.createdAt}] ${note.author} (${note.role}): ${note.content}`;
      const wrapped = doc.splitTextToSize(line, maxWidth);
      doc.text(wrapped, margin, y);
      y += wrapped.length * 12 + 4;
    }
  }

  const matchedIds = new Set(incident.eventIds);
  const incEvents = events.filter((e) => matchedIds.has(e.id)).slice(0, 20);
  if (incEvents.length > 0) {
    y += 10;
    ensureSpace(60);
    doc.setFont('helvetica', 'bold');
    doc.text(`Supporting Evidence Events (${incEvents.length} shown)`, margin, y);
    y += 14;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    for (const ev of incEvents) {
      ensureSpace(18);
      doc.text(
        `${ev.id} | ${ev.timestamp} | ${ev.sourceIp} | ${ev.username} | ${ev.eventType} | ${ev.targetHost} | HTTP ${ev.statusCode}`,
        margin,
        y,
      );
      y += 12;
    }
  }

  doc.save(`tracemind-x-${incident.id.toLowerCase()}.pdf`);
}
