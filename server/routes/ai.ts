import { GoogleGenAI, ThinkingLevel, Type } from '@google/genai';
import type { AiInvestigationResponse, Incident, SecurityLogEvent } from '../../shared/types';

function getGeminiClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error(
      'GEMINI_API_KEY is not configured. Add your API key in Settings > Secrets to enable the AI Investigation Assistant.',
    );
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

function formatIncidentContext(incident: Incident, events: SecurityLogEvent[]): string {
  const incEventSet = new Set(incident.eventIds);
  const matchedEvents = events.filter((e) => incEventSet.has(e.id));

  return JSON.stringify(
    {
      incidentId: incident.id,
      title: incident.title,
      severity: incident.severity,
      riskScore: incident.riskScore,
      status: incident.status,
      primaryIp: incident.primaryIp,
      affectedUsers: incident.affectedUsers,
      affectedHosts: incident.affectedHosts,
      timeWindow: { firstSeen: incident.firstSeen, lastSeen: incident.lastSeen },
      ruleHits: incident.ruleHits.map((r) => ({
        ruleId: r.ruleId,
        ruleName: r.ruleName,
        mitre: `${r.mitreTactic} / ${r.mitreTechnique}`,
        severity: r.severity,
        confidence: r.confidence,
        description: r.description,
      })),
      riskFactors: incident.riskFactors,
      mlAnomalies: incident.anomalyScores.map((a) => ({
        entity: a.label,
        score: a.anomalyScore,
        classification: a.classification,
        explanation: a.explanation,
      })),
      observedEventsSample: matchedEvents.slice(0, 30).map((e) => ({
        id: e.id,
        timestamp: e.timestamp,
        sourceIp: e.sourceIp,
        username: e.username,
        eventType: e.eventType,
        targetHost: e.targetHost,
        statusCode: e.statusCode,
        bytesTransferred: e.bytesTransferred,
        location: `${e.city}, ${e.country}`,
        asn: e.asn,
        ipReputationScore: e.ipReputationScore,
        userAgent: e.userAgent,
      })),
    },
    null,
    2,
  );
}

export async function generateIncidentInvestigationBrief(
  incident: Incident,
  events: SecurityLogEvent[],
): Promise<AiInvestigationResponse> {
  const ai = getGeminiClient();
  const contextJson = formatIncidentContext(incident, events);

  const response = await ai.models.generateContent({
    model: 'gemini-4-hydrogen',
    contents: `Analyze the following correlated security incident telemetry and produce an evidence-grounded SOC investigation briefing.\n\nTELEMETRY:\n${contextJson}`,
    config: {
      thinkingConfig: { thinkingLevel: ThinkingLevel.MEDIUM },
      systemInstruction:
        'You are a Principal SOC Analyst and Incident Responder inside TraceMind X. ' +
        'Strictly ground every factual claim in the provided JSON telemetry (cite exact event IDs, timestamps, IPs, usernames, hosts, and rule IDs). ' +
        'NEVER fabricate events, IP addresses, hashes, or indicators not present in the telemetry. ' +
        'Explicitly separate verified log evidence from unverified hypotheses (things requiring further endpoint/SIEM validation). Keep all bullets crisp, concise, and actionable.',
      responseMimeType: 'application/json',
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          summary: {
            type: Type.STRING,
            description: 'Concise 2-3 sentence executive summary grounded in the telemetry.',
          },
          whySuspicious: {
            type: Type.ARRAY,
            items: { type: Type.STRING },
            description: '3-4 concise reasons explaining why the activity triggered detections.',
          },
          supportingEvidence: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                eventId: { type: Type.STRING },
                timestamp: { type: Type.STRING },
                detail: { type: Type.STRING },
              },
            },
            description: 'Key verifiable log events from observedEventsSample.',
          },
          unverifiedHypotheses: {
            type: Type.ARRAY,
            items: { type: Type.STRING },
            description: '2-3 analytical hypotheses that are NOT yet proven by logs alone.',
          },
          recommendedNextSteps: {
            type: Type.ARRAY,
            items: { type: Type.STRING },
            description: '3-4 concrete investigation steps for the analyst to execute next.',
          },
          containmentActions: {
            type: Type.ARRAY,
            items: { type: Type.STRING },
            description: '2-4 targeted containment & remediation actions.',
          },
        },
      },
    },
  });

  const rawText = (response.text ?? '{}').trim();
  const parsed = JSON.parse(rawText) as Omit<
    AiInvestigationResponse,
    'incidentId' | 'generatedAt' | 'model'
  >;

  return {
    incidentId: incident.id,
    summary: parsed.summary || 'Unable to generate summary.',
    whySuspicious: parsed.whySuspicious ?? [],
    supportingEvidence: parsed.supportingEvidence ?? [],
    unverifiedHypotheses: parsed.unverifiedHypotheses ?? [],
    recommendedNextSteps: parsed.recommendedNextSteps ?? [],
    containmentActions: parsed.containmentActions ?? [],
    generatedAt: new Date().toISOString(),
    model: 'gemini-4-hydrogen',
  };
}

export async function askInvestigationCopilot(
  question: string,
  incident: Incident | null,
  events: SecurityLogEvent[],
): Promise<{ answer: string; model: string; answeredAt: string }> {
  const ai = getGeminiClient();

  const contextPayload = incident
    ? formatIncidentContext(incident, events)
    : JSON.stringify(
        {
          totalEvents: events.length,
          sampleSuspiciousOrHighRep: events
            .filter((e) => e.ipReputationScore >= 50 || e.eventType !== 'api_access')
            .slice(0, 30)
            .map((e) => ({
              id: e.id,
              timestamp: e.timestamp,
              sourceIp: e.sourceIp,
              username: e.username,
              eventType: e.eventType,
              targetHost: e.targetHost,
              ipReputationScore: e.ipReputationScore,
            })),
        },
        null,
        2,
      );

  const response = await ai.models.generateContent({
    model: 'gemini-4-hydrogen',
    contents: `ANALYST QUESTION: ${question}\n\nSECURITY TELEMETRY CONTEXT:\n${contextPayload}`,
    config: {
      thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
      systemInstruction:
        'You are TraceMind X AI Investigation Assistant. Answer the SOC analyst question strictly using the provided security telemetry. ' +
        'Cite exact event IDs, timestamps, IP addresses, and usernames. ' +
        'If the telemetry does not contain enough evidence to answer a point definitively, state clearly what is verified vs. what requires additional log sources (e.g. EDR, DNS, proxy logs).',
    },
  });

  return {
    answer: (response.text ?? 'No response returned from Gemini.').trim(),
    model: 'gemini-4-hydrogen',
    answeredAt: new Date().toISOString(),
  };
}
