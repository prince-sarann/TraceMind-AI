import { useState } from 'react';
import { Send, Bot, AlertCircle, CheckCircle2, HelpCircle, ShieldAlert } from 'lucide-react';
import type { AiInvestigationResponse, Incident } from '../../shared/types';
import { SeverityText } from '../components/SeverityText';
import { SocCard } from '../components/SocUi';
import { askAiCopilot, requestAiInvestigation, type AnalystIdentity } from '../lib/api';

interface ChatTurn {
  role: 'analyst' | 'assistant';
  content: string;
  timestamp: string;
}

export function AiAssistantView({
  incidents,
  selectedIncidentId,
  onSelectIncidentId,
  identity,
}: {
  incidents: Incident[];
  selectedIncidentId: string | null;
  onSelectIncidentId: (id: string) => void;
  identity: AnalystIdentity;
}) {
  const selected =
    incidents.find((i) => i.id === selectedIncidentId) ?? incidents[0] ?? null;

  const [briefByIncident, setBriefByIncident] = useState<Record<string, AiInvestigationResponse>>({});
  const [loadingBrief, setLoadingBrief] = useState(false);
  const [briefError, setBriefError] = useState<string | null>(null);

  const [question, setQuestion] = useState('');
  const [chatHistory, setChatHistory] = useState<ChatTurn[]>([]);
  const [asking, setAsking] = useState(false);
  const [askError, setAskError] = useState<string | null>(null);

  const currentBrief = selected ? briefByIncident[selected.id] : undefined;

  const handleGenerateBrief = async () => {
    if (!selected) return;
    setLoadingBrief(true);
    setBriefError(null);
    try {
      const res = await requestAiInvestigation(selected.id, identity);
      setBriefByIncident((prev) => ({ ...prev, [selected.id]: res }));
    } catch (err) {
      setBriefError(err instanceof Error ? err.message : 'Failed to generate AI briefing.');
    } finally {
      setLoadingBrief(false);
    }
  };

  const handleAsk = async (e: React.FormEvent) => {
    e.preventDefault();
    const q = question.trim();
    if (!q) return;
    setAskError(null);
    setQuestion('');
    setChatHistory((prev) => [
      ...prev,
      { role: 'analyst', content: q, timestamp: new Date().toISOString() },
    ]);
    setAsking(true);
    try {
      const res = await askAiCopilot(q, selected?.id ?? null, identity);
      setChatHistory((prev) => [
        ...prev,
        { role: 'assistant', content: res.answer, timestamp: res.answeredAt },
      ]);
    } catch (err) {
      setAskError(err instanceof Error ? err.message : 'AI Copilot query failed.');
    } finally {
      setAsking(false);
    }
  };

  const quickPrompts = [
    'Which exact events prove privilege escalation or data exfiltration in this incident?',
    'What is the difference between ci-release-bot anomaly and this incident?',
    'What containment steps should Tier-2 take in the first 15 minutes?',
  ];

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-start min-w-0">
      {/* Left: Evidence-Grounded Investigation Brief */}
      <div className="xl:col-span-7 space-y-5 min-w-0">
        <SocCard className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div className="min-w-0">
              <h2 className="text-sm font-semibold text-slate-100">
                Evidence-Grounded AI Investigation Brief
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Powered by Gemini · Cites verified log evidence and separates unverified hypotheses
              </p>
            </div>

            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 min-w-0 shrink-0">
              <select
                value={selected?.id ?? ''}
                onChange={(e) => onSelectIncidentId(e.target.value)}
                className="min-h-[40px] w-full sm:w-auto max-w-full bg-[#090D16] border border-slate-800 rounded px-2.5 py-2 text-xs font-mono text-slate-200"
              >
                {incidents.map((inc) => (
                  <option key={inc.id} value={inc.id}>
                    {inc.id} — {inc.severity} ({inc.riskScore}/100)
                  </option>
                ))}
              </select>

              <button
                type="button"
                disabled={!selected || loadingBrief}
                onClick={handleGenerateBrief}
                className="min-h-[40px] px-4 py-2 text-xs font-medium bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded transition-colors whitespace-nowrap"
              >
                {loadingBrief ? 'Analyzing Telemetry...' : 'Generate Brief'}
              </button>
            </div>
          </div>

          {selected && (
            <div className="bg-[#090D16] border border-slate-800/80 rounded p-3 flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="min-w-0 flex-1">
                <span className="font-mono text-slate-400">{selected.id} · </span>
                <span className="text-slate-200 font-medium break-words">{selected.title}</span>
              </div>
              <SeverityText severity={selected.severity} />
            </div>
          )}

          {briefError && (
            <div className="p-3 bg-red-950/30 border border-red-900/60 rounded text-xs text-red-300 flex items-start gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{briefError}</span>
            </div>
          )}

          {!currentBrief && !loadingBrief && (
            <div className="py-10 px-4 text-center text-xs text-slate-400 border border-dashed border-slate-800 rounded leading-relaxed">
              Click <strong className="text-slate-200">Generate Brief</strong> to synthesize an evidence-grounded Gemini investigation report for {selected?.id ?? 'the selected incident'}.
            </div>
          )}

          {loadingBrief && (
            <div className="space-y-3 animate-pulse">
              <div className="h-4 bg-slate-800 rounded w-3/4" />
              <div className="h-4 bg-slate-800 rounded w-full" />
              <div className="h-24 bg-slate-800 rounded w-full" />
            </div>
          )}

          {currentBrief && (
            <div className="space-y-5 pt-2">
              <div>
                <div className="text-xs font-semibold text-slate-300 mb-1">Executive Assessment</div>
                <p className="text-xs text-slate-200 leading-relaxed">{currentBrief.summary}</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-[#090D16] border border-slate-800/80 rounded p-3.5">
                  <div className="text-xs font-semibold text-cyan-300 flex items-center gap-1.5 mb-2">
                    <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                    <span>Why This Activity Is Suspicious</span>
                  </div>
                  <ul className="space-y-1.5 text-xs text-slate-300 list-disc pl-4 leading-relaxed">
                    {currentBrief.whySuspicious.map((item, idx) => (
                      <li key={idx}>{item}</li>
                    ))}
                  </ul>
                </div>

                <div className="bg-[#090D16] border border-slate-800/80 rounded p-3.5">
                  <div className="text-xs font-semibold text-amber-300 flex items-center gap-1.5 mb-2">
                    <HelpCircle className="w-3.5 h-3.5 shrink-0" />
                    <span>Unverified Hypotheses (Require Validation)</span>
                  </div>
                  <ul className="space-y-1.5 text-xs text-slate-300 list-disc pl-4 leading-relaxed">
                    {currentBrief.unverifiedHypotheses.map((item, idx) => (
                      <li key={idx}>{item}</li>
                    ))}
                  </ul>
                </div>
              </div>

              <div>
                <div className="text-xs font-semibold text-slate-300 mb-2">
                  Verified Supporting Log Evidence
                </div>
                <div className="divide-y divide-slate-800/70 border border-slate-800 rounded bg-[#090D16]">
                  {currentBrief.supportingEvidence.map((ev, idx) => (
                    <div key={idx} className="p-2.5 text-xs flex flex-col sm:flex-row sm:items-center gap-1.5 sm:gap-2">
                      <span className="font-mono text-cyan-300 shrink-0">{ev.eventId}</span>
                      <span className="font-mono text-[11px] text-slate-500 shrink-0">{ev.timestamp}</span>
                      <span className="text-slate-300 leading-relaxed">{ev.detail}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <div className="text-xs font-semibold text-slate-300 mb-1.5">
                    Recommended Next Investigation Steps
                  </div>
                  <ul className="space-y-1.5 text-xs text-slate-300 list-decimal pl-4 leading-relaxed">
                    {currentBrief.recommendedNextSteps.map((s, idx) => (
                      <li key={idx}>{s}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <div className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5 mb-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                    <span>Containment Actions</span>
                  </div>
                  <ul className="space-y-1.5 text-xs text-slate-300 list-disc pl-4 leading-relaxed">
                    {currentBrief.containmentActions.map((c, idx) => (
                      <li key={idx}>{c}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}
        </SocCard>
      </div>

      {/* Right: Interactive Analyst Copilot Chat */}
      <SocCard className="xl:col-span-5 flex flex-col h-[480px] lg:h-[600px]">
        <div className="pb-3 border-b border-slate-800 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <Bot className="w-4 h-4 text-blue-400 shrink-0" />
            <h3 className="text-sm font-semibold text-slate-100 truncate">Analyst Q&A Copilot</h3>
          </div>
          <span className="text-[11px] font-mono text-slate-500 shrink-0">
            Context: {selected?.id ?? 'Global'}
          </span>
        </div>

        <div className="flex-1 overflow-y-auto py-4 space-y-3 min-h-0">
          {chatHistory.length === 0 ? (
            <div className="space-y-3">
              <p className="text-xs text-slate-400 leading-relaxed">
                Ask targeted forensic questions grounded in {selected?.id ?? 'current telemetry'}.
              </p>
              <div className="space-y-2">
                {quickPrompts.map((qp) => (
                  <button
                    key={qp}
                    type="button"
                    onClick={() => setQuestion(qp)}
                    className="w-full min-h-[42px] text-left text-xs p-3 rounded bg-[#090D16] border border-slate-800 hover:border-slate-700 text-slate-300 transition-colors leading-relaxed"
                  >
                    {qp}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            chatHistory.map((turn, i) => (
              <div
                key={i}
                className={`p-3 rounded text-xs leading-relaxed break-words ${
                  turn.role === 'analyst'
                    ? 'bg-blue-950/40 border border-blue-800/50 text-slate-100 ml-3 sm:ml-6'
                    : 'bg-[#090D16] border border-slate-800 text-slate-200 mr-2 sm:mr-4 whitespace-pre-wrap'
                }`}
              >
                <div className="text-[10px] font-mono text-slate-500 mb-1">
                  {turn.role === 'analyst' ? identity.name : 'TraceMind AI Assistant'}
                </div>
                {turn.content}
              </div>
            ))
          )}
          {asking && (
            <div className="text-xs text-slate-400 font-mono">Querying Gemini telemetry context...</div>
          )}
          {askError && (
            <div className="text-xs text-red-400 bg-red-950/30 border border-red-900/50 rounded p-2.5">
              {askError}
            </div>
          )}
        </div>

        <form onSubmit={handleAsk} className="pt-3 border-t border-slate-800 flex flex-col sm:flex-row gap-2">
          <input
            type="text"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask about IPs, event IDs, or response steps..."
            className="flex-1 min-h-[40px] bg-[#090D16] border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
          />
          <button
            type="submit"
            disabled={asking || !question.trim()}
            className="min-h-[40px] px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded inline-flex items-center justify-center gap-1.5 text-xs font-medium whitespace-nowrap"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Send</span>
          </button>
        </form>
      </SocCard>
    </div>
  );
}
