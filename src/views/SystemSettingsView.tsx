import { useState } from 'react';
import { RotateCcw, Save, ShieldCheck } from 'lucide-react';
import type { AnalystRole, PipelineSettings } from '../../shared/types';
import { SocCard } from '../components/SocUi';
import type { AnalystIdentity } from '../lib/api';

export function SystemSettingsView({
  settings,
  identity,
  onChangeIdentity,
  onSaveSettings,
  onResetDataset,
}: {
  settings: PipelineSettings;
  identity: AnalystIdentity;
  onChangeIdentity: (next: AnalystIdentity) => void;
  onSaveSettings: (next: PipelineSettings) => Promise<void>;
  onResetDataset: () => Promise<void>;
}) {
  const [form, setForm] = useState<PipelineSettings>(settings);
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setStatusMsg(null);
    setErrorMsg(null);
    try {
      await onSaveSettings(form);
      setStatusMsg('Detection thresholds, ML hyperparameters, and risk weights updated.');
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to save settings.');
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    setSaving(true);
    setStatusMsg(null);
    setErrorMsg(null);
    try {
      await onResetDataset();
      setStatusMsg('Synthetic dataset and baseline settings restored.');
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to reset dataset.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl min-w-0">
      {/* About & Lead SOC Analyst Attribution */}
      <SocCard className="space-y-3">
        <div className="flex items-start gap-3">
          <ShieldCheck className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
          <div className="min-w-0">
            <h2 className="text-sm sm:text-base font-semibold text-slate-100">
              About TraceMind AI
            </h2>
            <p className="text-xs text-slate-300 mt-1 leading-relaxed">
              TraceMind AI is an AI-powered Cyber Threat Intelligence and Security Incident Investigation Platform designed for automated log normalization, rule-based MITRE ATT&CK threat detection, Isolation Forest behavioural anomaly isolation, graph correlation, explainable risk scoring, and evidence-grounded Gemini investigation.
            </p>
            <div className="mt-3 pt-3 border-t border-slate-800/80 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
              <div>
                <div className="text-slate-500">Lead SOC Analyst</div>
                <div className="font-semibold text-slate-100 mt-0.5">Prince Kumar Saran</div>
              </div>
              <div>
                <div className="text-slate-500">ML & Correlation Engine</div>
                <div className="font-mono text-slate-300 mt-0.5">Isolation Forest + BFS Graph</div>
              </div>
              <div>
                <div className="text-slate-500">Persistence & AI</div>
                <div className="font-mono text-slate-300 mt-0.5">SQLite + Gemini 4 Hydrogen</div>
              </div>
            </div>
          </div>
        </div>
      </SocCard>

      {/* RBAC Session Context */}
      <SocCard className="space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">
            Demo Analyst Session & Role Simulation
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            This is a learning/demo role selector, not real authentication. The API trusts client-supplied role headers, so users can change them. Never rely on these demo roles to protect real data or a public deployment.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs text-slate-400 mb-1">Active Analyst Name</label>
            <input
              type="text"
              value={identity.name}
              onChange={(e) => onChangeIdentity({ ...identity, name: e.target.value })}
              className="w-full min-h-[40px] bg-[#090D16] border border-slate-800 rounded px-3 py-2 text-xs text-slate-100"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Simulated Analyst Role</label>
            <select
              value={identity.role}
              onChange={(e) =>
                onChangeIdentity({ ...identity, role: e.target.value as AnalystRole })
              }
              className="w-full min-h-[40px] bg-[#090D16] border border-slate-800 rounded px-3 py-2 text-xs text-slate-100"
            >
              <option value="Lead SOC Analyst">Lead SOC Analyst (Demo permissions)</option>
              <option value="Tier-2 Responder">Tier-2 Responder (Demo permissions)</option>
              <option value="Read-Only Auditor">Read-Only Auditor (Demo permissions)</option>
            </select>
          </div>
        </div>
      </SocCard>

      {/* Detection & Isolation Forest Configuration */}
      <form onSubmit={handleSave}>
        <SocCard className="space-y-5">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Detection Engine & Isolation Forest Configuration
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Changes immediately recompute rule hits, ML anomaly classifications, correlations, and incident risk scores.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Brute-Force Threshold (failures)</label>
              <input
                type="number"
                min={2}
                max={50}
                value={form.bruteForceThreshold}
                onChange={(e) =>
                  setForm({ ...form, bruteForceThreshold: Number(e.target.value) })
                }
                className="w-full min-h-[40px] bg-[#090D16] border border-slate-800 rounded px-3 py-2 text-xs font-mono text-slate-100"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Brute-Force Window (minutes)</label>
              <input
                type="number"
                min={1}
                max={180}
                value={form.bruteForceWindowMin}
                onChange={(e) =>
                  setForm({ ...form, bruteForceWindowMin: Number(e.target.value) })
                }
                className="w-full min-h-[40px] bg-[#090D16] border border-slate-800 rounded px-3 py-2 text-xs font-mono text-slate-100"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Password Spray Accounts</label>
              <input
                type="number"
                min={2}
                max={50}
                value={form.sprayAccountThreshold}
                onChange={(e) =>
                  setForm({ ...form, sprayAccountThreshold: Number(e.target.value) })
                }
                className="w-full min-h-[40px] bg-[#090D16] border border-slate-800 rounded px-3 py-2 text-xs font-mono text-slate-100"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Off-Hours Start (UTC 0-23)</label>
              <input
                type="number"
                min={0}
                max={23}
                value={form.offHoursStartUtc}
                onChange={(e) => setForm({ ...form, offHoursStartUtc: Number(e.target.value) })}
                className="w-full min-h-[40px] bg-[#090D16] border border-slate-800 rounded px-3 py-2 text-xs font-mono text-slate-100"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Off-Hours End (UTC 0-23)</label>
              <input
                type="number"
                min={0}
                max={23}
                value={form.offHoursEndUtc}
                onChange={(e) => setForm({ ...form, offHoursEndUtc: Number(e.target.value) })}
                className="w-full min-h-[40px] bg-[#090D16] border border-slate-800 rounded px-3 py-2 text-xs font-mono text-slate-100"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">
                Isolation Forest Threshold (0.40–0.85)
              </label>
              <input
                type="number"
                step={0.01}
                min={0.4}
                max={0.85}
                value={form.anomalyScoreThreshold}
                onChange={(e) =>
                  setForm({ ...form, anomalyScoreThreshold: Number(e.target.value) })
                }
                className="w-full min-h-[40px] bg-[#090D16] border border-slate-800 rounded px-3 py-2 text-xs font-mono text-slate-100"
              />
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <button
              type="button"
              disabled={saving}
              onClick={handleReset}
              className="min-h-[40px] inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset Synthetic Dataset</span>
            </button>

            <button
              type="submit"
              disabled={saving}
              className="min-h-[40px] inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{saving ? 'Applying Pipeline...' : 'Save & Recompute Pipeline'}</span>
            </button>
          </div>

          {statusMsg && <div className="text-xs text-emerald-400">{statusMsg}</div>}
          {errorMsg && <div className="text-xs text-red-400">{errorMsg}</div>}
        </SocCard>
      </form>
    </div>
  );
}
