import { useState } from 'react';
import type { AnomalyEntityResult, WorkspaceSnapshot } from '../../shared/types';
import { AnomalyScoreScatter } from '../components/Charts';
import { SeverityText } from '../components/SeverityText';
import { SectionHeader, SocCard } from '../components/SocUi';

export function ThreatDetectionView({ snapshot }: { snapshot: WorkspaceSnapshot }) {
  const { ruleHits, anomalies, modelEvaluation, settings } = snapshot;
  const [selectedAnomaly, setSelectedAnomaly] = useState<AnomalyEntityResult | null>(
    anomalies.find((a) => a.classification === 'Behavioural Anomaly') ?? anomalies[0] ?? null,
  );
  const [classFilter, setClassFilter] = useState<
    'All' | 'Confirmed Malicious' | 'Behavioural Anomaly' | 'Normal'
  >('All');

  const filteredAnomalies = anomalies.filter(
    (a) => classFilter === 'All' || a.classification === classFilter,
  );

  return (
    <div className="space-y-6 min-w-0">
      {/* Rule-Based Threat Detection Section */}
      <SocCard>
        <SectionHeader
          title="Rule-Based Threat Detection Engine"
          subtitle={`Configurable deterministic heuristics mapped to MITRE ATT&CK tactics (${ruleHits.length} detections active)`}
          action={
            <div className="text-xs font-mono tabular-nums text-slate-400">
              Brute ≥ {settings.bruteForceThreshold}/{settings.bruteForceWindowMin}m · Spray ≥ {settings.sprayAccountThreshold} accts · Off-Hours {String(settings.offHoursStartUtc).padStart(2, '0')}–{String(settings.offHoursEndUtc).padStart(2, '0')} UTC
            </div>
          }
        />

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs min-w-[780px]">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2 pr-3 font-medium">Rule</th>
                <th className="py-2 pr-3 font-medium">Severity</th>
                <th className="py-2 pr-3 font-medium">MITRE ATT&CK</th>
                <th className="py-2 pr-3 font-medium">Source IP</th>
                <th className="py-2 pr-3 font-medium">Affected Accounts</th>
                <th className="py-2 pr-3 font-medium">Evidence Summary</th>
                <th className="py-2 font-medium text-right">Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {ruleHits.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No deterministic rules matched under current thresholds.
                  </td>
                </tr>
              ) : (
                ruleHits.map((hit) => (
                  <tr key={hit.id} className="hover:bg-slate-800/35">
                    <td className="py-3 pr-3 align-top">
                      <div className="font-mono text-cyan-300">{hit.ruleId}</div>
                      <div className="font-medium text-slate-100 mt-0.5">{hit.ruleName}</div>
                    </td>
                    <td className="py-3 pr-3 align-top">
                      <SeverityText severity={hit.severity} />
                    </td>
                    <td className="py-3 pr-3 align-top text-slate-300">
                      <div>{hit.mitreTactic}</div>
                      <div className="text-[11px] font-mono text-slate-500">{hit.mitreTechnique}</div>
                    </td>
                    <td className="py-3 pr-3 align-top font-mono text-slate-200 whitespace-nowrap">
                      {hit.primaryIp}
                    </td>
                    <td className="py-3 pr-3 align-top font-mono text-slate-300">
                      {hit.affectedUsers.join(', ')}
                    </td>
                    <td className="py-3 pr-3 align-top text-slate-300 max-w-md">
                      {hit.description}
                    </td>
                    <td className="py-3 align-top text-right font-mono tabular-nums text-slate-200">
                      {hit.confidence}%
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </SocCard>

      {/* Isolation Forest ML Anomaly Detection & Model Evaluation */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 items-stretch">
        <SocCard className="xl:col-span-7">
          <SectionHeader
            title="Isolation Forest Behavioural Anomaly Scoring"
            subtitle="Unsupervised anomaly scores s(x, n) distinguishing statistical outliers from rule-confirmed threats"
          />
          <AnomalyScoreScatter
            anomalies={anomalies}
            threshold={settings.anomalyScoreThreshold}
            selectedKey={selectedAnomaly?.entityKey ?? null}
            onSelect={setSelectedAnomaly}
          />
        </SocCard>

        <SocCard className="xl:col-span-5 space-y-4">
          <SectionHeader
            title="ML Model Evaluation & Confusion Matrix"
            subtitle={`${modelEvaluation.algorithm} · ${modelEvaluation.nEstimators} trees`}
          />

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center bg-[#090D16] border border-slate-800/80 rounded p-3">
            <div>
              <div className="text-[11px] text-slate-500">Precision</div>
              <div className="text-base font-mono tabular-nums font-semibold text-slate-100 mt-0.5">
                {(modelEvaluation.precision * 100).toFixed(1)}%
              </div>
            </div>
            <div>
              <div className="text-[11px] text-slate-500">Recall</div>
              <div className="text-base font-mono tabular-nums font-semibold text-slate-100 mt-0.5">
                {(modelEvaluation.recall * 100).toFixed(1)}%
              </div>
            </div>
            <div>
              <div className="text-[11px] text-slate-500">F1 Score</div>
              <div className="text-base font-mono tabular-nums font-semibold text-cyan-400 mt-0.5">
                {modelEvaluation.f1Score.toFixed(3)}
              </div>
            </div>
            <div>
              <div className="text-[11px] text-slate-500">ROC-AUC</div>
              <div className="text-base font-mono tabular-nums font-semibold text-blue-400 mt-0.5">
                {modelEvaluation.rocAucEstimate.toFixed(3)}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs font-mono tabular-nums">
            <div className="bg-[#090D16] border border-slate-800/80 rounded p-2.5 flex justify-between">
              <span className="text-slate-400">True Positives</span>
              <span className="text-emerald-400 font-semibold">{modelEvaluation.truePositives}</span>
            </div>
            <div className="bg-[#090D16] border border-slate-800/80 rounded p-2.5 flex justify-between">
              <span className="text-slate-400">False Positives</span>
              <span className="text-amber-300 font-semibold">{modelEvaluation.falsePositives}</span>
            </div>
            <div className="bg-[#090D16] border border-slate-800/80 rounded p-2.5 flex justify-between">
              <span className="text-slate-400">True Negatives</span>
              <span className="text-slate-200 font-semibold">{modelEvaluation.trueNegatives}</span>
            </div>
            <div className="bg-[#090D16] border border-slate-800/80 rounded p-2.5 flex justify-between">
              <span className="text-slate-400">False Negatives</span>
              <span className="text-red-400 font-semibold">{modelEvaluation.falseNegatives}</span>
            </div>
          </div>

          {selectedAnomaly && (
            <div className="pt-2 border-t border-slate-800">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                <span className="font-semibold text-slate-100 font-mono">
                  Explainability: {selectedAnomaly.label}
                </span>
                <span className="font-mono tabular-nums text-cyan-300">
                  s(x) = {selectedAnomaly.anomalyScore.toFixed(3)}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                {selectedAnomaly.explanation}
              </p>
            </div>
          )}
        </SocCard>
      </div>

      {/* Explainable Entity Classification Table */}
      <SocCard>
        <SectionHeader
          title="Entity Behavioural Profiles (Anomalous vs. Confirmed Malicious)"
          subtitle="Click any row to inspect Z-score feature deviations"
          action={
            <div className="flex flex-wrap items-center gap-1 p-1 bg-[#090D16] border border-slate-800 rounded-md">
              {(['All', 'Confirmed Malicious', 'Behavioural Anomaly', 'Normal'] as const).map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setClassFilter(tab)}
                  className={`min-h-[34px] px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap ${
                    classFilter === tab
                      ? 'bg-slate-800 text-slate-100'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>
          }
        />

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs min-w-[740px]">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2 pr-3 font-medium">Entity</th>
                <th className="py-2 pr-3 font-medium">Type</th>
                <th className="py-2 pr-3 font-medium">Classification</th>
                <th className="py-2 pr-3 font-medium text-right">Anomaly Score</th>
                <th className="py-2 pr-3 font-medium text-right">Events/Hr</th>
                <th className="py-2 pr-3 font-medium text-right">Fail Ratio</th>
                <th className="py-2 pr-3 font-medium">Top Z-Score Feature Drivers</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filteredAnomalies.map((a) => (
                <tr
                  key={a.entityKey}
                  onClick={() => setSelectedAnomaly(a)}
                  className={`cursor-pointer hover:bg-slate-800/40 ${
                    selectedAnomaly?.entityKey === a.entityKey ? 'bg-slate-800/50' : ''
                  }`}
                >
                  <td className="py-2.5 pr-3 font-mono text-slate-100 whitespace-nowrap">{a.label}</td>
                  <td className="py-2.5 pr-3 text-slate-400 uppercase">{a.entityType}</td>
                  <td className="py-2.5 pr-3 whitespace-nowrap">
                    <span
                      className={
                        a.classification === 'Confirmed Malicious'
                          ? 'text-red-400 font-medium'
                          : a.classification === 'Behavioural Anomaly'
                            ? 'text-cyan-300 font-medium'
                            : 'text-slate-400'
                      }
                    >
                      {a.classification}
                    </span>
                  </td>
                  <td className="py-2.5 pr-3 text-right font-mono tabular-nums text-slate-200">
                    {a.anomalyScore.toFixed(3)}
                  </td>
                  <td className="py-2.5 pr-3 text-right font-mono tabular-nums text-slate-300">
                    {a.features.eventRatePerHour.toFixed(1)}
                  </td>
                  <td className="py-2.5 pr-3 text-right font-mono tabular-nums text-slate-300">
                    {(a.features.failedLoginRatio * 100).toFixed(0)}%
                  </td>
                  <td className="py-2.5 pr-3 text-slate-400 font-mono text-[11px]">
                    {a.topContributors
                      .slice(0, 2)
                      .map((c) => `${c.label} (z=${c.zScore >= 0 ? '+' : ''}${c.zScore})`)
                      .join(' · ')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </SocCard>
    </div>
  );
}
