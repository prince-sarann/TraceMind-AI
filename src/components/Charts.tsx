import { useState } from 'react';
import type {
  AnomalyEntityResult,
  GeoIntelligencePoint,
  HourlyTrendPoint,
} from '../../shared/types';

export function ActivityTrendChart({ data }: { data: HourlyTrendPoint[] }) {
  const [activeIdx, setActiveIdx] = useState<number | null>(null);

  if (data.length === 0) {
    return (
      <div className="h-48 sm:h-56 flex items-center justify-center text-sm text-slate-500">
        No time-series telemetry available.
      </div>
    );
  }

  const width = 680;
  const height = 220;
  const padL = 38;
  const padR = 16;
  const padT = 16;
  const padB = 34;
  const innerW = width - padL - padR;
  const innerH = height - padT - padB;

  const maxY = Math.max(5, ...data.map((d) => d.totalEvents));
  const xStep = data.length > 1 ? innerW / (data.length - 1) : innerW / 2;

  const toX = (i: number) => (data.length > 1 ? padL + i * xStep : padL + innerW / 2);
  const toY = (v: number) => padT + innerH - (v / maxY) * innerH;

  const totalPath = data
    .map((d, i) => `${i === 0 ? 'M' : 'L'} ${toX(i).toFixed(1)} ${toY(d.totalEvents).toFixed(1)}`)
    .join(' ');
  const totalArea = `${totalPath} L ${toX(data.length - 1).toFixed(1)} ${(padT + innerH).toFixed(1)} L ${toX(0).toFixed(1)} ${(padT + innerH).toFixed(1)} Z`;

  const suspPath = data
    .map((d, i) => `${i === 0 ? 'M' : 'L'} ${toX(i).toFixed(1)} ${toY(d.suspiciousEvents).toFixed(1)}`)
    .join(' ');

  const gridTicks = [0, 0.25, 0.5, 0.75, 1];
  const hovered = activeIdx !== null ? data[activeIdx] : null;

  return (
    <div className="w-full min-w-0">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-slate-400">
          <span className="inline-flex items-center gap-2 whitespace-nowrap">
            <span className="w-2.5 h-0.5 bg-blue-400 inline-block" />
            Total Events
          </span>
          <span className="inline-flex items-center gap-2 whitespace-nowrap">
            <span className="w-2.5 h-2 bg-amber-500/70 inline-block rounded-xs" />
            Failed Logins
          </span>
          <span className="inline-flex items-center gap-2 whitespace-nowrap">
            <span className="w-2.5 h-0.5 bg-red-400 inline-block" />
            Correlated Suspicious
          </span>
        </div>
        {hovered && (
          <div className="text-xs font-mono tabular-nums text-cyan-300">
            {hovered.hourLabel} UTC · Total {hovered.totalEvents} · Failed {hovered.failedLogins} · Susp {hovered.suspiciousEvents}
          </div>
        )}
      </div>

      <div className="w-full overflow-hidden">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          preserveAspectRatio="xMidYMid meet"
          className="w-full h-auto min-h-[170px] max-h-[240px]"
        >
          <defs>
            <linearGradient id="totalFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.24" />
              <stop offset="100%" stopColor="#3B82F6" stopOpacity="0.01" />
            </linearGradient>
          </defs>

          {gridTicks.map((t) => {
            const yVal = Math.round(maxY * t);
            const yPos = toY(yVal);
            return (
              <g key={t}>
                <line
                  x1={padL}
                  x2={width - padR}
                  y1={yPos}
                  y2={yPos}
                  stroke="#1E293B"
                  strokeDasharray="3 3"
                />
                <text
                  x={padL - 8}
                  y={yPos + 3}
                  textAnchor="end"
                  className="fill-slate-500 text-[10px] font-mono"
                >
                  {yVal}
                </text>
              </g>
            );
          })}

          <path d={totalArea} fill="url(#totalFill)" />

          {data.map((d, i) => {
            const barW = Math.max(4, Math.min(14, xStep * 0.45));
            const barH = (d.failedLogins / maxY) * innerH;
            return (
              <rect
                key={`bar-${d.hourLabel}`}
                x={toX(i) - barW / 2}
                y={padT + innerH - barH}
                width={barW}
                height={barH}
                rx={1.5}
                fill="#F59E0B"
                fillOpacity={activeIdx === i ? 0.9 : 0.45}
              />
            );
          })}

          <path d={totalPath} fill="none" stroke="#3B82F6" strokeWidth={1.8} />
          <path d={suspPath} fill="none" stroke="#EF4444" strokeWidth={1.8} />

          {data.map((d, i) => {
            const x = toX(i);
            const showLabel = data.length <= 7 || i % Math.ceil(data.length / 6) === 0;
            return (
              <g key={d.hourLabel}>
                {showLabel && (
                  <text
                    x={x}
                    y={height - 10}
                    textAnchor="middle"
                    className="fill-slate-500 text-[10px] font-mono"
                  >
                    {d.hourLabel.slice(6)}
                  </text>
                )}
                {activeIdx === i && (
                  <g>
                    <line
                      x1={x}
                      x2={x}
                      y1={padT}
                      y2={padT + innerH}
                      stroke="#475569"
                      strokeWidth={1}
                    />
                    <circle cx={x} cy={toY(d.totalEvents)} r={3.5} fill="#3B82F6" />
                    <circle cx={x} cy={toY(d.suspiciousEvents)} r={3.5} fill="#EF4444" />
                  </g>
                )}
                <rect
                  x={x - Math.max(10, xStep / 2)}
                  y={padT}
                  width={Math.max(20, xStep)}
                  height={innerH}
                  fill="transparent"
                  className="cursor-pointer"
                  onMouseEnter={() => setActiveIdx(i)}
                  onMouseLeave={() => setActiveIdx(null)}
                  onClick={() => setActiveIdx(activeIdx === i ? null : i)}
                />
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

export function GeoThreatMap({ points }: { points: GeoIntelligencePoint[] }) {
  const [selected, setSelected] = useState<GeoIntelligencePoint | null>(
    points[0] ?? null,
  );

  const width = 640;
  const height = 270;
  const project = (lat: number, lon: number) => ({
    x: ((lon + 180) / 360) * width,
    y: ((90 - lat) / 180) * height,
  });

  const continents = [
    'M 55,48 L 155,36 L 198,66 L 182,110 L 140,126 L 116,138 L 95,112 L 62,82 Z',
    'M 145,146 L 195,154 L 216,192 L 188,244 L 166,252 L 152,204 Z',
    'M 294,48 L 368,42 L 382,78 L 348,96 L 304,92 L 292,70 Z',
    'M 294,104 L 362,102 L 392,148 L 366,216 L 332,222 L 308,162 L 286,132 Z',
    'M 378,42 L 542,46 L 568,94 L 516,142 L 456,148 L 404,118 L 380,82 Z',
    'M 498,176 L 564,178 L 574,218 L 518,226 L 494,202 Z',
  ];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start min-w-0">
      <div className="lg:col-span-7 bg-[#090D16] border border-slate-800/80 rounded-lg p-3 min-w-0">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          preserveAspectRatio="xMidYMid meet"
          className="w-full h-auto min-h-[160px] max-h-[230px]"
        >
          {[0.25, 0.5, 0.75].map((f) => (
            <line
              key={`h-${f}`}
              x1={0}
              x2={width}
              y1={height * f}
              y2={height * f}
              stroke="#1E293B"
              strokeWidth={0.6}
            />
          ))}
          {[0.2, 0.4, 0.6, 0.8].map((f) => (
            <line
              key={`v-${f}`}
              x1={width * f}
              x2={width * f}
              y1={0}
              y2={height}
              stroke="#1E293B"
              strokeWidth={0.6}
            />
          ))}

          {continents.map((d, idx) => (
            <path
              key={idx}
              d={d}
              fill="#151E32"
              stroke="#26334D"
              strokeWidth={1}
              strokeLinejoin="round"
            />
          ))}

          {points.map((pt) => {
            const { x, y } = project(pt.latitude, pt.longitude);
            const isThreat = pt.suspiciousCount > 0 || pt.maxReputationScore >= 60;
            const radius = Math.min(13, Math.max(4.5, 4 + Math.sqrt(pt.eventCount) * 1.4));
            const color =
              pt.maxReputationScore >= 80
                ? '#EF4444'
                : isThreat
                  ? '#F97316'
                  : '#06B6D4';
            const isSel = selected?.city === pt.city && selected?.country === pt.country;
            return (
              <g
                key={`${pt.country}-${pt.city}`}
                className="cursor-pointer"
                onClick={() => setSelected(pt)}
              >
                <circle
                  cx={x}
                  cy={y}
                  r={radius + 5}
                  fill={color}
                  fillOpacity={isSel ? 0.25 : 0.12}
                />
                <circle
                  cx={x}
                  cy={y}
                  r={radius}
                  fill={color}
                  fillOpacity={0.85}
                  stroke={isSel ? '#F8FAFC' : '#090D16'}
                  strokeWidth={isSel ? 1.8 : 1}
                />
              </g>
            );
          })}
        </svg>
        {selected && (
          <div className="mt-2 pt-2 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1 text-xs">
            <span className="text-slate-200 font-medium">
              {selected.city}, {selected.country}
            </span>
            <span className="font-mono tabular-nums text-slate-400">
              {selected.topIp} · Events {selected.eventCount} · Susp {selected.suspiciousCount} · Rep {selected.maxReputationScore}/100
            </span>
          </div>
        )}
      </div>

      <div className="lg:col-span-5 overflow-x-auto min-w-0">
        <table className="w-full text-left text-xs min-w-[280px]">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2 pr-2 font-medium">Location</th>
              <th className="py-2 px-2 font-medium text-right">Events</th>
              <th className="py-2 px-2 font-medium text-right">Susp</th>
              <th className="py-2 pl-2 font-medium text-right">Rep</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {points.slice(0, 6).map((pt) => (
              <tr
                key={`${pt.country}-${pt.city}`}
                onClick={() => setSelected(pt)}
                className={`cursor-pointer transition-colors hover:bg-slate-800/40 ${
                  selected?.city === pt.city ? 'bg-slate-800/50' : ''
                }`}
              >
                <td className="py-2.5 pr-2">
                  <div className="text-slate-200 font-medium truncate max-w-[140px]">
                    {pt.city}, {pt.country}
                  </div>
                  <div className="font-mono text-[11px] text-slate-500">{pt.topIp}</div>
                </td>
                <td className="py-2.5 px-2 text-right font-mono tabular-nums text-slate-300">
                  {pt.eventCount}
                </td>
                <td
                  className={`py-2.5 px-2 text-right font-mono tabular-nums ${
                    pt.suspiciousCount > 0 ? 'text-red-400 font-medium' : 'text-slate-500'
                  }`}
                >
                  {pt.suspiciousCount}
                </td>
                <td className="py-2.5 pl-2 text-right font-mono tabular-nums text-slate-300">
                  {pt.maxReputationScore}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function AnomalyScoreScatter({
  anomalies,
  threshold,
  selectedKey,
  onSelect,
}: {
  anomalies: AnomalyEntityResult[];
  threshold: number;
  selectedKey: string | null;
  onSelect: (a: AnomalyEntityResult) => void;
}) {
  const width = 560;
  const height = 220;
  const padL = 44;
  const padR = 20;
  const padT = 16;
  const padB = 34;
  const innerW = width - padL - padR;
  const innerH = height - padT - padB;

  const maxRate = Math.max(10, ...anomalies.map((a) => a.features.eventRatePerHour));
  const toX = (rate: number) => padL + (Math.min(rate, maxRate) / maxRate) * innerW;
  const toY = (score: number) => padT + innerH - Math.min(1, Math.max(0, score)) * innerH;
  const threshY = toY(threshold);

  return (
    <div className="w-full min-w-0">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3 text-xs text-slate-400">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
          <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
            <span className="w-2 h-2 rounded-xs bg-red-500" />
            Confirmed Malicious
          </span>
          <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
            <span className="w-2 h-2 rounded-xs bg-cyan-400" />
            Behavioural Anomaly
          </span>
          <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
            <span className="w-2 h-2 rounded-xs bg-slate-500" />
            Normal Baseline
          </span>
        </div>
        <span className="font-mono tabular-nums shrink-0">
          Threshold s(x) = {threshold.toFixed(2)}
        </span>
      </div>

      <div className="w-full overflow-hidden">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          preserveAspectRatio="xMidYMid meet"
          className="w-full h-auto min-h-[175px] max-h-[240px]"
        >
          {[0.2, 0.4, 0.6, 0.8, 1.0].map((v) => {
            const y = toY(v);
            return (
              <g key={v}>
                <line x1={padL} x2={width - padR} y1={y} y2={y} stroke="#1E293B" strokeDasharray="3 3" />
                <text x={padL - 8} y={y + 3} textAnchor="end" className="fill-slate-500 text-[10px] font-mono">
                  {v.toFixed(1)}
                </text>
              </g>
            );
          })}

          <line
            x1={padL}
            x2={width - padR}
            y1={threshY}
            y2={threshY}
            stroke="#06B6D4"
            strokeWidth={1.2}
            strokeDasharray="4 4"
          />

          {anomalies.map((a) => {
            const cx = toX(a.features.eventRatePerHour);
            const cy = toY(a.anomalyScore);
            const color =
              a.classification === 'Confirmed Malicious'
                ? '#EF4444'
                : a.classification === 'Behavioural Anomaly'
                  ? '#06B6D4'
                  : '#64748B';
            const isSel = selectedKey === a.entityKey;
            return (
              <g key={a.entityKey} className="cursor-pointer" onClick={() => onSelect(a)}>
                <circle
                  cx={cx}
                  cy={cy}
                  r={isSel ? 7.5 : 5.5}
                  fill={color}
                  fillOpacity={0.85}
                  stroke={isSel ? '#FFFFFF' : '#090D16'}
                  strokeWidth={isSel ? 2 : 1}
                />
                <title>
                  {`${a.label} (${a.entityType}) | Score: ${a.anomalyScore} | Rate: ${a.features.eventRatePerHour}/hr | ${a.classification}`}
                </title>
              </g>
            );
          })}

          <text
            x={padL + innerW / 2}
            y={height - 6}
            textAnchor="middle"
            className="fill-slate-500 text-[10px] font-sans"
          >
            Event Velocity (Events / Hour)
          </text>
        </svg>
      </div>
    </div>
  );
}
