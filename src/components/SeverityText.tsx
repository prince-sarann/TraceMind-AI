import type { IncidentStatus, SeverityLevel } from '../../shared/types';

const SEVERITY_STYLES: Record<SeverityLevel, { dot: string; text: string }> = {
  Critical: { dot: 'bg-red-500', text: 'text-red-400' },
  High: { dot: 'bg-orange-500', text: 'text-orange-400' },
  Medium: { dot: 'bg-amber-400', text: 'text-amber-300' },
  Low: { dot: 'bg-emerald-500', text: 'text-emerald-400' },
  Info: { dot: 'bg-slate-500', text: 'text-slate-400' },
};

export function SeverityText({ severity }: { severity: SeverityLevel }) {
  const style = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.Info;
  return (
    <span className={`inline-flex items-center gap-2 text-xs font-medium whitespace-nowrap ${style.text}`}>
      <span className={`w-1.5 h-1.5 rounded-xs shrink-0 ${style.dot}`} aria-hidden="true" />
      <span>{severity}</span>
    </span>
  );
}

const STATUS_STYLES: Record<IncidentStatus, string> = {
  Open: 'text-red-400',
  Investigating: 'text-cyan-400',
  Contained: 'text-amber-300',
  Resolved: 'text-emerald-400',
};

export function StatusText({ status }: { status: IncidentStatus }) {
  return (
    <span className={`text-xs font-medium whitespace-nowrap ${STATUS_STYLES[status]}`}>
      {status}
    </span>
  );
}
