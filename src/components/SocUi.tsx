import type { ReactNode } from 'react';

export function SocCard({
  children,
  className = '',
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`bg-[#111827] border border-slate-800/90 rounded-lg p-4 sm:p-5 min-w-0 ${className}`}
    >
      {children}
    </section>
  );
}

export function SectionHeader({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 sm:gap-4 mb-4 min-w-0">
      <div className="min-w-0">
        <h2 className="text-sm sm:text-[15px] font-semibold text-slate-100 leading-snug">
          {title}
        </h2>
        {subtitle && (
          <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">
            {subtitle}
          </p>
        )}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}

export function KpiCard({
  label,
  value,
  subvalue,
  caption,
  valueColor = 'text-slate-100',
}: {
  label: string;
  value: string | number;
  subvalue?: string;
  caption: string;
  valueColor?: string;
}) {
  return (
    <div className="bg-[#111827] border border-slate-800/90 rounded-lg p-4 sm:p-5 flex flex-col justify-between min-w-0">
      <div className="text-xs font-medium text-slate-400 truncate">{label}</div>
      <div className="mt-2.5 flex items-baseline justify-between gap-2 min-w-0">
        <span className={`text-2xl sm:text-[26px] font-semibold font-mono tabular-nums leading-none ${valueColor}`}>
          {value}
        </span>
        {subvalue && (
          <span className="text-xs font-mono tabular-nums text-slate-400 whitespace-nowrap">
            {subvalue}
          </span>
        )}
      </div>
      <div className="mt-2.5 text-xs text-slate-400 leading-relaxed line-clamp-2">
        {caption}
      </div>
    </div>
  );
}
