import { useMemo, useState } from 'react';
import { Download, Search, Upload, CheckCircle2, AlertTriangle, X } from 'lucide-react';
import type { EventType, IngestionSummary, SecurityLogEvent, SeverityLevel } from '../../shared/types';
import { SeverityText } from '../components/SeverityText';
import { SocCard } from '../components/SocUi';
import { exportEventsCsv, fetchSampleCsv } from '../lib/api';

const PAGE_SIZE = 15;

export function LogExplorerView({
  events,
  lastIngestion,
  onIngest,
  ingesting,
}: {
  events: SecurityLogEvent[];
  lastIngestion?: IngestionSummary;
  onIngest: (payload: { content: string; format: 'csv' | 'json'; sourceName: string }) => Promise<void>;
  ingesting: boolean;
}) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'All' | SeverityLevel>('All');
  const [eventTypeFilter, setEventTypeFilter] = useState<'All' | EventType>('All');
  const [ipFilter, setIpFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [sortField, setSortField] = useState<'epochMs' | 'ipReputationScore' | 'bytesTransferred'>('epochMs');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(1);

  const [showIngestModal, setShowIngestModal] = useState(false);
  const [ingestFormat, setIngestFormat] = useState<'csv' | 'json'>('csv');
  const [ingestContent, setIngestContent] = useState('');
  const [ingestSource, setIngestSource] = useState('custom-upload.csv');
  const [ingestError, setIngestError] = useState<string | null>(null);

  const uniqueEventTypes = useMemo(
    () => Array.from(new Set(events.map((e) => e.eventType))).sort(),
    [events],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return events
      .filter((e) => {
        if (severityFilter !== 'All' && e.baseSeverity !== severityFilter) return false;
        if (eventTypeFilter !== 'All' && e.eventType !== eventTypeFilter) return false;
        if (ipFilter && !e.sourceIp.toLowerCase().includes(ipFilter.toLowerCase())) return false;
        if (userFilter && !e.username.toLowerCase().includes(userFilter.toLowerCase())) return false;
        if (q) {
          const hay = `${e.id} ${e.sourceIp} ${e.username} ${e.eventType} ${e.targetHost} ${e.country} ${e.city} ${e.asn}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      })
      .sort((a, b) => {
        const diff = a[sortField] - b[sortField];
        return sortDir === 'asc' ? diff : -diff;
      });
  }, [events, search, severityFilter, eventTypeFilter, ipFilter, userFilter, sortField, sortDir]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pageRows = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  const toggleSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  };

  const handleFileChange = async (file: File | undefined) => {
    if (!file) return;
    setIngestError(null);
    if (file.size > 5 * 1024 * 1024) {
      setIngestError('File exceeds 5 MB security limit.');
      return;
    }
    const ext = file.name.toLowerCase().endsWith('.json')
      ? 'json'
      : file.name.toLowerCase().endsWith('.csv')
        ? 'csv'
        : null;
    if (!ext) {
      setIngestError('Only .csv and .json log files are permitted.');
      return;
    }
    const text = await file.text();
    setIngestFormat(ext);
    setIngestSource(file.name);
    setIngestContent(text);
  };

  const handleLoadSample = async () => {
    setIngestError(null);
    const csv = await fetchSampleCsv();
    setIngestFormat('csv');
    setIngestSource('ssh-bastion-attack-sample.csv');
    setIngestContent(csv);
  };

  const handleSubmitIngest = async () => {
    setIngestError(null);
    try {
      await onIngest({ content: ingestContent, format: ingestFormat, sourceName: ingestSource });
      setShowIngestModal(false);
    } catch (err) {
      setIngestError(err instanceof Error ? err.message : 'Failed to ingest logs.');
    }
  };

  return (
    <div className="space-y-5 min-w-0">
      {lastIngestion && (
        <SocCard className="p-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-start gap-3 min-w-0">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
            <div className="min-w-0">
              <div className="text-sm font-medium text-slate-100 break-words">
                Ingested {lastIngestion.sourceName} ({lastIngestion.format.toUpperCase()})
              </div>
              <div className="text-xs font-mono tabular-nums text-slate-400 mt-0.5">
                Submitted {lastIngestion.totalSubmitted} · Accepted {lastIngestion.acceptedCount} · Deduplicated {lastIngestion.duplicateCount} · Rejected {lastIngestion.rejectedCount}
              </div>
              {lastIngestion.rejectedRecords.length > 0 && (
                <div className="mt-1.5 text-xs text-amber-300 flex items-start gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                  <span>
                    Sample rejection (line {lastIngestion.rejectedRecords[0].lineNumber}): {lastIngestion.rejectedRecords[0].reason}
                  </span>
                </div>
              )}
            </div>
          </div>
        </SocCard>
      )}

      {/* Responsive Filter & Action Bar */}
      <SocCard className="p-4 space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-2.5">
          <div className="relative sm:col-span-2">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              placeholder="Search IP, user, host, ASN..."
              className="w-full min-h-[40px] bg-[#090D16] border border-slate-800 rounded-md pl-8 pr-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value as 'All' | SeverityLevel);
              setPage(1);
            }}
            className="w-full min-h-[40px] bg-[#090D16] border border-slate-800 rounded-md px-2.5 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Info">Info</option>
          </select>

          <select
            value={eventTypeFilter}
            onChange={(e) => {
              setEventTypeFilter(e.target.value as 'All' | EventType);
              setPage(1);
            }}
            className="w-full min-h-[40px] bg-[#090D16] border border-slate-800 rounded-md px-2.5 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
          >
            <option value="All">All Event Types</option>
            {uniqueEventTypes.map((et) => (
              <option key={et} value={et}>
                {et}
              </option>
            ))}
          </select>

          <input
            type="text"
            value={ipFilter}
            onChange={(e) => {
              setIpFilter(e.target.value);
              setPage(1);
            }}
            placeholder="Filter IP"
            className="w-full min-h-[40px] bg-[#090D16] border border-slate-800 rounded-md px-2.5 py-2 text-xs font-mono text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
          />

          <input
            type="text"
            value={userFilter}
            onChange={(e) => {
              setUserFilter(e.target.value);
              setPage(1);
            }}
            placeholder="Filter User"
            className="w-full min-h-[40px] bg-[#090D16] border border-slate-800 rounded-md px-2.5 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
          <span className="text-xs font-mono tabular-nums text-slate-400">
            {filtered.length} matching log records
          </span>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => exportEventsCsv(filtered)}
              className="min-h-[40px] inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md transition-colors whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export CSV</span>
            </button>
            <button
              type="button"
              onClick={() => setShowIngestModal(true)}
              className="min-h-[40px] inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white rounded-md transition-colors whitespace-nowrap"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Ingest Logs</span>
            </button>
          </div>
        </div>
      </SocCard>

      {/* Normalized Log Table */}
      <div className="bg-[#111827] border border-slate-800/90 rounded-lg overflow-hidden min-w-0">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs min-w-[920px]">
            <thead>
              <tr className="border-b border-slate-800 bg-[#0E1422] text-slate-400">
                <th className="py-2.5 px-4 font-medium">Event ID</th>
                <th className="py-2.5 px-3 font-medium">
                  <button
                    type="button"
                    onClick={() => toggleSort('epochMs')}
                    className="hover:text-slate-200 py-1"
                  >
                    Timestamp (UTC) {sortField === 'epochMs' ? (sortDir === 'desc' ? '↓' : '↑') : ''}
                  </button>
                </th>
                <th className="py-2.5 px-3 font-medium">Severity</th>
                <th className="py-2.5 px-3 font-medium">Event Type</th>
                <th className="py-2.5 px-3 font-medium">User</th>
                <th className="py-2.5 px-3 font-medium">Source IP</th>
                <th className="py-2.5 px-3 font-medium">Location / ASN</th>
                <th className="py-2.5 px-3 font-medium">Target Host</th>
                <th className="py-2.5 px-3 font-medium text-right">
                  <button
                    type="button"
                    onClick={() => toggleSort('ipReputationScore')}
                    className="hover:text-slate-200 py-1"
                  >
                    IP Rep {sortField === 'ipReputationScore' ? (sortDir === 'desc' ? '↓' : '↑') : ''}
                  </button>
                </th>
                <th className="py-2.5 px-4 font-medium text-right">
                  <button
                    type="button"
                    onClick={() => toggleSort('bytesTransferred')}
                    className="hover:text-slate-200 py-1"
                  >
                    Bytes {sortField === 'bytesTransferred' ? (sortDir === 'desc' ? '↓' : '↑') : ''}
                  </button>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {pageRows.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-10 text-center text-slate-500">
                    No security log events match the active filters.
                  </td>
                </tr>
              ) : (
                pageRows.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-800/35 transition-colors">
                    <td className="py-2.5 px-4 font-mono text-slate-300 whitespace-nowrap">{ev.id}</td>
                    <td className="py-2.5 px-3 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                      {ev.timestamp.replace('T', ' ').slice(0, 19)}
                    </td>
                    <td className="py-2.5 px-3">
                      <SeverityText severity={ev.baseSeverity} />
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-200 whitespace-nowrap">{ev.eventType}</td>
                    <td className="py-2.5 px-3 text-slate-200 whitespace-nowrap">{ev.username}</td>
                    <td className="py-2.5 px-3 font-mono text-cyan-300 whitespace-nowrap">{ev.sourceIp}</td>
                    <td className="py-2.5 px-3 text-slate-400 max-w-[200px] truncate">
                      {ev.city}, {ev.country} · {ev.asn}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">{ev.targetHost}</td>
                    <td
                      className={`py-2.5 px-3 text-right font-mono tabular-nums ${
                        ev.ipReputationScore >= 75
                          ? 'text-red-400 font-semibold'
                          : ev.ipReputationScore >= 40
                            ? 'text-amber-300'
                            : 'text-slate-400'
                      }`}
                    >
                      {ev.ipReputationScore}
                    </td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-400">
                      {ev.bytesTransferred.toLocaleString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="px-4 py-3 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 text-xs text-slate-400">
          <span className="font-mono tabular-nums">
            Showing {pageRows.length} of {filtered.length} normalized events
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={safePage <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="min-h-[36px] px-3 py-1.5 rounded bg-slate-800 disabled:opacity-40 hover:bg-slate-700 text-slate-200"
            >
              Previous
            </button>
            <span className="font-mono tabular-nums px-1">
              Page {safePage} / {totalPages}
            </span>
            <button
              type="button"
              disabled={safePage >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              className="min-h-[36px] px-3 py-1.5 rounded bg-slate-800 disabled:opacity-40 hover:bg-slate-700 text-slate-200"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Responsive Ingestion Modal */}
      {showIngestModal && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-3 sm:p-4">
          <div className="bg-[#111827] border border-slate-700 rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto p-4 sm:p-6 space-y-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="text-base font-semibold text-slate-100">
                  Ingest & Normalize Security Logs
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Upload .csv or .json logs (max 5 MB). Records are validated, deduplicated, and re-scored automatically.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowIngestModal(false)}
                className="min-w-[36px] min-h-[36px] flex items-center justify-center text-slate-400 hover:text-slate-200 rounded"
                aria-label="Close modal"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setIngestFormat('csv')}
                  className={`min-h-[36px] px-3 py-1.5 text-xs font-medium rounded ${
                    ingestFormat === 'csv'
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  CSV Format
                </button>
                <button
                  type="button"
                  onClick={() => setIngestFormat('json')}
                  className={`min-h-[36px] px-3 py-1.5 text-xs font-medium rounded ${
                    ingestFormat === 'json'
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  JSON / NDJSON
                </button>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={handleLoadSample}
                  className="min-h-[36px] px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded"
                >
                  Load Sample Attack CSV
                </button>
                <label className="min-h-[36px] inline-flex items-center px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded cursor-pointer">
                  Choose File
                  <input
                    type="file"
                    accept=".csv,.json"
                    onChange={(e) => handleFileChange(e.target.files?.[0])}
                    className="hidden"
                  />
                </label>
              </div>
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Source Name</label>
              <input
                type="text"
                value={ingestSource}
                onChange={(e) => setIngestSource(e.target.value)}
                className="w-full min-h-[38px] bg-[#090D16] border border-slate-800 rounded px-3 py-1.5 text-xs font-mono text-slate-200"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Raw Log Payload</label>
              <textarea
                rows={8}
                value={ingestContent}
                onChange={(e) => setIngestContent(e.target.value)}
                placeholder="Paste CSV rows with headers (timestamp,source_ip,username,event_type,target_host) or JSON array..."
                className="w-full bg-[#090D16] border border-slate-800 rounded p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-blue-500"
              />
            </div>

            {ingestError && (
              <div className="text-xs text-red-400 bg-red-950/30 border border-red-900/50 rounded p-2.5">
                {ingestError}
              </div>
            )}

            <div className="flex flex-wrap justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowIngestModal(false)}
                className="min-h-[40px] px-4 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={ingesting || !ingestContent.trim()}
                onClick={handleSubmitIngest}
                className="min-h-[40px] px-4 py-2 text-xs font-medium bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded"
              >
                {ingesting ? 'Validating & Running Pipeline...' : 'Ingest & Run Analysis'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
