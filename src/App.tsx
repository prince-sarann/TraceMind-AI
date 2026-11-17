/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  Bot,
  Clock,
  FileBarChart2,
  FolderSearch,
  Menu,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  RefreshCw,
  Settings,
  Shield,
  ShieldAlert,
  UserCheck,
  X,
} from 'lucide-react';
import type {
  Incident,
  IncidentStatus,
  PipelineSettings,
  WorkspaceSnapshot,
} from '../shared/types';
import {
  addIncidentNote,
  fetchWorkspace,
  ingestLogs,
  logExportAudit,
  resetDataset,
  saveSettings,
  updateIncidentStatus,
  type AnalystIdentity,
} from './lib/api';
import { AiAssistantView } from './views/AiAssistantView';
import { AttackTimelineView } from './views/AttackTimelineView';
import { IncidentInvestigationView } from './views/IncidentInvestigationView';
import { LogExplorerView } from './views/LogExplorerView';
import { OverviewView } from './views/OverviewView';
import { RelationshipGraphView } from './views/RelationshipGraphView';
import { ReportsAnalyticsView } from './views/ReportsAnalyticsView';
import { SystemSettingsView } from './views/SystemSettingsView';
import { ThreatDetectionView } from './views/ThreatDetectionView';

type PageId =
  | 'overview'
  | 'logs'
  | 'detection'
  | 'incidents'
  | 'timeline'
  | 'graph'
  | 'ai'
  | 'reports'
  | 'settings';

interface NavGroup {
  heading: string;
  items: { id: PageId; label: string; icon: typeof Activity }[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    heading: 'Core Operations',
    items: [
      { id: 'overview', label: 'Security Overview', icon: Activity },
      { id: 'detection', label: 'Threat Detection', icon: ShieldAlert },
      { id: 'incidents', label: 'Security Incidents', icon: Shield },
      { id: 'logs', label: 'Log Explorer', icon: FolderSearch },
    ],
  },
  {
    heading: 'Investigation & Intel',
    items: [
      { id: 'timeline', label: 'Attack Timeline', icon: Clock },
      { id: 'graph', label: 'Threat Intelligence', icon: Network },
      { id: 'ai', label: 'AI Assistant', icon: Bot },
    ],
  },
  {
    heading: 'Reporting & System',
    items: [
      { id: 'reports', label: 'Analytics & Reports', icon: FileBarChart2 },
      { id: 'settings', label: 'Settings & About', icon: Settings },
    ],
  },
];

const ALL_NAV_ITEMS = NAV_GROUPS.flatMap((g) => g.items);

export default function App() {
  const [activePage, setActivePage] = useState<PageId>('overview');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [snapshot, setSnapshot] = useState<WorkspaceSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [identity, setIdentity] = useState<AnalystIdentity>({
    name: 'Prince Kumar Saran',
    role: 'Lead SOC Analyst',
  });

  const loadWorkspace = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);
    try {
      const data = await fetchWorkspace();
      setSnapshot(data);
      setSelectedIncidentId((prev) => prev ?? data.incidents[0]?.id ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to reach TraceMind X backend.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void loadWorkspace(false);
  }, [loadWorkspace]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMobileMenuOpen(false);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const handleNavigate = (page: PageId) => {
    setActivePage(page);
    setMobileMenuOpen(false);
  };

  const handleIngest = async (payload: {
    content: string;
    format: 'csv' | 'json';
    sourceName: string;
  }) => {
    setActionError(null);
    const next = await ingestLogs(payload, identity);
    setSnapshot(next);
    if (next.incidents[0]) {
      setSelectedIncidentId(next.incidents[0].id);
    }
  };

  const handleUpdateIncidentStatus = async (
    id: string,
    status: IncidentStatus,
    assignee: string,
  ) => {
    setActionError(null);
    try {
      const next = await updateIncidentStatus(id, status, assignee, identity);
      setSnapshot(next);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to update incident.');
    }
  };

  const handleAddNote = async (id: string, content: string) => {
    setActionError(null);
    try {
      const next = await addIncidentNote(id, content, identity);
      setSnapshot(next);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to save note.');
    }
  };

  const handleSaveSettings = async (nextSettings: PipelineSettings) => {
    setActionError(null);
    const next = await saveSettings(nextSettings, identity);
    setSnapshot(next);
  };

  const handleResetDataset = async () => {
    setActionError(null);
    const next = await resetDataset(identity);
    setSnapshot(next);
    setSelectedIncidentId(next.incidents[0]?.id ?? null);
  };

  const handleSelectIncident = (inc: Incident) => {
    setSelectedIncidentId(inc.id);
    handleNavigate('incidents');
  };

  const handleAuditExport = (format: 'CSV' | 'PDF', target: string) => {
    void logExportAudit(format, target, identity).then(() => loadWorkspace(true));
  };

  const activeNav = ALL_NAV_ITEMS.find((n) => n.id === activePage) ?? ALL_NAV_ITEMS[0];

  const renderNavContent = (isCollapsed: boolean) => (
    <>
      <nav className="flex-1 py-3 px-2.5 space-y-4 overflow-y-auto">
        {NAV_GROUPS.map((group) => (
          <div key={group.heading}>
            {!isCollapsed && (
              <div className="px-3 mb-1.5 text-[11px] font-medium text-slate-500">
                {group.heading}
              </div>
            )}
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activePage === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => handleNavigate(item.id)}
                    title={isCollapsed ? item.label : undefined}
                    className={`w-full min-h-[40px] flex items-center gap-3 px-3 py-2 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                      isActive
                        ? 'bg-blue-600/15 text-cyan-300'
                        : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
                    }`}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    {!isCollapsed && <span className="truncate">{item.label}</span>}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {!isCollapsed && (
        <div className="p-4 border-t border-slate-800/90 text-xs bg-[#090D16]/40">
          <div className="text-[11px] text-slate-500">{identity.role}</div>
          <div className="font-semibold text-slate-100 truncate mt-0.5">{identity.name}</div>
        </div>
      )}
    </>
  );

  return (
    <div className="min-h-screen bg-[#090D16] text-slate-100 flex overflow-x-hidden">
      {/* Desktop Persistent Collapsible Sidebar (lg+) */}
      <aside
        className={`hidden lg:flex ${
          sidebarCollapsed ? 'w-16' : 'w-64'
        } shrink-0 bg-[#0B1120] border-r border-slate-800/90 flex-col transition-all duration-150 sticky top-0 h-screen`}
      >
        <div className="h-14 px-4 border-b border-slate-800/90 flex items-center justify-between gap-2">
          {!sidebarCollapsed && (
            <span className="font-display text-base font-bold tracking-tight text-slate-100 whitespace-nowrap">
              TraceMind X
            </span>
          )}
          <button
            type="button"
            onClick={() => setSidebarCollapsed((c) => !c)}
            className="min-w-[36px] min-h-[36px] flex items-center justify-center rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800/60 transition-colors"
            title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {sidebarCollapsed ? (
              <PanelLeftOpen className="w-4 h-4" />
            ) : (
              <PanelLeftClose className="w-4 h-4" />
            )}
          </button>
        </div>

        {renderNavContent(sidebarCollapsed)}
      </aside>

      {/* Mobile & Tablet Slide-Over Drawer (< lg) */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div
            className="fixed inset-0 bg-black/70"
            onClick={() => setMobileMenuOpen(false)}
            aria-hidden="true"
          />
          <aside className="relative z-10 w-72 max-w-[85vw] bg-[#0B1120] border-r border-slate-800 flex flex-col h-full">
            <div className="h-14 px-4 border-b border-slate-800 flex items-center justify-between">
              <span className="font-display text-base font-bold tracking-tight text-slate-100">
                TraceMind X
              </span>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                className="min-w-[40px] min-h-[40px] flex items-center justify-center rounded text-slate-400 hover:text-slate-100"
                aria-label="Close navigation menu"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            {renderNavContent(false)}
          </aside>
        </div>
      )}

      {/* Main Content Workspace */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Responsive Top Header Bar */}
        <header className="h-14 px-3 sm:px-6 border-b border-slate-800/90 bg-[#0B1120]/95 flex items-center justify-between gap-3 sm:gap-6 shrink-0 sticky top-0 z-30">
          <div className="flex items-center gap-2.5 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              className="lg:hidden min-w-[40px] min-h-[40px] flex items-center justify-center rounded-md bg-slate-800/60 hover:bg-slate-800 text-slate-200 shrink-0"
              aria-label="Open navigation menu"
            >
              <Menu className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-2 text-sm min-w-0">
              <span className="hidden sm:inline text-slate-500 whitespace-nowrap">
                TraceMind SOC
              </span>
              <span className="hidden sm:inline text-slate-600">/</span>
              <h1 className="font-display font-semibold text-slate-100 truncate">
                {activeNav.label}
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-3 shrink-0">
            <div className="hidden md:flex items-center gap-2 pr-3 border-r border-slate-800 text-xs whitespace-nowrap">
              <UserCheck className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span className="text-slate-400">{identity.role}:</span>
              <span className="font-medium text-slate-100">{identity.name}</span>
            </div>

            <button
              type="button"
              disabled={refreshing}
              onClick={() => void loadWorkspace(true)}
              className="min-h-[38px] inline-flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-md transition-colors whitespace-nowrap shrink-0"
              aria-label="Recompute pipeline"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              <span className="hidden sm:inline">Recompute</span>
            </button>
            <button
              type="button"
              onClick={() => handleNavigate('logs')}
              className="min-h-[38px] px-3 sm:px-3.5 py-1.5 text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              Ingest Logs
            </button>
          </div>
        </header>

        {/* Scrollable Viewport */}
        <main className="flex-1 p-3 sm:p-5 lg:p-6 max-w-[1440px] w-full mx-auto min-w-0">
          {actionError && (
            <div className="mb-4 p-3 rounded bg-red-950/40 border border-red-800/60 text-xs text-red-300 flex items-center justify-between gap-3">
              <span>{actionError}</span>
              <button
                type="button"
                onClick={() => setActionError(null)}
                className="text-red-400 hover:text-red-200 underline shrink-0"
              >
                Dismiss
              </button>
            </div>
          )}

          {loading ? (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
                {[1, 2, 3, 4].map((k) => (
                  <div key={k} className="h-28 bg-[#111827] border border-slate-800 rounded-lg animate-pulse" />
                ))}
              </div>
              <div className="h-72 bg-[#111827] border border-slate-800 rounded-lg animate-pulse" />
            </div>
          ) : error || !snapshot ? (
            <div className="bg-[#111827] border border-red-900/60 rounded-lg p-8 text-center space-y-3">
              <div className="text-sm font-semibold text-red-300">
                Telemetry Pipeline Unavailable
              </div>
              <p className="text-xs text-slate-400">{error || 'No snapshot received.'}</p>
              <button
                type="button"
                onClick={() => void loadWorkspace(false)}
                className="min-h-[40px] px-4 py-2 text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white rounded"
              >
                Retry Connection
              </button>
            </div>
          ) : (
            <>
              {activePage === 'overview' && (
                <OverviewView
                  snapshot={snapshot}
                  onSelectIncident={handleSelectIncident}
                  onNavigate={(p) => handleNavigate(p as PageId)}
                />
              )}
              {activePage === 'logs' && (
                <LogExplorerView
                  events={snapshot.events}
                  lastIngestion={snapshot.lastIngestion}
                  onIngest={handleIngest}
                  ingesting={refreshing}
                />
              )}
              {activePage === 'detection' && <ThreatDetectionView snapshot={snapshot} />}
              {activePage === 'incidents' && (
                <IncidentInvestigationView
                  incidents={snapshot.incidents}
                  events={snapshot.events}
                  selectedIncidentId={selectedIncidentId}
                  onSelectIncidentId={setSelectedIncidentId}
                  onUpdateStatus={handleUpdateIncidentStatus}
                  onAddNote={handleAddNote}
                  onOpenAiBrief={(id) => {
                    setSelectedIncidentId(id);
                    handleNavigate('ai');
                  }}
                  onAuditExport={handleAuditExport}
                />
              )}
              {activePage === 'timeline' && (
                <AttackTimelineView
                  incidents={snapshot.incidents}
                  selectedIncidentId={selectedIncidentId}
                  onSelectIncidentId={setSelectedIncidentId}
                  onOpenInvestigation={(id) => {
                    setSelectedIncidentId(id);
                    handleNavigate('incidents');
                  }}
                />
              )}
              {activePage === 'graph' && <RelationshipGraphView graph={snapshot.graph} />}
              {activePage === 'ai' && (
                <AiAssistantView
                  incidents={snapshot.incidents}
                  selectedIncidentId={selectedIncidentId}
                  onSelectIncidentId={setSelectedIncidentId}
                  identity={identity}
                />
              )}
              {activePage === 'reports' && (
                <ReportsAnalyticsView
                  snapshot={snapshot}
                  onAuditExport={handleAuditExport}
                />
              )}
              {activePage === 'settings' && (
                <SystemSettingsView
                  settings={snapshot.settings}
                  identity={identity}
                  onChangeIdentity={setIdentity}
                  onSaveSettings={handleSaveSettings}
                  onResetDataset={handleResetDataset}
                />
              )}
            </>
          )}
        </main>

        {/* Quiet Enterprise Attribution Footer */}
        <footer className="px-3 sm:px-6 py-3 border-t border-slate-800/80 text-xs text-slate-500 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <span>TraceMind X · Cyber Threat Intelligence & Incident Investigation</span>
          <span>
            Lead SOC Analyst: <span className="text-slate-300 font-medium">{identity.name}</span>
          </span>
        </footer>
      </div>
    </div>
  );
}
