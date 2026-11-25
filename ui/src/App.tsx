/*
ui/src/App.tsx
Root application component rendering navigation sidebar, control-plane header, and active views.
*/

import { useState, useEffect, useCallback } from 'react';
import Runs from './pages/Runs';
import PlanApproval from './pages/PlanApproval';
import GraphExplorer from './pages/GraphExplorer';
import PolicyExceptions from './pages/PolicyExceptions';
import Expiry from './pages/Expiry';
import Metrics from './pages/Metrics';
import {
  IconShield,
  IconScale,
  IconNetwork,
  IconFileText,
  IconClock,
  IconBarChart,
  IconShieldCheck,
  IconAlertTriangle,
  IconRefresh,
} from './components/Icons';
import { fetchPendingApprovals } from './api/client';

type TabType = 'runs' | 'approval' | 'graph' | 'exceptions' | 'expiry' | 'metrics';

interface NavConfig {
  id: TabType;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

const NAV_CONFIGS: NavConfig[] = [
  { id: 'runs', label: 'Remediation Runs', icon: IconShield },
  { id: 'approval', label: 'Plan & Approvals', icon: IconScale },
  { id: 'graph', label: 'Graph & Blast Radius', icon: IconNetwork },
  { id: 'exceptions', label: 'Policy Exceptions', icon: IconFileText },
  { id: 'expiry', label: 'Expiry & Tokens', icon: IconClock },
  { id: 'metrics', label: 'Metrics & KPIs', icon: IconBarChart },
];

function readTab(): TabType {
  const hash = window.location.hash.replace(/^#\/?/, '');
  return NAV_CONFIGS.find((item) => item.id === hash)?.id ?? 'runs';
}

export function App() {
  const [activeTab, setActiveTab] = useState<TabType>(readTab);
  const [pendingApprovalsCount, setPendingApprovalsCount] = useState<number>(0);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  const loadApprovalStatus = useCallback(async () => {
    try {
      const items = await fetchPendingApprovals();
      setPendingApprovalsCount(Array.isArray(items) ? items.length : 0);
    } catch {
      setPendingApprovalsCount(0);
    }
  }, []);

  useEffect(() => {
    const onHashChange = () => setActiveTab(readTab());
    window.addEventListener('hashchange', onHashChange);
    const initialLoad = setTimeout(loadApprovalStatus, 0);

    // Poll every 12 seconds for fresh approval gate changes
    const interval = setInterval(loadApprovalStatus, 12000);
    return () => {
      clearTimeout(initialLoad);
      clearInterval(interval);
      window.removeEventListener('hashchange', onHashChange);
    };
  }, [loadApprovalStatus]);

  const handleManualRefresh = async () => {
    setIsRefreshing(true);
    await loadApprovalStatus();
    setTimeout(() => setIsRefreshing(false), 600);
  };

  const handleTabChange = (tab: TabType) => {
    setActiveTab(tab);
    window.history.pushState(null, '', `#/${tab}`);
    loadApprovalStatus();
  };

  const renderActiveView = () => {
    switch (activeTab) {
      case 'runs':
        return <Runs />;
      case 'approval':
        return <PlanApproval />;
      case 'graph':
        return <GraphExplorer />;
      case 'exceptions':
        return <PolicyExceptions />;
      case 'expiry':
        return <Expiry />;
      case 'metrics':
        return <Metrics />;
      default:
        return <Runs />;
    }
  };

  const activeNav = NAV_CONFIGS.find((n) => n.id === activeTab);

  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900 font-sans antialiased">
      {/* Sidebar Navigation */}
      <aside className="w-64 bg-slate-950 text-slate-100 flex flex-col border-r border-slate-800 shadow-xl shrink-0 select-none">
        <div className="p-5 border-b border-slate-800/80">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400">
              <IconShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <h1 className="text-sm font-bold tracking-tight text-white">VulnFlow AI</h1>
                <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.2 rounded font-semibold bg-sky-500/20 text-sky-300 border border-sky-400/30">
                  Control
                </span>
              </div>
              <p className="text-[11px] text-slate-400">Autonomous Security Fabric</p>
            </div>
          </div>
        </div>

        <nav className="p-3 flex-1 flex flex-col gap-1">
          {NAV_CONFIGS.map((item) => {
            const isActive = activeTab === item.id;
            const Icon = item.icon;
            const showBadge = item.id === 'approval' && pendingApprovalsCount > 0;

            return (
              <button
                key={item.id}
                onClick={() => handleTabChange(item.id)}
                className={`flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all text-left cursor-pointer ${
                  isActive
                    ? 'bg-sky-500/15 text-sky-400 font-semibold shadow-inner border border-sky-500/30'
                    : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </div>
                {showBadge && (
                  <span className="px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-400/20 text-amber-300 border border-amber-400/30">
                    {pendingApprovalsCount}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-800/80 text-xs text-slate-400">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="font-medium text-slate-300 text-[11px]">Core Orchestrator</span>
            </div>
            <span className="text-[10px] font-mono text-slate-500">READY</span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col overflow-y-auto">
        <header className="h-14 bg-white border-b border-slate-200 flex items-center justify-between px-8 shadow-xs sticky top-0 z-10">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400 font-medium">Control Plane</span>
            <span className="text-slate-300">/</span>
            <span className="font-semibold text-slate-800">{activeNav?.label}</span>
          </div>

          <div className="flex items-center gap-3">
            {pendingApprovalsCount > 0 ? (
              <button
                onClick={() => handleTabChange('approval')}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-amber-50 border border-amber-200 text-amber-900 text-xs font-medium hover:bg-amber-100 transition-colors cursor-pointer"
              >
                <IconAlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                <span>
                  Approval Gate: <strong className="font-bold">{pendingApprovalsCount} Pending</strong>
                </span>
              </button>
            ) : null}

            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-50/70 border border-emerald-100 text-[11px] font-medium text-emerald-700">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              <span>System Operational</span>
            </div>

            <button
              onClick={handleManualRefresh}
              title="Refresh Control Plane Status"
              className="p-1.5 rounded-md text-slate-500 hover:text-slate-800 hover:bg-slate-100 border border-slate-200 transition-colors cursor-pointer"
            >
              <IconRefresh className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-sky-600' : ''}`} />
            </button>
          </div>
        </header>

        <section className="flex-1 p-8">{renderActiveView()}</section>
      </main>
    </div>
  );
}

export default App;
