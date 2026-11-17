/*
ui/src/App.tsx
Root application component rendering navigation sidebar, control-plane header, and active views.
*/

import { useState, useEffect } from 'react';
import Runs from './pages/Runs';
import PlanApproval from './pages/PlanApproval';
import GraphExplorer from './pages/GraphExplorer';
import PolicyExceptions from './pages/PolicyExceptions';
import Expiry from './pages/Expiry';
import Metrics from './pages/Metrics';

type TabType = 'runs' | 'approval' | 'graph' | 'exceptions' | 'expiry' | 'metrics';

interface NavItem {
  id: TabType;
  label: string;
  icon: string;
  badge?: string;
}

const NAV_ITEMS: NavItem[] = [
  { id: 'runs', label: 'Remediation Runs', icon: '🛡️' },
  { id: 'approval', label: 'Plan & Approvals', icon: '⚖️', badge: '1' },
  { id: 'graph', label: 'Graph & Blast Radius', icon: '🕸️' },
  { id: 'exceptions', label: 'Policy Exceptions', icon: '📋' },
  { id: 'expiry', label: 'Expiry & Tokens', icon: '⏳' },
  { id: 'metrics', label: 'Metrics & KPIs', icon: '📊' },
];

export function App() {
  const [activeTab, setActiveTab] = useState<TabType>('runs');

  useEffect(() => {
    const hash = window.location.hash.replace('#/', '').replace('#', '') as TabType;
    if (NAV_ITEMS.some((item) => item.id === hash)) {
      setActiveTab(hash);
    }
  }, []);

  const handleTabChange = (tab: TabType) => {
    setActiveTab(tab);
    window.location.hash = `#/${tab}`;
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

  return (
    <div className="flex min-h-screen bg-slate-100 text-slate-900 font-sans antialiased">
      {/* Sidebar Navigation */}
      <aside className="w-64 bg-slate-950 text-slate-100 flex flex-col border-r border-slate-800 shadow-xl shrink-0">
        <div className="p-6 border-b border-slate-800/80">
          <div className="flex items-center gap-3">
            <span className="text-3xl">🛡️</span>
            <div>
              <h1 className="text-base font-bold tracking-tight text-sky-400">VulnFlow AI</h1>
              <p className="text-xs text-slate-400">Autonomous Remediation</p>
            </div>
          </div>
        </div>

        <nav className="p-3 flex-1 flex flex-col gap-1">
          {NAV_ITEMS.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleTabChange(item.id)}
                className={`flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all text-left ${
                  isActive
                    ? 'bg-sky-500/15 text-sky-400 font-semibold shadow-inner border border-sky-500/30'
                    : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <span className="text-base">{item.icon}</span>
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-amber-400/20 text-amber-300 border border-amber-400/30">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-800/80 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="font-medium text-slate-300">Engine Online</span>
          </div>
          <div className="mt-1 text-slate-400">v1.0.0 (Phase 3 Breadth)</div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col overflow-y-auto">
        <header className="h-16 bg-white border-b border-slate-200 flex items-center justify-between px-8 shadow-xs sticky top-0 z-10">
          <div className="flex items-center gap-2 text-sm">
            <span className="text-slate-400 font-medium">Control Plane</span>
            <span className="text-slate-300">/</span>
            <span className="font-semibold text-slate-800">
              {NAV_ITEMS.find((n) => n.id === activeTab)?.label}
            </span>
          </div>

          <div className="flex items-center gap-4 text-xs">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-amber-50 border border-amber-200 text-amber-900 font-medium">
              <span>Approval Gate:</span>
              <span className="font-bold">1 Pending Review</span>
            </div>
            <div className="flex items-center gap-1.5 text-emerald-600 font-medium">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              API Connected
            </div>
          </div>
        </header>

        <section className="flex-1 p-8">{renderActiveView()}</section>
      </main>
    </div>
  );
}

export default App;
