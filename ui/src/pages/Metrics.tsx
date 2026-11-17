/*
ui/src/pages/Metrics.tsx
Dashboard page showing MTTR, policy compliance, and autonomous remediation rates.
*/

export const Metrics: React.FC = () => {
  const kpis = [
    { label: 'Autonomous Fix Rate', value: '88.4%', change: '+4.2% vs last month', color: 'text-emerald-600' },
    { label: 'Deduplication Ratio', value: '3.6x', change: 'Transitive root causes collapsed', color: 'text-sky-600' },
    { label: 'Avg Time to Verified PR', value: '3.4 min', change: 'Sandbox build & verify duration', color: 'text-purple-600' },
    { label: 'Unverified Fix Invariant', value: '100%', change: '0 broken fixes merged', color: 'text-teal-600' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-slate-900 flex items-center gap-2">
          <span>📊</span> Remediation & Governance Metrics (F41)
        </h2>
        <p className="text-sm text-slate-500 mt-1">
          Real-time telemetry measuring remediation velocity, policy compliance, and deduplication efficiency.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {kpis.map((k) => (
          <div
            key={k.label}
            className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs space-y-2"
          >
            <p className="text-xs uppercase font-bold text-slate-500 tracking-wider">{k.label}</p>
            <p className={`text-3xl font-extrabold tracking-tight ${k.color}`}>{k.value}</p>
            <p className="text-xs text-slate-400 font-medium">{k.change}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-4">
          <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <span>🎯</span> Findings Resolution Distribution
          </h3>
          <div className="space-y-3 text-sm">
            <div className="flex items-center justify-between p-3 rounded-lg bg-emerald-50/60 border border-emerald-100">
              <span className="font-medium text-emerald-950">Auto-Remediated (AUTO Tier)</span>
              <span className="font-bold text-emerald-800">64 plans</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-amber-50/60 border border-amber-100">
              <span className="font-medium text-amber-950">Human Verified (REVIEW Tier)</span>
              <span className="font-bold text-amber-800">18 plans</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-rose-50/60 border border-rose-100">
              <span className="font-medium text-rose-950">Policy Blocked (BLOCKED Tier)</span>
              <span className="font-bold text-rose-800">6 plans</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-purple-50/60 border border-purple-100">
              <span className="font-medium text-purple-950">Self-Corrected Retries</span>
              <span className="font-bold text-purple-800">8 plans</span>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-4">
          <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <span>📦</span> Ecosystem Breakdown
          </h3>
          <div className="space-y-4 text-sm">
            <div>
              <div className="flex justify-between font-medium text-slate-700 mb-1">
                <span>npm (Node.js)</span>
                <span className="font-bold text-slate-900">74%</span>
              </div>
              <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                <div className="bg-sky-600 h-2 rounded-full" style={{ width: '74%' }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between font-medium text-slate-700 mb-1">
                <span>PyPI (Python)</span>
                <span className="font-bold text-slate-900">18%</span>
              </div>
              <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                <div className="bg-teal-600 h-2 rounded-full" style={{ width: '18%' }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between font-medium text-slate-700 mb-1">
                <span>Maven (Java)</span>
                <span className="font-bold text-slate-900">8%</span>
              </div>
              <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                <div className="bg-indigo-600 h-2 rounded-full" style={{ width: '8%' }} />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Metrics;
