/*
ui/src/pages/Runs.tsx
Page displaying list of all remediation runs with status filters, exit codes, and PR links.
*/

import { useEffect, useState } from 'react';
import { fetchRuns, type RunSummary } from '../api/client';

export const Runs: React.FC = () => {
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [filter, setFilter] = useState<string>('all');
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    fetchRuns().then((data) => {
      setRuns(data);
      setLoading(false);
    });
  }, []);

  const filteredRuns = runs.filter((r) => {
    if (filter === 'all') return true;
    if (filter === 'completed') return r.exit_code === 0;
    if (filter === 'pending') return r.exit_code === 10;
    if (filter === 'blocked') return r.exit_code === 20;
    return true;
  });

  const getStatusBadge = (run: RunSummary) => {
    if (run.exit_code === 0) {
      return (
        <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
          COMPLETED (EXIT 0)
        </span>
      );
    }
    if (run.exit_code === 10) {
      return (
        <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-semibold bg-amber-50 text-amber-800 border border-amber-200">
          PENDING APPROVAL (EXIT 10)
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-semibold bg-rose-50 text-rose-800 border border-rose-200">
        BLOCKED BY POLICY (EXIT 20)
      </span>
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-slate-900 flex items-center gap-2">
            <span>🛡️</span> Remediation Runs Dashboard
          </h2>
          <p className="text-sm text-slate-500 mt-1">
            Track autonomous remediation cycles, verification sandbox gates, and generated PRs.
          </p>
        </div>

        <div className="flex items-center bg-white p-1 rounded-lg border border-slate-200 shadow-xs">
          {(['all', 'completed', 'pending', 'blocked'] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => setFilter(mode)}
              className={`px-3.5 py-1.5 rounded-md text-xs font-medium capitalize transition-all cursor-pointer ${
                filter === mode
                  ? 'bg-slate-900 text-white shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              {mode}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="bg-white rounded-xl border border-slate-200 p-12 text-center text-slate-500 shadow-xs">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-slate-900 mb-3" />
          <p className="text-sm font-medium">Loading remediation runs from VulnFlow API...</p>
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-700">
              <thead className="bg-slate-50 border-b border-slate-200 text-xs uppercase font-semibold text-slate-500">
                <tr>
                  <th className="px-5 py-3.5">Run ID</th>
                  <th className="px-5 py-3.5">Repository</th>
                  <th className="px-5 py-3.5">Status</th>
                  <th className="px-5 py-3.5 text-center">Findings</th>
                  <th className="px-5 py-3.5 text-center">Plans</th>
                  <th className="px-5 py-3.5">Pull Request</th>
                  <th className="px-5 py-3.5">Details / Rationale</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-normal">
                {filteredRuns.map((r) => (
                  <tr key={r.run_id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="px-5 py-4 font-mono text-xs font-medium text-slate-900">
                      <code>{r.run_id}</code>
                    </td>
                    <td className="px-5 py-4 text-slate-600 truncate max-w-xs">
                      {r.repo_path || 'workspace'}
                    </td>
                    <td className="px-5 py-4">{getStatusBadge(r)}</td>
                    <td className="px-5 py-4 text-center">
                      <span className="font-semibold text-slate-900">{r.findings_count}</span>
                    </td>
                    <td className="px-5 py-4 text-center">
                      <span className="font-semibold text-slate-900">{r.plans_count}</span>
                    </td>
                    <td className="px-5 py-4">
                      {r.prs && r.prs.length > 0 ? (
                        <a
                          href={r.prs[0].pr_url || '#'}
                          target="_blank"
                          rel="noreferrer"
                          className="font-medium text-sky-600 hover:text-sky-800 hover:underline flex items-center gap-1"
                        >
                          <span>🔗</span> {r.prs[0].title || 'View Pull Request'}
                        </a>
                      ) : (
                        <span className="text-slate-400 italic">None</span>
                      )}
                    </td>
                    <td className="px-5 py-4 text-xs text-slate-500 max-w-sm">
                      {r.blocking_reason || 'Sandbox verification passed. Fix cleanly deployed.'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default Runs;
