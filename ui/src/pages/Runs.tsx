/*
ui/src/pages/Runs.tsx
Enterprise-grade dashboard displaying remediation runs, KPIs, verification gates, and generated PRs.
*/

import { useEffect, useState, useMemo } from 'react';
import { fetchRunReport, fetchRuns, type RunSummary } from '../api/client';
import { ReportModal } from '../components/ReportModal';
import {
  IconShield,
  IconShieldCheck,
  IconAlertTriangle,
  IconGitPullRequest,
  IconFileText,
  IconExternalLink,
  IconCopy,
  IconCheck,
  IconRefresh,
} from '../components/Icons';

export const Runs: React.FC = () => {
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [filter, setFilter] = useState<'all' | 'completed' | 'pending' | 'blocked'>('all');
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [selectedRunReport, setSelectedRunReport] = useState<{ runId: string; markdown: string } | null>(null);
  const [reportLoading, setReportLoading] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const loadData = async (isManual = false) => {
    if (isManual) setRefreshing(true);
    try {
      const data = await fetchRuns();
      setRuns(data);
    } finally {
      setLoading(false);
      if (isManual) setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(() => loadData(false), 15000);
    return () => clearInterval(interval);
  }, []);

  const handleCopyRunId = (runId: string) => {
    navigator.clipboard.writeText(runId);
    setCopiedId(runId);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const handleOpenReport = async (runId: string) => {
    setReportLoading(true);
    const md = await fetchRunReport(runId);
    setSelectedRunReport({ runId, markdown: md });
    setReportLoading(false);
  };

  // KPI Calculations
  const metrics = useMemo(() => {
    const total = runs.length;
    const completed = runs.filter((r) => r.exit_code === 0).length;
    const pending = runs.filter((r) => r.exit_code === 10).length;
    const blocked = runs.filter((r) => r.exit_code === 20).length;
    const prsTotal = runs.reduce((acc, r) => acc + (r.prs ? r.prs.length : 0), 0);
    return { total, completed, pending, blocked, prsTotal };
  }, [runs]);

  const filteredRuns = useMemo(() => {
    return runs.filter((r) => {
      if (filter === 'all') return true;
      if (filter === 'completed') return r.exit_code === 0;
      if (filter === 'pending') return r.exit_code === 10;
      if (filter === 'blocked') return r.exit_code === 20;
      return true;
    });
  }, [runs, filter]);

  const renderStatusPill = (run: RunSummary) => {
    if (run.exit_code === 0) {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200/80 whitespace-nowrap">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          Completed
        </span>
      );
    }
    if (run.exit_code === 10) {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-50 text-amber-800 border border-amber-200/80 whitespace-nowrap">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse" />
          Review Required
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-50 text-rose-800 border border-rose-200/80 whitespace-nowrap">
        <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
        Policy Blocked
      </span>
    );
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900 flex items-center gap-2">
            Remediation Runs
          </h2>
          <p className="text-xs text-slate-500 mt-1">
            Real-time telemetry on autonomous vulnerability triage, sandbox verification gates, and pull request generation.
          </p>
        </div>

        <button
          onClick={() => loadData(true)}
          className="self-start sm:self-auto inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-white text-slate-700 border border-slate-200 shadow-2xs hover:bg-slate-50 transition-colors cursor-pointer"
        >
          <IconRefresh className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-sky-600' : 'text-slate-400'}`} />
          <span>Sync Runs</span>
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-2xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
            <span>Total Executions</span>
            <IconShield className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-900">{metrics.total}</span>
            <span className="text-[11px] text-slate-400">runs recorded</span>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-2xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
            <span>Clean / Completed</span>
            <IconShieldCheck className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-emerald-700">{metrics.completed}</span>
            <span className="text-[11px] text-emerald-600 font-medium">verified clean</span>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-2xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
            <span>Approval Gate</span>
            <IconAlertTriangle className="w-4 h-4 text-amber-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-amber-700">{metrics.pending}</span>
            <span className="text-[11px] text-amber-600 font-medium">awaiting review</span>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-2xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
            <span>Pull Requests</span>
            <IconGitPullRequest className="w-4 h-4 text-sky-500" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-sky-700">{metrics.prsTotal}</span>
            <span className="text-[11px] text-sky-600 font-medium">automated branches</span>
          </div>
        </div>
      </div>

      {/* Segmented Filter Bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs font-medium">
          <button
            onClick={() => setFilter('all')}
            className={`px-3 py-1.5 rounded-md transition-all cursor-pointer ${
              filter === 'all'
                ? 'bg-white text-slate-900 font-semibold shadow-2xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            All Runs <span className="ml-1 text-[11px] text-slate-400">({metrics.total})</span>
          </button>
          <button
            onClick={() => setFilter('completed')}
            className={`px-3 py-1.5 rounded-md transition-all cursor-pointer ${
              filter === 'completed'
                ? 'bg-white text-slate-900 font-semibold shadow-2xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Completed <span className="ml-1 text-[11px] text-slate-400">({metrics.completed})</span>
          </button>
          <button
            onClick={() => setFilter('pending')}
            className={`px-3 py-1.5 rounded-md transition-all cursor-pointer ${
              filter === 'pending'
                ? 'bg-white text-slate-900 font-semibold shadow-2xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Pending Review <span className="ml-1 text-[11px] text-amber-600 font-semibold">({metrics.pending})</span>
          </button>
          <button
            onClick={() => setFilter('blocked')}
            className={`px-3 py-1.5 rounded-md transition-all cursor-pointer ${
              filter === 'blocked'
                ? 'bg-white text-slate-900 font-semibold shadow-2xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Blocked <span className="ml-1 text-[11px] text-slate-400">({metrics.blocked})</span>
          </button>
        </div>
      </div>

      {/* Table Section */}
      {loading ? (
        <div className="bg-white rounded-xl border border-slate-200 p-12 text-center text-slate-500 shadow-2xs">
          <div className="inline-block animate-spin rounded-full h-7 w-7 border-2 border-slate-300 border-t-sky-600 mb-3" />
          <p className="text-xs font-medium text-slate-600">Loading telemetry from VulnFlow API...</p>
        </div>
      ) : filteredRuns.length === 0 ? (
        <div className="bg-white rounded-xl border border-slate-200 p-12 text-center text-slate-500 shadow-2xs">
          <IconShield className="w-8 h-8 text-slate-300 mx-auto mb-2" />
          <p className="text-sm font-semibold text-slate-700">No runs found</p>
          <p className="text-xs text-slate-400 mt-1">No remediation executions match the selected filter.</p>
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-slate-200 shadow-2xs overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-700">
              <thead className="bg-slate-50/80 border-b border-slate-200 text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
                <tr>
                  <th className="px-5 py-3 w-40">Run ID</th>
                  <th className="px-4 py-3 w-44">Target Repo</th>
                  <th className="px-4 py-3 w-36">Status</th>
                  <th className="px-3 py-3 w-28 text-center">Findings / Plans</th>
                  <th className="px-4 py-3 w-56">Pull Requests</th>
                  <th className="px-4 py-3 min-w-[220px]">Verification / Policy Gate</th>
                  <th className="px-4 py-3 w-28 text-right">Report</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-normal">
                {filteredRuns.map((r) => {
                  const isCopied = copiedId === r.run_id;
                  const prList = r.prs || [];

                  return (
                    <tr key={r.run_id} className="hover:bg-slate-50/70 transition-colors">
                      {/* Run ID with one-click copy */}
                      <td className="px-5 py-3.5 whitespace-nowrap">
                        <div className="flex items-center gap-1.5 font-mono text-[11px] font-semibold text-slate-800">
                          <span>{r.run_id}</span>
                          <button
                            onClick={() => handleCopyRunId(r.run_id)}
                            title={isCopied ? 'Copied!' : 'Copy Run ID'}
                            className="p-1 rounded text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer"
                          >
                            {isCopied ? (
                              <IconCheck className="w-3 h-3 text-emerald-600" />
                            ) : (
                              <IconCopy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                      </td>

                      {/* Repository */}
                      <td className="px-4 py-3.5">
                        <span
                          className="font-mono text-[11px] text-slate-600 truncate block max-w-[150px]"
                          title={r.repo_path || 'workspace'}
                        >
                          {r.repo_path ? r.repo_path.replace(/^\.\.\//, '') : 'workspace'}
                        </span>
                      </td>

                      {/* Status */}
                      <td className="px-4 py-3.5">{renderStatusPill(r)}</td>

                      {/* Findings / Plans count */}
                      <td className="px-3 py-3.5 text-center whitespace-nowrap">
                        <span className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-600">
                          <strong className="text-slate-900">{r.findings_count}</strong> findings
                          <span className="text-slate-300">/</span>
                          <strong className="text-slate-900">{r.plans_count}</strong> plans
                        </span>
                      </td>

                      {/* Pull Requests - Compact & Clean */}
                      <td className="px-4 py-3.5">
                        {prList.length > 0 ? (
                          <div className="flex flex-col gap-1 max-w-[210px]">
                            {prList.map((pr, idx) => {
                              const match = pr.pr_url?.match(/\/pull\/(\d+)/);
                              const prNumber = match ? `#${match[1]}` : `PR`;
                              const shortTitle = pr.title || pr.branch || 'Pull Request';

                              return (
                                <a
                                  key={idx}
                                  href={pr.pr_url || '#'}
                                  target="_blank"
                                  rel="noreferrer"
                                  title={`${shortTitle} (${pr.pr_url})`}
                                  className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-medium bg-sky-50 text-sky-700 hover:bg-sky-100 hover:text-sky-900 border border-sky-200/80 transition-colors truncate"
                                >
                                  <IconGitPullRequest className="w-3 h-3 shrink-0 text-sky-600" />
                                  <span className="font-semibold">{prNumber}</span>
                                  <span className="truncate text-slate-600">{shortTitle.replace(/^fix\([^)]+\):\s*/, '')}</span>
                                  <IconExternalLink className="w-2.5 h-2.5 shrink-0 opacity-60" />
                                </a>
                              );
                            })}
                          </div>
                        ) : (
                          <span className="text-slate-400 italic text-[11px]">—</span>
                        )}
                      </td>

                      {/* Rationale / Details with clamp */}
                      <td className="px-4 py-3.5">
                        <p
                          className="text-[11px] text-slate-500 line-clamp-2 leading-relaxed"
                          title={r.blocking_reason || 'Sandbox verification passed. Fix cleanly deployed.'}
                        >
                          {r.blocking_reason || 'Sandbox verification passed. Fix cleanly deployed.'}
                        </p>
                      </td>

                      {/* Report Action Button */}
                      <td className="px-4 py-3.5 text-right whitespace-nowrap">
                        <button
                          onClick={() => handleOpenReport(r.run_id)}
                          disabled={reportLoading}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-medium bg-white text-slate-700 hover:text-sky-700 hover:bg-sky-50 border border-slate-200 hover:border-sky-200 transition-colors cursor-pointer shadow-2xs"
                        >
                          <IconFileText className="w-3.5 h-3.5 text-slate-400 group-hover:text-sky-600" />
                          <span>View Report</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Rendered Markdown Report Modal */}
      {selectedRunReport && (
        <ReportModal
          runId={selectedRunReport.runId}
          markdown={selectedRunReport.markdown}
          onClose={() => setSelectedRunReport(null)}
        />
      )}
    </div>
  );
};

export default Runs;
