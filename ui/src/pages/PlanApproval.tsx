/*
ui/src/pages/PlanApproval.tsx
Page presenting proposed remediation plans for human review, verification diffs, and sign-off.
*/

import { useEffect, useState } from 'react';
import { fetchPendingApprovals, submitPlanApproval } from '../api/client';
import {
  IconScale,
  IconCheck,
  IconAlertTriangle,
  IconShieldCheck,
  IconCheckCircle,
} from '../components/Icons';

interface PendingPlan {
  id: string;
  repo: string;
  targetPackage: string;
  currentVersion: string;
  proposedVersion: string;
  action: string;
  riskTier: string;
  reason: string;
  rationale: string;
  diff: string;
}

export const PlanApproval: React.FC = () => {
  const [plans, setPlans] = useState<PendingPlan[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [message, setMessage] = useState<{ text: string; type: 'success' | 'danger' } | null>(null);

  const loadApprovals = () => {
    fetchPendingApprovals().then((livePlans) => {
      if (livePlans.length > 0) {
        setPlans(livePlans);
      } else {
        setPlans([]);
      }
      setLoading(false);
    });
  };

  useEffect(() => {
    loadApprovals();
  }, []);

  const handleDecision = async (planId: string, approved: boolean) => {
    const reason = approved
      ? 'Authorized via VulnFlow Control Plane'
      : 'Rejected by security reviewer';
    await submitPlanApproval(planId, approved, 'security-lead@corp.internal', reason);

    setMessage({
      text: approved
        ? `Plan ${planId} authorized. Workflow resumed and PR creation initiated.`
        : `Plan ${planId} rejected. Policy block enforced.`,
      type: approved ? 'success' : 'danger',
    });
    setPlans(plans.filter((p) => p.id !== planId));
    setTimeout(loadApprovals, 1500);
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-slate-900 flex items-center gap-2">
          <IconScale className="w-5 h-5 text-slate-700" />
          <span>Human Security Approval Queue</span>
        </h2>
        <p className="text-xs text-slate-500 mt-1">
          Review remediation proposals classified under the <strong className="text-slate-800">REVIEW</strong> tier before any changes are committed or pull requests opened.
        </p>
      </div>

      {message && (
        <div
          className={`p-3.5 rounded-lg border text-xs font-medium shadow-2xs flex items-center gap-2 ${
            message.type === 'success'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
              : 'bg-rose-50 border-rose-200 text-rose-900'
          }`}
        >
          {message.type === 'success' ? (
            <IconCheckCircle className="w-4 h-4 text-emerald-600 shrink-0" />
          ) : (
            <IconAlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
          )}
          <span>{message.text}</span>
        </div>
      )}

      {loading ? (
        <div className="bg-white rounded-xl border border-slate-200 p-12 text-center text-slate-500 shadow-2xs">
          <div className="inline-block animate-spin rounded-full h-7 w-7 border-2 border-slate-300 border-t-sky-600 mb-3" />
          <p className="text-xs font-medium text-slate-600">Checking pending authorization ledger...</p>
        </div>
      ) : plans.length === 0 ? (
        <div className="bg-white rounded-xl border border-slate-200 p-14 text-center shadow-2xs">
          <div className="w-12 h-12 rounded-full bg-emerald-50 border border-emerald-200/80 flex items-center justify-center text-emerald-600 mx-auto mb-3">
            <IconShieldCheck className="w-6 h-6" />
          </div>
          <h3 className="text-sm font-bold text-slate-900">No Plans Awaiting Security Review</h3>
          <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
            All pending remediation proposals have either been authorized or automatically resolved through corporate whitelist policy.
          </p>
        </div>
      ) : (
        <div className="space-y-5">
          {plans.map((p) => (
            <div
              key={p.id}
              className="bg-white rounded-xl border border-slate-200 p-5 shadow-2xs space-y-4"
            >
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-slate-100 pb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[11px] font-bold uppercase bg-slate-100 text-slate-800 border border-slate-200">
                      {p.action}
                    </span>
                    <h3 className="text-base font-bold text-slate-900 font-mono">
                      {p.targetPackage}
                    </h3>
                    <span className="text-xs font-semibold text-slate-500">
                      ({p.currentVersion} &rarr; {p.proposedVersion})
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 font-mono mt-1">
                    Plan ID: <span className="text-slate-700 font-semibold">{p.id}</span> | Repository: <span className="text-slate-700">{p.repo}</span>
                  </p>
                </div>

                <span className="self-start sm:self-auto px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-50 text-amber-800 border border-amber-200 tracking-wider">
                  TIER: {p.riskTier}
                </span>
              </div>

              <div className="bg-amber-50/70 border border-amber-200/80 rounded-lg p-3.5 text-xs text-amber-900">
                <div className="font-semibold flex items-center gap-1.5 mb-1 text-amber-950">
                  <IconAlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                  <span>Policy Gate Trigger</span>
                </div>
                <p className="leading-relaxed text-[11px]">{p.reason}</p>
              </div>

              <div>
                <h4 className="text-[11px] uppercase font-semibold text-slate-500 tracking-wider mb-1">
                  AI Remediation Rationale
                </h4>
                <p className="text-xs text-slate-700 bg-slate-50/80 p-3 rounded-lg border border-slate-200/60 leading-relaxed font-sans">
                  {p.rationale}
                </p>
              </div>

              <div>
                <h4 className="text-[11px] uppercase font-semibold text-slate-500 tracking-wider mb-1">
                  Proposed Diff Preview
                </h4>
                <pre className="bg-slate-950 text-emerald-400 font-mono text-[11px] p-3.5 rounded-lg overflow-x-auto shadow-inner leading-relaxed">
                  {p.diff}
                </pre>
              </div>

              <div className="flex items-center gap-2.5 pt-1">
                <button
                  onClick={() => handleDecision(p.id, true)}
                  className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white shadow-2xs transition-colors cursor-pointer flex items-center gap-1.5"
                >
                  <IconCheck className="w-3.5 h-3.5" />
                  <span>Authorize &amp; Resume PR</span>
                </button>
                <button
                  onClick={() => handleDecision(p.id, false)}
                  className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-white hover:bg-rose-50 text-rose-700 border border-rose-200 hover:border-rose-300 shadow-2xs transition-colors cursor-pointer flex items-center gap-1.5"
                >
                  <span>Reject Proposal</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default PlanApproval;
