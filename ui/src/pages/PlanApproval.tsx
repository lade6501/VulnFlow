/*
ui/src/pages/PlanApproval.tsx
Page presenting proposed remediation plans for human review, verification diffs, and sign-off.
*/

import { useState } from 'react';
import { submitPlanApproval } from '../api/client';

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
  const [plans, setPlans] = useState<PendingPlan[]>([
    {
      id: 'PLAN-b47c229e01df',
      repo: 'workspace/auth-gateway',
      targetPackage: 'npm:my-unknown-crypto',
      currentVersion: '1.0.0',
      proposedVersion: '1.1.0',
      action: 'BUMP',
      riskTier: 'REVIEW',
      reason: 'Target package is not on corporate pre-approved whitelist (UNKNOWN).',
      rationale: 'Upgrade resolves CVE-2024-9999. Backward compatibility tests passed in sandbox runner.',
      diff: '--- package.json\n+++ package.json\n- "my-unknown-crypto": "1.0.0"\n+ "my-unknown-crypto": "1.1.0"',
    },
    {
      id: 'PLAN-sec-8812c3f9',
      repo: 'workspace/payment-service',
      targetPackage: 'secret:aws-access-key',
      currentVersion: 'hardcoded',
      proposedVersion: 'env-var',
      action: 'ROTATE',
      riskTier: 'REVIEW',
      reason: 'Plaintext secret credential detected in repository source code.',
      rationale: 'Exposed AWS Access Key in config.js. Must be revoked in AWS IAM and rotated to environment variable.',
      diff: '--- src/config.js\n+++ src/config.js\n- const KEY = "AKIAIOSFODNN7EXAMPLE";\n+ const KEY = process.env.AWS_ACCESS_KEY_ID;',
    },
  ]);

  const [message, setMessage] = useState<string | null>(null);

  const handleDecision = async (planId: string, approved: boolean) => {
    const reason = approved
      ? 'Approved via VulnFlow Web Dashboard'
      : 'Rejected: requires additional security vetting';
    await submitPlanApproval(planId, approved, 'security-lead@corp.internal', reason);

    setMessage(
      approved
        ? `✅ Plan ${planId} approved! VulnFlow workflow resumed and PR creation initiated.`
        : `🛑 Plan ${planId} rejected.`
    );
    setPlans(plans.filter((p) => p.id !== planId));
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-slate-900 flex items-center gap-2">
          <span>⚖️</span> Human Security Approval Queue
        </h2>
        <p className="text-sm text-slate-500 mt-1">
          Review remediation plans classified as <strong className="text-slate-800">REVIEW</strong> tier before any changes are committed or pull requests opened.
        </p>
      </div>

      {message && (
        <div className="p-4 rounded-lg bg-blue-50 border border-blue-200 text-blue-900 text-sm font-medium shadow-xs">
          {message}
        </div>
      )}

      {plans.length === 0 ? (
        <div className="bg-white rounded-xl border border-slate-200 p-16 text-center shadow-xs">
          <div className="text-4xl mb-3">🎉</div>
          <h3 className="text-lg font-bold text-slate-900">No Plans Awaiting Human Approval</h3>
          <p className="text-sm text-slate-500 mt-1">
            All pending remediation proposals have been authorized or automatically resolved.
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {plans.map((p) => (
            <div
              key={p.id}
              className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-5"
            >
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-slate-100 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-0.5 rounded text-xs font-bold uppercase bg-slate-100 text-slate-800 border border-slate-200">
                      {p.action}
                    </span>
                    <h3 className="text-lg font-bold text-slate-900 font-mono">
                      {p.targetPackage}
                    </h3>
                    <span className="text-xs font-semibold text-slate-400">
                      ({p.currentVersion} &rarr; {p.proposedVersion})
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 font-mono mt-1">
                    Plan ID: <span className="text-slate-700">{p.id}</span> | Repository: <span className="text-slate-700">{p.repo}</span>
                  </p>
                </div>

                <span className="self-start sm:self-auto px-3 py-1 rounded-md text-xs font-bold bg-amber-50 text-amber-800 border border-amber-200 tracking-wider">
                  TIER: {p.riskTier}
                </span>
              </div>

              <div className="bg-amber-50/60 border border-amber-200/80 rounded-lg p-4 text-sm text-amber-900">
                <div className="font-semibold flex items-center gap-1.5 mb-1 text-amber-950">
                  <span>⚠️</span> Policy Gate Trigger
                </div>
                <p className="text-xs leading-relaxed">{p.reason}</p>
              </div>

              <div>
                <h4 className="text-xs uppercase font-semibold text-slate-500 tracking-wider mb-1.5">
                  AI Engineering Rationale
                </h4>
                <p className="text-sm text-slate-700 bg-slate-50 p-3.5 rounded-lg border border-slate-200/60 leading-relaxed">
                  {p.rationale}
                </p>
              </div>

              <div>
                <h4 className="text-xs uppercase font-semibold text-slate-500 tracking-wider mb-1.5">
                  Proposed Diff Preview
                </h4>
                <pre className="bg-slate-950 text-emerald-400 font-mono text-xs p-4 rounded-lg overflow-x-auto shadow-inner leading-relaxed">
                  {p.diff}
                </pre>
              </div>

              <div className="flex items-center gap-3 pt-2">
                <button
                  onClick={() => handleDecision(p.id, true)}
                  className="px-4 py-2 rounded-lg text-sm font-semibold bg-emerald-600 hover:bg-emerald-700 text-white shadow-xs transition-colors cursor-pointer flex items-center gap-1.5"
                >
                  <span>✅</span> Authorize & Resume PR
                </button>
                <button
                  onClick={() => handleDecision(p.id, false)}
                  className="px-4 py-2 rounded-lg text-sm font-semibold bg-rose-600 hover:bg-rose-700 text-white shadow-xs transition-colors cursor-pointer flex items-center gap-1.5"
                >
                  <span>🛑</span> Reject Plan
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
