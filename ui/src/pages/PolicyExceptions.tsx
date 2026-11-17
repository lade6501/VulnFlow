/*
ui/src/pages/PolicyExceptions.tsx
Page managing temporary policy exceptions and expiration timelines.
*/

import { useState } from 'react';

interface PolicyException {
  ticketId: string;
  package: string;
  cve: string;
  reason: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  expiresAt: string;
}

export const PolicyExceptions: React.FC = () => {
  const [exceptions] = useState<PolicyException[]>([
    {
      ticketId: 'SEC-8921',
      package: 'npm:left-pad',
      cve: 'CVE-2020-28469',
      reason: 'Package is banned by organizational policy',
      status: 'APPROVED',
      expiresAt: '2026-12-01',
    },
    {
      ticketId: 'SEC-9104',
      package: 'npm:unknown-crypto',
      cve: 'CVE-2024-5512',
      reason: 'Target library not on approved enterprise whitelist',
      status: 'PENDING',
      expiresAt: '2026-11-28',
    },
  ]);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-slate-900 flex items-center gap-2">
          <span>📋</span> Policy Exceptions & Banned Package Waivers
        </h2>
        <p className="text-sm text-slate-500 mt-1">
          Track security exception tickets and manage time-bound policy waivers issued by security review.
        </p>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-700">
            <thead className="bg-slate-50 border-b border-slate-200 text-xs uppercase font-semibold text-slate-500">
              <tr>
                <th className="px-5 py-3.5">Ticket ID</th>
                <th className="px-5 py-3.5">Package</th>
                <th className="px-5 py-3.5">Vulnerability</th>
                <th className="px-5 py-3.5">Policy Blocking Reason</th>
                <th className="px-5 py-3.5">Status</th>
                <th className="px-5 py-3.5">Expires At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {exceptions.map((ex) => (
                <tr key={ex.ticketId} className="hover:bg-slate-50/80 transition-colors">
                  <td className="px-5 py-4 font-mono text-xs font-semibold text-slate-900">
                    <code>{ex.ticketId}</code>
                  </td>
                  <td className="px-5 py-4 font-mono text-xs text-slate-800 font-medium">
                    {ex.package}
                  </td>
                  <td className="px-5 py-4 font-mono text-xs text-rose-700">
                    {ex.cve}
                  </td>
                  <td className="px-5 py-4 text-xs text-slate-600 max-w-sm">
                    {ex.reason}
                  </td>
                  <td className="px-5 py-4">
                    <span
                      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold ${
                        ex.status === 'APPROVED'
                          ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                          : 'bg-amber-50 text-amber-700 border border-amber-200'
                      }`}
                    >
                      {ex.status}
                    </span>
                  </td>
                  <td className="px-5 py-4 font-mono text-xs text-slate-500">
                    {ex.expiresAt}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default PolicyExceptions;
