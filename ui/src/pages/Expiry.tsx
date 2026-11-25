/*
ui/src/pages/Expiry.tsx
Page monitoring expired packages, policy waivers, and scheduled reviews.
*/

import { useState } from 'react';
import { IconClock, IconAlertTriangle, IconShieldCheck } from '../components/Icons';

interface ExpiryItem {
  name: string;
  type: string;
  daysRemaining: number;
  riskWindow: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  expiresAt: string;
}

export const Expiry: React.FC = () => {
  const [items] = useState<ExpiryItem[]>([
    {
      name: 'production-ingress-tls',
      type: 'certificate',
      daysRemaining: 3,
      riskWindow: 'CRITICAL',
      expiresAt: '2026-11-20',
    },
    {
      name: 'temporary-lodash-exception',
      type: 'policy_waiver',
      daysRemaining: 8,
      riskWindow: 'HIGH',
      expiresAt: '2026-11-25',
    },
    {
      name: 'datadog-api-key',
      type: 'api_token',
      daysRemaining: 410,
      riskWindow: 'LOW',
      expiresAt: '2027-12-31',
    },
  ]);

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <p role="status" className="text-xs text-slate-600">Example records. Live expiry monitoring is unavailable in this view.</p>
      <div>
        <h2 className="text-xl font-bold tracking-tight text-slate-900 flex items-center gap-2">
          <IconClock className="w-5 h-5 text-slate-700" />
          <span>Credential &amp; Policy Expiry Monitor</span>
        </h2>
        <p className="text-xs text-slate-500 mt-1">
          Proactively monitors expiring secrets, TLS certificates, and temporary policy waivers before scanner flags them.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-rose-50/70 border border-rose-200/80 rounded-xl p-4 shadow-2xs">
          <div className="flex items-center justify-between">
            <h4 className="text-[11px] uppercase font-bold text-rose-800 tracking-wider">
              Critical Expiry (&le; 7 days)
            </h4>
            <IconAlertTriangle className="w-4 h-4 text-rose-600" />
          </div>
          <p className="text-2xl font-bold text-rose-900 mt-2">1</p>
          <p className="text-[11px] text-rose-600 mt-0.5">Requires urgent rotation</p>
        </div>

        <div className="bg-amber-50/70 border border-amber-200/80 rounded-xl p-4 shadow-2xs">
          <div className="flex items-center justify-between">
            <h4 className="text-[11px] uppercase font-bold text-amber-800 tracking-wider">
              Warning Window (&le; 30 days)
            </h4>
            <IconClock className="w-4 h-4 text-amber-600" />
          </div>
          <p className="text-2xl font-bold text-amber-900 mt-2">1</p>
          <p className="text-[11px] text-amber-600 mt-0.5">Renewal tickets queued</p>
        </div>

        <div className="bg-emerald-50/70 border border-emerald-200/80 rounded-xl p-4 shadow-2xs">
          <div className="flex items-center justify-between">
            <h4 className="text-[11px] uppercase font-bold text-emerald-800 tracking-wider">
              Healthy Artifacts (&gt; 30 days)
            </h4>
            <IconShieldCheck className="w-4 h-4 text-emerald-600" />
          </div>
          <p className="text-2xl font-bold text-emerald-900 mt-2">1</p>
          <p className="text-[11px] text-emerald-600 mt-0.5">Valid credential state</p>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 shadow-2xs overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-700">
            <thead className="bg-slate-50/80 border-b border-slate-200 text-[11px] uppercase font-semibold text-slate-500">
              <tr>
                <th className="px-5 py-3">Artifact Name</th>
                <th className="px-5 py-3">Type</th>
                <th className="px-5 py-3">Days Remaining</th>
                <th className="px-5 py-3">Risk Window</th>
                <th className="px-5 py-3">Expiration Date</th>
                <th className="px-5 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {items.map((it) => (
                <tr key={it.name} className="hover:bg-slate-50/70 transition-colors">
                  <td className="px-5 py-3.5 font-semibold text-slate-900">
                    {it.name}
                  </td>
                  <td className="px-5 py-3.5 font-mono text-[11px] text-slate-600">
                    <code>{it.type}</code>
                  </td>
                  <td className="px-5 py-3.5 text-slate-700 font-medium">
                    {it.daysRemaining} days
                  </td>
                  <td className="px-5 py-3.5">
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold ${
                        it.riskWindow === 'CRITICAL'
                          ? 'bg-rose-50 text-rose-700 border border-rose-200'
                          : it.riskWindow === 'HIGH'
                          ? 'bg-amber-50 text-amber-700 border border-amber-200'
                          : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                      }`}
                    >
                      {it.riskWindow}
                    </span>
                  </td>
                  <td className="px-5 py-3.5 font-mono text-[11px] text-slate-500">
                    {it.expiresAt}
                  </td>
                  <td className="px-5 py-3.5 text-right">
                    <button className="px-2.5 py-1 rounded-md text-[11px] font-medium bg-slate-900 hover:bg-slate-800 text-white shadow-2xs transition-colors cursor-pointer">
                      Renew Now
                    </button>
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

export default Expiry;
