/*
ui/src/pages/GraphExplorer.tsx
Interactive page for exploring dependency graph, root cause hierarchies, and blast radius.
*/

import { useState } from 'react';
import { IconNetwork, IconShield, IconAlertTriangle } from '../components/Icons';

export const GraphExplorer: React.FC = () => {
  const [selectedPackage, setSelectedPackage] = useState('npm:lodash');
  const [blastRadius] = useState<string[]>([
    'payment-service',
    'auth-gateway',
    'web-frontend',
  ]);

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-slate-900 flex items-center gap-2">
          <IconNetwork className="w-5 h-5 text-slate-700" />
          <span>Dependency Graph &amp; Blast Radius Explorer</span>
        </h2>
        <p className="text-xs text-slate-500 mt-1">
          Trace root-cause dependency trees and calculate affected blast radius across organizational microservices.
        </p>
      </div>

      <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-2xs flex flex-col sm:flex-row sm:items-center gap-3">
        <label className="text-xs font-semibold uppercase tracking-wider text-slate-500">
          Target Package:
        </label>
        <div className="relative flex-1 max-w-md">
          <input
            type="text"
            value={selectedPackage}
            onChange={(e) => setSelectedPackage(e.target.value)}
            className="w-full px-3 py-1.5 rounded-lg border border-slate-200 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-sky-500"
            placeholder="e.g. npm:lodash, maven:org.yaml:snakeyaml"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-2xs space-y-4">
          <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
            <IconShield className="w-4 h-4 text-sky-600" />
            <span>Root Cause Hierarchy</span>
          </h3>

          <div className="bg-slate-50 rounded-lg p-3.5 border border-slate-200/70 space-y-3 font-mono text-xs">
            <div className="flex items-center gap-2 text-slate-800 font-semibold">
              <span className="w-2 h-2 rounded-full bg-blue-500" />
              <span>Direct Dependency:</span>
              <span className="bg-blue-100 text-blue-900 px-2 py-0.5 rounded text-[11px]">my-frontend-lib@1.2.0</span>
            </div>

            <div className="pl-5 border-l-2 border-slate-200 ml-1 space-y-2">
              <div className="flex items-center gap-2 text-rose-800 font-semibold">
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                <span>Transitive Vulnerability:</span>
                <span className="bg-rose-100 text-rose-900 px-2 py-0.5 rounded text-[11px]">{selectedPackage}@4.17.15</span>
              </div>

              <div className="pl-4 border-l-2 border-rose-200 ml-0.5 space-y-1 text-slate-600 text-[11px]">
                <p>&bull; CVE-2020-8203 (Prototype Pollution in defaultsDeep)</p>
                <p>&bull; CVSS 7.4 (High Severity)</p>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-2xs space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <IconAlertTriangle className="w-4 h-4 text-rose-600" />
              <span>Calculated Blast Radius</span>
            </h3>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200">
              {blastRadius.length} Services Affected
            </span>
          </div>

          <div className="space-y-2">
            {blastRadius.map((svc) => (
              <div
                key={svc}
                className="flex items-center justify-between p-2.5 rounded-lg bg-slate-50 border border-slate-200/60 text-xs font-medium"
              >
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                  <span className="font-mono text-slate-800">{svc}</span>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded font-semibold bg-rose-100 text-rose-800">
                  RE-TEST REQUIRED
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default GraphExplorer;
