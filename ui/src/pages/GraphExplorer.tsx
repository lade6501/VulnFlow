/*
ui/src/pages/GraphExplorer.tsx
Interactive page for exploring dependency graph and blast radius.
*/

import React, { useState } from 'react';

interface GraphNode {
  id: string;
  label: string;
  type: 'vulnerability' | 'dependency' | 'service' | 'repository';
}

export const GraphExplorer: React.FC = () => {
  const [selectedPackage, setSelectedPackage] = useState('npm:lodash');
  const [blastRadius, setBlastRadius] = useState<string[]>([
    'payment-service',
    'auth-gateway',
    'web-frontend',
  ]);

  return (
    <div style={{ padding: '24px', fontFamily: 'sans-serif' }}>
      <h2>🕸️ Dependency Graph & Blast Radius Explorer</h2>
      <p style={{ color: '#666' }}>
        Visualize root-cause dependency trees and calculate affected blast radius services.
      </p>

      <div style={{ marginBottom: '16px' }}>
        <label style={{ fontWeight: 'bold', marginRight: '8px' }}>Target Package:</label>
        <input
          type="text"
          value={selectedPackage}
          onChange={(e) => setSelectedPackage(e.target.value)}
          style={{ padding: '6px 10px', width: '260px' }}
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        <div style={{ border: '1px solid #ddd', padding: '16px', borderRadius: '8px' }}>
          <h3>Root Cause Hierarchy</h3>
          <ul>
            <li><strong>Direct Dependency:</strong> <code>my-frontend-lib@1.2.0</code> (Manifest: package.json)</li>
            <ul>
              <li><strong>Transitive Dependency:</strong> <code>{selectedPackage}@4.17.15</code> (Vulnerable)</li>
              <ul>
                <li>CVE-2020-8203 (Prototype Pollution)</li>
              </ul>
            </ul>
          </ul>
        </div>

        <div style={{ border: '1px solid #ddd', padding: '16px', borderRadius: '8px' }}>
          <h3>Calculated Blast Radius ({blastRadius.length} services affected)</h3>
          <ul>
            {blastRadius.map((svc) => (
              <li key={svc} style={{ marginBottom: '6px' }}>
                <span style={{ backgroundColor: '#fee2e2', color: '#991b1b', padding: '2px 8px', borderRadius: '4px' }}>
                  {svc}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};

export default GraphExplorer;
