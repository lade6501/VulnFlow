/*
ui/src/pages/Expiry.tsx
Page monitoring expired packages, policy waivers, and scheduled reviews.
*/

import React, { useState } from 'react';

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
    <div style={{ padding: '24px', fontFamily: 'sans-serif' }}>
      <h2>⏳ Credential & Policy Expiry Monitor</h2>
      <p style={{ color: '#666' }}>
        Proactively monitors expiring secrets, TLS certificates, and temporary policy waivers before scanner flags them.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginTop: '16px' }}>
        <div style={{ backgroundColor: '#fee2e2', padding: '16px', borderRadius: '8px' }}>
          <h4 style={{ margin: '0 0 8px 0', color: '#991b1b' }}>🚨 Critical Expiry (&le; 7 days)</h4>
          <p style={{ fontSize: '24px', margin: 0, fontWeight: 'bold', color: '#991b1b' }}>1</p>
        </div>
        <div style={{ backgroundColor: '#fef3c7', padding: '16px', borderRadius: '8px' }}>
          <h4 style={{ margin: '0 0 8px 0', color: '#92400e' }}>⚠️ Warning (&le; 30 days)</h4>
          <p style={{ fontSize: '24px', margin: 0, fontWeight: 'bold', color: '#92400e' }}>1</p>
        </div>
        <div style={{ backgroundColor: '#dcfce7', padding: '16px', borderRadius: '8px' }}>
          <h4 style={{ margin: '0 0 8px 0', color: '#166534' }}>✅ Healthy (&gt; 30 days)</h4>
          <p style={{ fontSize: '24px', margin: 0, fontWeight: 'bold', color: '#166534' }}>1</p>
        </div>
      </div>

      <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '24px' }}>
        <thead>
          <tr style={{ backgroundColor: '#f3f4f6', textAlign: 'left' }}>
            <th style={{ padding: '10px', border: '1px solid #ddd' }}>Artifact Name</th>
            <th style={{ padding: '10px', border: '1px solid #ddd' }}>Type</th>
            <th style={{ padding: '10px', border: '1px solid #ddd' }}>Days Remaining</th>
            <th style={{ padding: '10px', border: '1px solid #ddd' }}>Risk Window</th>
            <th style={{ padding: '10px', border: '1px solid #ddd' }}>Expiration Date</th>
            <th style={{ padding: '10px', border: '1px solid #ddd' }}>Action</th>
          </tr>
        </thead>
        <tbody>
          {items.map((it) => (
            <tr key={it.name}>
              <td style={{ padding: '10px', border: '1px solid #ddd' }}><strong>{it.name}</strong></td>
              <td style={{ padding: '10px', border: '1px solid #ddd' }}><code>{it.type}</code></td>
              <td style={{ padding: '10px', border: '1px solid #ddd' }}>{it.daysRemaining} days</td>
              <td style={{ padding: '10px', border: '1px solid #ddd' }}>
                <span
                  style={{
                    backgroundColor: it.riskWindow === 'CRITICAL' ? '#fee2e2' : it.riskWindow === 'HIGH' ? '#fef3c7' : '#dcfce7',
                    color: it.riskWindow === 'CRITICAL' ? '#991b1b' : it.riskWindow === 'HIGH' ? '#92400e' : '#166534',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 'bold',
                  }}
                >
                  {it.riskWindow}
                </span>
              </td>
              <td style={{ padding: '10px', border: '1px solid #ddd' }}>{it.expiresAt}</td>
              <td style={{ padding: '10px', border: '1px solid #ddd' }}>
                <button style={{ padding: '4px 10px', cursor: 'pointer' }}>Renew Now</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default Expiry;
