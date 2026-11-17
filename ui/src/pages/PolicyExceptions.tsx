/*
ui/src/pages/PolicyExceptions.tsx
Page managing temporary policy exceptions and expiration timelines.
*/

import React, { useState } from 'react';

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
    <div style={{ padding: '24px', fontFamily: 'sans-serif' }}>
      <h2>📋 Policy Exceptions & Banned Package Waivers</h2>
      <p style={{ color: '#666' }}>
        Track security exception tickets and manage time-bound policy waivers.
      </p>

      <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '16px' }}>
        <thead>
          <tr style={{ backgroundColor: '#f3f4f6', textAlign: 'left' }}>
            <th style={{ padding: '10px', border: '1px solid #ddd' }}>Ticket ID</th>
            <th style={{ padding: '10px', border: '1px solid #ddd' }}>Package</th>
            <th style={{ padding: '10px', border: '1px solid #ddd' }}>Vulnerability</th>
            <th style={{ padding: '10px', border: '1px solid #ddd' }}>Policy Blocking Reason</th>
            <th style={{ padding: '10px', border: '1px solid #ddd' }}>Status</th>
            <th style={{ padding: '10px', border: '1px solid #ddd' }}>Expires At</th>
          </tr>
        </thead>
        <tbody>
          {exceptions.map((ex) => (
            <tr key={ex.ticketId}>
              <td style={{ padding: '10px', border: '1px solid #ddd' }}><code>{ex.ticketId}</code></td>
              <td style={{ padding: '10px', border: '1px solid #ddd' }}>{ex.package}</td>
              <td style={{ padding: '10px', border: '1px solid #ddd' }}>{ex.cve}</td>
              <td style={{ padding: '10px', border: '1px solid #ddd' }}>{ex.reason}</td>
              <td style={{ padding: '10px', border: '1px solid #ddd' }}>
                <span
                  style={{
                    backgroundColor: ex.status === 'APPROVED' ? '#dcfce7' : '#fef9c3',
                    color: ex.status === 'APPROVED' ? '#166534' : '#854d0e',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '12px',
                  }}
                >
                  {ex.status}
                </span>
              </td>
              <td style={{ padding: '10px', border: '1px solid #ddd' }}>{ex.expiresAt}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default PolicyExceptions;
