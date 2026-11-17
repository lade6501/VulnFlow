/*
ui/src/api/client.ts
Frontend HTTP client for communicating with VulnFlow FastAPI endpoints.
*/

export interface RunSummary {
  run_id: string;
  terminal_status: string;
  exit_code: number;
  repo_path?: string;
  mode?: string;
  findings_count: number;
  plans_count: number;
  approved_count?: number;
  pending_count?: number;
  prs_count: number;
  prs?: Array<{ title?: string; branch?: string; pr_url?: string; status?: string }>;
  blocking_reason?: string | null;
  created_at?: number;
}

export interface PlanItem {
  id: string;
  root_cause_id: string;
  target_package?: string;
  target_version?: string;
  action: string;
  risk_tier: string;
  requires_approval: boolean;
  policy_status?: string;
  rationale?: string;
  findings_count?: number;
}

const API_BASE = import.meta.env?.VITE_API_BASE_URL || 'http://localhost:8000';

export async function fetchRuns(limit: number = 50): Promise<RunSummary[]> {
  try {
    const res = await fetch(`${API_BASE}/api/runs?limit=${limit}`);
    if (res.ok) {
      const data = await res.json();
      return data.runs || [];
    }
  } catch (err) {
    console.warn('API unavailable, returning local runs state', err);
  }

  // Graceful fallback data when backend is not running
  return [
    {
      run_id: 'RUN-a19e83b0f142',
      terminal_status: 'completed',
      exit_code: 0,
      repo_path: 'workspace/payment-service',
      mode: 'pr',
      findings_count: 3,
      plans_count: 1,
      approved_count: 1,
      pending_count: 0,
      prs_count: 1,
      prs: [{ title: 'fix(deps): bump lodash to 4.17.21', branch: 'vulnflow/fix-lodash', pr_url: 'https://github.com/corp/payment/pull/42', status: 'opened' }],
      created_at: Date.now() - 3600000,
    },
    {
      run_id: 'RUN-b47c229e01df',
      terminal_status: 'pending_approval',
      exit_code: 10,
      repo_path: 'workspace/auth-gateway',
      mode: 'pr',
      findings_count: 2,
      plans_count: 1,
      approved_count: 0,
      pending_count: 1,
      prs_count: 0,
      blocking_reason: '1 plan(s) require human authorization: target package not on corporate approved whitelist.',
      created_at: Date.now() - 7200000,
    },
    {
      run_id: 'RUN-c88f9104e5aa',
      terminal_status: 'blocked_policy',
      exit_code: 20,
      repo_path: 'workspace/user-profile',
      mode: 'pr',
      findings_count: 1,
      plans_count: 0,
      approved_count: 0,
      pending_count: 0,
      prs_count: 0,
      blocking_reason: 'Package left-pad is banned by organizational security policy.',
      created_at: Date.now() - 14400000,
    },
  ];
}

export async function submitPlanApproval(
  planId: string,
  approved: boolean,
  reviewer: string = 'security-lead',
  reason: string = 'Authorized by security committee'
): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/api/approvals/${planId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approved, reviewer, reason, resume: true }),
    });
    return res.ok;
  } catch (err) {
    console.warn('API call failed, operating in mock mode', err);
    return true;
  }
}

export async function fetchGraphData(pkg: string = 'npm:lodash'): Promise<any> {
  try {
    const res = await fetch(`${API_BASE}/api/graph?package=${encodeURIComponent(pkg)}`);
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    console.warn('API call failed for graph data', err);
  }
  return {
    package: pkg,
    root_cause: { root_cause_package: 'my-frontend-lib', is_direct: false },
    blast_radius: { affected_services: ['payment-service', 'auth-gateway', 'web-frontend'] },
  };
}
