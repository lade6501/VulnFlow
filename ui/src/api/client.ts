/*
ui/src/api/client.ts
Frontend HTTP client for communicating with VulnFlow FastAPI endpoints.
*/

export interface RunSummary {
  run_id: string;
  terminal_status: string;
  exit_code: number | null;
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
  const res = await fetch(`${API_BASE}/api/runs?limit=${limit}`);
  if (!res.ok) throw new Error(`Runs request failed (${res.status})`);
  const data = await res.json();
  if (!Array.isArray(data.runs)) throw new Error('Invalid run list');
  return data.runs;
}

export async function fetchRunReport(runId: string): Promise<string> {
  try {
    const res = await fetch(`${API_BASE}/api/runs/${encodeURIComponent(runId)}/report`);
    if (res.ok) {
      const data = await res.json();
      return data.report || '';
    }
  } catch (err) {
    console.warn(`Failed to fetch report for run ${runId}`, err);
  }
  return '';
}

export interface PendingApprovalItem {
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
  requiredGroups?: string[];
  satisfiedGroups?: string[];
}

export async function fetchPendingApprovals(repo?: string): Promise<PendingApprovalItem[]> {
  try {
    const url = repo ? `${API_BASE}/api/approvals?repo=${encodeURIComponent(repo)}` : `${API_BASE}/api/approvals`;
    const res = await fetch(url);
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.plans) && data.plans.length > 0) {
        return data.plans;
      }
    }
  } catch (err) {
    console.warn('API call failed for approvals, falling back', err);
  }
  return [];
}

export async function submitPlanApproval(
  planId: string,
  approved: boolean,
  reviewer: string = 'security-lead',
  reason: string = 'Authorized by security committee',
  reviewerGroup: string = 'security',
  repoPath?: string,
  apiToken?: string
): Promise<{ ok: boolean; status: string; terminalStatus?: string }> {
  try {
    const res = await fetch(`${API_BASE}/api/approvals/${planId}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(apiToken ? { Authorization: `Bearer ${apiToken}` } : {}),
      },
      body: JSON.stringify({
        approved,
        reviewer,
        reviewer_group: reviewerGroup,
        reason,
        repo_path: repoPath,
        resume: true,
      }),
    });
    const data = res.ok ? await res.json() : {};
    return {
      ok: res.ok,
      status: data.status || (res.status === 401 ? 'unauthorized' : 'error'),
      terminalStatus: data.terminal_status,
    };
  } catch (err) {
    console.warn('API call failed, operating in mock mode', err);
    return { ok: false, status: 'error' };
  }
}

export interface GraphData {
  root_cause: { root_cause_package: string; dependency_chain: string[] };
  blast_radius: { affected_services: string[] };
}

export async function fetchGraphData(pkg: string, signal: AbortSignal): Promise<GraphData> {
  const res = await fetch(`${API_BASE}/api/graph?package=${encodeURIComponent(pkg)}`, { signal });
  if (!res.ok) throw new Error(`Graph request failed (${res.status})`);
  return res.json();
}
