import type {
  AttackPath, CompareRow, CustomSuiteInput, Health, ProbeResult, Replay, Report, RunSummary, Suite, Target, TargetInput, TaskDetail,
} from './types'

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...init.headers,
    },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({} as Record<string, unknown>))
    const detail = (body as { detail?: unknown }).detail
    const message = typeof detail === 'string' ? detail : `请求失败 (${response.status})`
    throw new ApiError(response.status, message)
  }
  return response.status === 204 ? (undefined as T) : response.json()
}

const seg = (value: string) => encodeURIComponent(value)

export const api = {
  health: () => request<Health>('/api/health'),

  listTargets: () => request<{ targets: Target[] }>('/api/targets'),
  createTarget: (input: TargetInput) =>
    request<Target>('/api/targets', { method: 'POST', body: JSON.stringify(input) }),
  deleteTarget: (id: string) =>
    request<{ deleted: boolean }>(`/api/targets/${seg(id)}`, { method: 'DELETE' }),
  probeTarget: (id: string) =>
    request<ProbeResult>(`/api/targets/${seg(id)}/probe`, { method: 'POST' }),

  listSuites: () => request<{ suites: Suite[] }>('/api/suites'),
  getSuite: (suiteId: string) => request<Suite>(`/api/suites/${seg(suiteId)}`),
  getTask: (suiteId: string, taskId: string) =>
    request<TaskDetail>(`/api/suites/${seg(suiteId)}/tasks/${seg(taskId)}`),
  validateCustomSuite: (input: CustomSuiteInput) =>
    request<{ ok: boolean; suite: CustomSuiteInput }>('/api/custom-suites/validate', {
      method: 'POST',
      body: JSON.stringify(input),
    }),
  createCustomSuite: (input: CustomSuiteInput) =>
    request<Suite>('/api/custom-suites', { method: 'POST', body: JSON.stringify(input) }),

  listRuns: () => request<{ runs: RunSummary[] }>('/api/runs'),
  createRun: (input: {
    target_id: string
    suite_id: string
    n_attempts?: number
    max_concurrent?: number
  }) => request<RunSummary>('/api/runs', { method: 'POST', body: JSON.stringify(input) }),
  getRun: (runId: string) => request<RunSummary>(`/api/runs/${seg(runId)}`),
  getRunAttackPath: (runId: string) => request<AttackPath>(`/api/runs/${seg(runId)}/attack-path`),
  cancelRun: (runId: string) =>
    request<{ cancelled: boolean }>(`/api/runs/${seg(runId)}/cancel`, { method: 'POST' }),

  getReport: (runId: string) => request<Report>(`/api/runs/${seg(runId)}/report`),
  reportMarkdownUrl: (runId: string) => `/api/runs/${seg(runId)}/report.md`,

  getReplay: (runId: string, taskId: string, attempt = 0) =>
    request<Replay>(`/api/runs/${seg(runId)}/replay/${seg(taskId)}?attempt=${attempt}`),

  compare: (runIds: string[], requiredNodes?: number) =>
    request<{ rows: CompareRow[]; count: number }>('/api/compare', {
      method: 'POST',
      body: JSON.stringify({
        run_ids: runIds,
        ...(requiredNodes ? { required_nodes: requiredNodes } : {}),
      }),
    }),

  eventsUrl: (runId: string, cursor = 0) => `/api/runs/${seg(runId)}/events?cursor=${cursor}`,
}

export function errorMessage(reason: unknown): string {
  if (reason instanceof ApiError) return reason.message
  if (reason instanceof Error) return reason.message
  return '未知错误'
}
