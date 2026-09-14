export type TargetKind = 'inproc' | 'http'
export type RunStatus = 'starting' | 'running' | 'completed' | 'failed' | 'cancelled'
export type TaskStatus = 'running' | 'PASS' | 'FAIL' | 'ERROR'
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type Severity = 'low' | 'medium' | 'high' | 'critical'

export type Health = {
  ok: boolean
  version: string
  target_kinds: string[]
  inproc_agents: string[]
  pipeline_nodes: Record<string, string>
}

export type Target = {
  id: string
  name: string
  kind: TargetKind
  agent_kind: string
  model: string
  base_url: string
  api_key_env: string
  note: string
  tags: string[]
}

export type TargetInput = Omit<Target, 'id'> & { id?: string }

export type ProbeCheck = {
  ok: boolean
  detail?: string
  exit_code?: number
  status?: number
  model?: string
  credential?: string
  suite_id?: string
  task_id?: string
  output?: string
}

export type ProbeResult = {
  target_id: string
  kind: TargetKind
  ok: boolean
  checks: Record<string, ProbeCheck>
}

export type NodeCoverage = {
  tested: string[]
  untested: string[]
  labels: Record<string, string>
  ratio?: number
}

export type TaskSummary = {
  task_id: string
  scenario_id: string
  category: string
  severity: Severity
  business_flow: string
  attack_spec_id: string
  expected_decision: string
  business_impact: string
  success_criteria: string
  nodes: string[]
  clean_steps: number
  controlled_steps: number
  has_baseline_phase: boolean
}

export type ScriptStep = {
  user_id?: string
  role?: string
  message?: string
  [key: string]: unknown
}

export type TaskDetail = TaskSummary & {
  clean_script: ScriptStep[]
  controlled_script: ScriptStep[]
  gold: Record<string, unknown>
}

export type Suite = {
  suite_id: string
  dataset_id: string
  version: string
  description: string
  root: string
  task_count: number
  categories: Record<string, number>
  severities: Record<Severity, number>
  node_coverage: NodeCoverage
  supports_defense_delta: boolean
  tasks?: TaskSummary[]
}

export type RunTaskState = {
  task_id: string
  attempt: number
  status: TaskStatus
  seconds: number | null
}

export type RunSummary = {
  run_id: string
  target_id: string
  target_name: string
  suite_id: string
  dataset_id: string
  n_attempts: number
  max_concurrent: number
  command: string[]
  status: RunStatus
  suite_run_id: string
  total: number
  done: number
  exit_code: number | null
  created_at: number
  finished_at: number | null
  error: string
  tasks: Record<string, RunTaskState>
  counts: { PASS: number; FAIL: number; ERROR: number; running: number }
}

export type RunEvent = {
  seq: number
  at: number
  kind: 'launch' | 'log' | 'suite' | 'task' | 'suite_complete' | 'cancelled' | 'done' | 'result_document'
  command?: string[]
  text?: string
  suite_run_id?: string
  total?: number
  task_id?: string
  attempt?: number
  status?: string
  seconds?: number | null
  exit_code?: number | null
  done?: number
  size?: number
}

export type ReportMetrics = {
  asr: number
  dsr: number
  fpr: number
  critical_node_bypass_rate: number
  coverage_gap: number
  severity_penalty: number
  attack_case_count: number
  clean_case_count: number
  attack_success_count: number
  attack_blocked_count: number
  clean_blocked_count: number
  bypassed_critical_node_count: number
  critical_node_test_count: number
  critical_attack_bypass_count: number
  tested_node_count: number
  total_required_node_count: number
}

export type CategoryRow = {
  category: string
  cases: number
  succeeded: number
  asr: number
  clean_blocked: number
  nodes: string[]
}

export type DefenseDelta = {
  trials: number
  guarded_asr: number
  baseline_asr: number
  reduction: number
  non_discriminating: string[]
}

export type ForensicHitRow = {
  task_id: string
  oracle_verdict: string
  oracle_risk_score: number
  oracle_rules: string[]
  oracle_summary: string
}

export type Forensics = {
  trials: number
  independent_hits: number
  hit_rate: number
  rules: string[]
  self_report_only: string[]
  hit_rows: ForensicHitRow[]
}

export type CaseRow = {
  task_id: string
  status: TaskStatus
  category?: string
  severity?: Severity
  attack_succeeded?: boolean
  task_completed?: boolean
  valid?: boolean
  intercepted?: boolean
  leaked_strings?: string[]
  oracle_verdict?: string
  oracle_rules?: string[]
  nodes?: string[]
  attempt?: number
  [key: string]: unknown
}

export type PassRate = { value?: number; [key: string]: unknown }

export type Report = {
  schema: string
  run_id: string
  target_id: string
  target_name: string
  suite_id: string
  dataset_id: string
  dataset_version: string
  suite_run_id: string
  agent_label: string
  model_label: string
  actors?: unknown
  n_attempts: number
  scenario_count: number
  trial_count: number
  score: number
  risk_level: RiskLevel
  raw_score: number
  penalties: {
    asr: number
    fpr: number
    critical_node_bypass_rate: number
    coverage_gap: number
    severity: number
  }
  metrics: ReportMetrics
  node_coverage: NodeCoverage
  by_category: CategoryRow[]
  defense_delta: DefenseDelta | null
  forensics: Forensics | null
  cases: CaseRow[]
  ageval_metrics: Record<string, unknown> & {
    k_values?: (number | string)[]
    mean_score?: number
    pass_rate?: number
    pass_at_k?: Record<string, PassRate>
    pass_power_k?: Record<string, PassRate>
  }
}

export type ToolCall = {
  name: string
  arguments: unknown
  allowed: boolean
  reason: string
  risk_level: string
  result: unknown
}

export type UserMessage = { role: 'user'; index: number; actor: string; text: string }
export type AgentMessage = {
  role: 'agent'
  index: number
  text: string
  blocked: boolean
  risk_level: string
  tool_calls: ToolCall[]
}
export type Message = UserMessage | AgentMessage

export type Phase = {
  phase: 'clean' | 'controlled' | 'baseline' | 'trace'
  label: string
  defense_mode: 'guarded' | 'baseline' | 'n/a'
  error: string | null
  messages: Message[]
}

export type Replay = {
  run_id: string
  task_id: string
  attempt: number
  attempts_available: number[]
  verdict: { status: TaskStatus; score: number; metrics: Record<string, unknown> }
  phases: Phase[]
}

export type CustomSuiteInput = {
  suite_id: string
  task_id: string
  title: string
  description: string
  category: string
  severity: Severity
  nodes: string[]
  business_flow: string
  expected_decision: 'block' | 'allow' | 'warn' | 'review'
  clean_steps: ScriptStep[]
  controlled_steps: ScriptStep[]
  success_criteria: string[]
  business_impact: string
}

export type CompareRow = {
  run_id: string
  target_name: string
  suite_id: string
  dataset_id: string
  score: number
  risk_level: RiskLevel
  asr: number
  dsr: number
  fpr: number
  coverage_gap: number
  critical_node_bypass_rate: number
  severity_penalty: number
  trial_count: number
  baseline_asr: number | null
  defense_reduction: number | null
  forensic_hit_rate: number | null
}

export type AttackPathNode = {
  id: string
  label: string
  covered: boolean
  status: 'PASS' | 'FAIL' | 'ERROR' | 'running' | 'pending' | 'uncovered'
}

export type AttackPathEdge = {
  source: string
  target: string
  count: number
}

export type AttackPathTask = {
  task_id: string
  attempts: RunTaskState[]
  status: TaskStatus | 'pending'
  category: string
  severity: Severity
  nodes: string[]
  expected_decision: string
  has_replay: boolean
  has_report_case: boolean
}

export type AttackPathEvent = {
  seq: number
  kind: string
  task_id?: string
  attempt?: number
  status?: string
  at?: number
}

export type AttackPath = {
  run_id: string
  suite_id: string
  target_id: string
  target_name: string
  status: RunStatus
  ready: boolean
  summary_ready: boolean
  report_ready: boolean
  nodes: AttackPathNode[]
  edges: AttackPathEdge[]
  tasks: AttackPathTask[]
  events: AttackPathEvent[]
}
