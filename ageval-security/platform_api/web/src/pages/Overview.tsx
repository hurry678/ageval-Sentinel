import { useEffect } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, Plus } from 'lucide-react'
import { api } from '../api'
import { useLoad } from '../hooks'
import { isTerminal } from '../useRunStream'
import { datetime, duration, percent } from '../format'
import {
  AsyncState, Card, NodeCoverageDots, PageHeader, SeverityDonut, Stat, StatusBadge,
} from '../components/ui'
import type { NodeCoverage, RunSummary, Severity, Suite } from '../types'

const POLL_INTERVAL = 2000

function mergeCoverage(coverages: NodeCoverage[]): NodeCoverage {
  const tested = new Set<string>()
  const all = new Set<string>()
  const labels: Record<string, string> = {}
  for (const coverage of coverages) {
    coverage.tested?.forEach((node) => { tested.add(node); all.add(node) })
    coverage.untested?.forEach((node) => all.add(node))
    Object.assign(labels, coverage.labels ?? {})
  }
  return {
    tested: [...tested],
    untested: [...all].filter((node) => !tested.has(node)),
    labels,
    ratio: all.size ? tested.size / all.size : 0,
  }
}

const FINDING_LIMIT = 6

function mergeSeverities(suites: Suite[]): Record<Severity, number> {
  const merged: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 }
  for (const suite of suites) {
    for (const key of Object.keys(merged) as Severity[]) {
      merged[key] += suite.severities?.[key] ?? 0
    }
  }
  return merged
}

function recentFindings(runs: RunSummary[]) {
  return runs
    .flatMap((run) => Object.values(run.tasks)
      .filter((task) => task.status === 'FAIL' || task.status === 'ERROR')
      .map((task) => ({ run, task })))
    .slice(0, FINDING_LIMIT)
}

export default function Overview() {
  const health = useLoad(api.health)
  const targets = useLoad(api.listTargets)
  const suites = useLoad(api.listSuites)
  const runs = useLoad(api.listRuns)

  const suiteList = suites.data?.suites ?? []
  const runList = runs.data?.runs ?? []
  const coverage = mergeCoverage(suiteList.map((suite) => suite.node_coverage).filter(Boolean))
  const nodeLabels = health.data?.pipeline_nodes ?? {}
  const queuedRuns = runList.filter((run) => !isTerminal(run.status))
  const activeRuns = queuedRuns.length
  const severities = mergeSeverities(suiteList)
  const findings = recentFindings(runList)

  useEffect(() => {
    if (!activeRuns) return
    let alive = true
    const timer = window.setInterval(() => {
      api.listRuns().then((result) => { if (alive) runs.setData(result) }).catch(() => {})
    }, POLL_INTERVAL)
    return () => { alive = false; window.clearInterval(timer) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeRuns])

  return (
    <>
      <PageHeader
        eyebrow="Overview"
        title="通用 Agent 检测总览"
        description="面向任意 Agent 的攻击面检测平台：注册目标、执行检测套件、生成可复现的安全评分报告。"
        actions={<Link className="button primary" to="/runs/new"><Plus size={15} />发起检测</Link>}
      />

      <div className="grid cols-4" style={{ marginBottom: 'var(--space-5)' }}>
        <Stat label="平台版本" value={health.data?.version ?? '—'} note={health.error || (health.data?.ok ? '服务在线' : '检查中')} />
        <Stat label="检测目标" value={targets.data?.targets.length ?? 0} note={`支持类型：${(health.data?.target_kinds ?? []).join(' / ') || '—'}`} />
        <Stat label="测试套件" value={suiteList.length} note={`共 ${suiteList.reduce((sum, suite) => sum + suite.task_count, 0)} 个场景`} />
        <Stat label="运行记录" value={runList.length} note={`进行中 ${activeRuns}`} />
      </div>

      <div className="dashboard-grid">
        <div className="dashboard-main">
          <Card title="场景严重度分布" subtitle="按全部测试套件的场景严重度合并统计">
            <AsyncState loading={suites.loading} error={suites.error} empty={!suiteList.length} emptyText="还没有测试套件">
              <SeverityDonut severities={severities} />
            </AsyncState>
          </Card>

          <Card title="最近运行" subtitle="点击进入运行详情" action={<Link className="button ghost small" to="/runs">全部<ArrowRight size={13} /></Link>}>
            <AsyncState loading={runs.loading} error={runs.error} empty={!runList.length} emptyText="还没有检测记录">
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr><th>运行</th><th>目标</th><th>状态</th><th>进度</th><th>耗时</th></tr>
                  </thead>
                  <tbody>
                    {runList.slice(0, 5).map((run) => (
                      <tr key={run.run_id}>
                        <td>
                          <Link to={`/runs/${run.run_id}`} className="mono-id">{run.run_id}</Link>
                          <div className="muted" style={{ fontSize: 11 }}>{datetime(run.created_at)}</div>
                        </td>
                        <td>{run.target_name || run.target_id}</td>
                        <td><StatusBadge status={run.status} /></td>
                        <td className="mono">{run.done}/{run.total || '?'}</td>
                        <td className="mono">{duration(run.created_at, run.finished_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </AsyncState>
          </Card>

          <Card title="N1–N8 攻击面覆盖" subtitle={`全部套件合并覆盖率 ${percent(coverage.ratio)}`}>
            <NodeCoverageDots coverage={{ ...coverage, labels: { ...nodeLabels, ...coverage.labels } }} />
            <dl className="kv" style={{ marginTop: 'var(--space-4)' }}>
              {Object.entries(nodeLabels).map(([node, label]) => (
                <div key={node}>
                  <dt className="mono">{node}</dt>
                  <dd>{label}{coverage.tested.includes(node) ? '' : '（未被任何套件覆盖）'}</dd>
                </div>
              ))}
            </dl>
          </Card>
        </div>

        <aside className="dashboard-rail" aria-label="运行动态">
          <Card title="运行队列" subtitle="进行中的检测任务">
            <AsyncState loading={runs.loading} error={runs.error} empty={!queuedRuns.length} emptyText="当前没有进行中的检测">
              <ul className="rail-list">
                {queuedRuns.map((run) => (
                  <li key={run.run_id}>
                    <div className="row">
                      <Link to={`/runs/${run.run_id}`} className="mono-id">{run.run_id}</Link>
                      <StatusBadge status={run.status} />
                    </div>
                    <span className="muted" style={{ fontSize: 11 }}>
                      {run.target_name || run.target_id} · {run.done}/{run.total || '?'}
                    </span>
                  </li>
                ))}
              </ul>
            </AsyncState>
          </Card>

          <Card title="最近发现" subtitle="最近运行中未通过或异常的用例">
            <AsyncState loading={runs.loading} error={runs.error} empty={!findings.length} emptyText="最近的运行中没有失败或异常用例">
              <ul className="rail-list">
                {findings.map(({ run, task }) => (
                  <li key={`${run.run_id}-${task.task_id}-${task.attempt}`}>
                    <div className="row">
                      <span className="mono-id">{task.task_id}</span>
                      <StatusBadge status={task.status} />
                    </div>
                    <Link to={`/runs/${run.run_id}/replay/${task.task_id}`} className="muted" style={{ fontSize: 11 }}>
                      查看回放 · {run.target_name || run.target_id}
                    </Link>
                  </li>
                ))}
              </ul>
            </AsyncState>
          </Card>
        </aside>
      </div>
    </>
  )
}
