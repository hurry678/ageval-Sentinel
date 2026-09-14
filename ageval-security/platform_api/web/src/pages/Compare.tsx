import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { ArrowLeft, GitCompareArrows } from 'lucide-react'
import { api } from '../api'
import { useLoad } from '../hooks'
import { datetime, num, percent } from '../format'
import { AsyncState, Card, Empty, MetricBar, PageHeader, RiskBadge, StatusBadge } from '../components/ui'
import type { CompareRow } from '../types'

type Axis = {
  key: keyof CompareRow
  label: string
  kind: 'percent' | 'score' | 'raw'
  max: number
  good?: boolean
}

const AXES: Axis[] = [
  { key: 'score', label: '综合评分 / 100', kind: 'score', max: 100, good: true },
  { key: 'asr', label: 'ASR 攻击成功率', kind: 'percent', max: 1 },
  { key: 'dsr', label: 'DSR 防御成功率', kind: 'percent', max: 1, good: true },
  { key: 'fpr', label: 'FPR 误拦率', kind: 'percent', max: 1 },
  { key: 'critical_node_bypass_rate', label: '关键节点绕过率', kind: 'percent', max: 1 },
  { key: 'coverage_gap', label: '覆盖缺口', kind: 'percent', max: 1 },
  { key: 'severity_penalty', label: '严重度扣分 / 10', kind: 'raw', max: 10 },
  { key: 'forensic_hit_rate', label: '取证命中率', kind: 'percent', max: 1, good: true },
]

const value = (row: CompareRow, axis: Axis) => Number(row[axis.key] ?? 0)

const display = (row: CompareRow, axis: Axis) => {
  const raw = row[axis.key]
  if (raw === null || raw === undefined) return '—'
  return axis.kind === 'percent' ? percent(Number(raw)) : num(Number(raw), axis.kind === 'score' ? 1 : 2)
}

export default function Compare() {
  const navigate = useNavigate()
  const [search, setSearch] = useSearchParams()
  const runIds = (search.get('runs') ?? '').split(',').map((id) => id.trim()).filter(Boolean)
  const allRuns = useLoad(api.listRuns)
  const { data, loading, error } = useLoad(
    () => (runIds.length ? api.compare(runIds) : Promise.resolve({ rows: [], count: 0 })),
    [runIds.join(',')],
  )
  const rows = data?.rows ?? []
  const completedRuns = (allRuns.data?.runs ?? []).filter((run) => run.status === 'completed')

  function toggleRun(runId: string) {
    const next = runIds.includes(runId) ? runIds.filter((id) => id !== runId) : [...runIds, runId]
    setSearch(next.length ? { runs: next.join(',') } : {})
  }

  return (
    <>
      <PageHeader
        eyebrow="Compare"
        title="横向对比"
        description="对比多次检测运行的评分与关键指标。指标含义一致时，越低越好的项以红色条呈现。"
        actions={
          <>
            <Link className="button ghost" to="/runs"><ArrowLeft size={15} />运行历史</Link>
            {runIds.length >= 2 && (
              <button type="button" className="button primary" onClick={() => navigate(`/compare?runs=${runIds.join(',')}`)}>
                <GitCompareArrows size={15} />对比（{runIds.length}）
              </button>
            )}
          </>
        }
      />

      <Card
        title="选择对比运行"
        subtitle={`已完成 ${completedRuns.length} 次，勾选 2 个以上后图表自动更新`}
      >
        <AsyncState loading={allRuns.loading} error={allRuns.error} empty={!completedRuns.length} emptyText="还没有已完成的运行">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 38 }} />
                  <th>运行 ID</th><th>目标</th><th>套件</th><th>状态</th><th>结果</th><th>创建时间</th>
                </tr>
              </thead>
              <tbody>
                {completedRuns.map((run) => (
                  <tr
                    key={run.run_id}
                    className={`clickable ${runIds.includes(run.run_id) ? 'row-selected' : ''}`}
                    onClick={() => toggleRun(run.run_id)}
                  >
                    <td>
                      <input
                        type="checkbox"
                        readOnly
                        aria-label={`选择 ${run.run_id}`}
                        checked={runIds.includes(run.run_id)}
                      />
                    </td>
                    <td className="mono-id">{run.run_id}</td>
                    <td>{run.target_name || run.target_id}</td>
                    <td className="mono">{run.suite_id}</td>
                    <td><StatusBadge status={run.status} /></td>
                    <td className="mono">
                      <span style={{ color: 'var(--success)' }}>{run.counts?.PASS ?? 0}</span>
                      {' / '}
                      <span style={{ color: 'var(--danger)' }}>{run.counts?.FAIL ?? 0}</span>
                    </td>
                    <td className="mono">{datetime(run.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </AsyncState>
      </Card>

      {runIds.length < 2 ? (
        <Card><Empty text={runIds.length === 1 ? '再勾选一个运行后即可对比' : '请在上方勾选两个或以上运行'} /></Card>
      ) : (
        <AsyncState loading={loading} error={error} empty={!rows.length} emptyText="没有可对比的报告">
          <>
            <Card title="指标总表" subtitle={`${rows.length} 个运行`}>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>运行</th><th>目标</th><th>套件</th><th>风险</th>
                      <th className="mono">评分</th><th className="mono">ASR</th><th className="mono">DSR</th>
                      <th className="mono">FPR</th><th className="mono">关键绕过</th><th className="mono">覆盖缺口</th>
                      <th className="mono">严重度</th><th className="mono">试次</th>
                      <th className="mono">基线 ASR</th><th className="mono">防御下降</th><th className="mono">取证命中</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <tr key={row.run_id}>
                        <td><Link className="mono-id" to={`/runs/${row.run_id}`}>{row.run_id}</Link></td>
                        <td>{row.target_name || '—'}</td>
                        <td className="mono">{row.suite_id}</td>
                        <td><RiskBadge level={row.risk_level} /></td>
                        <td className="mono">{num(row.score, 1)}</td>
                        <td className="mono">{percent(row.asr)}</td>
                        <td className="mono">{percent(row.dsr)}</td>
                        <td className="mono">{percent(row.fpr)}</td>
                        <td className="mono">{percent(row.critical_node_bypass_rate)}</td>
                        <td className="mono">{percent(row.coverage_gap)}</td>
                        <td className="mono">{num(row.severity_penalty, 2)}</td>
                        <td className="mono">{row.trial_count}</td>
                        <td className="mono">{row.baseline_asr === null ? '—' : percent(row.baseline_asr)}</td>
                        <td className="mono">{row.defense_reduction === null ? '—' : percent(row.defense_reduction)}</td>
                        <td className="mono">{row.forensic_hit_rate === null ? '—' : percent(row.forensic_hit_rate)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>

            <div className="grid cols-2">
              {AXES.map((axis) => (
                <Card key={String(axis.key)} title={axis.label}>
                  <div className="grid" style={{ gap: 'var(--space-4)' }}>
                    {rows.map((row) => (
                      <MetricBar
                        key={row.run_id}
                        label={<span className="mono">{row.target_name || row.run_id}</span>}
                        value={value(row, axis) / axis.max}
                        display={display(row, axis)}
                        tone={axis.good ? 'good' : value(row, axis) / axis.max > 0.5 ? 'bad' : 'warn'}
                      />
                    ))}
                  </div>
                </Card>
              ))}
            </div>
          </>
        </AsyncState>
      )}
    </>
  )
}
