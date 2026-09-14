import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { GitCompareArrows, RefreshCw } from 'lucide-react'
import { api } from '../api'
import { useLoad } from '../hooks'
import { isTerminal } from '../useRunStream'
import { datetime, duration } from '../format'
import { AsyncState, Card, PageHeader, StatusBadge } from '../components/ui'

const POLL_INTERVAL = 2000

export default function Runs() {
  const navigate = useNavigate()
  const runs = useLoad(api.listRuns)
  const [selected, setSelected] = useState<string[]>([])
  const list = runs.data?.runs ?? []
  const live = list.filter((run) => !isTerminal(run.status)).length

  // Refresh through setData rather than reload: reload flips `loading`, which
  // would blink the whole table away every two seconds.
  useEffect(() => {
    if (!live) return
    let alive = true
    const timer = window.setInterval(() => {
      api.listRuns().then((result) => { if (alive) runs.setData(result) }).catch(() => {})
    }, POLL_INTERVAL)
    return () => { alive = false; window.clearInterval(timer) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live])

  const toggle = (runId: string) =>
    setSelected((prev) => (prev.includes(runId) ? prev.filter((id) => id !== runId) : [...prev, runId]))

  return (
    <>
      <PageHeader
        eyebrow="Runs"
        title="运行历史"
        description="勾选两个或以上已完成的运行，可进入横向对比查看评分与指标差异。"
        actions={
          <>
            <button type="button" className="button ghost" onClick={runs.reload}><RefreshCw size={15} />刷新</button>
            <button
              type="button"
              className="button primary"
              disabled={selected.length < 2}
              onClick={() => navigate(`/compare?runs=${selected.join(',')}`)}
            >
              <GitCompareArrows size={15} />对比（{selected.length}）
            </button>
          </>
        }
      />
      <Card
        title={`共 ${list.length} 次运行`}
        subtitle={live ? `按创建时间倒序 · ${live} 个运行中，每 2 秒自动刷新` : '按创建时间倒序'}
      >
        <AsyncState loading={runs.loading} error={runs.error} empty={!list.length} emptyText="还没有检测记录">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 38 }} />
                  <th>运行 ID</th><th>目标</th><th>套件</th><th>状态</th>
                  <th>进度</th><th>结果</th><th>耗时</th><th>创建时间</th>
                </tr>
              </thead>
              <tbody>
                {list.map((run) => (
                  <tr key={run.run_id}>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`选择 ${run.run_id}`}
                        checked={selected.includes(run.run_id)}
                        onChange={() => toggle(run.run_id)}
                      />
                    </td>
                    <td><Link className="mono-id" to={`/runs/${run.run_id}`}>{run.run_id}</Link></td>
                    <td>{run.target_name || run.target_id}</td>
                    <td className="mono">{run.suite_id}</td>
                    <td><StatusBadge status={run.status} /></td>
                    <td className="mono">{run.done}/{run.total || '?'}</td>
                    <td className="mono">
                      <span style={{ color: 'var(--success)' }}>{run.counts?.PASS ?? 0}</span>
                      {' / '}
                      <span style={{ color: 'var(--danger)' }}>{run.counts?.FAIL ?? 0}</span>
                      {' / '}
                      <span style={{ color: 'var(--warning)' }}>{run.counts?.ERROR ?? 0}</span>
                    </td>
                    <td className="mono">{duration(run.created_at, run.finished_at)}</td>
                    <td className="mono">{datetime(run.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </AsyncState>
      </Card>
    </>
  )
}
