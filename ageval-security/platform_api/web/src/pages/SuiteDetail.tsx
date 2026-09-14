import { Fragment, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, ChevronDown, ChevronRight } from 'lucide-react'
import { api } from '../api'
import { useLoad } from '../hooks'
import { percent, pretty } from '../format'
import {
  AsyncState, Card, Empty, ErrorNote, Loading, NodeCoverageDots, PageHeader, SeverityDot, SeverityStrip,
} from '../components/ui'
import { SuiteCoverageGraph } from '../components/PathGraphs'
import type { ScriptStep, TaskSummary } from '../types'

function StepList({
  steps, label, contrast,
}: { steps: ScriptStep[]; label: string; contrast?: ScriptStep[] }) {
  if (!steps.length) {
    return (
      <div>
        <p className="muted" style={{ margin: '0 0 6px' }}>{label}</p>
        <Empty text="该场景由单条指令驱动，没有分步脚本" />
      </div>
    )
  }
  return (
    <div>
      <p className="muted" style={{ margin: '0 0 6px' }}>{label}（{steps.length} 步）</p>
      <ol className="step-list">
        {steps.map((step, index) => {
          // The one step that differs from the clean run *is* the attack.
          const injected = contrast ? contrast[index]?.message !== step.message : false
          return (
            <li key={index} className={injected ? 'injected' : undefined}>
              <div className="row" style={{ gap: 6 }}>
                <span className="tag mono">#{index + 1}</span>
                {step.role && <span className="tag">{step.role}</span>}
                {step.user_id && <span className="mono-id">{step.user_id}</span>}
                {injected && <span className="badge status-failed">攻击注入</span>}
              </div>
              <p>{step.message || pretty(step)}</p>
            </li>
          )
        })}
      </ol>
    </div>
  )
}

function GoldView({ gold }: { gold: Record<string, unknown> }) {
  const entries = Object.entries(gold ?? {})
  if (!entries.length) return <Empty text="无 gold 判据" />
  return (
    <dl className="kv">
      {entries.map(([key, value]) => (
        <div key={key}>
          <dt className="mono">{key}</dt>
          <dd>
            {Array.isArray(value)
              ? value.map((item, index) => <div key={index}>{typeof item === 'string' ? item : pretty(item)}</div>)
              : typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
                ? String(value)
                : <pre className="code" style={{ margin: 0 }}>{pretty(value)}</pre>}
          </dd>
        </div>
      ))}
    </dl>
  )
}

function TaskDetailPanel({ suiteId, taskId }: { suiteId: string; taskId: string }) {
  const { data, loading, error } = useLoad(() => api.getTask(suiteId, taskId), [suiteId, taskId])
  if (loading) return <Loading text="加载场景脚本…" />
  if (error) return <ErrorNote text={error} />
  if (!data) return null
  const clean = Array.isArray(data.clean_script) ? data.clean_script : []
  const controlled = Array.isArray(data.controlled_script) ? data.controlled_script : []
  return (
    <div className="detail-panel">
      <dl className="kv">
        <div><dt>业务流程</dt><dd>{data.business_flow || '—'}</dd></div>
        <div><dt>攻击规格</dt><dd className="mono">{data.attack_spec_id || '—'}</dd></div>
        <div><dt>期望决策</dt><dd>{data.expected_decision || '—'}</dd></div>
        <div><dt>业务影响</dt><dd>{data.business_impact || '—'}</dd></div>
        <div><dt>判定标准</dt><dd>{data.success_criteria || '—'}</dd></div>
        <div><dt>基线相位</dt><dd>{data.has_baseline_phase ? '有' : '无'}</dd></div>
      </dl>
      <div className="grid cols-3">
        <StepList steps={clean} label="clean 脚本（正常业务）" />
        <StepList steps={controlled} label="controlled 脚本（受控攻击）" contrast={clean} />
        <div>
          <p className="muted" style={{ margin: '0 0 6px' }}>gold 判据</p>
          <GoldView gold={data.gold} />
        </div>
      </div>
    </div>
  )
}

export default function SuiteDetail() {
  const { suiteId = '' } = useParams()
  const { data, loading, error } = useLoad(() => api.getSuite(suiteId), [suiteId])
  const [openTask, setOpenTask] = useState('')
  const tasks: TaskSummary[] = data?.tasks ?? []

  return (
    <>
      <PageHeader
        eyebrow="Suite"
        title={data?.suite_id || suiteId}
        description={data?.description || '套件场景明细，点击任意行展开 clean / controlled 脚本与 gold 判据。'}
        actions={<Link className="button ghost" to="/suites"><ArrowLeft size={15} />返回套件列表</Link>}
      />
      <AsyncState loading={loading} error={error} empty={!data} emptyText="套件不存在">
        <>
          <Card title="套件覆盖路径" subtitle="按 N1-N8 Agent 攻击面展示该套件覆盖结构" className="suite-graph-card">
            <SuiteCoverageGraph coverage={data?.node_coverage} />
          </Card>

          <div className="grid cols-3" style={{ marginBottom: 'var(--space-5)' }}>
            <Card title="基本信息">
              <dl className="kv">
                <div><dt>数据集</dt><dd className="mono">{data?.dataset_id || '—'}</dd></div>
                <div><dt>版本</dt><dd className="mono">{data?.version || '—'}</dd></div>
                <div><dt>场景数</dt><dd className="mono">{data?.task_count ?? 0}</dd></div>
                <div><dt>防御增益</dt><dd>{data?.supports_defense_delta ? '支持' : '不支持'}</dd></div>
                <div><dt>数据根目录</dt><dd className="mono-id">{data?.root || '—'}</dd></div>
              </dl>
            </Card>
            <Card title="严重度分布"><SeverityStrip severities={data?.severities} /></Card>
            <Card title={`节点覆盖 ${percent(data?.node_coverage?.ratio ?? 0, 0)}`}>
              <NodeCoverageDots coverage={data?.node_coverage} />
            </Card>
          </div>

          <Card title="场景列表" subtitle={`${tasks.length} 个场景`}>
            {!tasks.length ? <p className="muted">该套件没有场景。</p> : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th style={{ width: 34 }} />
                      <th>场景 ID</th><th>攻击面</th><th>严重度</th><th>节点</th><th>期望决策</th><th>步数</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tasks.map((task) => {
                      const open = openTask === task.task_id
                      return (
                        <Fragment key={task.task_id}>
                          <tr
                            className="clickable"
                            onClick={() => setOpenTask(open ? '' : task.task_id)}
                          >
                            <td>{open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}</td>
                            <td className="mono">{task.task_id}</td>
                            <td>{task.category || '—'}</td>
                            <td><SeverityDot severity={task.severity} /></td>
                            <td>
                              <div className="row" style={{ gap: 4 }}>
                                {(task.nodes ?? []).map((node) => <span key={node} className="tag">{node}</span>)}
                              </div>
                            </td>
                            <td>{task.expected_decision || '—'}</td>
                            <td className="mono">{task.clean_steps}/{task.controlled_steps}</td>
                          </tr>
                          {open && (
                            <tr>
                              <td colSpan={7}><TaskDetailPanel suiteId={suiteId} taskId={task.task_id} /></td>
                            </tr>
                          )}
                        </Fragment>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      </AsyncState>
    </>
  )
}
