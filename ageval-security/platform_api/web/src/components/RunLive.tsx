import { useEffect, useRef, useState } from 'react'
import { Ban } from 'lucide-react'
import { Link } from 'react-router-dom'
import { api, errorMessage } from '../api'
import { datetime, duration, num } from '../format'
import { Card, Empty, ErrorNote, Stat } from './ui'
import type { RunEvent, RunSummary } from '../types'

function eventLine(event: RunEvent) {
  switch (event.kind) {
    case 'launch': return `$ ${(event.command ?? []).join(' ')}`
    case 'log': return event.text ?? ''
    case 'suite': return `套件启动 ${event.suite_run_id ?? ''}，共 ${event.total ?? 0} 个场景`
    case 'task': return `[${event.status}] ${event.task_id}#${event.attempt} ${num(event.seconds, 1)}s`
    case 'suite_complete': return `套件结束 exit=${event.exit_code}, done=${event.done}`
    case 'cancelled': return '运行已取消'
    case 'done': return `运行结束：${event.status} exit=${event.exit_code}`
    case 'result_document': return `结果文档已生成（${event.size ?? 0} 字节）`
    default: return JSON.stringify(event)
  }
}

export default function RunLive({ run, events, onRefresh }: {
  run: RunSummary
  events: RunEvent[]
  onRefresh: () => void
}) {
  const terminalRef = useRef<HTMLDivElement>(null)
  const [error, setError] = useState('')
  const tasks = Object.values(run.tasks ?? {})
  const active = run.status === 'running' || run.status === 'starting'
  const progress = run.total ? Math.round((run.done / run.total) * 100) : 0

  useEffect(() => {
    const node = terminalRef.current
    if (node) node.scrollTop = node.scrollHeight
  }, [events.length])

  async function cancel() {
    setError('')
    try {
      await api.cancelRun(run.run_id)
      onRefresh()
    } catch (reason) {
      setError(errorMessage(reason))
    }
  }

  return (
    <>
      <div className="grid cols-4" style={{ marginBottom: 'var(--space-5)' }}>
        <Stat label="进度" value={`${run.done}/${run.total || '?'}`} note={`${progress}%`} />
        <Stat label="通过 / 失败 / 异常" value={`${run.counts?.PASS ?? 0} / ${run.counts?.FAIL ?? 0} / ${run.counts?.ERROR ?? 0}`} note={`执行中 ${run.counts?.running ?? 0}`} />
        <Stat label="耗时" value={duration(run.created_at, run.finished_at)} note={datetime(run.created_at)} />
        <Stat label="采样 / 并发" value={`k=${run.n_attempts} / ${run.max_concurrent}`} note={run.suite_run_id || '等待套件启动'} />
      </div>

      {error && <div style={{ marginBottom: 'var(--space-4)' }}><ErrorNote text={error} /></div>}
      {run.error && <div style={{ marginBottom: 'var(--space-4)' }}><ErrorNote text={run.error} /></div>}

      <Card
        title="场景执行状态"
        subtitle={`${tasks.length} 个试次`}
        action={active && (
          <button type="button" className="button danger small" onClick={cancel}><Ban size={13} />取消运行</button>
        )}
      >
        <div className="progress-track" style={{ marginBottom: 'var(--space-4)' }}>
          <i style={{ width: `${progress}%` }} />
        </div>
        {!tasks.length ? <Empty text="尚未收到场景事件" /> : (
          <div className="task-grid">
            {tasks.map((task) => (
              <div key={`${task.task_id}#${task.attempt}`} className={`task-cell s-${task.status.toLowerCase()}`}>
                <strong title={task.task_id}>
                  {task.status !== 'running'
                    ? <Link to={`/runs/${run.run_id}/replay/${task.task_id}?attempt=${task.attempt}`}>{task.task_id}</Link>
                    : task.task_id}
                </strong>
                <span>#{task.attempt} · {task.status} · {num(task.seconds, 1)}s</span>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title="执行日志" subtitle="SSE 实时推流">
        <div className="terminal" ref={terminalRef}>
          {!events.length && <div><em>{active ? '等待事件…' : '该运行已结束，历史日志见报告与结果文档。'}</em></div>}
          {events.map((event) => (
            <div key={event.seq} className={`k-${event.kind}`}>
              <em>{new Date(event.at * 1000).toLocaleTimeString('zh-CN', { hour12: false })} </em>
              {eventLine(event)}
            </div>
          ))}
        </div>
        <pre className="code" style={{ marginTop: 'var(--space-4)' }}>{(run.command ?? []).join(' ') || '—'}</pre>
      </Card>
    </>
  )
}
