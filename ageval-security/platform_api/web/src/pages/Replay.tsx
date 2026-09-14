import { useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { ArrowLeft, Bot, ShieldAlert, User, Wrench } from 'lucide-react'
import { api } from '../api'
import { useLoad } from '../hooks'
import { num, pretty } from '../format'
import { AsyncState, Card, Empty, PageHeader, StatusBadge, Tabs } from '../components/ui'
import type { AgentMessage, Message, ToolCall } from '../types'

function ToolCallCard({ call }: { call: ToolCall }) {
  return (
    <div className={`tool-card ${call.allowed ? 'allowed' : 'denied'}`}>
      <header>
        <Wrench size={13} />
        <strong>{call.name}</strong>
        <span className={`badge ${call.allowed ? 'risk-low' : 'status-failed'}`}>
          {call.allowed ? '已放行' : '已拦截'}
        </span>
        {call.risk_level && <span className="tag">risk: {call.risk_level}</span>}
      </header>
      {call.reason && <p>{call.reason}</p>}
      <pre>{pretty(call.arguments)}</pre>
      {call.result !== undefined && call.result !== null && (
        <pre style={{ color: 'var(--text-secondary)' }}>结果：{pretty(call.result)}</pre>
      )}
    </div>
  )
}

function AgentBubble({ message }: { message: AgentMessage }) {
  return (
    <div className="bubble-row agent">
      <div className={`bubble agent ${message.blocked ? 'blocked' : ''}`}>
        <div className="bubble-meta">
          <Bot size={12} />
          <span>AGENT #{message.index}</span>
          {message.blocked && <span className="badge status-failed"><ShieldAlert size={11} />已阻断</span>}
          {message.risk_level && <span className="badge">risk: {message.risk_level}</span>}
        </div>
        {message.text && <p className="bubble-text">{message.text}</p>}
        {(message.tool_calls ?? []).map((call, index) => (
          <ToolCallCard key={`${call.name}-${index}`} call={call} />
        ))}
      </div>
    </div>
  )
}

function Bubble({ message }: { message: Message }) {
  if (message.role === 'user') {
    return (
      <div className="bubble-row user">
        <div className="bubble user">
          <div className="bubble-meta"><User size={12} /><span>{message.actor || 'USER'} #{message.index}</span></div>
          <p className="bubble-text">{message.text}</p>
        </div>
      </div>
    )
  }
  return <AgentBubble message={message} />
}

export default function ReplayPage() {
  const { runId = '', taskId = '' } = useParams()
  const [search, setSearch] = useSearchParams()
  const attempt = Number(search.get('attempt') ?? 0) || 0
  const { data, loading, error } = useLoad(() => api.getReplay(runId, taskId, attempt), [runId, taskId, attempt])
  const [phaseKey, setPhaseKey] = useState('')

  const phases = data?.phases ?? []
  const active = phases.find((phase) => phase.phase === phaseKey) ?? phases[0]
  const shape = phases.some((phase) => phase.phase === 'controlled')
    ? '三相对话回放（clean 正常业务 / controlled 受控攻击 / baseline 无防护基线）'
    : '单轨迹回放（黑盒目标只有一条真实执行轨迹，无防护开关对照）'

  return (
    <>
      <PageHeader
        eyebrow="Replay"
        title={<span className="mono">{taskId}</span>}
        description={`运行 ${runId} · 第 ${attempt} 次采样 · ${shape}`}
        actions={
          <>
            {data && <StatusBadge status={data.verdict?.status ?? 'running'} />}
            <Link className="button ghost" to={`/runs/${runId}`}><ArrowLeft size={15} />返回运行</Link>
          </>
        }
      />
      <AsyncState loading={loading} error={error} empty={!data} emptyText="没有该场景的回放产物">
        {data && (
          <>
            <Card title="判定结果">
              <div className="row" style={{ justifyContent: 'space-between' }}>
                <div className="row">
                  <span className="tag">score {num(data.verdict?.score, 3)}</span>
                  {(data.attempts_available ?? []).map((value) => (
                    <button
                      key={value}
                      type="button"
                      className={`button small ${value === attempt ? 'primary' : 'ghost'}`}
                      onClick={() => setSearch({ attempt: String(value) })}
                    >
                      采样 #{value}
                    </button>
                  ))}
                </div>
                {phases.length > 1 && (
                  <Tabs
                    active={active?.phase ?? ''}
                    onChange={setPhaseKey}
                    tabs={phases.map((phase) => ({ key: phase.phase, label: phase.label || phase.phase }))}
                  />
                )}
              </div>
              <pre className="code" style={{ marginTop: 'var(--space-4)' }}>{pretty(data.verdict?.metrics)}</pre>
            </Card>

            <Card
              title={active?.label || '对话回放'}
              subtitle={active ? `相位 ${active.phase} · 防护模式 ${active.defense_mode}` : undefined}
            >
              {active?.error && <div className="error-note" style={{ marginBottom: 'var(--space-4)' }}>{active.error}</div>}
              {!active?.messages?.length ? <Empty text="该相位没有消息记录" /> : (
                <div className="chat">
                  {active.messages.map((message, index) => (
                    <Bubble key={`${message.role}-${message.index}-${index}`} message={message} />
                  ))}
                </div>
              )}
            </Card>
          </>
        )}
      </AsyncState>
    </>
  )
}
