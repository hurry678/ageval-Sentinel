import type { ReactNode } from 'react'
import { AlertTriangle, Inbox } from 'lucide-react'
import { RISK_LABELS, RUN_STATUS_LABELS, SEVERITY_LABELS, percent } from '../format'
import type { NodeCoverage, RiskLevel, Severity } from '../types'

export function Card({ title, subtitle, action, children, className = '' }: {
  title?: ReactNode
  subtitle?: ReactNode
  action?: ReactNode
  children?: ReactNode
  className?: string
}) {
  return (
    <section className={`card ${className}`}>
      {(title || action) && (
        <header className="card-head">
          <div>
            {title && <h2>{title}</h2>}
            {subtitle && <p>{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      {children}
    </section>
  )
}

export function Loading({ text = '加载中…' }: { text?: string }) {
  return <div className="state"><span className="spinner" />{text}</div>
}

export function Empty({ text = '暂无数据', children }: { text?: string; children?: ReactNode }) {
  return (
    <div className="state empty">
      <Inbox size={22} />
      <p>{text}</p>
      {children}
    </div>
  )
}

export function ErrorNote({ text }: { text: string }) {
  return <div className="error-note"><AlertTriangle size={16} />{text}</div>
}

export function AsyncState({ loading, error, empty, emptyText, children }: {
  loading?: boolean
  error?: string
  empty?: boolean
  emptyText?: string
  children: ReactNode
}) {
  if (loading) return <Loading />
  if (error) return <ErrorNote text={error} />
  if (empty) return <Empty text={emptyText} />
  return <>{children}</>
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`badge status-${status.toLowerCase()}`}>
      {RUN_STATUS_LABELS[status] ?? status}
    </span>
  )
}

export function RiskBadge({ level }: { level: RiskLevel | string }) {
  return <span className={`badge risk-${level}`}>{RISK_LABELS[level] ?? level}</span>
}

export function SeverityDot({ severity }: { severity: Severity | string }) {
  return (
    <span className="severity">
      <i className={`dot sev-${severity}`} />
      {SEVERITY_LABELS[severity] ?? severity}
    </span>
  )
}

export function MetricBar({ label, value, display, tone = 'primary' }: {
  label: ReactNode
  value: number
  display?: string
  tone?: 'primary' | 'good' | 'warn' | 'bad'
}) {
  const width = Math.max(0, Math.min(100, value * 100))
  return (
    <div className="metric-bar">
      <label><span>{label}</span><strong>{display ?? percent(value)}</strong></label>
      <i><b className={`bar-${tone}`} style={{ width: `${width}%` }} /></i>
    </div>
  )
}

export function NodeCoverageDots({ coverage }: { coverage?: NodeCoverage | null }) {
  const tested = new Set(coverage?.tested ?? [])
  const all = [...(coverage?.tested ?? []), ...(coverage?.untested ?? [])]
  const nodes = all.length ? Array.from(new Set(all)).sort() : []
  if (!nodes.length) return <span className="muted">无节点信息</span>
  return (
    <div className="node-dots">
      {nodes.map((node) => (
        <span
          key={node}
          className={`node-dot ${tested.has(node) ? 'on' : 'off'}`}
          title={`${node} ${coverage?.labels?.[node] ?? ''}${tested.has(node) ? '（已覆盖）' : '（未覆盖）'}`}
        >
          {node}
        </span>
      ))}
    </div>
  )
}

const SEVERITY_ORDER: Severity[] = ['low', 'medium', 'high', 'critical']

export function SeverityStrip({ severities }: { severities?: Partial<Record<Severity, number>> | null }) {
  const total = SEVERITY_ORDER.reduce((sum, key) => sum + (severities?.[key] ?? 0), 0)
  if (!total) return <span className="muted">无严重度分布</span>
  return (
    <div style={{ display: 'grid', gap: 8 }}>
      <div className="sev-strip">
        {SEVERITY_ORDER.map((key) => {
          const count = severities?.[key] ?? 0
          return count ? <i key={key} className={`sev-${key}`} style={{ width: `${(count / total) * 100}%` }} /> : null
        })}
      </div>
      <div className="sev-legend">
        {SEVERITY_ORDER.map((key) => (
          <span key={key}><i className={`dot sev-${key}`} />{SEVERITY_LABELS[key]} {severities?.[key] ?? 0}</span>
        ))}
      </div>
    </div>
  )
}

export function SeverityDonut({ severities }: { severities?: Partial<Record<Severity, number>> | null }) {
  const counts = SEVERITY_ORDER.map((key) => ({ key, count: severities?.[key] ?? 0 }))
  const total = counts.reduce((sum, item) => sum + item.count, 0)
  if (!total) return <Empty text="尚无严重度数据，运行一次检测后即可统计" />

  const radius = 52
  const circumference = 2 * Math.PI * radius
  let offset = 0
  const segments = counts
    .filter((item) => item.count)
    .map((item) => {
      const length = (item.count / total) * circumference
      const segment = { ...item, length, offset }
      offset += length
      return segment
    })
  const summary = counts.map((item) => `${SEVERITY_LABELS[item.key]} ${item.count} 个`).join('，')

  return (
    <div className="sev-donut-wrap">
      <svg className="sev-donut" viewBox="0 0 140 140" role="img" aria-label={`严重度分布：共 ${total} 个场景，${summary}`}>
        <circle className="sev-donut-track" cx="70" cy="70" r={radius} />
        {segments.map((segment) => (
          <circle
            key={segment.key}
            className={`sev-${segment.key}`}
            cx="70"
            cy="70"
            r={radius}
            strokeDasharray={`${segment.length.toFixed(3)} ${(circumference - segment.length).toFixed(3)}`}
            strokeDashoffset={(-segment.offset).toFixed(3)}
          />
        ))}
        <text className="sev-donut-total" x="70" y="66">{total}</text>
        <text className="sev-donut-unit" x="70" y="86">场景</text>
      </svg>
      <div className="sev-legend">
        {counts.map((item) => (
          <span key={item.key}>
            <i className={`dot sev-${item.key}`} />
            {SEVERITY_LABELS[item.key]} {item.count}
          </span>
        ))}
      </div>
    </div>
  )
}

export function Tabs<T extends string>({ tabs, active, onChange }: {
  tabs: { key: T; label: ReactNode }[]
  active: T
  onChange: (key: T) => void
}) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((tab) => (
        <button
          key={tab.key}
          type="button"
          role="tab"
          aria-selected={tab.key === active}
          className={tab.key === active ? 'active' : ''}
          onClick={() => onChange(tab.key)}
        >
          {tab.label}
        </button>
      ))}
    </div>
  )
}

export function PageHeader({ eyebrow, title, description, actions }: {
  eyebrow?: string
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
}) {
  return (
    <header className="page-header">
      <div>
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h1>{title}</h1>
        {description && <p className="page-description">{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  )
}

export function Stat({ label, value, note }: { label: ReactNode; value: ReactNode; note?: ReactNode }) {
  return (
    <div className="stat">
      <span>{label}</span>
      <strong>{value}</strong>
      {note && <small>{note}</small>}
    </div>
  )
}

export function Field({ label, hint, children }: { label: ReactNode; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  )
}
