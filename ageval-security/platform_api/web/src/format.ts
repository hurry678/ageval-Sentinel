export const percent = (value: number | null | undefined, digits = 1) =>
  value === null || value === undefined || Number.isNaN(value)
    ? '—'
    : `${(value * 100).toFixed(digits)}%`

export const num = (value: number | null | undefined, digits = 2) =>
  value === null || value === undefined || Number.isNaN(value) ? '—' : value.toFixed(digits)

export function datetime(unixSeconds: number | null | undefined) {
  if (!unixSeconds) return '—'
  return new Date(unixSeconds * 1000).toLocaleString('zh-CN', { hour12: false })
}

export function duration(from: number, to: number | null) {
  if (!from) return '—'
  const end = to ?? Date.now() / 1000
  const seconds = Math.max(0, Math.round(end - from))
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`
}

export const NODE_IDS = ['N1', 'N2', 'N3', 'N4', 'N5', 'N6', 'N7', 'N8']

export const RUN_STATUS_LABELS: Record<string, string> = {
  starting: '启动中',
  running: '执行中',
  completed: '已完成',
  failed: '失败',
  cancelled: '已取消',
}

export const RISK_LABELS: Record<string, string> = {
  low: '低风险',
  medium: '中风险',
  high: '高风险',
  critical: '严重风险',
}

export const SEVERITY_LABELS: Record<string, string> = {
  low: '低',
  medium: '中',
  high: '高',
  critical: '严重',
}

export function pretty(value: unknown) {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}
