import { useEffect, useRef, useState } from 'react'
import { api } from './api'
import type { RunEvent, RunSummary } from './types'

const TERMINAL_STATUSES = ['completed', 'failed', 'cancelled']

export function isTerminal(status: string | undefined) {
  return TERMINAL_STATUSES.includes(status ?? '')
}

export function useRunStream(runId: string) {
  const [run, setRun] = useState<RunSummary>()
  const [events, setEvents] = useState<RunEvent[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const cursorRef = useRef(0)

  const refresh = () => api.getRun(runId).then(setRun).catch(() => undefined)

  useEffect(() => {
    let alive = true
    let source: EventSource | null = null
    cursorRef.current = 0
    setEvents([])
    setLoading(true)
    setError('')

    api.getRun(runId)
      .then((summary) => {
        if (!alive) return
        setRun(summary)
        setLoading(false)
        // Events are persisted, so a finished run still replays its whole log
        // from the cursor and then closes with `end`.
        source = new EventSource(api.eventsUrl(runId, 0))
        source.onmessage = (message) => {
          if (!alive) return
          let event: RunEvent
          try {
            event = JSON.parse(message.data) as RunEvent
          } catch {
            return
          }
          cursorRef.current = Math.max(cursorRef.current, event.seq + 1)
          setEvents((prev) => [...prev.slice(-800), event])
          if (event.kind === 'task' || event.kind === 'suite' || event.kind === 'done') void refresh()
        }
        source.addEventListener('end', () => {
          source?.close()
          void refresh()
        })
        source.onerror = () => {
          source?.close()
          void refresh()
        }
      })
      .catch((reason: unknown) => {
        if (!alive) return
        setError(reason instanceof Error ? reason.message : '无法读取运行状态')
        setLoading(false)
      })

    return () => {
      alive = false
      source?.close()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId])

  return { run, events, error, loading, refresh }
}
