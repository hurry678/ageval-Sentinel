import { useCallback, useEffect, useState } from 'react'
import { errorMessage } from './api'

export function useLoad<T>(loader: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T>()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [nonce, setNonce] = useState(0)

  const reload = useCallback(() => setNonce((value) => value + 1), [])

  useEffect(() => {
    let alive = true
    setLoading(true)
    setError('')
    loader()
      .then((result) => { if (alive) setData(result) })
      .catch((reason) => { if (alive) setError(errorMessage(reason)) })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nonce, ...deps])

  return { data, loading, error, reload, setData }
}
