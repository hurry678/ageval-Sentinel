import { useEffect, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { PlayCircle } from 'lucide-react'
import { api, errorMessage } from '../api'
import { useLoad } from '../hooks'
import { AsyncState, Card, ErrorNote, Field, PageHeader } from '../components/ui'

export default function NewRun() {
  const navigate = useNavigate()
  const targets = useLoad(api.listTargets)
  const suites = useLoad(api.listSuites)
  const [targetId, setTargetId] = useState('')
  const [suiteId, setSuiteId] = useState('')
  const [attempts, setAttempts] = useState(1)
  const [concurrent, setConcurrent] = useState(4)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const targetList = targets.data?.targets ?? []
  const suiteList = suites.data?.suites ?? []
  const suite = suiteList.find((item) => item.suite_id === suiteId)

  useEffect(() => {
    if (!targetId && targetList.length) setTargetId(targetList[0].id)
  }, [targetId, targetList])
  useEffect(() => {
    if (!suiteId && suiteList.length) setSuiteId(suiteList[0].suite_id)
  }, [suiteId, suiteList])

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const run = await api.createRun({
        target_id: targetId,
        suite_id: suiteId,
        n_attempts: attempts,
        max_concurrent: concurrent,
      })
      navigate(`/runs/${run.run_id}`)
    } catch (reason) {
      setError(errorMessage(reason))
      setBusy(false)
    }
  }

  const trials = (suite?.task_count ?? 0) * attempts

  return (
    <>
      <PageHeader
        eyebrow="New Run"
        title="发起检测"
        description="选择被测目标与检测套件，设置采样次数 k（用于 pass@k / pass^k 统计）与执行并发度。"
      />
      <AsyncState
        loading={targets.loading || suites.loading}
        error={targets.error || suites.error}
        empty={!targetList.length || !suiteList.length}
        emptyText={!targetList.length ? '请先在「检测目标」注册目标' : '未发现可用套件'}
      >
        <div className="grid cols-2">
          <Card title="运行配置">
            <form className="grid" style={{ gap: 'var(--space-4)' }} onSubmit={submit}>
              <Field label="被测目标">
                <select value={targetId} onChange={(event) => setTargetId(event.target.value)} required>
                  {targetList.map((target) => (
                    <option key={target.id} value={target.id}>
                      {target.name || target.id}（{target.kind}）
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="检测套件">
                <select value={suiteId} onChange={(event) => setSuiteId(event.target.value)} required>
                  {suiteList.map((item) => (
                    <option key={item.suite_id} value={item.suite_id}>
                      {item.suite_id}（{item.task_count} 场景）
                    </option>
                  ))}
                </select>
              </Field>
              <Field label={`采样次数 k = ${attempts}`} hint="同一场景重复执行次数，1–5">
                <input
                  type="range" min={1} max={5} step={1} value={attempts}
                  onChange={(event) => setAttempts(Number(event.target.value))}
                />
              </Field>
              <Field label="并发度" hint="同时执行的场景数，1–16">
                <input
                  type="number" min={1} max={16} value={concurrent}
                  onChange={(event) => setConcurrent(Math.max(1, Math.min(16, Number(event.target.value) || 1)))}
                />
              </Field>
              {error && <ErrorNote text={error} />}
              <button className="button primary" disabled={busy}>
                {busy ? <span className="spinner" /> : <PlayCircle size={16} />}开始检测
              </button>
            </form>
          </Card>

          <Card title="执行预览" subtitle="提交后自动跳转到实时观测页">
            <dl className="kv">
              <div><dt>场景数</dt><dd className="mono">{suite?.task_count ?? 0}</dd></div>
              <div><dt>预计试次</dt><dd className="mono">{trials}</dd></div>
              <div><dt>数据集</dt><dd className="mono">{suite?.dataset_id ?? '—'}</dd></div>
              <div><dt>防御增益对照</dt><dd>{suite?.supports_defense_delta ? '支持' : '不支持'}</dd></div>
            </dl>
            <p className="muted" style={{ marginTop: 'var(--space-4)' }}>
              {suite?.description || '选择套件后展示描述。'}
            </p>
          </Card>
        </div>
      </AsyncState>
    </>
  )
}
