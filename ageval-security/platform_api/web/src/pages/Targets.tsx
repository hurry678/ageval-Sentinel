import { useState, type FormEvent } from 'react'
import { Plus, RadioTower, Trash2 } from 'lucide-react'
import { api, errorMessage } from '../api'
import { useLoad } from '../hooks'
import { AsyncState, Card, ErrorNote, Field, PageHeader } from '../components/ui'
import type { ProbeResult, TargetKind } from '../types'

const emptyForm = {
  id: '',
  name: '',
  kind: 'inproc' as TargetKind,
  agent_kind: '',
  model: '',
  base_url: '',
  api_key_env: '',
  note: '',
  tags: '',
}

export default function Targets() {
  const targets = useLoad(api.listTargets)
  const health = useLoad(api.health)
  const [form, setForm] = useState(emptyForm)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [probes, setProbes] = useState<Record<string, ProbeResult | undefined>>({})
  const [probing, setProbing] = useState('')

  const agentKinds = health.data?.inproc_agents ?? []
  const set = <K extends keyof typeof form>(key: K, value: (typeof form)[K]) =>
    setForm((prev) => ({ ...prev, [key]: value }))

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await api.createTarget({
        ...(form.id.trim() ? { id: form.id.trim() } : {}),
        name: form.name.trim(),
        kind: form.kind,
        agent_kind: form.kind === 'inproc' ? form.agent_kind : '',
        model: form.kind === 'http' ? form.model.trim() : '',
        base_url: form.kind === 'http' ? form.base_url.trim() : '',
        api_key_env: form.kind === 'http' ? form.api_key_env.trim() : '',
        note: form.note.trim(),
        tags: form.tags.split(',').map((tag) => tag.trim()).filter(Boolean),
      })
      setForm(emptyForm)
      targets.reload()
    } catch (reason) {
      setError(errorMessage(reason))
    } finally {
      setBusy(false)
    }
  }

  async function remove(id: string) {
    setError('')
    try {
      await api.deleteTarget(id)
      targets.reload()
    } catch (reason) {
      setError(errorMessage(reason))
    }
  }

  async function runProbe(id: string) {
    setProbing(id)
    setProbes((prev) => ({ ...prev, [id]: undefined }))
    try {
      const result = await api.probeTarget(id)
      setProbes((prev) => ({ ...prev, [id]: result }))
    } catch (reason) {
      setError(errorMessage(reason))
    } finally {
      setProbing('')
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Targets"
        title="检测目标"
        description="inproc 目标直接调用平台内置 Agent；http 目标通过 OpenAI 兼容接口远程调用，密钥只保存环境变量名。"
      />
      {error && <div style={{ marginBottom: 'var(--space-4)' }}><ErrorNote text={error} /></div>}

      <div className="grid cols-2">
        <Card title="目标列表" subtitle={`共 ${targets.data?.targets.length ?? 0} 个`}>
          <AsyncState loading={targets.loading} error={targets.error} empty={!targets.data?.targets.length} emptyText="还没有注册检测目标">
            <div className="grid" style={{ gap: 'var(--space-3)' }}>
              {(targets.data?.targets ?? []).map((target) => (
                <div key={target.id} className="stat" style={{ gap: 8 }}>
                  <div className="row" style={{ justifyContent: 'space-between' }}>
                    <div>
                      <strong style={{ fontSize: 15 }}>{target.name || target.id}</strong>
                      <div className="mono-id">{target.id}</div>
                    </div>
                    <div className="row" style={{ gap: 6 }}>
                      <button
                        type="button"
                        className="button ghost small"
                        disabled={probing === target.id}
                        onClick={() => runProbe(target.id)}
                      >
                        {probing === target.id ? <span className="spinner" /> : <RadioTower size={13} />}探测
                      </button>
                      <button type="button" className="button danger small" onClick={() => remove(target.id)}>
                        <Trash2 size={13} />删除
                      </button>
                    </div>
                  </div>
                  <div className="row" style={{ gap: 6 }}>
                    <span className="tag">{target.kind}</span>
                    {target.kind === 'inproc'
                      ? <span className="tag">{target.agent_kind || '—'}</span>
                      : <><span className="tag">{target.model || '—'}</span><span className="tag">{target.api_key_env || '无需密钥'}</span></>}
                    {target.tags?.map((tag) => <span key={tag} className="tag">#{tag}</span>)}
                  </div>
                  {target.kind === 'http' && <div className="mono-id">{target.base_url}</div>}
                  {target.note && <p className="muted" style={{ margin: 0 }}>{target.note}</p>}
                  {probes[target.id] && (
                    <div className="grid" style={{ gap: 4 }}>
                      {Object.entries(probes[target.id]!.checks).map(([name, check]) => (
                        <div key={name} className="row" style={{ gap: 8 }}>
                          <span className={check.ok ? 'dot-on' : 'dot-off'}>●</span>
                          <span className="tag">{name === 'config' ? '配置与凭据' : '端点握手'}</span>
                          <span className="muted" style={{ fontSize: 12 }}>{check.detail}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </AsyncState>
        </Card>

        <Card title="新增目标" subtitle="必填字段随目标类型变化">
          <form className="grid" style={{ gap: 'var(--space-4)' }} onSubmit={submit}>
            <Field label="目标类型">
              <select value={form.kind} onChange={(event) => set('kind', event.target.value as TargetKind)}>
                {(health.data?.target_kinds ?? ['inproc', 'http']).map((kind) => (
                  <option key={kind} value={kind}>{kind}</option>
                ))}
              </select>
            </Field>
            <Field label="名称"><input required value={form.name} placeholder="内置电商 Agent" onChange={(event) => set('name', event.target.value)} /></Field>
            <Field label="目标 ID" hint="留空则由后端生成">
              <input value={form.id} placeholder="可选" onChange={(event) => set('id', event.target.value)} />
            </Field>

            {form.kind === 'inproc' ? (
              <Field label="内置 Agent" hint="来自 /api/health 的 inproc_agents">
                <select required value={form.agent_kind} onChange={(event) => set('agent_kind', event.target.value)}>
                  <option value="">请选择…</option>
                  {agentKinds.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
                </select>
              </Field>
            ) : (
              <>
                <Field label="模型名（必填）"><input required value={form.model} placeholder="gpt-4o-mini" onChange={(event) => set('model', event.target.value)} /></Field>
                <Field label="Base URL（必填）"><input required value={form.base_url} placeholder="https://api.openai.com/v1" onChange={(event) => set('base_url', event.target.value)} /></Field>
                <Field
                  label="API Key 环境变量名"
                  hint="填写环境变量名称（如 OPENAI_API_KEY），不要填写真实密钥。指向 127.0.0.1 的本地端点可留空。"
                >
                  <input value={form.api_key_env} placeholder="OPENAI_API_KEY" onChange={(event) => set('api_key_env', event.target.value)} />
                </Field>
              </>
            )}

            <Field label="标签" hint="英文逗号分隔"><input value={form.tags} placeholder="ecommerce,baseline" onChange={(event) => set('tags', event.target.value)} /></Field>
            <Field label="备注"><textarea value={form.note} onChange={(event) => set('note', event.target.value)} /></Field>
            <button className="button primary" disabled={busy}>
              {busy ? <span className="spinner" /> : <Plus size={15} />}注册目标
            </button>
          </form>
        </Card>
      </div>
    </>
  )
}
