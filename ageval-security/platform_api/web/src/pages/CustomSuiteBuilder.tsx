import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowLeft, PlusCircle } from 'lucide-react'
import { api, errorMessage } from '../api'
import { NODE_IDS } from '../format'
import { Card, ErrorNote, Field, PageHeader } from '../components/ui'
import type { CustomSuiteInput, ScriptStep, Severity } from '../types'

const blankStep = (): ScriptStep => ({ user_id: 'user', role: 'employee', message: '' })

export default function CustomSuiteBuilder() {
  const navigate = useNavigate()
  const [input, setInput] = useState<CustomSuiteInput>({
    suite_id: 'custom-agent-flow',
    task_id: 'custom-risk-check',
    title: '自定义风险检测',
    description: 'User-defined Sentinel test flow',
    category: 'custom_risk',
    severity: 'medium',
    nodes: ['N1', 'N6', 'N7'],
    business_flow: 'custom',
    expected_decision: 'block',
    clean_steps: [blankStep()],
    controlled_steps: [blankStep()],
    success_criteria: ['Agent blocks the unsafe controlled request.'],
    business_impact: 'User-defined impact',
  })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const patch = (patches: Partial<CustomSuiteInput>) => setInput((prev) => ({ ...prev, ...patches }))
  const updateStep = (field: 'clean_steps' | 'controlled_steps', index: number, message: string) => {
    const steps = [...input[field]]
    steps[index] = { ...steps[index], message }
    patch({ [field]: steps } as Partial<CustomSuiteInput>)
  }
  const addStep = (field: 'clean_steps' | 'controlled_steps') => patch({ [field]: [...input[field], blankStep()] } as Partial<CustomSuiteInput>)
  const toggleNode = (node: string) => {
    patch({ nodes: input.nodes.includes(node) ? input.nodes.filter((item) => item !== node) : [...input.nodes, node] })
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const suite = await api.createCustomSuite(input)
      navigate(`/suites/${encodeURIComponent(suite.suite_id)}`)
    } catch (reason) {
      setError(errorMessage(reason))
      setBusy(false)
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Custom Suite"
        title="新建自定义测试流程"
        description="用表单生成 ageval 兼容测试套件，保存后会自动出现在测试套件列表。"
        actions={<button type="button" className="button ghost" onClick={() => navigate('/suites')}><ArrowLeft size={15} />返回</button>}
      />
      <form className="grid" onSubmit={submit}>
        <Card title="基础信息">
          <div className="grid cols-2">
            <Field label="Suite ID" hint="必须以 custom- 开头，例如 custom-agent-flow">
              <input value={input.suite_id} onChange={(event) => patch({ suite_id: event.target.value })} required />
            </Field>
            <Field label="Task ID">
              <input value={input.task_id} onChange={(event) => patch({ task_id: event.target.value })} required />
            </Field>
            <Field label="标题">
              <input value={input.title} onChange={(event) => patch({ title: event.target.value })} required />
            </Field>
            <Field label="风险分类">
              <input value={input.category} onChange={(event) => patch({ category: event.target.value })} required />
            </Field>
            <Field label="严重度">
              <select value={input.severity} onChange={(event) => patch({ severity: event.target.value as Severity })}>
                <option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option>
              </select>
            </Field>
            <Field label="期望决策">
              <select value={input.expected_decision} onChange={(event) => patch({ expected_decision: event.target.value as CustomSuiteInput['expected_decision'] })}>
                <option value="block">block</option><option value="allow">allow</option><option value="warn">warn</option><option value="review">review</option>
              </select>
            </Field>
          </div>
        </Card>

        <Card title="攻击面节点" subtitle="选择该流程覆盖的 N1-N8 节点">
          <div className="node-picker">
            {NODE_IDS.map((node) => (
              <button key={node} type="button" className={`node-dot ${input.nodes.includes(node) ? 'on' : 'off'}`} onClick={() => toggleNode(node)}>
                {node}
              </button>
            ))}
          </div>
        </Card>

        <div className="grid cols-2">
          <Card title="Clean Steps" subtitle="正常业务请求">
            <div className="grid" style={{ gap: 10 }}>
              {input.clean_steps.map((step, index) => (
                <Field key={index} label={`Clean #${index + 1}`}>
                  <textarea value={String(step.message || '')} onChange={(event) => updateStep('clean_steps', index, event.target.value)} />
                </Field>
              ))}
              <button type="button" className="button ghost" onClick={() => addStep('clean_steps')}>添加 clean step</button>
            </div>
          </Card>
          <Card title="Controlled Steps" subtitle="受控攻击请求">
            <div className="grid" style={{ gap: 10 }}>
              {input.controlled_steps.map((step, index) => (
                <Field key={index} label={`Attack #${index + 1}`}>
                  <textarea value={String(step.message || '')} onChange={(event) => updateStep('controlled_steps', index, event.target.value)} />
                </Field>
              ))}
              <button type="button" className="button ghost" onClick={() => addStep('controlled_steps')}>添加 attack step</button>
            </div>
          </Card>
        </div>

        <Card title="判定标准">
          <div className="grid cols-2">
            <Field label="Success Criteria" hint="每行一条">
              <textarea value={input.success_criteria.join('\n')} onChange={(event) => patch({ success_criteria: event.target.value.split('\n').filter(Boolean) })} />
            </Field>
            <Field label="业务影响">
              <textarea value={input.business_impact} onChange={(event) => patch({ business_impact: event.target.value })} />
            </Field>
          </div>
        </Card>

        {error && <ErrorNote text={error} />}
        <button className="button primary" disabled={busy} style={{ justifySelf: 'start' }}>
          {busy ? <span className="spinner" /> : <PlusCircle size={16} />}保存自定义流程
        </button>
      </form>
    </>
  )
}
