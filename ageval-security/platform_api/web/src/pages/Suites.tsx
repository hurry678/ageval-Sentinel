import { Link } from 'react-router-dom'
import { ArrowRight, CheckCircle2, MinusCircle, PlusCircle } from 'lucide-react'
import { api } from '../api'
import { useLoad } from '../hooks'
import { percent } from '../format'
import {
  AsyncState, Card, NodeCoverageDots, PageHeader, SeverityStrip,
} from '../components/ui'

export default function Suites() {
  const suites = useLoad(api.listSuites)
  const list = suites.data?.suites ?? []

  return (
    <>
      <PageHeader
        eyebrow="Suites"
        title="测试套件"
        description="每个套件是一组带 gold 判据的业务场景，覆盖 N1–N8 攻击面节点，可选支持防御增益（defense delta）对照。"
        actions={<Link className="button primary" to="/suites/custom/new"><PlusCircle size={15} />新建自定义流程</Link>}
      />
      <AsyncState loading={suites.loading} error={suites.error} empty={!list.length} emptyText="未发现测试套件">
        <div className="grid cols-2">
          {list.map((suite) => (
            <Card
              key={suite.suite_id}
              title={suite.suite_id}
              subtitle={suite.description || suite.dataset_id}
              action={<Link className="button ghost small" to={`/suites/${encodeURIComponent(suite.suite_id)}`}>详情<ArrowRight size={13} /></Link>}
            >
              <div className="row" style={{ gap: 6, marginBottom: 'var(--space-4)' }}>
                <span className="tag">{suite.task_count} 个场景</span>
                <span className="tag">v{suite.version || '—'}</span>
                <span className="tag">{suite.dataset_id}</span>
                <span className={`badge ${suite.supports_defense_delta ? 'risk-low' : ''}`}>
                  {suite.supports_defense_delta ? <CheckCircle2 size={12} /> : <MinusCircle size={12} />}
                  防御增益对照{suite.supports_defense_delta ? '可用' : '不可用'}
                </span>
              </div>

              <div className="grid" style={{ gap: 'var(--space-4)' }}>
                <div>
                  <p className="muted" style={{ margin: '0 0 8px' }}>严重度分布</p>
                  <SeverityStrip severities={suite.severities} />
                </div>
                <div>
                  <p className="muted" style={{ margin: '0 0 8px' }}>
                    节点覆盖 {percent(suite.node_coverage?.ratio ?? 0, 0)}
                  </p>
                  <NodeCoverageDots coverage={suite.node_coverage} />
                </div>
                <div>
                  <p className="muted" style={{ margin: '0 0 8px' }}>攻击面分类</p>
                  <div className="row" style={{ gap: 6 }}>
                    {Object.entries(suite.categories ?? {}).map(([category, count]) => (
                      <span key={category} className="tag">{category} · {count}</span>
                    ))}
                    {!Object.keys(suite.categories ?? {}).length && <span className="muted">无分类信息</span>}
                  </div>
                </div>
              </div>
            </Card>
          ))}
        </div>
      </AsyncState>
    </>
  )
}
