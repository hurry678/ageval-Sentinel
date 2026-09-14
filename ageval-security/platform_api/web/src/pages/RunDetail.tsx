import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, RefreshCw } from 'lucide-react'
import { api } from '../api'
import { useLoad } from '../hooks'
import { AsyncState, Card, ErrorNote, Loading, PageHeader, StatusBadge, Tabs } from '../components/ui'
import RunLive from '../components/RunLive'
import ReportView from '../components/ReportView'
import { useRunStream } from '../useRunStream'

type Tab = 'live' | 'report'

function ReportTab({ runId, ready }: { runId: string; ready: boolean }) {
  const { data, loading, error } = useLoad(() => api.getReport(runId), [runId, ready])
  if (loading) return <Loading text="加载报告…" />
  if (error) {
    return (
      <Card title="报告尚未就绪">
        <div className="info-note">{error || '运行完成后才能生成检测报告，请先在「实时观测」中等待执行结束。'}</div>
      </Card>
    )
  }
  if (!data) return <Card title="报告不可用"><p className="muted">后端未返回报告内容。</p></Card>
  return <ReportView report={data} />
}

export default function RunDetail() {
  const { runId = '' } = useParams()
  const { run, events, error, loading, refresh } = useRunStream(runId)
  const [tab, setTab] = useState<Tab>('live')
  const finished = run?.status === 'completed'

  return (
    <>
      <PageHeader
        eyebrow="Run"
        title={<span className="mono">{runId}</span>}
        description={run ? `${run.target_name || run.target_id} · 套件 ${run.suite_id} · 数据集 ${run.dataset_id}` : '读取运行状态…'}
        actions={
          <>
            {run && <StatusBadge status={run.status} />}
            <button type="button" className="button ghost" onClick={refresh}><RefreshCw size={15} />刷新</button>
            <Link className="button ghost" to="/runs"><ArrowLeft size={15} />运行历史</Link>
          </>
        }
      />

      <div style={{ marginBottom: 'var(--space-5)' }}>
        <Tabs
          active={tab}
          onChange={setTab}
          tabs={[{ key: 'live', label: '实时观测' }, { key: 'report', label: '报告' }]}
        />
      </div>

      {error && <ErrorNote text={error} />}
      <AsyncState loading={loading} error={error} empty={!run} emptyText="运行不存在">
        {run && (tab === 'live'
          ? <RunLive run={run} events={events} onRefresh={refresh} />
          : <ReportTab runId={runId} ready={Boolean(finished)} />)}
      </AsyncState>
    </>
  )
}
