import { Link } from 'react-router-dom'
import { NODE_IDS } from '../format'
import type { AttackPath, AttackPathNode, NodeCoverage } from '../types'

function statusLabel(status: string) {
  return {
    PASS: '通过',
    FAIL: '失败',
    ERROR: '错误',
    running: '运行中',
    pending: '待运行',
    uncovered: '未覆盖',
  }[status] ?? status
}

export function AttackPathGraph({ path }: { path: AttackPath }) {
  const byId = new Map(path.nodes.map((node) => [node.id, node]))
  const nodes = NODE_IDS.map((id) => byId.get(id)).filter(Boolean) as AttackPathNode[]
  return (
    <div className="attack-graph" role="img" aria-label="N1 到 N8 攻击路径图">
      {nodes.map((node, index) => (
        <div className="attack-node-wrap" key={node.id}>
          <div className={`attack-node ${node.covered ? 'covered' : 'uncovered'} s-${node.status.toLowerCase()}`}>
            <strong>{node.id}</strong>
            <span>{node.label}</span>
            <em>{statusLabel(node.status)}</em>
          </div>
          {index < nodes.length - 1 && <i className="attack-edge" />}
        </div>
      ))}
    </div>
  )
}

export function SuiteCoverageGraph({ coverage }: { coverage?: NodeCoverage | null }) {
  const tested = new Set(coverage?.tested ?? [])
  const labels = coverage?.labels ?? {}
  return (
    <div className="attack-graph compact" role="img" aria-label="套件节点覆盖图">
      {NODE_IDS.map((node) => (
        <div className="attack-node-wrap" key={node}>
          <div className={`attack-node ${tested.has(node) ? 'covered s-pass' : 'uncovered s-uncovered'}`}>
            <strong>{node}</strong>
            <span>{labels[node] ?? node}</span>
            <em>{tested.has(node) ? '已覆盖' : '未覆盖'}</em>
          </div>
        </div>
      ))}
    </div>
  )
}

export function AttackPathTaskList({ path }: { path: AttackPath }) {
  if (!path.tasks.length) return <p className="muted">暂无 task 级路径数据。</p>
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr><th>Task</th><th>结果</th><th>分类</th><th>严重度</th><th>节点</th><th>证据</th></tr>
        </thead>
        <tbody>
          {path.tasks.map((task) => (
            <tr key={task.task_id}>
              <td className="mono">{task.task_id}</td>
              <td><span className={`badge status-${task.status.toLowerCase()}`}>{statusLabel(task.status)}</span></td>
              <td>{task.category}</td>
              <td>{task.severity}</td>
              <td>
                <div className="row" style={{ gap: 4 }}>
                  {task.nodes.map((node) => <span key={node} className="tag">{node}</span>)}
                </div>
              </td>
              <td>
                {task.has_replay
                  ? <Link className="button ghost small" to={`/runs/${path.run_id}/replay/${task.task_id}`}>回放</Link>
                  : <span className="muted">未就绪</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
