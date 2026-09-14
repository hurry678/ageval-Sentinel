import { Link } from 'react-router-dom'
import { Download } from 'lucide-react'
import { api } from '../api'
import { num, percent } from '../format'
import {
  Card, Empty, MetricBar, NodeCoverageDots, RiskBadge, SeverityDot, StatusBadge,
} from './ui'
import type { PassRate, Report } from '../types'

const METRIC_ROWS: { key: keyof Report['metrics']; label: string; hint: string; fraction: boolean }[] = [
  { key: 'asr', label: 'ASR 攻击成功率', hint: '受控攻击中被攻破的比例，越低越好', fraction: true },
  { key: 'dsr', label: 'DSR 防御成功率', hint: '攻击被成功拦截的比例，越高越好', fraction: true },
  { key: 'fpr', label: 'FPR 误拦率', hint: '正常业务被错误拦截的比例，越低越好', fraction: true },
  { key: 'critical_node_bypass_rate', label: '关键节点绕过率', hint: '关键攻击面节点被绕过的比例', fraction: true },
  { key: 'coverage_gap', label: '覆盖缺口', hint: '未被测试覆盖的必要节点比例', fraction: true },
  { key: 'severity_penalty', label: '严重度扣分', hint: '0–10 原始分，非百分比', fraction: false },
]

const PENALTY_LABELS: Record<keyof Report['penalties'], string> = {
  asr: 'ASR 扣分',
  fpr: 'FPR 扣分',
  critical_node_bypass_rate: '关键节点绕过扣分',
  coverage_gap: '覆盖缺口扣分',
  severity: '严重度扣分',
}

export default function ReportView({ report }: { report: Report }) {
  const failedCases = (report.cases ?? []).filter((row) => row.status !== 'PASS')
  const ageval = report.ageval_metrics ?? {}
  const kValues = (ageval.k_values ?? []).map(String)
  // ageval reports each rate as an object, not a bare number.
  const rate = (bucket: Record<string, PassRate> | undefined, k: string) => bucket?.[k]?.value
  return (
    <>
      <Card className="score-card">
        <div className="score-hero">
          <div className={`score-ring risk-${report.risk_level}`}>
            <strong>{num(report.score, 1)}</strong>
            <span>SCORE / 100</span>
          </div>
          <div className="score-meta">
            <div className="row">
              <RiskBadge level={report.risk_level} />
              <span className="tag">原始分 {num(report.raw_score, 1)}</span>
              <span className="tag">{report.trial_count} 试次 / {report.scenario_count} 场景 / k={report.n_attempts}</span>
            </div>
            <h2>{report.target_name || report.target_id}</h2>
            <div className="score-facts">
              <span>套件 <code className="mono">{report.suite_id}</code></span>
              <span>数据集 <code className="mono">{report.dataset_id} {report.dataset_version}</code></span>
              <span>Agent <code className="mono">{report.agent_label || '—'}</code></span>
              <span>模型 <code className="mono">{report.model_label || '—'}</code></span>
            </div>
            <div className="row">
              <a className="button ghost small" href={api.reportMarkdownUrl(report.run_id)} target="_blank" rel="noreferrer">
                <Download size={13} />下载 Markdown 报告
              </a>
            </div>
          </div>
        </div>
      </Card>

      <div className="grid cols-2">
        <Card title="六大核心指标">
          <div className="grid" style={{ gap: 'var(--space-4)' }}>
            {METRIC_ROWS.map((row) => {
              const value = Number(report.metrics?.[row.key] ?? 0)
              const good = row.key === 'dsr'
              return (
                <MetricBar
                  key={row.key}
                  label={<span title={row.hint}>{row.label}</span>}
                  value={row.fraction ? value : value / 10}
                  display={row.fraction ? percent(value) : `${num(value, 2)} / 10`}
                  tone={good ? 'good' : value > 0.5 ? 'bad' : value > 0.2 ? 'warn' : 'primary'}
                />
              )
            })}
          </div>
        </Card>

        <Card title="扣分构成" subtitle={`原始分 ${num(report.raw_score, 1)} → 最终分 ${num(report.score, 1)}`}>
          <div className="table-wrap">
            <table>
              <thead><tr><th>扣分项</th><th className="mono">扣分</th></tr></thead>
              <tbody>
                {(Object.keys(PENALTY_LABELS) as (keyof Report['penalties'])[]).map((key) => (
                  <tr key={key}>
                    <td>{PENALTY_LABELS[key]}</td>
                    <td className="mono">{num(report.penalties?.[key] ?? 0, 2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <dl className="kv" style={{ marginTop: 'var(--space-4)' }}>
            <div><dt>攻击用例 / 成功 / 拦截</dt><dd className="mono">{report.metrics?.attack_case_count ?? 0} / {report.metrics?.attack_success_count ?? 0} / {report.metrics?.attack_blocked_count ?? 0}</dd></div>
            <div><dt>正常用例 / 误拦</dt><dd className="mono">{report.metrics?.clean_case_count ?? 0} / {report.metrics?.clean_blocked_count ?? 0}</dd></div>
            <div><dt>关键节点测试 / 绕过</dt><dd className="mono">{report.metrics?.critical_node_test_count ?? 0} / {report.metrics?.bypassed_critical_node_count ?? 0}</dd></div>
            <div><dt>pass_rate / mean_score</dt><dd className="mono">{percent(report.ageval_metrics?.pass_rate as number)} / {num(report.ageval_metrics?.mean_score as number, 3)}</dd></div>
          </dl>
        </Card>

        <Card
          title="采样稳定性（pass@k / pass^k）"
          subtitle={`k=${report.n_attempts} · ${report.trial_count} 次试验`}
        >
          <p className="muted" style={{ marginTop: 0 }}>
            <code className="mono">pass@k</code> 是至少通过一次，<code className="mono">pass^k</code> 是 k 次全过。
            安全结论该看后者：偶尔挡住不算防住。
          </p>
          {kValues.length < 2 ? (
            <Empty text="单次采样（k=1）无法衡量稳定性，请在「发起检测」中把采样次数调到 2 以上" />
          ) : (
            <div className="table-wrap">
              <table>
                <thead><tr><th className="mono">k</th><th className="mono">pass@k</th><th className="mono">pass^k</th><th className="mono">波动</th></tr></thead>
                <tbody>
                  {kValues.map((k) => {
                    const atK = rate(ageval.pass_at_k, k)
                    const powK = rate(ageval.pass_power_k, k)
                    const spread = atK !== undefined && powK !== undefined ? atK - powK : undefined
                    return (
                      <tr key={k}>
                        <td className="mono">{k}</td>
                        <td className="mono">{percent(atK)}</td>
                        <td className="mono">{percent(powK)}</td>
                        <td className="mono" style={{ color: (spread ?? 0) > 0 ? 'var(--warning)' : 'var(--text-secondary)' }}>
                          {spread === undefined ? '—' : percent(spread)}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card title="分攻击面 ASR">
          {!report.by_category?.length ? <Empty text="无分类数据" /> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>攻击面</th><th className="mono">用例</th><th className="mono">攻破</th><th className="mono">ASR</th><th className="mono">误拦</th><th>节点</th></tr></thead>
                <tbody>
                  {report.by_category.map((row) => (
                    <tr key={row.category}>
                      <td>{row.category}</td>
                      <td className="mono">{row.cases}</td>
                      <td className="mono">{row.succeeded}</td>
                      <td className="mono" style={{ color: row.asr > 0 ? 'var(--danger)' : 'var(--success)' }}>{percent(row.asr)}</td>
                      <td className="mono">{row.clean_blocked}</td>
                      <td>{(row.nodes ?? []).join(' ')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card title="节点覆盖" subtitle={`已测 ${report.metrics?.tested_node_count ?? 0} / 需测 ${report.metrics?.total_required_node_count ?? 0}`}>
          <NodeCoverageDots coverage={report.node_coverage} />
          {!!report.node_coverage?.untested?.length && (
            <p className="muted" style={{ marginTop: 'var(--space-3)' }}>
              未覆盖：{report.node_coverage.untested.map((node) => `${node} ${report.node_coverage.labels?.[node] ?? ''}`).join('、')}
            </p>
          )}
        </Card>

        <Card title="防御增益（Defense Delta）">
          {!report.defense_delta ? <Empty text="该套件不支持防御增益对照" /> : (
            <div className="grid" style={{ gap: 'var(--space-4)' }}>
              <MetricBar label="基线 ASR（无防护）" value={report.defense_delta.baseline_asr} tone="bad" />
              <MetricBar label="受护 ASR" value={report.defense_delta.guarded_asr} tone="good" />
              <MetricBar label="风险下降幅度" value={Math.max(0, report.defense_delta.reduction)} tone="primary" />
              <p className="muted" style={{ margin: 0 }}>
                对照试次 {report.defense_delta.trials}
                {report.defense_delta.non_discriminating?.length
                  ? `；无区分度场景：${report.defense_delta.non_discriminating.join('、')}`
                  : ''}
              </p>
            </div>
          )}
        </Card>

        <Card title="独立取证（Forensics）">
          {!report.forensics ? <Empty text="本次运行没有独立取证数据" /> : (
            <>
              <div className="grid cols-3" style={{ marginBottom: 'var(--space-4)' }}>
                <div className="stat"><span>取证命中率</span><strong>{percent(report.forensics.hit_rate)}</strong></div>
                <div className="stat"><span>独立命中 / 试次</span><strong>{report.forensics.independent_hits}/{report.forensics.trials}</strong></div>
                <div className="stat"><span>仅自述</span><strong>{report.forensics.self_report_only?.length ?? 0}</strong></div>
              </div>
              <div className="row" style={{ gap: 6, marginBottom: 'var(--space-3)' }}>
                {(report.forensics.rules ?? []).map((rule) => <span key={rule} className="tag">{rule}</span>)}
              </div>
              {!!report.forensics.hit_rows?.length && (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>场景</th><th>裁定</th><th className="mono">风险分</th><th>命中规则</th></tr></thead>
                    <tbody>
                      {report.forensics.hit_rows.map((row, index) => (
                        <tr key={`${row.task_id}-${index}`}>
                          <td className="mono">{row.task_id}</td>
                          <td>{row.oracle_verdict}<div className="muted" style={{ fontSize: 11 }}>{row.oracle_summary}</div></td>
                          <td className="mono">{num(row.oracle_risk_score, 2)}</td>
                          <td>{(row.oracle_rules ?? []).join('、')}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </Card>
      </div>

      <Card title="失败与异常用例" subtitle="点击行进入三相聊天回放">
        {!failedCases.length ? <Empty text="全部用例通过" /> : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>场景</th><th>状态</th><th>攻击面</th><th>严重度</th><th>攻击成功</th><th>被拦截</th><th>泄露串</th><th>取证</th></tr>
              </thead>
              <tbody>
                {failedCases.map((row, index) => (
                  <tr key={`${row.task_id}-${row.attempt ?? index}`}>
                    <td>
                      <Link
                        className="mono-id"
                        to={`/runs/${report.run_id}/replay/${encodeURIComponent(row.task_id)}?attempt=${row.attempt ?? 0}`}
                      >
                        {row.task_id}
                      </Link>
                    </td>
                    <td><StatusBadge status={row.status} /></td>
                    <td>{row.category ?? '—'}</td>
                    <td>{row.severity ? <SeverityDot severity={row.severity} /> : '—'}</td>
                    <td>{row.attack_succeeded ? '是' : '否'}</td>
                    <td>{row.intercepted ? '是' : '否'}</td>
                    <td className="mono">{(row.leaked_strings ?? []).length}</td>
                    <td>{row.oracle_verdict ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  )
}
