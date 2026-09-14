import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'

const HEALTH = {
  ok: true,
  version: '0.1.0',
  target_kinds: ['inproc', 'http'],
  inproc_agents: ['demo-agent'],
  pipeline_nodes: {
    N1: '输入解析', N2: '意图识别', N3: '规划', N4: '工具选择',
    N5: '参数构造', N6: '工具执行', N7: '结果融合', N8: '输出生成',
  },
}

const TARGETS = {
  targets: [{
    id: 'tgt-demo', name: '演示 Agent', kind: 'inproc', agent_kind: 'demo-agent',
    model: 'gpt-4o-mini', base_url: '', api_key_env: '', note: '', tags: ['demo'],
  }],
}

const SUITES = {
  suites: [{
    suite_id: 'suite-basic', dataset_id: 'ds-basic', version: '0.1.0',
    description: '基础攻击面套件', root: '/data/suite-basic', task_count: 14,
    categories: { injection: 8, leakage: 6 },
    severities: { low: 3, medium: 5, high: 4, critical: 2 },
    node_coverage: { tested: ['N1', 'N2', 'N6'], untested: ['N3', 'N4', 'N5', 'N7', 'N8'], labels: {}, ratio: 0.375 },
    supports_defense_delta: true,
  }],
}

const RUNS = {
  runs: [
    {
      run_id: 'run-20240501-002', target_id: 'tgt-demo', target_name: '演示 Agent',
      suite_id: 'suite-basic', dataset_id: 'ds-basic', n_attempts: 1, max_concurrent: 2,
      command: ['redsentinel', 'run'], status: 'running', suite_run_id: 'sr-002',
      total: 14, done: 6, exit_code: null, created_at: 1714521600, finished_at: null, error: '',
      tasks: { 'task-01': { task_id: 'task-01', attempt: 0, status: 'running', seconds: null } },
      counts: { PASS: 5, FAIL: 1, ERROR: 0, running: 1 },
    },
    {
      run_id: 'run-20240501-001', target_id: 'tgt-demo', target_name: '演示 Agent',
      suite_id: 'suite-basic', dataset_id: 'ds-basic', n_attempts: 1, max_concurrent: 2,
      command: ['redsentinel', 'run'], status: 'completed', suite_run_id: 'sr-001',
      total: 14, done: 14, exit_code: 0, created_at: 1714435200, finished_at: 1714436100, error: '',
      tasks: {
        'task-01': { task_id: 'task-01', attempt: 0, status: 'PASS', seconds: 12.5 },
        'task-07': { task_id: 'task-07', attempt: 0, status: 'FAIL', seconds: 9.1 },
        'task-12': { task_id: 'task-12', attempt: 0, status: 'ERROR', seconds: 3.4 },
      },
      counts: { PASS: 12, FAIL: 1, ERROR: 1, running: 0 },
    },
  ],
}

async function openOverview(page: Page) {
  await page.route('**/api/health', (route) => route.fulfill({ json: HEALTH }))
  await page.route('**/api/targets', (route) => route.fulfill({ json: TARGETS }))
  await page.route('**/api/suites', (route) => route.fulfill({ json: SUITES }))
  await page.route('**/api/runs', (route) => route.fulfill({ json: RUNS }))
  await page.goto('/')
  await expect(page.getByRole('heading', { name: '通用 Agent 检测总览' })).toBeVisible()
  await expect(page.getByRole('img', { name: /严重度分布/ })).toBeVisible()
  // 主题切换与状态徽标带过渡/脉冲动画，axe 会测到中间态混合色，故在检测前冻结动画
  await page.addStyleTag({
    content: '*, *::before, *::after { transition: none !important; animation: none !important; }',
  })
}

async function axeIds(page: Page) {
  const results = await new AxeBuilder({ page }).analyze()
  return results.violations.map((violation) => `${violation.id}: ${violation.nodes.map((node) => node.target.join(' ')).join(', ')}`)
}

test('总览页在当前视口下无横向溢出', async ({ page }) => {
  await openOverview(page)
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  )
  expect(overflow).toBeLessThanOrEqual(0)
})

test('暗色与亮色主题下均无 axe 可达性违规', async ({ page }) => {
  await openOverview(page)
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  expect(await axeIds(page)).toEqual([])

  await page.getByRole('button', { name: '切换到亮色主题' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  expect(await axeIds(page)).toEqual([])
})

test('切换主题后刷新仍保持所选主题', async ({ page }) => {
  await openOverview(page)
  await page.getByRole('button', { name: '切换到亮色主题' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')

  await page.reload()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await expect(page.getByRole('button', { name: '切换到暗色主题' })).toBeVisible()
})
