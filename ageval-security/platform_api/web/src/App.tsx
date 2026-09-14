import { useState } from 'react'
import { NavLink, Navigate, Outlet, Route, Routes } from 'react-router-dom'
import {
  GitCompareArrows, History, LayoutDashboard, Layers, Moon, PlayCircle, ShieldHalf, Sun, Target,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { api } from './api'
import { useLoad } from './hooks'
import { initTheme, setTheme } from './theme'
import Overview from './pages/Overview'
import Targets from './pages/Targets'
import Suites from './pages/Suites'
import SuiteDetail from './pages/SuiteDetail'
import NewRun from './pages/NewRun'
import Runs from './pages/Runs'
import RunDetail from './pages/RunDetail'
import ReplayPage from './pages/Replay'
import Compare from './pages/Compare'

type NavItem = { to: string; label: string; icon: LucideIcon; end?: boolean }

const NAV_GROUPS: { title: string; items: NavItem[] }[] = [
  {
    title: '工作台',
    items: [{ to: '/', label: '总览', icon: LayoutDashboard, end: true }],
  },
  {
    title: '检测作业',
    items: [
      { to: '/targets', label: '检测目标', icon: Target },
      { to: '/suites', label: '测试套件', icon: Layers },
      { to: '/runs/new', label: '发起检测', icon: PlayCircle },
      { to: '/runs', label: '运行历史', icon: History, end: true },
    ],
  },
  {
    title: '分析对比',
    items: [{ to: '/compare', label: '横向对比', icon: GitCompareArrows }],
  },
]

function Shell() {
  const { data: health, error } = useLoad(api.health)
  const [theme, setThemeState] = useState(initTheme)
  const online = Boolean(health?.ok) && !error

  function toggleTheme() {
    const next = theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    setThemeState(next)
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark"><ShieldHalf size={19} /></span>
          <strong>Sentinel<span>Agent Detection</span></strong>
        </div>
        <nav aria-label="主导航">
          {NAV_GROUPS.map((group) => (
            <div className="nav-group" key={group.title}>
              <p className="nav-group-title">{group.title}</p>
              {group.items.map(({ to, label, icon: Icon, end }) => (
                <NavLink to={to} end={end} key={to}><Icon size={17} />{label}</NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span className={online ? 'dot-on' : 'dot-off'}>● {online ? '平台服务在线' : '平台服务不可用'}</span>
          <span>v{health?.version ?? '—'}</span>
        </div>
      </aside>
      <div className="main-col">
        <header className="topbar">
          <button
            type="button"
            className="button ghost small"
            onClick={toggleTheme}
            aria-label={theme === 'dark' ? '切换到亮色主题' : '切换到暗色主题'}
          >
            {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
            {theme === 'dark' ? '亮色' : '暗色'}
          </button>
        </header>
        <div className="workspace">
          <main><Outlet /></main>
        </div>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<Overview />} />
        <Route path="targets" element={<Targets />} />
        <Route path="suites" element={<Suites />} />
        <Route path="suites/:suiteId" element={<SuiteDetail />} />
        <Route path="runs" element={<Runs />} />
        <Route path="runs/new" element={<NewRun />} />
        <Route path="runs/:runId" element={<RunDetail />} />
        <Route path="runs/:runId/replay/:taskId" element={<ReplayPage />} />
        <Route path="compare" element={<Compare />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
