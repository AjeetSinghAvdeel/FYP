import { useEffect, useMemo, useRef, useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import axios from 'axios'
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  Lock,
  Network,
  Radar,
  Shield,
  ShieldAlert,
  Sparkles,
  Target,
  TerminalSquare,
} from 'lucide-react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Background, Controls, ReactFlow } from '@xyflow/react'
import '@xyflow/react/dist/style.css'

const api = axios.create({ baseURL: 'http://127.0.0.1:8000/api' })

const toolConfig = [
  { name: 'Nmap', status: 'Mock fallback', description: 'Service and port discovery' },
  { name: 'FFUF', status: 'Mock fallback', description: 'Hidden content discovery' },
  { name: 'Gobuster', status: 'Mock fallback', description: 'Directory and resource enumeration' },
  { name: 'Nikto', status: 'Mock fallback', description: 'Web server checks' },
]

const defaultSummary = {
  targets: 0,
  assessments: 0,
  findings: 0,
  high_risk_findings: 0,
  risk_trend: [
    { label: 'Recon', score: 25 },
    { label: 'Enum', score: 45 },
    { label: 'Validation', score: 68 },
    { label: 'Report', score: 81 },
  ],
}

type DashboardReport = {
  id?: number
  status?: string
  target?: { url?: string }
  findings: Array<Record<string, any>>
  graph: { nodes: Array<Record<string, any>>; edges: Array<Record<string, any>> }
  timeline: Array<Record<string, any>>
  executions: Array<Record<string, any>>
}

const emptyReport: DashboardReport = { findings: [], graph: { nodes: [], edges: [] }, timeline: [], executions: [] }

function buildAssessmentGraph(report: any) {
  const executions = report?.executions || []
  if (!executions.length) return { nodes: [], edges: [] }

  const targetUrl = report.target?.url || executions[0].target || 'Assessment target'
  const rowGap = 92
  const nodes: any[] = [{
    id: 'assessment-target',
    type: 'default',
    position: { x: 0, y: Math.max(0, (executions.length - 1) * rowGap / 2) },
    data: { label: `AUTHORIZED TARGET\n${targetUrl}` },
    style: { background: '#0d2940', color: '#e8f4ff', border: '1px solid #3b82a0', borderRadius: 12, width: 190, minHeight: 76, padding: 12, fontSize: 12, fontWeight: 600, lineHeight: 1.5, whiteSpace: 'pre-line' },
  }]
  const edges: any[] = []

  executions.forEach((execution: any, index: number) => {
    const y = index * rowGap
    const observations = Array.isArray(execution.observations) ? execution.observations : []
    const services = observations.filter((item: any) => item?.type === 'service')
    const paths = observations.filter((item: any) => item?.type === 'path')
    const serverNotes = observations.filter((item: any) => item?.type === 'potential_server_issue')
    const observationDetails = services.length
      ? services.slice(0, 2).map((item: any) => `${item.port}/${item.protocol} ${item.name || 'service'} · ${item.state || 'observed'}`)
      : paths.length
        ? paths.slice(0, 2).map((item: any) => {
          const value = String(item.url || item.value || 'path')
          const path = value.match(/^([^\s]+).*?\(Status:\s*(\d+)/i)
          if (path) return `${path[1]} · HTTP ${path[2]}`
          try {
            const parsed = new URL(value)
            return `${parsed.pathname} · HTTP ${item.status || 'observed'}`
          } catch {
            return value.slice(0, 42)
          }
        })
      : serverNotes
        .map((item: any) => String(item.value || ''))
        .filter((value: string) => /access-control-allow-origin|security header missing/i.test(value))
        .slice(0, 2)
        .map((value: string) => {
          const normalized = value.toLowerCase()
          if (normalized.includes('access-control-allow-origin')) return 'CORS header: *'
          if (normalized.includes('strict-transport-security')) return 'Missing HSTS header'
          if (normalized.includes('content-security-policy')) return 'Missing CSP header'
          if (normalized.includes('permissions-policy')) return 'Missing Permissions-Policy'
          if (normalized.includes('referrer-policy')) return 'Missing Referrer-Policy'
          return value.replace(/^\[[^\]]+\]\s*/, '').slice(0, 34)
        })
    const summary = services.length
      ? `${services.length} service observation${services.length === 1 ? '' : 's'}`
      : paths.length
        ? `${paths.length} path observation${paths.length === 1 ? '' : 's'}`
        : serverNotes.length
          ? `${serverNotes.length} server observations`
          : `${observations.length} observation${observations.length === 1 ? '' : 's'}`
    const elapsed = Number.isFinite(Number(execution.duration_ms)) ? `${(Number(execution.duration_ms) / 1000).toFixed(1)} s` : 'duration unavailable'
    const hasRequestCount = execution.requests_made !== null && execution.requests_made !== undefined && Number.isFinite(Number(execution.requests_made))
    const requests = hasRequestCount ? `\n${execution.requests_made} requests` : ''
    const toolId = `execution-${execution.id}`
    const evidenceId = `evidence-${execution.id}`
    const finding = (report.findings || []).find((item: any) => item.source_tool === execution.tool)
    const evidenceLabel = finding
      ? `${summary}${observationDetails.length ? `\n${observationDetails.join(' · ')}` : ''}\n${String(finding.status || 'observed').toUpperCase()} · ${finding.title}`
      : `${summary}\nNo finding record linked`

    nodes.push({
      id: toolId,
      type: 'default',
      position: { x: 230, y },
      data: { label: `${String(execution.tool || 'tool').toUpperCase()} · ${String(execution.status || 'unknown').toUpperCase()}\n${execution.mode || 'mode unavailable'} · ${elapsed}${requests}` },
      style: { background: '#102d3a', color: '#e3f7ff', border: '1px solid #39a7c7', borderRadius: 12, width: 205, minHeight: 76, padding: 12, fontSize: 12, fontWeight: 600, lineHeight: 1.5, whiteSpace: 'pre-line' },
    })
    nodes.push({
      id: evidenceId,
      type: 'default',
      position: { x: 490, y },
      data: { label: evidenceLabel },
      style: { background: finding?.status === 'confirmed' ? '#12382d' : '#352b19', color: '#f5f0e2', border: `1px solid ${finding?.status === 'confirmed' ? '#3f9f76' : '#bb9146'}`, borderRadius: 12, width: 220, minHeight: 76, padding: 12, fontSize: 12, fontWeight: 500, lineHeight: 1.5, whiteSpace: 'pre-line' },
    })
    edges.push({ id: `target-${toolId}`, source: 'assessment-target', target: toolId, type: 'smoothstep', style: { stroke: '#4ca8c7', strokeWidth: 1.5 } })
    edges.push({ id: `${toolId}-${evidenceId}`, source: toolId, target: evidenceId, type: 'smoothstep', style: { stroke: '#8a7546', strokeWidth: 1.5 } })
  })
  return { nodes, edges }
}

const getAuthHeader = () => ({
  headers: { Authorization: `Bearer ${localStorage.getItem('token') || ''}` },
})

function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'))
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login')
  const [authForm, setAuthForm] = useState({ username: '', email: '', password: '' })
  const [authError, setAuthError] = useState('')
  const [authSubmitting, setAuthSubmitting] = useState(false)
  const [targetForm, setTargetForm] = useState({
    name: 'Demo Web App',
    target_url: 'http://127.0.0.1:3000',
    network_range: '10.10.10.0/24',
    description: 'Authorized testing target for risk-guided assessment',
    scope: 'allowlisted',
    allowed_tools: 'nmap,ffuf,gobuster,nikto',
  })
  const [summary, setSummary] = useState(defaultSummary)
  const [targets, setTargets] = useState<Array<Record<string, unknown>>>([])
  const [assessments, setAssessments] = useState<Array<Record<string, unknown>>>([])
  const [report, setReport] = useState<DashboardReport>(emptyReport)
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<number | null>(null)
  const [activityEvents, setActivityEvents] = useState<Array<Record<string, any>>>([])
  const activeEventStreams = useRef(new Set<number>())
  const [lastDecision, setLastDecision] = useState<Record<string, any> | null>(null)
  const [toolHealth, setToolHealth] = useState<Record<string, Record<string, unknown>>>({})
  const [currentUser, setCurrentUser] = useState<Record<string, unknown> | null>(null)
  const [dashboardLoading, setDashboardLoading] = useState(true)
  const [dashboardError, setDashboardError] = useState('')
  const [adminUsers, setAdminUsers] = useState<Array<Record<string, unknown>>>([])
  const [evaluationForm, setEvaluationForm] = useState({ scenario: 'local-lab', vulnerabilities: '', attackPaths: '', configuration: 'C' })
  const [evaluationResult, setEvaluationResult] = useState<Record<string, any> | null>(null)

  const isLoggedIn = Boolean(token)

  const fetchDashboard = async () => {
    if (!token) return
    setDashboardLoading(true)
    setDashboardError('')
    try {
      const [summaryRes, targetsRes, assessmentsRes, meRes] = await Promise.all([
        api.get('/dashboard/summary', getAuthHeader()),
        api.get('/targets', getAuthHeader()),
        api.get('/assessments', getAuthHeader()),
        api.get('/auth/me', getAuthHeader()),
      ])
      setSummary(summaryRes.data)
      setTargets(targetsRes.data)
      setAssessments(assessmentsRes.data)
      setCurrentUser(meRes.data)
      void api.get('/tools/health', getAuthHeader()).then((response) => setToolHealth(response.data)).catch(() => setToolHealth({}))
      const latestAssessment = assessmentsRes.data[0]
      if (latestAssessment) {
        setSelectedAssessmentId(Number(latestAssessment.id))
        const reportRes = await api.get(`/assessments/${latestAssessment.id}/report`, getAuthHeader())
        setReport(reportRes.data)
        setActivityEvents(reportRes.data.timeline || [])
        if (latestAssessment.status === 'running') {
          const lastEventId = Math.max(0, ...(reportRes.data.timeline || []).map((event: any) => Number(event.id) || 0))
          void subscribeToAssessment(Number(latestAssessment.id), lastEventId)
        }
      } else {
        setSelectedAssessmentId(null)
        setReport(emptyReport)
        setActivityEvents([])
      }
      if (meRes.data.role === 'administrator') {
        const usersRes = await api.get('/admin/users', getAuthHeader())
        setAdminUsers(usersRes.data)
      }
    } catch (error) {
      console.error('Dashboard fetch failed', error)
      setDashboardError(axios.isAxiosError(error) && error.response?.status === 401
        ? 'Your session expired. Log out and sign in again.'
        : 'Dashboard data could not be loaded. Check the backend connection and retry.')
    } finally {
      setDashboardLoading(false)
    }
  }

  const handleSelectAssessment = async (assessmentId: number) => {
    setSelectedAssessmentId(assessmentId)
    try {
      const response = await api.get(`/assessments/${assessmentId}/report`, getAuthHeader())
      setReport(response.data)
      setActivityEvents(response.data.timeline || [])
      const lastEventId = Math.max(0, ...(response.data.timeline || []).map((event: any) => Number(event.id) || 0))
      if (response.data.status === 'running') void subscribeToAssessment(assessmentId, lastEventId)
    } catch (error) {
      console.error('Assessment report fetch failed', error)
    }
  }

  const subscribeToAssessment = async (assessmentId: number, afterEventId = 0) => {
    if (!token) return
    if (activeEventStreams.current.has(assessmentId)) return
    activeEventStreams.current.add(assessmentId)
    try {
      const response = await fetch(`${api.defaults.baseURL}/assessments/${assessmentId}/events?after_event_id=${afterEventId}`, getAuthHeader())
      if (!response.ok || !response.body) return
      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const blocks = buffer.split('\n\n')
        buffer = blocks.pop() || ''
        for (const block of blocks) {
          const eventLine = block.split('\n').find((line) => line.startsWith('event: '))
          const dataLine = block.split('\n').find((line) => line.startsWith('data: '))
          if (!dataLine) continue
          const state = JSON.parse(dataLine.slice(6))
          if (eventLine?.slice(7) === 'activity') {
            setActivityEvents((current) => current.some((item) => item.id === state.id) ? current : [...current, state].slice(-80))
            if (state.event_type === 'tool_execution' || state.event_type === 'graph_update') {
              const reportResponse = await api.get(`/assessments/${assessmentId}/report`, getAuthHeader())
              setReport(reportResponse.data)
            }
          } else {
            setAssessments((current) => current.map((item) => item.id === assessmentId ? { ...item, ...state } : item))
            setReport((current) => ({ ...current, status: state.status || current.status }))
          }
        }
      }
    } catch (error) {
      console.error('Assessment event stream failed', error)
    } finally {
      activeEventStreams.current.delete(assessmentId)
    }
  }

  useEffect(() => {
    fetchDashboard()
  }, [token])

  const handleAuth = async () => {
    setAuthError('')
    const username = authForm.username.trim()
    const email = authForm.email.trim()
    if (!username || !authForm.password) {
      setAuthError('Enter your username and password.')
      return
    }
    if (authMode === 'register') {
      if (username.length < 3) {
        setAuthError('Username must be at least 3 characters.')
        return
      }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        setAuthError('Enter a valid email address.')
        return
      }
      if (authForm.password.length < 8) {
        setAuthError('Password must be at least 8 characters.')
        return
      }
    }
    if (authSubmitting) return
    setAuthSubmitting(true)
    try {
      const endpoint = authMode === 'login' ? '/auth/login' : '/auth/register'
      const key = authMode === 'login'
        ? { username, password: authForm.password }
        : { username, email, password: authForm.password }
      const response = await api.post(endpoint, key)
      localStorage.setItem('token', response.data.access_token)
      setToken(response.data.access_token)
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const detail = error.response?.data?.detail
        if (typeof detail === 'string') {
          setAuthError(detail)
        } else if (Array.isArray(detail)) {
          const messages = detail
            .map((item) => typeof item?.msg === 'string' ? item.msg : '')
            .filter(Boolean)
          setAuthError(messages.join(' ') || 'Check the submitted details and try again.')
        } else {
          setAuthError(error.response
            ? `The request failed with HTTP ${error.response.status}. Please try again.`
            : 'Could not reach the FastAPI backend at 127.0.0.1:8000.')
        }
      } else {
        setAuthError('Authentication could not be completed. Please try again.')
      }
    } finally {
      setAuthSubmitting(false)
    }
  }

  const handleCreateTarget = async () => {
    if (!token) return
    try {
      const response = await api.post('/targets', targetForm, getAuthHeader())
      setTargets((current) => [response.data, ...current])
      setTargetForm({
        name: '',
        target_url: '',
        network_range: '',
        description: '',
        scope: 'allowlisted',
        allowed_tools: 'nmap,ffuf,gobuster,nikto',
      })
    } catch (error) {
      console.error(error)
      alert('Target creation failed.')
    }
  }

  const handleCreateAssessment = async (targetId: number) => {
    if (!token) return
    try {
      const payload = { name: `Assessment for ${targetForm.name || 'Target'}`, target_id: targetId, budget: 6 }
      const response = await api.post('/assessments', payload, getAuthHeader())
      setAssessments((current) => [response.data, ...current])
      setSelectedAssessmentId(Number(response.data.id))
      const reportRes = await api.get(`/assessments/${response.data.id}/report`, getAuthHeader())
      setReport(reportRes.data)
      setActivityEvents(reportRes.data.timeline || [])
    } catch (error) {
      console.error(error)
      alert('Assessment creation failed.')
    }
  }

  const handleRunAssessment = async (assessmentId: number) => {
    if (!token) return
    setSelectedAssessmentId(assessmentId)
    const lastEventId = Math.max(0, ...activityEvents.map((event) => Number(event.id) || 0))
    void subscribeToAssessment(assessmentId, lastEventId)
    try {
      const response = await api.post(`/assessments/${assessmentId}/run`, {}, getAuthHeader())
      setLastDecision(response.data.tool === 'none' ? null : response.data)
      const reportRes = await api.get(`/assessments/${assessmentId}/report`, getAuthHeader())
      setReport(reportRes.data)
      setActivityEvents(reportRes.data.timeline || [])
      setAssessments((current) =>
        current.map((item) => (item.id === assessmentId ? {
          ...item,
          status: reportRes.data.status || response.data.status || item.status,
          next_action: response.data.tool === 'none' ? null : response.data.tool,
          requests_used: reportRes.data.budget?.used ?? item.requests_used,
          progress: reportRes.data.budget?.utilization != null ? Math.round(reportRes.data.budget.utilization * 100) : item.progress,
        } : item)),
      )
    } catch (error) {
      console.error(error)
      alert('Execution step failed.')
    }
  }

  const handleAssessmentControl = async (assessmentId: number, action: 'start' | 'pause' | 'resume' | 'stop') => {
    if (!token) return
    try {
      const response = await api.post(`/assessments/${assessmentId}/${action}`, {}, getAuthHeader())
      setAssessments((current) => current.map((item) => (item.id === assessmentId ? { ...item, status: response.data.status } : item)))
      if (action === 'start' || action === 'resume') {
        setSelectedAssessmentId(assessmentId)
        const lastEventId = Math.max(0, ...activityEvents.map((event) => Number(event.id) || 0))
        void subscribeToAssessment(assessmentId, lastEventId)
      }
    } catch (error) {
      console.error(error)
      alert(`Assessment ${action} failed.`)
    }
  }

  const downloadReport = async (assessmentId: number) => {
    if (!token) return
    const response = await api.get(`/assessments/${assessmentId}/report.pdf`, { ...getAuthHeader(), responseType: 'blob' })
    const link = document.createElement('a')
    link.href = URL.createObjectURL(response.data)
    link.download = `assessment-${assessmentId}.pdf`
    link.click()
    URL.revokeObjectURL(link.href)
  }

  const runEvaluation = async () => {
    if (!token) return
    const observedVulnerabilities = report.findings.map((item) => String(item.title))
    const observedPaths = (report.graph?.edges || []).map((edge: any) => String(edge.id))
    const response = await api.post('/evaluations/run', {
      scenario: evaluationForm.scenario,
      configuration: evaluationForm.configuration,
      ground_truth: {
        vulnerabilities: evaluationForm.vulnerabilities.split(',').map((item) => item.trim()).filter(Boolean),
        attack_paths: evaluationForm.attackPaths.split(',').map((item) => item.trim()).filter(Boolean),
      },
      observed: {
        vulnerabilities: observedVulnerabilities,
        candidate_vulnerabilities: observedVulnerabilities,
        confirmed_vulnerabilities: report.findings.filter((item) => item.status === 'confirmed').map((item) => String(item.title)),
        attack_paths: observedPaths,
        tool_actions: report.executions?.length || 0,
        elapsed_seconds: 0,
        selected_actions: report.executions?.map((item) => String(item.tool)) || [],
        risk_rank: report.executions?.map((item) => String(item.tool)) || [],
      },
    }, getAuthHeader())
    setEvaluationResult(response.data)
  }

  const updateUserRole = async (userId: number, role: string) => {
    await api.patch(`/admin/users/${userId}/role`, { role }, getAuthHeader())
    setAdminUsers((users) => users.map((user) => user.id === userId ? { ...user, role } : user))
  }

  const assessmentGraph = useMemo(() => buildAssessmentGraph(report), [report])
  const graphNodes = assessmentGraph.nodes
  const graphEdges = assessmentGraph.edges

  const authPanel = (
    <div className="rounded-3xl border border-slate-700 bg-slate-950/60 p-8 shadow-glow">
      <div className="mb-6 flex items-center gap-3">
        <div className="rounded-xl bg-cyberspace-500/15 p-3 text-cyberspace-300">
          <ShieldAlert size={22} />
        </div>
        <div>
          <p className="text-xs uppercase tracking-[0.28em] text-cyberspace-300">Security Control Plane</p>
          <h2 className="mt-1 text-2xl font-semibold text-white">Risk-Guided Pentest</h2>
        </div>
      </div>

      <div className="mb-6 flex rounded-xl border border-slate-700 bg-slate-900/80 p-1 text-sm">
        {(['login', 'register'] as const).map((option) => (
          <button
            key={option}
            className={`flex-1 rounded-xl px-3 py-2 font-medium ${authMode === option ? 'bg-cyberspace-500 text-slate-950' : 'text-slate-300'}`}
            onClick={() => { setAuthMode(option); setAuthError('') }}
          >
            {option === 'login' ? 'Login' : 'Register'}
          </button>
        ))}
      </div>

      <div className="space-y-4">
        <label className="block text-sm text-slate-300">
          Username
          <input autoComplete="username" value={authForm.username} onChange={(e) => { setAuthForm((cur) => ({ ...cur, username: e.target.value })); setAuthError('') }} className="mt-2 w-full rounded-xl border border-slate-700 bg-slate-900/80 px-3 py-2 text-white outline-none ring-0" />
        </label>
        {authMode === 'register' && (
          <label className="block text-sm text-slate-300">
            Email
            <input type="email" autoComplete="email" value={authForm.email} onChange={(e) => { setAuthForm((cur) => ({ ...cur, email: e.target.value })); setAuthError('') }} className="mt-2 w-full rounded-xl border border-slate-700 bg-slate-900/80 px-3 py-2 text-white outline-none ring-0" />
          </label>
        )}
        <label className="block text-sm text-slate-300">
          Password
          <input type="password" autoComplete={authMode === 'login' ? 'current-password' : 'new-password'} value={authForm.password} onChange={(e) => { setAuthForm((cur) => ({ ...cur, password: e.target.value })); setAuthError('') }} className="mt-2 w-full rounded-xl border border-slate-700 bg-slate-900/80 px-3 py-2 text-white outline-none ring-0" />
        </label>
        {authMode === 'register' && <p className="-mt-2 text-xs text-slate-400">Password must be at least 8 characters.</p>}
      </div>

      {authError && <p role="alert" className="mt-4 rounded-lg border border-rose-400/30 bg-rose-950/30 px-3 py-2 text-sm text-rose-200">{authError}</p>}

      <button onClick={handleAuth} disabled={authSubmitting} className="mt-6 flex w-full items-center justify-center gap-2 rounded-xl bg-cyberspace-500 px-4 py-3 font-semibold text-slate-950 transition hover:bg-cyberspace-400 disabled:cursor-wait disabled:opacity-70">
        {authSubmitting ? 'Please wait...' : authMode === 'login' ? 'Authenticate' : 'Create account'}
        <ArrowRight size={18} />
      </button>
    </div>
  )

  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/"
          element={
            !isLoggedIn ? (
              <div className="bg-slate-950 min-h-screen text-slate-100">
                <div className="mx-auto grid max-w-6xl gap-10 px-6 py-16 lg:grid-cols-[1.2fr_0.8fr] lg:items-center">
                  <div>
                    <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-cyberspace-500/30 bg-cyberspace-500/10 px-3 py-1 text-xs uppercase tracking-[0.24em] text-cyberspace-300">
                      <Sparkles size={14} /> Autonomous security operations
                    </div>
                    <h1 className="max-w-xl text-5xl font-bold tracking-tight text-white lg:text-6xl">
                      Adaptive pentesting driven by evidence and risk.
                    </h1>
                    <p className="mt-6 max-w-xl text-lg text-slate-300">
                      The platform selects the next authorized security test based on asset criticality, threat context, and observed validation evidence.
                    </p>
                    <div className="mt-8 grid gap-4 sm:grid-cols-3">
                      {[
                        { label: 'Risk engine', value: '89%' },
                        { label: 'Policy checks', value: 'Always' },
                        { label: 'Evidence strength', value: '7/10' },
                      ].map((stat) => (
                        <div key={stat.label} className="rounded-2xl border border-slate-700 bg-slate-900/60 p-4">
                          <div className="text-2xl font-semibold text-white">{stat.value}</div>
                          <div className="mt-2 text-xs uppercase tracking-[0.2em] text-slate-400">{stat.label}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                  {authPanel}
                </div>
              </div>
            ) : (
              <div className="min-h-screen bg-slate-950 text-slate-100">
                <div className="mx-auto max-w-7xl px-4 py-10">
                  <header className="mb-8 flex flex-col gap-4 rounded-3xl border border-slate-700 bg-slate-900/80 p-6 md:flex-row md:items-center md:justify-between">
                    <div>
                      <p className="text-xs uppercase tracking-[0.32em] text-cyberspace-300">Mission control</p>
                      <h2 className="mt-2 text-3xl font-semibold text-white">Adaptive assessment dashboard</h2>
                    </div>
                    <button
                      onClick={() => {
                        localStorage.removeItem('token')
                        setToken(null)
                      }}
                      className="rounded-xl border border-slate-700 bg-slate-950 px-4 py-2 text-sm text-slate-200"
                    >
                      Logout
                    </button>
                  </header>

                  {dashboardError && <p role="alert" className="mb-6 rounded-xl border border-rose-400/30 bg-rose-950/30 px-4 py-3 text-sm text-rose-200">{dashboardError}</p>}

                  <section className="mb-8 grid gap-4 md:grid-cols-4">
                    {[
                      { label: 'Targets', value: summary.targets, icon: <Target size={18} /> },
                      { label: 'Assessments', value: summary.assessments, icon: <Radar size={18} /> },
                      { label: 'Findings', value: summary.findings, icon: <Shield size={18} /> },
                      { label: 'High risk', value: summary.high_risk_findings, icon: <ShieldAlert size={18} /> },
                    ].map((card) => (
                      <div key={card.label} className="rounded-3xl border border-slate-700 bg-slate-900/80 p-5">
                        <div className="flex items-center justify-between text-cyberspace-300">{card.icon}<span className="text-xs uppercase tracking-[0.2em]">{card.label}</span></div>
                        <div className="mt-6 text-4xl font-bold text-white">{dashboardLoading ? '…' : card.value}</div>
                      </div>
                    ))}
                  </section>

                  <div className="grid gap-8 xl:grid-cols-[1.2fr_0.8fr]">
                    <div className="space-y-8">
                      <div className="rounded-3xl border border-slate-700 bg-slate-900/80 p-5">
                        <div className="mb-5 flex items-center justify-between">
                          <div>
                            <p className="text-xs uppercase tracking-[0.2em] text-cyberspace-300">Risk trend</p>
                            <h3 className="mt-2 text-xl font-semibold text-white">Adaptive prioritization curve</h3>
                          </div>
                          <div className="rounded-full bg-emerald-500/15 px-2 py-1 text-xs font-medium text-emerald-300">Stable</div>
                        </div>
                        <div className="h-72 w-full">
                          <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={summary.risk_trend}>
                              <defs>
                                <linearGradient id="riskFill" x1="0" x2="0" y1="0" y2="1">
                                  <stop offset="5%" stopColor="#5ec7ff" stopOpacity={0.8} />
                                  <stop offset="95%" stopColor="#5ec7ff" stopOpacity={0.08} />
                                </linearGradient>
                              </defs>
                              <CartesianGrid stroke="#334155" strokeDasharray="3 3" />
                              <XAxis dataKey="label" stroke="#94a3b8" />
                              <YAxis stroke="#94a3b8" domain={[0, 100]} />
                              <Tooltip />
                              <Area type="monotone" dataKey="score" stroke="#5ec7ff" fill="url(#riskFill)" strokeWidth={3} />
                            </AreaChart>
                          </ResponsiveContainer>
                        </div>
                      </div>

                      <div className="rounded-3xl border border-slate-700 bg-slate-900/80 p-5">
                        <div className="mb-5 flex items-center justify-between">
                          <div>
                            <p className="text-xs uppercase tracking-[0.2em] text-cyberspace-300">Attack graph</p>
                            <h3 className="mt-2 text-xl font-semibold text-white">Assessment evidence map</h3>
                            <p className="mt-1 text-xs text-slate-400">Execution order and observed evidence; candidate observations are not confirmed vulnerabilities.</p>
                          </div>
                          <div className="flex items-center gap-2 rounded-full bg-cyberspace-500/15 px-3 py-1 text-xs text-cyberspace-200">
                            <Network size={14} /> {selectedAssessmentId ? `Assessment ${selectedAssessmentId} · ${report.status || 'saved'}` : 'No assessment selected'}
                          </div>
                        </div>
                        <div className="h-[28rem] overflow-hidden rounded-xl border border-slate-700/70 bg-slate-950/70">
                          {graphNodes.length ? (
                            <ReactFlow key={`${selectedAssessmentId ?? 'none'}-${graphNodes.length}`} nodes={graphNodes} edges={graphEdges} fitView fitViewOptions={{ padding: 0.08, minZoom: 0.78, maxZoom: 1 }}>
                              <Background color="#294052" gap={20} size={1} />
                              <Controls />
                            </ReactFlow>
                          ) : (
                            <div className="flex h-full flex-col items-center justify-center gap-2 px-6 text-center">
                              <Network size={24} className="text-slate-500" />
                              <p className="font-medium text-slate-200">{dashboardLoading ? 'Loading assessment data' : 'No assessment evidence yet'}</p>
                              <p className="max-w-md text-sm text-slate-400">{dashboardLoading ? 'Checking the latest authorized assessment and its persisted tool records.' : 'Create an assessment, then run an authorized step. Actual tool executions and observations will appear here.'}</p>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="space-y-8">
                      <div className="rounded-3xl border border-slate-700 bg-slate-900/80 p-5">
                        <div className="mb-5 flex items-center gap-3 text-cyberspace-300">
                          <Lock size={18} />
                          <p className="text-xs uppercase tracking-[0.2em]">Target registration</p>
                        </div>
                        <div className="space-y-3">
                          <input value={targetForm.name} onChange={(e) => setTargetForm((cur) => ({ ...cur, name: e.target.value }))} placeholder="Target name" className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
                          <input value={targetForm.target_url} onChange={(e) => setTargetForm((cur) => ({ ...cur, target_url: e.target.value }))} placeholder="https://example.com" className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
                          <input value={targetForm.network_range} onChange={(e) => setTargetForm((cur) => ({ ...cur, network_range: e.target.value }))} placeholder="Network range" className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
                          <textarea value={targetForm.description} onChange={(e) => setTargetForm((cur) => ({ ...cur, description: e.target.value }))} placeholder="Scope and notes" className="h-24 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
                          <button onClick={handleCreateTarget} className="w-full rounded-xl bg-cyberspace-500 px-4 py-3 font-semibold text-slate-950">Register target</button>
                        </div>
                      </div>

                      <div className="rounded-3xl border border-slate-700 bg-slate-900/80 p-5">
                        <div className="mb-5 flex items-center gap-3 text-cyberspace-300">
                          <Activity size={18} />
                          <p className="text-xs uppercase tracking-[0.2em]">Execution adapters</p>
                        </div>
                        <div className="space-y-3">
                          {toolConfig.map((tool) => (
                            <div key={tool.name} className="rounded-2xl border border-slate-700 bg-slate-950/70 p-3">
                              <div className="flex items-center justify-between">
                                <span className="font-medium text-white">{tool.name}</span>
                                  <span className={`rounded-full px-2 py-1 text-xs ${toolHealth[tool.name.toLowerCase()]?.installed ? 'bg-emerald-500/15 text-emerald-300' : 'bg-amber-500/15 text-amber-300'}`}>{toolHealth[tool.name.toLowerCase()]?.installed ? String(toolHealth[tool.name.toLowerCase()]?.version || 'Installed') : 'Mock fallback'}</span>
                              </div>
                              <p className="mt-2 text-sm text-slate-300">{tool.description}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="mt-8 grid gap-8 lg:grid-cols-2">
                    <div className="rounded-3xl border border-slate-700 bg-slate-900/80 p-5">
                      <div className="mb-5 flex items-center gap-3 text-cyberspace-300">
                        <TerminalSquare size={18} />
                        <p className="text-xs uppercase tracking-[0.2em]">Authorized targets</p>
                      </div>
                      <div className="space-y-3">
                        {targets.length === 0 ? <p className="text-slate-400">{dashboardLoading ? 'Loading authorized targets…' : 'No targets registered.'}</p> : targets.map((target) => (
                          <div key={String(target.id)} className="rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                            <div className="flex items-center justify-between">
                              <div>
                                <div className="font-medium text-white">{String(target.name)}</div>
                                <div className="text-sm text-slate-400">{String(target.target_url)}</div>
                              </div>
                              <button onClick={() => handleCreateAssessment(Number(target.id))} className="rounded-lg bg-slate-800 px-3 py-2 text-sm text-cyberspace-200">Create assessment</button>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="rounded-3xl border border-slate-700 bg-slate-900/80 p-5">
                      <div className="mb-5 flex items-center gap-3 text-cyberspace-300">
                        <CheckCircle2 size={18} />
                        <p className="text-xs uppercase tracking-[0.2em]">Assessment queue</p>
                      </div>
                      <div className="space-y-3">
                        {assessments.length === 0 ? <p className="text-slate-400">{dashboardLoading ? 'Loading assessments…' : 'No assessments started.'}</p> : assessments.map((assessment) => (
                          <div key={String(assessment.id)} className={`rounded-2xl border bg-slate-950/70 p-4 ${selectedAssessmentId === Number(assessment.id) ? 'border-cyberspace-500/70' : 'border-slate-700'}`}>
                            <div className="flex items-center justify-between gap-3">
                              <div>
                                <div className="font-medium text-white">{String(assessment.name)}</div>
                                <div className="text-sm text-slate-400">{String(assessment.status || 'initialized')}</div>
                              </div>
                              <div className="flex flex-wrap justify-end gap-2">
                                <button onClick={() => void handleSelectAssessment(Number(assessment.id))} className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-200">View activity</button>
                                <button disabled={['completed', 'failed', 'stopped', 'paused'].includes(String(assessment.status))} onClick={() => handleRunAssessment(Number(assessment.id))} className="rounded-lg bg-cyberspace-500 px-3 py-2 text-sm font-medium text-slate-950 disabled:cursor-not-allowed disabled:opacity-50">Run next step</button>
                                <button disabled={['completed', 'failed', 'stopped'].includes(String(assessment.status))} onClick={() => handleAssessmentControl(Number(assessment.id), 'start')} className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-200 disabled:cursor-not-allowed disabled:opacity-50">Start job</button>
                                <button onClick={() => handleAssessmentControl(Number(assessment.id), assessment.status === 'paused' ? 'resume' : 'pause')} className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-200">{assessment.status === 'paused' ? 'Resume' : 'Pause'}</button>
                                <button onClick={() => handleAssessmentControl(Number(assessment.id), 'stop')} className="rounded-lg border border-red-500/40 px-3 py-2 text-xs text-red-300">Stop</button>
                                <button onClick={() => downloadReport(Number(assessment.id))} className="rounded-lg border border-cyberspace-500/40 px-3 py-2 text-xs text-cyberspace-200">PDF report</button>
                              </div>
                            </div>
                            <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-slate-800"><div className="h-full bg-cyberspace-500" style={{ width: `${Number(assessment.progress || 0)}%` }} /></div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {lastDecision && (
                    <div className="mt-8 rounded-3xl border border-cyberspace-500/30 bg-cyberspace-500/5 p-5">
                      <div className="mb-4 flex items-center justify-between">
                        <div>
                          <p className="text-xs uppercase tracking-[0.2em] text-cyberspace-300">Decision transparency</p>
                          <h3 className="mt-2 text-xl font-semibold text-white">{String(lastDecision.tool).toUpperCase()} selected next</h3>
                        </div>
                        <span className="rounded-full bg-emerald-500/15 px-3 py-1 text-xs text-emerald-300">{String(lastDecision.authorization)}</span>
                      </div>
                      <p className="text-sm text-slate-300">{String(lastDecision.recommendation)}</p>
                      <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                        {Object.entries(lastDecision.score_breakdown || {}).map(([factor, contribution]) => (
                          <div key={factor} className="rounded-xl border border-slate-700 bg-slate-950/70 px-3 py-2">
                            <div className="text-xs uppercase tracking-wider text-slate-400">{factor.replaceAll('_', ' ')}</div>
                            <div className="mt-1 font-semibold text-white">{String(contribution)}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="mt-8 grid gap-8 lg:grid-cols-2">
                    <div className="rounded-3xl border border-slate-700 bg-slate-900/80 p-5">
                          <div className="mb-4 flex items-center justify-between">
                            <div><p className="text-xs uppercase tracking-[0.2em] text-cyberspace-300">Live activity</p><h3 className="mt-2 text-xl font-semibold text-white">Assessment run log</h3></div>
                          <span className="rounded-full bg-cyberspace-500/10 px-2 py-1 text-xs text-cyberspace-200">{activityEvents.length} events · {report.status === 'running' ? 'LIVE' : 'SAVED'}</span>
                      </div>
                      <div className="max-h-64 space-y-3 overflow-auto">
                        {activityEvents.length === 0 ? <p className="text-sm text-slate-400">Start an assessment to stream planning, policy, tool, and evidence events here.</p> : [...activityEvents].slice(-16).reverse().map((event: any) => (
                          <div key={String(event.id)} className="flex gap-3 border-l border-cyberspace-500/50 pl-3">
                            <time className="min-w-16 pt-0.5 text-[11px] tabular-nums text-slate-500">{event.created_at ? new Date(String(event.created_at)).toLocaleTimeString() : '--:--'}</time>
                            <div className="min-w-0 flex-1">
                              <div className="text-xs font-medium uppercase tracking-wider text-cyberspace-300">{String(event.event_type).replaceAll('_', ' ')}{event.action ? ` · ${String(event.action)}` : ''}</div>
                              <div className="break-words text-sm text-slate-300">{String(event.outcome || event.decision || event.current_state?.phase || '')}</div>
                              {(event.current_state?.selection?.selection_reason || event.current_state?.selection_reason) && <div className="mt-1 text-xs text-slate-400">{String(event.current_state?.selection?.selection_reason || event.current_state?.selection_reason)}</div>}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="rounded-3xl border border-slate-700 bg-slate-900/80 p-5">
                      <div className="mb-4"><p className="text-xs uppercase tracking-[0.2em] text-cyberspace-300">Evaluation</p><h3 className="mt-2 text-xl font-semibold text-white">Compare a measured run</h3></div>
                      <div className="space-y-3">
                        <input value={evaluationForm.scenario} onChange={(e) => setEvaluationForm((current) => ({ ...current, scenario: e.target.value }))} placeholder="Scenario name" className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
                        <input value={evaluationForm.vulnerabilities} onChange={(e) => setEvaluationForm((current) => ({ ...current, vulnerabilities: e.target.value }))} placeholder="Known vulnerabilities, comma separated" className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
                        <input value={evaluationForm.attackPaths} onChange={(e) => setEvaluationForm((current) => ({ ...current, attackPaths: e.target.value }))} placeholder="Known attack paths, comma separated" className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white" />
                        <select value={evaluationForm.configuration} onChange={(e) => setEvaluationForm((current) => ({ ...current, configuration: e.target.value }))} className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-white"><option value="A">A · Fixed workflow</option><option value="B">B · LLM without risk</option><option value="C">C · Risk-guided adaptive</option></select>
                        <button onClick={runEvaluation} className="w-full rounded-xl bg-cyberspace-500 px-4 py-3 font-semibold text-slate-950">Calculate measured metrics</button>
                      </div>
                      {evaluationResult && <div className="mt-4 grid grid-cols-2 gap-2">{Object.entries(evaluationResult.metrics || {}).map(([metric, result]: any) => <div key={metric} className="rounded-xl border border-slate-700 bg-slate-950/70 p-3"><div className="text-xs uppercase tracking-wider text-slate-400">{metric.replaceAll('_', ' ')}</div><div className="mt-1 text-lg font-semibold text-white">{Number(result.value).toFixed(2)}</div></div>)}</div>}
                    </div>
                  </div>

                  {currentUser?.role === 'administrator' && (
                    <div className="mt-8 rounded-3xl border border-slate-700 bg-slate-900/80 p-5">
                      <div className="mb-4"><p className="text-xs uppercase tracking-[0.2em] text-cyberspace-300">Administration</p><h3 className="mt-2 text-xl font-semibold text-white">User roles</h3></div>
                      <div className="grid gap-3 md:grid-cols-2">
                        {adminUsers.map((user) => <div key={String(user.id)} className="flex items-center justify-between rounded-xl border border-slate-700 bg-slate-950/70 p-3"><div><div className="font-medium text-white">{String(user.username)}</div><div className="text-xs text-slate-400">{String(user.email)}</div></div><select value={String(user.role)} onChange={(event) => void updateUserRole(Number(user.id), event.target.value)} className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-white"><option value="security_operator">Operator</option><option value="administrator">Administrator</option></select></div>)}
                      </div>
                    </div>
                  )}

                  <div className="mt-8 rounded-3xl border border-slate-700 bg-slate-900/80 p-5">
                    <div className="mb-5 flex items-center justify-between">
                      <div>
                        <p className="text-xs uppercase tracking-[0.2em] text-cyberspace-300">Findings and evidence</p>
                        <h3 className="mt-2 text-xl font-semibold text-white">Validated evidence stream</h3>
                      </div>
                    </div>
                    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                      {report.findings.length === 0 ? (
                        <p className="text-slate-400">No recorded findings yet. Start an assessment to populate the evidence queue.</p>
                      ) : report.findings.map((finding: any, index: number) => (
                        <div key={`${finding.title || 'finding'}-${index}`} className="rounded-2xl border border-slate-700 bg-slate-950/70 p-4">
                          <div className="mb-3 flex items-center justify-between">
                            <span className="rounded-full bg-cyberspace-500/15 px-2 py-1 text-xs text-cyberspace-200">{finding.source_tool}</span>
                            <span className="text-xs uppercase tracking-[0.2em] text-amber-300">{finding.severity}</span>
                          </div>
                          <div className="font-medium text-white">{finding.title}</div>
                          <div className="mt-2 text-sm text-slate-300">{finding.status}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
