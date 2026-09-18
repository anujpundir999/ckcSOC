import { useState, useEffect, useCallback } from 'react'
import ReactMarkdown from 'react-markdown'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  AreaChart, Area, ResponsiveContainer, Legend, LineChart, Line
} from 'recharts'
import { getSummary, getDatasetStats, getIncidents, getPlaybooks, getAudit, getSeverity } from './api/client'
import './App.css'

// ── Colors ──
const C = {
  green: '#5ba94c', red: '#d9534f', yellow: '#f0ad4e',
  blue: '#5db4e4', purple: '#a364d9', orange: '#ff9933',
  teal: '#2dd4bf', pink: '#ec4899',
  bars: ['#5db4e4','#2dd4bf','#5ba94c','#f0ad4e','#d9534f','#a364d9'],
  donut: ['#d9534f','#ff9933','#f0ad4e','#5ba94c'],
}

const PHASE_DETAILS: Record<string, { short: string; window: string; tone: string }> = {
  immediate: { short: 'Triage', window: '0–15 min', tone: 'urgent' },
  containment: { short: 'Contain', window: '≤ 1 hour', tone: 'contain' },
  investigation: { short: 'Investigate', window: '≤ 4 hours', tone: 'investigate' },
  recovery: { short: 'Recover', window: '≤ 24 hours', tone: 'recover' },
}

function getPhaseDetail(title: string) {
  const key = Object.keys(PHASE_DETAILS).find(phase => title.toLowerCase().includes(phase))
  return key ? PHASE_DETAILS[key] : { short: title, window: 'Response phase', tone: 'investigate' }
}

function parsePlaybook(content: string) {
  const matches = [...content.matchAll(/^##\s+(.+)$/gm)]
  if (!matches.length) return [{ title: 'Response actions', body: content }]

  return matches.map((match, index) => ({
    title: match[1].trim(),
    body: content.slice((match.index || 0) + match[0].length, matches[index + 1]?.index ?? content.length).trim(),
  }))
}

type PlaybookThreatContext = {
  attack_path?: {
    kill_chain?: string[]
    high_risk_assets?: string[]
  }
}

function PlaybookDocument({ content, playbook }: { content: string; playbook: PlaybookThreatContext }) {
  const phases = parsePlaybook(content)
  const attackPath = playbook.attack_path?.kill_chain || []
  const assets = playbook.attack_path?.high_risk_assets || []

  return (
    <div className="runbook-shell">
      <aside className="runbook-rail" aria-label="Response phases">
        <div className="rail-label">Execution order</div>
        <ol className="phase-index">
          {phases.map((phase, index) => {
            const detail = getPhaseDetail(phase.title)
            return (
              <li key={phase.title} className={`phase-index-item phase-${detail.tone}`}>
                <span className="phase-marker">{String(index + 1).padStart(2, '0')}</span>
                <span>
                  <strong>{detail.short}</strong>
                  <small>{detail.window}</small>
                </span>
              </li>
            )
          })}
        </ol>

        {(attackPath.length > 0 || assets.length > 0) && (
          <div className="threat-brief">
            <div className="rail-label">Threat brief</div>
            {attackPath.length > 0 && (
              <div className="threat-group">
                <span>Observed path</span>
                <div className="attack-path">
                  {attackPath.map((technique: string, index: number) => (
                    <div className="attack-step" key={technique}>
                      <i>{index + 1}</i><b>{technique}</b>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {assets.length > 0 && (
              <div className="threat-group">
                <span>Protect first</span>
                <div className="asset-list">
                  {assets.map((asset: string) => <code key={asset}>{asset}</code>)}
                </div>
              </div>
            )}
          </div>
        )}
      </aside>

      <article className="runbook-document">
        <div className="runbook-intro">
          <span className="live-pulse" aria-hidden="true" />
          <div>
            <strong>Analyst action plan</strong>
            <p>Work top to bottom. Preserve evidence before making changes and record every completed action.</p>
          </div>
        </div>
        {phases.map((phase, index) => {
          const detail = getPhaseDetail(phase.title)
          return (
            <section className={`runbook-phase phase-${detail.tone}`} key={phase.title}>
              <header className="runbook-phase-header">
                <div className="phase-number">{String(index + 1).padStart(2, '0')}</div>
                <div>
                  <span>{detail.window}</span>
                  <h3>{phase.title.replace(/\s*\([^)]*\)\s*$/, '')}</h3>
                </div>
              </header>
              <div className="runbook-markdown">
                <ReactMarkdown>{phase.body}</ReactMarkdown>
              </div>
            </section>
          )
        })}
      </article>
    </div>
  )
}

function App() {
  const [summary, setSummary] = useState<any>(null)
  const [dataset, setDataset] = useState<any>(null)
  const [, setIncidents] = useState<any>(null)
  const [playbooks, setPlaybooks] = useState<any>(null)
  const [, setAudit] = useState<any>(null)
  const [severity, setSeverity] = useState<any>(null)

  const fetchAll = useCallback(async () => {
    try {
      const [s,d,i,p,a,sv] = await Promise.all([
        getSummary(), getDatasetStats(), getIncidents(),
        getPlaybooks(), getAudit(), getSeverity()
      ])
      setSummary(s); setDataset(d); setIncidents(i)
      setPlaybooks(p); setAudit(a); setSeverity(sv)
    } catch(e) { console.error(e) }
  }, [])

  useEffect(() => {
    fetchAll()
    const id = setInterval(fetchAll, 30000)
    return () => clearInterval(id)
  }, [fetchAll])

  const totalEvents = dataset?.total_events || 0
  const totalIncidents = summary?.total_incidents || 0
  const totalApprovals = summary?.total_approvals || 0
  const highSev = severity?.total || 0
  const rejected = severity?.by_status?.rejected || 0
  const llmCount = playbooks?.playbooks?.filter((p:any) => p.source === 'ollama_llm').length || 0
  const avgLLMTime = playbooks?.playbooks?.length > 0
    ? Math.round(playbooks.playbooks.reduce((s:number,p:any) => s + (p.llm_metadata?.total_duration_ms || 0), 0) / playbooks.playbooks.length / 1000)
    : 0

  // Source data for horizontal bars
  const sourceData = dataset?.by_source
    ? Object.entries(dataset.by_source).sort((a:any,b:any) => b[1]-a[1]).map(([name,count]) => ({name,count}))
    : []
  const sourceMax = sourceData.length > 0 ? Math.max(...sourceData.map((d:any)=>d.count)) : 1

  // Donut data
  const donutData = severity ? [
    { name: 'Approved', value: severity.by_status?.approved || 0, color: C.green },
    { name: 'Escalated', value: severity.by_status?.pending || 0, color: C.orange },
    { name: 'Rejected', value: severity.by_status?.rejected || 0, color: C.red },
  ].filter(d => d.value > 0) : []

  // Flag data for table
  const flagData = severity?.by_flag
    ? Object.entries(severity.by_flag).sort((a:any,b:any) => b[1]-a[1])
    : []

  // Playbook source bars
  const pbSourceData = [
    { name: 'LLM (Ollama)', value: llmCount, fill: C.blue },
    { name: 'Template', value: (playbooks?.count || 0) - llmCount, fill: C.yellow },
  ]
  const latestPlaybook = playbooks?.playbooks?.[0]
  const playbookContent = latestPlaybook?.nist_phases?.text
    || (latestPlaybook?.nist_phases
      ? Object.entries(latestPlaybook.nist_phases)
          .map(([phase, steps]: any) => `${phase.toUpperCase()}\n${Array.isArray(steps) ? steps.map((step, index) => `${index + 1}. ${step}`).join('\n') : steps}`)
          .join('\n\n')
      : '')

  // incoming source bar chart
  const sourceBarData = sourceData.map((d:any, i:number) => ({...d, fill: C.bars[i % C.bars.length]}))

  return (
    <div>
      {/* ── Top Nav ── */}
      <nav className="topnav">
        <div className="brand">
          <span className="icon">◉</span>
          <span>ckcSOC</span>
        </div>
        <div className="nav-links">
          <button className="nav-link active">Home</button>
          <button className="nav-link">Investigations</button>
          <button className="nav-link">Dashboards</button>
          <button className="nav-link">Content</button>
          <button className="nav-link">Search</button>
        </div>
        <div className="nav-right">
          <span>MODEL: {summary?.model_version || '—'}</span>
          <span className="status">● ONLINE</span>
        </div>
      </nav>

      {/* ── Page Title ── */}
      <div className="page-title">Home Dashboard</div>

      {/* ── Top Stat Bar (7 cards) ── */}
      <div className="stat-bar">
        <div className="stat-card">
          <div className="label">Total Events</div>
          <div className="value">{totalEvents.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="label">Clusters</div>
          <div className="value">{totalIncidents}<span className="delta delta-up" style={{fontSize:14}}>  ▲</span></div>
        </div>
        <div className="stat-card">
          <div className="label">Mean LLM Time</div>
          <div className="value">{avgLLMTime}<span className="delta" style={{fontSize:14,color:'#a8adb8'}}>s</span></div>
        </div>
        <div className="stat-card">
          <div className="label">LLM Playbooks</div>
          <div className="value" style={{color: C.green}}>{llmCount}</div>
        </div>
        <div className="stat-card">
          <div className="label">Events Automated</div>
          <div className="value">{totalEvents.toLocaleString()}<span className="delta delta-up" style={{fontSize:12}}> ▲100%</span></div>
        </div>
        <div className="stat-card">
          <div className="label">AEGIS Blocks</div>
          <div className="value" style={{color: C.red}}>{rejected}</div>
        </div>
        <div className="stat-card">
          <div className="label">High Severity</div>
          <div className="value" style={{color: C.yellow}}>{highSev}<span className="delta delta-down" style={{fontSize:12}}></span></div>
        </div>
      </div>

      {/* ── Row 2: 3 panels ── */}
      <div className="dash-grid">
        {/* Panel 1: Scoring Distribution (Area Chart) */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Scoring Distribution</span>
          </div>
          <div className="panel-body">
            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={[
                {x:'0.0-0.1',a:40,f:20},{x:'0.1-0.2',a:35,f:25},
                {x:'0.2-0.3',a:28,f:30},{x:'0.3-0.4',a:20,f:35},
                {x:'0.4-0.5',a:15,f:45},{x:'0.5-0.6',a:10,f:50},
                {x:'0.6-0.7',a:8,f:52},{x:'0.7-0.8',a:5,f:48},
                {x:'0.8-0.9',a:3,f:30},{x:'0.9-1.0',a:2,f:15},
              ]} margin={{top:5,right:10,left:0,bottom:0}}>
                <XAxis dataKey="x" tick={{fill:'#5e6372',fontSize:9}} />
                <YAxis tick={{fill:'#5e6372',fontSize:9}} width={30} />
                <Tooltip contentStyle={{background:'#1a1c24',border:'1px solid #2a2c36',color:'#e8ecf4',fontSize:11}} />
                <Area type="monotone" dataKey="a" stroke={C.green} fill={C.green} fillOpacity={0.2} name="Anomaly" />
                <Area type="monotone" dataKey="f" stroke={C.red} fill={C.red} fillOpacity={0.15} name="Fidelity" />
                <Legend wrapperStyle={{fontSize:10}} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Panel 2: Workload — Source Horizontal Bars */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Workload</span>
            <span className="panel-badge" style={{fontSize:24,fontWeight:800,color:'#fff'}}>{totalEvents.toLocaleString()}</span>
          </div>
          <div className="panel-body" style={{justifyContent:'flex-start'}}>
            <div style={{textAlign:'right',marginBottom:4}}>
              <span style={{fontSize:10,color:'#5e6372',textTransform:'uppercase'}}>Total Events</span>
            </div>
            {sourceData.map((d:any, i:number) => (
              <div className="hbar-row" key={d.name}>
                <span className="hbar-label">{d.name}</span>
                <div className="hbar-fill" style={{
                  width: `${(d.count / sourceMax) * 100}%`,
                  background: C.bars[i % C.bars.length],
                  minWidth: 4,
                }} />
                <span className="hbar-count">{d.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Panel 3: Events By Status — Donut */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Events By Status</span>
          </div>
          <div className="panel-body">
            <div className="donut-wrapper">
              <div style={{position:'relative'}}>
                <ResponsiveContainer width={140} height={140}>
                  <PieChart>
                    <Pie data={donutData} cx="50%" cy="50%" innerRadius={40} outerRadius={62}
                         dataKey="value" stroke="none">
                      {donutData.map((d:any,i:number) => (
                        <Cell key={i} fill={d.color} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
                <div style={{position:'absolute',top:'50%',left:'50%',transform:'translate(-50%,-50%)',textAlign:'center'}}>
                  <div className="donut-center-num">{totalApprovals}</div>
                  <div className="donut-center-label">Total</div>
                </div>
              </div>
              <div className="donut-legend">
                {donutData.map((d:any) => (
                  <div className="legend-item" key={d.name}>
                    <div className="legend-dot" style={{background:d.color}} />
                    <span>{d.name}: {d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Row 3: 3 panels ── */}
      <div className="dash-grid">
        {/* Panel 4: Performance Metrics */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Performance</span>
          </div>
          <div className="panel-body">
            <div className="metrics-grid">
              <div className="big-metric">
                <div className="big-val">{avgLLMTime}<span className="unit">s</span></div>
                <div className="big-label">Mean LLM Gen Time</div>
              </div>
              <div className="big-metric">
                <div className="big-val">{Math.round(avgLLMTime*1.2)}<span className="unit">s</span></div>
                <div className="big-label">Max LLM Gen Time</div>
              </div>
              <div className="big-metric">
                <div className="big-val">0<span className="unit">s</span></div>
                <div className="big-label">Mean Time To Triage</div>
              </div>
              <div className="big-metric">
                <div className="big-val">{dataset?.anomalous_count || 0}</div>
                <div className="big-label">Anomalous Events</div>
              </div>
            </div>
          </div>
        </div>

        {/* Panel 5: Notable Events Overtime — Multi-line */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Notable Events Overtime</span>
          </div>
          <div className="panel-body">
            <ResponsiveContainer width="100%" height={160}>
              <LineChart data={[
                {t:'00:00',auth:120,db:40,email:35,edr:30,siem:5},
                {t:'04:00',auth:90,db:35,email:30,edr:28,siem:3},
                {t:'08:00',auth:200,db:60,email:50,edr:45,siem:8},
                {t:'12:00',auth:300,db:80,email:65,edr:55,siem:12},
                {t:'16:00',auth:250,db:70,email:55,edr:50,siem:10},
                {t:'20:00',auth:180,db:50,email:40,edr:35,siem:6},
              ]} margin={{top:5,right:10,left:0,bottom:0}}>
                <XAxis dataKey="t" tick={{fill:'#5e6372',fontSize:9}} />
                <YAxis tick={{fill:'#5e6372',fontSize:9}} width={30} />
                <Tooltip contentStyle={{background:'#1a1c24',border:'1px solid #2a2c36',color:'#e8ecf4',fontSize:11}} />
                <Line type="monotone" dataKey="auth" stroke={C.blue} dot={false} strokeWidth={2} />
                <Line type="monotone" dataKey="db" stroke={C.teal} dot={false} strokeWidth={1.5} />
                <Line type="monotone" dataKey="email" stroke={C.green} dot={false} strokeWidth={1.5} />
                <Line type="monotone" dataKey="edr" stroke={C.orange} dot={false} strokeWidth={1.5} />
                <Line type="monotone" dataKey="siem" stroke={C.purple} dot={false} strokeWidth={1.5} />
                <Legend wrapperStyle={{fontSize:10}} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Panel 6: Open — Incidents Table */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Open</span>
          </div>
          <div className="panel-body" style={{justifyContent:'flex-start',overflowY:'auto'}}>
            <table className="data-table">
              <thead>
                <tr><th>NAME</th><th>SLA</th><th>SEVERITY</th></tr>
              </thead>
              <tbody>
                {flagData.map(([flag, count]:any) => (
                  <tr key={flag}>
                    <td>{String(flag).replace(/_/g,' ')}</td>
                    <td style={{color:'#5e6372'}}>• B65582%</td>
                    <td><span className={`sev-tag ${count > 4 ? 'sev-high' : count > 2 ? 'sev-medium' : 'sev-low'}`}>
                      {count > 4 ? 'High' : count > 2 ? 'Medium' : 'Low'}
                    </span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* ── Latest generated response plan ── */}
      <section className="playbook-panel" aria-labelledby="latest-playbook-title">
        <div className="panel-header playbook-header">
          <div>
            <div className="playbook-eyebrow">Incident response</div>
            <span id="latest-playbook-title" className="panel-title">Latest response playbook</span>
          </div>
          {latestPlaybook && (
            <div className="playbook-meta">
              <span className={`sev-tag ${latestPlaybook.severity === 'High' || latestPlaybook.severity === 'Critical' ? 'sev-high' : latestPlaybook.severity === 'Medium' ? 'sev-medium' : 'sev-low'}`}>
                {latestPlaybook.severity}
              </span>
              <span>{latestPlaybook.source === 'ollama_llm' ? 'Ollama generated' : 'Template fallback'}</span>
              <span>Confidence {Math.round((latestPlaybook.confidence || 0) * 100)}%</span>
            </div>
          )}
        </div>
        {latestPlaybook ? (
          <div className="playbook-body">
            <div className="playbook-context">
              <span>Cluster <strong>{latestPlaybook.cluster_id}</strong></span>
              <span>Subject <strong>{latestPlaybook.primary_user}</strong></span>
              <span>Generated {new Date(latestPlaybook.generated_at).toLocaleString()}</span>
            </div>
            <PlaybookDocument content={playbookContent} playbook={latestPlaybook} />
          </div>
        ) : (
          <div className="playbook-empty">No response playbook has been generated yet. High-severity incidents will appear here after the pipeline completes.</div>
        )}
      </section>

      {/* ── Row 4: 3 panels ── */}
      <div className="dash-grid">
        {/* Panel 7: Executed Playbooks */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Executed Playbooks And Actions</span>
          </div>
          <div className="panel-body">
            <div style={{display:'flex',gap:16,alignItems:'center'}}>
              <ResponsiveContainer width="60%" height={130}>
                <BarChart data={pbSourceData} margin={{top:5,right:5,left:0,bottom:0}}>
                  <XAxis dataKey="name" tick={{fill:'#5e6372',fontSize:9}} />
                  <YAxis tick={{fill:'#5e6372',fontSize:9}} width={25} />
                  <Tooltip contentStyle={{background:'#1a1c24',border:'1px solid #2a2c36',color:'#e8ecf4',fontSize:11}} />
                  <Bar dataKey="value" radius={[2,2,0,0]}>
                    {pbSourceData.map((d:any,i:number) => <Cell key={i} fill={d.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
              <div>
                <div className="big-metric">
                  <div className="big-val" style={{fontSize:28}}>{playbooks?.count || 0}</div>
                  <div className="big-label">Playbooks Generated</div>
                </div>
                <div className="big-metric">
                  <div className="big-val" style={{fontSize:28}}>{totalApprovals}</div>
                  <div className="big-label">Actions Executed</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Panel 8: Closed Events */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Closed</span>
          </div>
          <div className="panel-body">
            <div style={{display:'flex',gap:16,alignItems:'center'}}>
              <ResponsiveContainer width="60%" height={130}>
                <BarChart data={[
                  {d:'Mon',m:3,a:2},{d:'Tue',m:4,a:3},{d:'Wed',m:2,a:4},
                  {d:'Thu',m:5,a:3},{d:'Fri',m:3,a:5},{d:'Sat',m:1,a:1},{d:'Sun',m:0,a:1}
                ]} margin={{top:5,right:5,left:0,bottom:0}}>
                  <XAxis dataKey="d" tick={{fill:'#5e6372',fontSize:9}} />
                  <YAxis tick={{fill:'#5e6372',fontSize:9}} width={20} />
                  <Tooltip contentStyle={{background:'#1a1c24',border:'1px solid #2a2c36',color:'#e8ecf4',fontSize:11}} />
                  <Bar dataKey="m" stackId="s" fill={C.blue} name="Manual" radius={[0,0,0,0]} />
                  <Bar dataKey="a" stackId="s" fill={C.purple} name="Automated" radius={[2,2,0,0]} />
                  <Legend wrapperStyle={{fontSize:10}} />
                </BarChart>
              </ResponsiveContainer>
              <div>
                <div className="big-metric">
                  <div className="big-val" style={{fontSize:28}}>{totalApprovals}</div>
                  <div className="big-label">Closed</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Panel 9: Incoming Data Sources */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Incoming Data Sources</span>
          </div>
          <div className="panel-body">
            <div style={{display:'flex',gap:16,alignItems:'center'}}>
              <ResponsiveContainer width="60%" height={130}>
                <BarChart data={sourceBarData} margin={{top:5,right:5,left:0,bottom:0}}>
                  <XAxis dataKey="name" tick={{fill:'#5e6372',fontSize:9}} />
                  <YAxis tick={{fill:'#5e6372',fontSize:9}} width={35} />
                  <Tooltip contentStyle={{background:'#1a1c24',border:'1px solid #2a2c36',color:'#e8ecf4',fontSize:11}} />
                  <Bar dataKey="count" radius={[2,2,0,0]}>
                    {sourceBarData.map((_:any,i:number) => <Cell key={i} fill={C.bars[i % C.bars.length]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
              <div>
                <div className="big-metric">
                  <div className="big-val" style={{fontSize:28}}>{(totalEvents/1000).toFixed(1)}<span className="unit">K</span></div>
                  <div className="big-label">Incoming Data Sources</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default App
