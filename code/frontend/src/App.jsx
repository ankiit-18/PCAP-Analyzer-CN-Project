import { useCallback, useEffect, useRef, useState } from 'react'
import { analyze, deleteReport, getOverview, getReport, health, uploadFile } from './api.js'
import { fmtBytes } from './lib.js'
import OverviewPage, { Warnings } from './pages/OverviewPage.jsx'
import ProtocolPage from './pages/ProtocolPage.jsx'
import TcpPage, { TCP_TABS } from './pages/TcpPage.jsx'
import ValidationPage from './pages/ValidationPage.jsx'

function Steps({ stage }) {
  const idx = { upload: 0, ready: 1, analyzing: 1, results: 2 }[stage]
  const steps = ['Upload PCAP', 'Analyze', 'Explore results']
  return (
    <div className="steps">
      {steps.map((s, i) => (
        <div key={s} className={`step ${i < idx ? 'done' : i === idx ? 'on' : ''}`}><span className="n">{i < idx ? '✓' : i + 1}</span>{s}</div>
      ))}
    </div>
  )
}

function UploadScreen({ stage, file, progress, error, onPick, onAnalyze, onReset, backend }) {
  const input = useRef(null)
  const [over, setOver] = useState(false)
  const drop = (e) => { e.preventDefault(); setOver(false); const f = e.dataTransfer.files?.[0]; f && onPick(f) }

  return (
    <div className="hero">
      <h1>PCAP Network Analyzer</h1>
      <div className="muted">Upload a packet capture, run the tshark engine, and explore TCP flows, RTT, retransmissions and sequence gaps.</div>
      <Steps stage={stage} />

      {backend && !backend.ok && <div className="err">Backend problem: {backend.error}</div>}

      {stage === 'upload' && (
        <div className={`dropzone ${over ? 'over' : ''}`} onClick={() => input.current.click()}
             onDragOver={(e) => { e.preventDefault(); setOver(true) }} onDragLeave={() => setOver(false)} onDrop={drop}>
          <div className="big">Drop a .pcap / .pcapng file here</div>
          <div className="muted">or click to browse{backend?.max_upload_mb ? ` · max ${backend.max_upload_mb} MB` : ''}</div>
          <input ref={input} type="file" accept=".pcap,.pcapng,.cap" hidden onChange={(e) => e.target.files[0] && onPick(e.target.files[0])} />
          {progress != null && <div className="progress"><i style={{ width: `${Math.round(progress * 100)}%` }} /></div>}
        </div>
      )}

      {stage === 'ready' && file && (
        <div className="card filecard">
          <div style={{ textAlign: 'left' }}>
            <div><b>{file.filename}</b></div>
            <div className="muted">{file.format.toUpperCase()} · {fmtBytes(file.size)} · uploaded and validated ✓</div>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <button className="btn" onClick={onReset}>Choose another</button>
            <button className="btn primary" onClick={onAnalyze}>Analyze</button>
          </div>
        </div>
      )}

      {stage === 'analyzing' && (
        <div className="card"><div className="spinner" /><b>Analyzing {file?.filename}…</b>
          <div className="muted">Running tshark: packet fields, TCP analysis, protocol hierarchy, endpoints. Large captures can take a minute.</div></div>
      )}
      {error && <div className="err">{error}</div>}
    </div>
  )
}

export default function App() {
  const [stage, setStage] = useState('upload')     // upload | ready | analyzing | results
  const [file, setFile] = useState(null)
  const [progress, setProgress] = useState(null)
  const [error, setError] = useState('')
  const [report, setReport] = useState(null)
  const [ov, setOv] = useState(null)               // overview-first payload
  const [view, setView] = useState('overview')     // 'overview' | 'tcp' | 'ip' | 'udp' | 'dns' | ... | 'x:<other>'
  const [flow, setFlow] = useState(null)           // shared per-flow scope for the TCP tabs
  const [tcpSub, setTcpSub] = useState('summary')   // active TCP tab
  const [backend, setBackend] = useState(null)

  useEffect(() => { health().then(setBackend).catch(() => setBackend({ ok: false, error: 'Cannot reach the backend on port 8000. Start it with: uvicorn main:app --port 8000' })) }, [])

  const pick = useCallback(async (f) => {
    setError(''); setProgress(0)
    try { setFile(await uploadFile(f, setProgress)); setStage('ready') }
    catch (e) { setError(e.message) }
    finally { setProgress(null) }
  }, [])

  const run = async () => {
    setError(''); setStage('analyzing')
    try { await analyze(file.id); const [r, o] = await Promise.all([getReport(file.id), getOverview(file.id)]); setReport(r); setOv(o); setFlow(null); setView('overview'); setStage('results') }
    catch (e) { setError(e.message); setStage('ready') }
  }

  const reset = () => {
    if (file) deleteReport(file.id).catch(() => {})
    setFile(null); setReport(null); setOv(null); setFlow(null); setError(''); setView('overview'); setStage('upload')
  }

  // keep the browser Back button working: the current page lives in the URL hash
  useEffect(() => {
    const read = () => setView(decodeURIComponent(window.location.hash.replace(/^#\/?/, '')) || 'overview')
    window.addEventListener('hashchange', read)
    return () => window.removeEventListener('hashchange', read)
  }, [])
  const title = view === 'ip' ? 'IP Analysis' : view === 'validation' ? 'Wireshark cross-validation' : (ov?.protocols.find((p) => p.key === view)?.label || view)
  const go = (key, opts = {}) => {
    // navigation from IP conversations etc.: { flow } jumps to that TCP flow's drill-down
    if (key === 'tcp' && opts.flow != null) { setFlow(opts.flow); setTcpSub('drill') }
    window.location.hash = key === 'overview' ? '' : `/${encodeURIComponent(key)}`
    setView(key); window.scrollTo(0, 0)
  }

  return (
    <>
      <header className="topbar">
        <div className="brand"><span className="brand-dot" />PCAP Analyzer</div>
        {stage === 'results' && file && (
          <div className="file-chip"><span><b>{file.filename}</b> · {fmtBytes(file.size)} · {report.summary.packets.toLocaleString()} packets</span>
            <button className="btn small" onClick={reset}>New capture</button></div>
        )}
      </header>

      {stage !== 'results' ? (
        <main className="page"><UploadScreen {...{ stage, file, progress, error, backend }} onPick={pick} onAnalyze={run} onReset={reset} /></main>
      ) : (
        <>
        <nav className="navbar">
          <button className={`navitem ${view === 'overview' ? 'on' : ''}`} onClick={() => go('overview')}>Overview</button>
          {ov.ip && <button className={`navitem ${view === 'ip' ? 'on' : ''}`} onClick={() => go('ip')}>IP Analysis</button>}
          {ov.protocols.map((p) => <button key={p.key} className={`navitem ${view === p.key ? 'on' : ''}`} onClick={() => go(p.key)}>{p.label}</button>)}
        </nav>
        <main className="page">
          {view === 'overview' ? <OverviewPage id={file.id} ov={ov} onOpen={go} /> : (
            <>
              <Warnings items={ov.warnings} />
              <div className="page-head">
                <button className="btn" onClick={() => go('overview')}>← Overview</button>
                <h2>{title}</h2>
                <span className="crumb">Overview / {title}</span>
              </div>
              {view === 'tcp' ? <TcpPage id={file.id} report={report} flow={flow} setFlow={setFlow} sub={tcpSub} setSub={setTcpSub} />
                : view === 'validation' ? <ValidationPage id={file.id} />
                : <ProtocolPage id={file.id} pkey={view} onNavigate={go} />}
            </>
          )}
        </main>
        </>
      )}
    </>
  )
}
