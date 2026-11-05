import { useEffect, useMemo, useState } from 'react'
import { getTcpRtt } from '../api.js'
import { GenericChart } from '../components/GenericChart.jsx'
import { Card, DataTable, Empty, FlowSelect, Stat } from '../components/ui.jsx'
import { Basis } from '../components/Spec.jsx'
import { PALETTE, fmtMs, fmtNum } from '../lib.js'

const METHOD_COLOR = { ack: PALETTE[0], handshake: PALETTE[3] }
const SHOWN = (m) => m.id !== 'timestamp'          // TCP timestamp-echo RTT is not shown in the UI

/** RTT analysis. Three methods are shown SEPARATELY and never combined: ACK-based, TCP-timestamp-echo, initial (handshake). */
export default function Rtt({ id, report, flow, setFlow }) {
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    setD(null); setErr('')
    getTcpRtt(id, flow).then(setD).catch((e) => setErr(e.message))
  }, [id, flow])

  const overTime = useMemo(() => d && ({
    id: 'rtt_time', title: '', type: 'scatter', unit: 'ms', xLabel: 'time (s)', yLabel: 'RTT',
    series: d.methods.filter((m) => SHOWN(m) && m.available).map((m) => ({ name: m.label, points: m.points.map((p) => [p[0], p[1]]) })),
  }), [d])
  const hist = useMemo(() => {
    const ack = d?.methods.find((m) => m.id === 'ack')
    if (!ack?.available) return null
    const v = ack.points.map((p) => p[1]); const lo = Math.min(...v), hi = Math.max(...v), n = 24, w = (hi - lo) / n || 1
    const bins = Array(n).fill(0); v.forEach((x) => { bins[Math.min(n - 1, Math.floor((x - lo) / w))]++ })
    return { id: 'rtt_hist', title: '', type: 'bar', unit: 'count', labels: bins.map((_, i) => (lo + i * w).toFixed(1)), xLabel: 'RTT (ms)', yLabel: 'samples', series: [{ name: 'samples', data: bins }] }
  }, [d])

  const cols = [
    { key: 'flow', label: 'Flow', num: true }, { key: 'client', label: 'Client' }, { key: 'server', label: 'Server' },
    { key: 'handshake_rtt_ms', label: 'Handshake RTT', num: true, render: (v) => fmtMs(v) },
    { key: 'rtt_samples', label: 'ACK samples', num: true }, { key: 'rtt_min_ms', label: 'ACK min', num: true, render: (v) => fmtMs(v) }, { key: 'rtt_avg_ms', label: 'ACK avg', num: true, render: (v) => fmtMs(v) },
    { key: 'rtt_max_ms', label: 'ACK max', num: true, render: (v) => fmtMs(v) }, { key: 'rtt_std_ms', label: 'ACK std dev', num: true, render: (v) => fmtMs(v) },
  ]
  return (
    <div className="stack">
      <div className="toolbar">
        <b>Scope:</b><FlowSelect flows={report.flows} value={flow} onChange={setFlow} allowAll />
      </div>
      {err && <div className="err">{err}</div>}
      {!d && !err && <Card><Empty>Loading…</Empty></Card>}
      {d && (
        <>
          <div className="grid cols-2">
            {d.methods.filter(SHOWN).map((m) => (
              <div key={m.id} className="method" style={{ borderLeft: `4px solid ${METHOD_COLOR[m.id]}` }}>
                <h4>{m.label} <Basis basis={m.basis} /></h4>
                {m.available ? (
                  <div className="stats" style={{ marginTop: 8 }}>
                    <Stat label="Samples" value={fmtNum(m.stats_ms.count)} /><Stat label="Min" value={fmtMs(m.stats_ms.min)} /><Stat label="Average" value={fmtMs(m.stats_ms.avg)} />
                    <Stat label="Std dev (variation)" value={fmtMs(m.stats_ms.std)} /><Stat label="95th percentile" value={fmtMs(m.stats_ms.p95)} /><Stat label="Max" value={fmtMs(m.stats_ms.max)} />
                  </div>
                ) : <div className="stat na" style={{ marginTop: 8 }}><div className="value">Not available</div><div className="sub">{m.reason}</div></div>}
              </div>
            ))}
          </div>
          {overTime?.series.length > 0 && (
            <div className="grid cols-2">
              <Card title="RTT over time"><GenericChart spec={overTime} height={320} /></Card>
              {hist && <Card title="ACK-based RTT distribution"><GenericChart spec={hist} height={320} /></Card>}
            </div>
          )}
          <Card title="Per-flow RTT"><DataTable rows={d.per_flow} columns={cols} pageSize={10} defaultSort={{ key: 'rtt_samples', dir: 'desc' }} /></Card>
        </>
      )}
    </div>
  )
}
