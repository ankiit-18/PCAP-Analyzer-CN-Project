import { useEffect, useMemo, useState } from 'react'
import { getFlowEvents } from '../api.js'
import Chart from '../components/Chart.jsx'
import { Card, DataTable, Empty } from '../components/ui.jsx'
import { INDICATORS, fmtNum, fmtSec } from '../lib.js'

// how each event is drawn on the timeline (the TCP indicators keep the colours / symbols used on the other tabs)
const STYLE = {
  'SYN': { color: '#4f46e5', symbol: 'circle', size: 9 },
  'SYN-ACK': { color: '#22c1c3', symbol: 'circle', size: 9 },
  'Handshake complete': { color: '#16a34a', symbol: 'rect', size: 12 },
  'First data': { color: '#0ea5e9', symbol: 'triangle', size: 11 },
  'Idle gap': { color: '#8b93a7', symbol: 'rect', size: 10 },
  'Retransmission': INDICATORS.retransmission,
  'Retransmission (unclassified)': { ...INDICATORS.retransmission, color: '#a0612b' },
  'Late arrival': { color: '#f08c00', symbol: 'diamond', size: 10 },
  'Duplicate copy': { color: '#8b93a7', symbol: 'rect', size: 9 },
  'Fast retransmission': INDICATORS.fast_retransmission,
  'Spurious retransmission': INDICATORS.spurious_retransmission,
  'Out-of-order': INDICATORS.out_of_order,
  'Duplicate ACKs': INDICATORS.duplicate_ack,
  'Zero window': { color: '#e5484d', symbol: 'rect', size: 11 },
  'Zero-window probe': { color: '#f08c00', symbol: 'circle', size: 9 },
  'Zero-window probe ACK': { color: '#f08c00', symbol: 'diamond', size: 9 },
  'Window update': { color: '#22c1c3', symbol: 'triangle', size: 9 },
  'Window full': { color: '#f08c00', symbol: 'rect', size: 10 },
  'Keep-alive': { color: '#8b93a7', symbol: 'circle', size: 8 },
  'CE mark': { color: '#e5484d', symbol: 'pin', size: 12 },
  'ECE echo': { color: '#f08c00', symbol: 'circle', size: 9 },
  'CWR': { color: '#4f46e5', symbol: 'circle', size: 9 },
  'FIN': { color: '#16a34a', symbol: 'diamond', size: 11 },
  'RST': { color: '#e5484d', symbol: 'pin', size: 13 },
}
const style = (e) => STYLE[e] || { color: '#8b93a7', symbol: 'circle', size: 8 }

/** The life of one TCP flow: set-up, data, retransmissions, reordering, flow control, ECN, closing. */
export default function FlowEvents({ id, flow }) {
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')
  const [lane, setLane] = useState('all')
  useEffect(() => {
    setD(null); setErr(''); setLane('all')
    getFlowEvents(id, flow).then(setD).catch((e) => setErr(e.message))
  }, [id, flow])

  const option = useMemo(() => {
    if (!d || !d.events.length) return null
    const kinds = [...new Set(d.events.map((e) => e.event))]
    const series = kinds.map((k) => {
      const st = style(k)
      return {
        name: k, type: 'scatter', symbol: st.symbol, symbolRotate: st.rotate || 0, symbolSize: st.size, itemStyle: { color: st.color, opacity: 0.85 },
        data: d.events.filter((e) => e.event === k).map((e) => [e.rel_time, e.lane, e.packet_no, e.details, e.direction]),
      }
    })
    return {
      grid: { left: 190, right: 20, top: 44, bottom: 62 }, legend: { top: 0, type: 'scroll' },
      tooltip: { trigger: 'item', formatter: (p) => `<b>${p.seriesName}</b> · packet #${p.data[2]}<br>${p.data[4]}<br>${p.data[3]}<br>t = ${p.data[0].toFixed(4)} s` },
      xAxis: { type: 'value', name: 'time (s)', nameLocation: 'middle', nameGap: 28, scale: true },
      yAxis: { type: 'category', data: d.lanes, inverse: true },
      dataZoom: [{ type: 'inside', xAxisIndex: 0 }, { type: 'slider', xAxisIndex: 0, height: 16, bottom: 6 }], series,
    }
  }, [d])

  if (err) return <div className="err">{err}</div>
  if (!d) return <Card title="Flow events"><Empty>Loading…</Empty></Card>
  const s = d.summary
  const rows = d.events.filter((e) => lane === 'all' || e.lane === lane)
  const cols = [
    { key: 'rel_time', label: 'Time (s)', num: true, render: (v) => v?.toFixed(6) }, { key: 'packet_no', label: 'Packet', num: true },
    { key: 'lane', label: 'Category' }, { key: 'event', label: 'Event', render: (v) => <span><i className="dot" style={{ background: style(v).color }} /> {v}</span> },
    { key: 'direction', label: 'Direction' }, { key: 'details', label: 'Details', wrap: true },
  ]
  return (
    <Card title="Flow events" sub="What happened in this connection, in order. Wireshark's flags are observed; the grouping, idle periods and end state are derived.">
      <div className="chips" style={{ marginBottom: 12 }}>
        <span className={`chip-info ${s.handshake_captured ? 'ok' : 'warn'}`}>{s.handshake_captured ? 'Handshake captured' : 'Handshake not captured: the capture started mid-connection'}</span>
        <span className="chip-info">Lasted {fmtSec(s.duration_s)} · {fmtNum(s.packets)} packets</span>
        <span className="chip-info">Ended: {s.end_state}</span>
        {!s.role_known && <span className="chip-info warn">client / server is a best guess (no SYN seen)</span>}
        {Object.entries(d.counts).map(([k, n]) => <span key={k} className="chip-info"><i className="dot" style={{ background: style(k).color }} /> {k} {fmtNum(n)}</span>)}
      </div>
      {option ? <Chart option={option} height={Math.max(260, 120 + d.lanes.length * 44)} /> : <Empty>No events.</Empty>}
      <div className="toolbar" style={{ marginTop: 14 }}>
        <b>Show:</b>
        <select value={lane} onChange={(e) => setLane(e.target.value)}>
          <option value="all">All categories ({fmtNum(d.total_events)})</option>
          {d.lanes.map((l) => <option key={l} value={l}>{l} ({fmtNum(d.events.filter((e) => e.lane === l).length)})</option>)}
        </select>
        {d.truncated && <span className="muted">showing the first {fmtNum(d.events.length)} of {fmtNum(d.total_events)} events</span>}
      </div>
      <DataTable rows={rows} columns={cols} pageSize={12} defaultSort={{ key: 'rel_time', dir: 'asc' }} />
    </Card>
  )
}
