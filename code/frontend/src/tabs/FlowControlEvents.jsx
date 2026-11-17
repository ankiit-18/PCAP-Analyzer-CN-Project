import { useMemo, useState } from 'react'
import Chart from '../components/Chart.jsx'
import { Card, DataTable, Empty, Stat } from '../components/ui.jsx'
import { fmtBytes, fmtDur, fmtNum } from '../lib.js'

const STYLE = {
  'Window scale': { color: '#4f46e5', symbol: 'circle', size: 9 },
  'Initial window': { color: '#22c1c3', symbol: 'circle', size: 9 },
  'Zero window': { color: '#e5484d', symbol: 'diamond', size: 13 },
  'Zero-window probe': { color: '#f08c00', symbol: 'circle', size: 9 },
  'Zero-window probe ACK': { color: '#f08c00', symbol: 'diamond', size: 9 },
  'Window update': { color: '#16a34a', symbol: 'triangle', size: 11 },
  'Window full': { color: '#f08c00', symbol: 'rect', size: 11 },
  'Window shrank': { color: '#8b5cf6', symbol: 'triangle', rotate: 180, size: 11 },
}
const style = (k) => STYLE[k] || { color: '#8b93a7', symbol: 'circle', size: 8 }

/** Receiver flow-control events: zero windows (and how long the sender was blocked), probes, window updates, window full, shrinking windows. */
export default function FlowControlEvents({ fc, flow }) {
  const [kind, setKind] = useState('all')
  const option = useMemo(() => {
    if (!fc || !fc.events.length) return null
    const lanes = fc.lanes
    const series = lanes.map((k) => {
      const st = style(k)
      return { name: k, type: 'scatter', symbol: st.symbol, symbolRotate: st.rotate || 0, symbolSize: st.size, itemStyle: { color: st.color, opacity: 0.9 }, z: 3,
        data: fc.events.filter((e) => e.event === k).map((e) => [e.rel_time, k, e.packet_no, e.flow, e.sender, e.details]) }
    })
    const zi = lanes.indexOf('Zero window')
    if (zi >= 0 && fc.stalls.length) {
      // a red bar from the start of each zero-window period until the window reopened (or the end of the capture)
      series.push({ name: 'Sender blocked', type: 'custom', z: 1, tooltip: { show: false }, itemStyle: { color: '#e5484d', opacity: 0.4 },
        renderItem: (params, api) => {
          const s = api.coord([api.value(0), api.value(2)]); const e = api.coord([api.value(1), api.value(2)])
          return { type: 'rect', shape: { x: s[0], y: s[1] - 8, width: Math.max(e[0] - s[0], 3), height: 16 }, style: api.style({ fill: '#e5484d', opacity: 0.3 }) }
        },
        data: fc.stalls.map((x) => [x.start_s, x.reopened ? x.reopened_s : x.start_s + x.duration_ms / 1000, zi]) })
    }
    return {
      grid: { left: 150, right: 20, top: 44, bottom: 62 }, legend: { top: 0, type: 'scroll' },
      tooltip: { trigger: 'item', formatter: (p) => (p.data && p.data.length > 5
        ? `<b>${p.seriesName}</b> · packet #${p.data[2]}${fc.flow == null ? ` · flow #${p.data[3]}` : ''}<br>${p.data[4]}<br>${p.data[5]}<br>t = ${p.data[0].toFixed(4)} s` : '') },
      xAxis: { type: 'value', name: 'time (s)', nameLocation: 'middle', nameGap: 28, scale: true },
      yAxis: { type: 'category', data: lanes, inverse: true },
      dataZoom: [{ type: 'inside', xAxisIndex: 0 }, { type: 'slider', xAxisIndex: 0, height: 16, bottom: 6 }], series,
    }
  }, [fc])

  if (!fc) return null
  const s = fc.summary
  const rows = fc.events.filter((e) => kind === 'all' || e.event === kind)
  const cols = [
    { key: 'rel_time', label: 'Time (s)', num: true, render: (v) => v?.toFixed(6) }, { key: 'packet_no', label: 'Packet', num: true },
    ...(flow == null ? [{ key: 'flow', label: 'Flow', num: true }] : []),
    { key: 'sender', label: 'Sender' }, { key: 'event', label: 'Event', render: (v) => <span><i className="dot" style={{ background: style(v).color }} /> {v}</span> },
    { key: 'window', label: 'Window', num: true, render: (v) => (v == null ? '–' : fmtBytes(v)) }, { key: 'via', label: 'Found by' }, { key: 'details', label: 'Details', wrap: true },
  ]
  const none = !fc.events.length
  return (
    <div className="stack">
      <div className="stats">
        <Stat label="Flow-control events" value={fmtNum(s.events)} sub={flow == null ? `${fmtNum(s.flows_affected)} flow${s.flows_affected === 1 ? '' : 's'} affected` : 'in this flow'} />
        <Stat label="Zero-window stalls" value={fmtNum(s.stalls)} sub={s.still_closed ? `${s.still_closed} still closed at the end` : 'sender had to stop'} tone={s.stalls ? 'bad' : undefined} />
        <Stat label="Time the sender was blocked" value={s.stalls ? fmtDur(s.total_stall_ms) : '–'} sub={s.longest_stall_ms ? `longest ${fmtDur(s.longest_stall_ms)}` : undefined} tone={s.stalls ? 'warn' : undefined} />
        <Stat label="Window full" value={fmtNum(fc.counts['Window full'] || 0)} sub="sender filled the window" tone="warn" />
        <Stat label="Window shrank" value={fmtNum(fc.counts['Window shrank'] || 0)} sub="to under 25% of its peak" tone="info" />
      </div>
      <Card title="Flow control events" sub="What the receiver did to slow the sender down, and when. Wireshark's flags are observed; stall durations and shrinking windows are derived. This is flow control (the receiver's limit), not congestion control.">
        {none && <Empty>✅ No flow-control problems {flow == null ? 'in this capture' : 'in this flow'}: no zero windows, no window-full events and no large window shrinks. The receivers always kept up.</Empty>}
        {option && <Chart option={option} height={Math.max(240, 110 + fc.lanes.length * 46)} />}
        {!none && (
          <>
            <div className="toolbar" style={{ marginTop: 14 }}>
              <b>Show:</b>
              <select value={kind} onChange={(e) => setKind(e.target.value)}>
                <option value="all">All events ({fmtNum(fc.total_events)})</option>
                {fc.lanes.map((k) => <option key={k} value={k}>{k} ({fmtNum(fc.counts[k])})</option>)}
              </select>
              {fc.truncated && <span className="muted">showing the first {fmtNum(fc.events.length)} of {fmtNum(fc.total_events)}</span>}
            </div>
            <DataTable rows={rows} columns={cols} pageSize={12} defaultSort={{ key: 'rel_time', dir: 'asc' }} />
          </>
        )}
      </Card>
      {fc.stalls.length > 0 && (
        <Card title="Zero-window stalls" sub="Each row is one period in which the receiver's window was 0 and the sender could not send.">
          <DataTable rows={fc.stalls} pageSize={8} defaultSort={{ key: 'duration_ms', dir: 'desc' }} columns={[
            { key: 'flow', label: 'Flow', num: true }, { key: 'sender', label: 'Closed by' }, { key: 'start_s', label: 'Started (s)', num: true, render: (v) => v?.toFixed(4) },
            { key: 'start_no', label: 'Packet', num: true }, { key: 'duration_ms', label: 'Blocked for', num: true, render: fmtDur },
            { key: 'reopened_no', label: 'Reopened by packet', num: true, render: (v) => (v == null ? 'still closed' : `#${v}`) }, { key: 'closed_packets', label: 'Zero-window packets', num: true },
          ]} />
        </Card>
      )}
      {flow == null && fc.by_flow.length > 0 && (
        <Card title="Flow-control events by flow">
          <DataTable rows={fc.by_flow} pageSize={8} defaultSort={{ key: 'events', dir: 'desc' }} columns={[
            { key: 'flow', label: 'Flow', num: true }, { key: 'events', label: 'Events', num: true }, { key: 'Zero window', label: 'Zero windows', num: true },
            { key: 'Window full', label: 'Window full', num: true }, { key: 'Window update', label: 'Window updates', num: true }, { key: 'Window shrank', label: 'Shrank', num: true },
            { key: 'stalls', label: 'Stalls', num: true, render: (v) => (v == null ? 0 : v) }, { key: 'stalled_ms', label: 'Blocked for', num: true, render: (v) => (v ? fmtDur(v) : '–') },
          ]} />
        </Card>
      )}
    </div>
  )
}
