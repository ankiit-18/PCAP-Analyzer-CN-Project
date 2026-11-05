import { useEffect, useMemo, useState } from 'react'
import { getFlowControl } from '../api.js'
import Chart from '../components/Chart.jsx'
import { Card, DataTable, Empty, FlowSelect } from '../components/ui.jsx'
import { PALETTE, fmtBytes, fmtNum } from '../lib.js'

const STATUS = { scaled: 'Scaled', unscaled: 'Not scaled', uncertain: 'Uncertain' }

export default function FlowControl({ id, report, flow, setFlow }) {
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    setD(null); setErr('')
    getFlowControl(id, flow).then(setD).catch((e) => setErr(e.message))
  }, [id, flow])

  const option = useMemo(() => {
    if (!d?.series) return null
    const series = []
    const roles = ['c2s', 's2c']
    roles.forEach((r, i) => {
      const s = d.series[r]
      if (!s?.effective.length) return
      series.push({ name: `${s.direction} – effective window${s.status === 'uncertain' ? ' (scale uncertain)' : ''}`, type: 'line', step: 'end', showSymbol: false, lineStyle: { width: 1.6, color: PALETTE[i] }, itemStyle: { color: PALETTE[i] }, data: s.effective })
      series.push({ name: `${s.direction} – advertised (raw 16-bit)`, type: 'line', step: 'end', showSymbol: false, lineStyle: { width: 1, type: 'dashed', color: PALETTE[i], opacity: 0.6 }, itemStyle: { color: PALETTE[i] }, data: s.raw })
    })
    const ev = d.events.filter((e) => e.kind === 'zero window')
    if (ev.length) series.push({ name: 'zero-window events', type: 'scatter', symbol: 'diamond', symbolSize: 12, itemStyle: { color: '#e5484d' }, data: ev.map((e) => [e.rel_time, 0]) })
    const up = d.events.filter((e) => e.kind === 'window update')
    if (up.length) series.push({ name: 'window updates', type: 'scatter', symbol: 'triangle', symbolSize: 11, itemStyle: { color: '#16a34a' }, data: up.map((e) => [e.rel_time, e.eff_win]) })
    return {
      grid: { left: 80, right: 24, top: 56, bottom: 70 }, tooltip: { trigger: 'axis', valueFormatter: (v) => fmtBytes(v) },
      xAxis: { type: 'value', name: 'time (s)', nameLocation: 'middle', nameGap: 28 }, yAxis: { type: 'value', name: 'receive window', axisLabel: { formatter: (v) => fmtBytes(v) } },
      legend: { top: 0, type: 'scroll' }, dataZoom: [{ type: 'inside' }, { type: 'slider', height: 16, bottom: 6 }], series,
    }
  }, [d])

  const rows = d?.directions || []
  const status = (v) => STATUS[v] || v
  return (
    <div className="stack">
      <div className="toolbar"><b>Scope:</b><FlowSelect flows={report.flows} value={flow} onChange={setFlow} allowAll /></div>
      {err && <div className="err">{err}</div>}
      {!d && !err && <Card><Empty>Loading…</Empty></Card>}
      {d && (
        <>
          {d.series && (
            <Card title="Advertised / effective window over time">
              {option ? <Chart option={option} height={360} /> : <Empty>No window data.</Empty>}
            </Card>
          )}
          <Card title="Receive window by flow and direction" sub={`${rows.length} direction${rows.length === 1 ? '' : 's'}`}>
            <DataTable rows={rows} pageSize={12} defaultSort={{ key: 'flow', dir: 'asc' }} columns={[
              { key: 'flow', label: 'Flow', num: true }, { key: 'direction', label: 'Direction' }, { key: 'scale_status', label: 'Window scale', render: status },
              { key: 'scale_shift', label: 'Shift', num: true, render: (v) => (v == null ? '–' : v) },
              { key: 'window_min', label: 'Min', num: true, render: fmtBytes }, { key: 'window_avg', label: 'Avg', num: true, render: fmtBytes }, { key: 'window_max', label: 'Max', num: true, render: fmtBytes },
              { key: 'zero_window_engine', label: 'Zero-window adverts', num: true }, { key: 'zero_window_wireshark', label: 'Zero-window (Wireshark)', num: true },
              { key: 'zero_window_probes', label: 'Probes', num: true }, { key: 'window_updates', label: 'Window updates', num: true }, { key: 'window_full', label: 'Window full', num: true },
            ]} />
          </Card>
          {d.events.length > 0 && (
            <Card title="Window events">
              <DataTable rows={d.events} pageSize={10} columns={[{ key: 'packet_no', label: 'Packet', num: true }, { key: 'rel_time', label: 'Time (s)', num: true, render: (v) => v?.toFixed(4) },
                { key: 'direction_label', label: 'Sender' }, { key: 'kind', label: 'Event' }, { key: 'eff_win', label: 'Effective window', num: true, render: fmtBytes }, { key: 'win_status', label: 'Scale status' }]} />
            </Card>
          )}
        </>
      )}
    </div>
  )
}
