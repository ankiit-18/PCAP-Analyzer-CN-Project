import { useEffect, useMemo, useState } from 'react'
import { getTcpRetransmissions } from '../api.js'
import Chart from '../components/Chart.jsx'
import { Card, DataTable, Empty, Stat } from '../components/ui.jsx'
import { INDICATORS, fmtDur, fmtMs, fmtNum } from '../lib.js'

// what each flagged retransmission most likely is (inferred from the interval and the flow's handshake RTT)
const VERDICT = {
  retransmission: { label: 'Likely retransmission', color: '#e5484d', hint: 'took at least one round trip: consistent with a loss recovery' },
  reordering: { label: 'Likely reordering (late arrival)', color: '#f08c00', hint: 'original not captured and it came back within one round trip: it was delayed, not resent' },
  duplicate: { label: 'Likely duplicate copy', color: '#8b93a7', hint: 'original captured, same bytes seen again within one round trip' },
  undetermined: { label: 'Undetermined', color: '#a0612b', hint: 'no handshake RTT to compare with' },
}
const VKEYS = Object.keys(VERDICT)

/** How long did each retransmission take? One dot per retransmission (log scale: the values span microseconds to seconds).
 *  Colour = what it most likely is (real retransmission / late arrival / duplicate). Filled circle = exact (original captured); hollow diamond = lower bound (original not captured). */
export default function RetxIntervals({ id, flow, onDrill }) {
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    setD(null); setErr('')
    getTcpRetransmissions(id, flow).then(setD).catch((e) => setErr(e.message))
  }, [id, flow])

  const option = useMemo(() => {
    if (!d || !d.points.length) return null
    // point = [time, interval ms, packet, flow, kind, transmission #, reference packet, shorter than one RTT?, basis, verdict]
    const series = VKEYS.map((v) => ({
      name: VERDICT[v].label, type: 'scatter', symbolSize: 9, itemStyle: { color: VERDICT[v].color },
      data: d.points.filter((p) => p[9] === v).map((p) => ({
        // plotted value is floored at 1 µs for the log axis; the real interval is kept for the tooltip
        value: [p[0], Math.max(p[1], 0.001), p[2], p[3], p[5], p[6], p[1], p[7], p[4], p[8], v],
        symbol: p[8] === 'original' ? 'circle' : 'diamond',
        itemStyle: p[8] === 'original' ? { color: VERDICT[v].color, opacity: 0.85 } : { color: 'transparent', borderColor: VERDICT[v].color, borderWidth: 2 },
      })),
    })).filter((x) => x.data.length)
    if (d.handshake_rtt_ms && series.length) {
      series[0].markLine = { symbol: 'none', silent: true, lineStyle: { type: 'dashed', color: '#16a34a' }, label: { formatter: 'handshake RTT', position: 'insideEndTop' }, data: [{ yAxis: d.handshake_rtt_ms }] }
    }
    return {
      grid: { left: 84, right: 20, top: 40, bottom: 62 }, legend: { top: 0 },
      tooltip: {
        trigger: 'item',
        formatter: (p) => {
          const v = p.data.value
          const how = v[9] === 'original'
            ? `<b>${fmtDur(v[6])}</b> after the original (packet #${v[5]})`
            : `original not captured<br>arrived <b>${fmtDur(v[6])}</b> after packet #${v[5]}, which overtook it<br>(so at least that long after the original)`
          return `${v[8]} · packet #${v[2]} · flow #${v[3]}${v[4] > 1 ? ` · transmission ${v[4]}` : ''}<br>${how}${v[7] === true ? '<br>shorter than one handshake RTT' : ''}<br><i>${VERDICT[v[10]].label}: ${VERDICT[v[10]].hint}</i><br>at t = ${v[0].toFixed(4)} s`
        },
      },
      xAxis: { type: 'value', name: 'time of the retransmission (s)', nameLocation: 'middle', nameGap: 28, scale: true },
      yAxis: { type: 'log', logBase: 10, min: 0.001, name: 'time until the retransmission', nameLocation: 'middle', nameGap: 62, axisLabel: { formatter: (v) => fmtDur(v) } },
      dataZoom: [{ type: 'inside' }, { type: 'slider', height: 16, bottom: 6 }], series,
    }
  }, [d])

  if (err) return <div className="err">{err}</div>
  if (!d) return <Card title="Retransmission interval"><Empty>Loading…</Empty></Card>
  if (d.total === 0) return null
  const st = d.stats_ms

  const flowCols = [
    { key: 'flow', label: 'Flow', num: true }, { key: 'retransmissions', label: 'Flagged', num: true }, { key: 'likely_real', label: 'Likely real', num: true }, { key: 'late_arrivals', label: 'Late arrivals', num: true }, { key: 'exact', label: 'Exact', num: true },
    { key: 'min_ms', label: 'Shortest', num: true, render: fmtDur }, { key: 'median_ms', label: 'Median', num: true, render: fmtDur },
    { key: 'p95_ms', label: '95th pct', num: true, render: fmtDur }, { key: 'max_ms', label: 'Longest', num: true, render: fmtDur },
    { key: 'handshake_rtt_ms', label: 'Handshake RTT', num: true, render: (v) => (v == null ? '–' : fmtMs(v)) },
  ]
  const evCols = [
    { key: 'packet_no', label: 'Packet', num: true }, { key: 'flow', label: 'Flow', num: true }, { key: 'rel_time', label: 'Time (s)', num: true, render: (v) => v?.toFixed(4) },
    { key: 'kind', label: 'Wireshark flag' }, { key: 'transmission', label: 'Transmission #', num: true, render: (v) => (v == null ? '–' : v) },
    { key: 'interval_ms', label: 'Interval', num: true, render: fmtDur },
    { key: 'basis', label: 'Measured from', render: (v, r) => (v === 'original' ? `original, packet #${r.reference_no}` : v === 'overtaken' ? `overtaking packet #${r.reference_no} (lower bound)` : 'not measurable') },
    { key: 'since_previous_ms', label: 'Since previous try', num: true, render: fmtDur },
    { key: 'verdict', label: 'Most likely', render: (v) => <span><i className="dot" style={{ background: VERDICT[v]?.color }} /> {VERDICT[v]?.label || v}</span> },
    { key: 'seq', label: 'Seq', num: true }, { key: 'length', label: 'Bytes', num: true },
  ]
  return (
    <div className="stack">
      <div className="stats">
        <Stat label="Flagged by Wireshark" value={fmtNum(d.total)} sub={`${fmtNum(d.timed)} timed · ${fmtNum(d.exact)} exact, ${fmtNum(d.lower_bound)} lower bound`} tone="bad" />
        <Stat label="Likely real retransmissions" value={fmtNum(d.verdicts.retransmission)} sub="took at least one round trip" tone="bad" />
        <Stat label="Late arrivals (reordering)" value={fmtNum(d.verdicts.reordering)} sub={d.verdicts.duplicate ? `+ ${fmtNum(d.verdicts.duplicate)} duplicate copies` : 'came back within one round trip'} tone="warn" />
        <Stat label="Unclassified" value={fmtNum(d.verdicts.undetermined)} sub="no handshake RTT to compare with" />
        <Stat label="Median interval" value={st ? fmtDur(st.median) : '–'} sub="until the retransmission" />
        <Stat label="95th percentile" value={st ? fmtDur(st.p95) : '–'} />
        <Stat label="Longest" value={st ? fmtDur(st.max) : '–'} />
        <Stat label="Handshake RTT" value={d.handshake_rtt_ms ? fmtMs(d.handshake_rtt_ms) : '–'} sub={d.handshake_rtt_ms ? 'the line used to tell resends from late arrivals' : 'pick one flow to see it'} tone="info" />
      </div>
      <Card title="Retransmission interval"
            sub="One dot per packet Wireshark flagged as a retransmission. Wireshark also flags segments that were merely reordered, so each one is sorted by how long it took compared with the flow's handshake RTT (derived and inferred).">
        {option ? <Chart option={option} height={320} onClick={(p) => p.data?.value && onDrill && onDrill(p.data.value[3])} />
          : <Empty>No interval could be measured for these retransmissions.</Empty>}
        <div className="muted" style={{ marginTop: 8, fontSize: 12 }}>
          {d.note} A retransmission caused by loss needs about one round trip of feedback, so dots below the dashed handshake-RTT line (one flow selected) were more likely late
          arrivals or duplicate copies than loss recoveries. This is an inference, not proof.
        </div>
      </Card>
      {flow == null && d.by_flow.length > 0 && (
        <Card title="Retransmission intervals per flow" sub="Click a row to open the flow">
          <DataTable rows={d.by_flow} columns={flowCols} pageSize={10} defaultSort={{ key: 'retransmissions', dir: 'desc' }} onRowClick={(r) => onDrill && onDrill(r.flow)} />
        </Card>
      )}
      <Card title="Every retransmission and its interval" sub={d.events.length < d.total ? `showing the first ${fmtNum(d.events.length)} of ${fmtNum(d.total)}` : undefined}>
        <DataTable rows={d.events} columns={evCols} pageSize={15} defaultSort={{ key: 'rel_time', dir: 'asc' }} onRowClick={(r) => onDrill && onDrill(r.flow)} />
      </Card>
    </div>
  )
}
