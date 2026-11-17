import { useEffect, useMemo, useState } from 'react'
import { getTcpThroughput } from '../api.js'
import Chart from '../components/Chart.jsx'
import { ChartCard } from '../components/GenericChart.jsx'
import { Card, Stat } from '../components/ui.jsx'
import { INDICATORS, INDICATOR_KEYS, fmtBytes, fmtMs, fmtNum, fmtSec } from '../lib.js'

export default function Overview({ id, report, onOpenFlow }) {
  const { summary: s, indicator_counts: ic, flows } = report
  const [thr, setThr] = useState(null)             // TCP throughput over time (all flows), fetched separately from the report
  const [thrErr, setThrErr] = useState('')
  useEffect(() => {
    setThr(null); setThrErr('')
    getTcpThroughput(id).then(setThr).catch((e) => setThrErr(e.message))
  }, [id])

  const indicatorOpt = useMemo(() => ({
    grid: { left: 150, right: 30, top: 10, bottom: 25 },
    xAxis: { type: 'value' },
    yAxis: { type: 'category', data: INDICATOR_KEYS.map((k) => INDICATORS[k].label), inverse: true },
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    series: [{ type: 'bar', data: INDICATOR_KEYS.map((k) => ({ value: ic[k] || 0, itemStyle: { color: INDICATORS[k].color } })), barMaxWidth: 22 }],
  }), [ic])

  const top = useMemo(() => [...flows].sort((a, b) => b.issues - a.issues || b.bytes - a.bytes).slice(0, 10), [flows])
  const issuesOpt = useMemo(() => ({
    grid: { left: 60, right: 20, top: 56, bottom: 55 },
    legend: { top: 0 },
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    xAxis: { type: 'category', data: top.map((f) => `#${f.flow}`), name: 'flow' },
    yAxis: { type: 'value', name: 'packets' },
    series: [
      { name: 'Retransmissions', type: 'bar', stack: 'i', data: top.map((f) => f.retransmissions), itemStyle: { color: INDICATORS.retransmission.color } },
      { name: 'Out-of-order', type: 'bar', stack: 'i', data: top.map((f) => f.out_of_order), itemStyle: { color: INDICATORS.out_of_order.color } },
      { name: 'Duplicate ACKs', type: 'bar', stack: 'i', data: top.map((f) => f.dup_acks), itemStyle: { color: INDICATORS.duplicate_ack.color } },
    ],
  }), [top])

  const retx = s.retransmissions || 0          // Wireshark flags a fast retransmission as a retransmission too: do not add the two counts
  const md = report.analysis_metadata || {}
  const part = md.partial ? ` · PARTIAL (first ${md.packets_processed?.toLocaleString()} pkts)` : ''
  return (
    <div className="stack">
      <div className="stats">
        <Stat label="Packets" value={fmtNum(s.packets)} sub={`${fmtNum(s.tcp_packets)} TCP${part}`} />
        <Stat label="Total bytes" value={fmtBytes(s.bytes)} />
        <Stat label="Duration" value={fmtSec(s.duration_s)} />
        <Stat label="TCP flows" value={fmtNum(s.tcp_flows)} sub={`${s.flows_with_issues} with issues${part}`} />
        <Stat label="Retransmissions" value={fmtNum(retx)} tone="bad"
              sub={`flagged by Wireshark · ${fmtNum(s.likely_retransmissions)} likely real, ${fmtNum(s.late_arrivals)} late arrivals${s.retx_undetermined ? `, ${fmtNum(s.retx_undetermined)} unclassified` : ''}${part}`} />
        <Stat label="Duplicate ACKs" value={fmtNum(s.dup_acks)} tone="info" />
        <Stat label="Out-of-order" value={fmtNum(s.out_of_order)} tone="warn" />
        <Stat label="RTT average" value={fmtMs(s.rtt_avg_ms)} sub={s.rtt_samples ? `min ${fmtMs(s.rtt_min_ms)} · max ${fmtMs(s.rtt_max_ms)} · ${fmtNum(s.rtt_samples)} samples` : 'no samples'} />
      </div>

      <div className="grid cols-2">
        <Card title="TCP indicators">
          <Chart option={indicatorOpt} height={260} />
        </Card>
        <Card title="Flows with the most issues">
          {top.length ? <Chart option={issuesOpt} height={260} onClick={(p) => { const f = top[p.dataIndex]; f && onOpenFlow(f.flow) }} /> : <div className="empty">No TCP flows.</div>}
        </Card>
      </div>

      {thrErr && <div className="err">{thrErr}</div>}
      {thr?.charts?.map((c) => <ChartCard key={c.id} spec={c} height={300} />)}
    </div>
  )
}
