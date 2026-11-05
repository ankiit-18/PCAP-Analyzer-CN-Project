import { useEffect, useMemo, useState } from 'react'
import { getIndicators } from '../api.js'
import Chart from '../components/Chart.jsx'
import { Card, DataTable, Empty, FlowSelect, Stat, TagBadges } from '../components/ui.jsx'
import { INDICATORS, INDICATOR_KEYS, fmtNum } from '../lib.js'

const TONE = { retransmission: 'bad', out_of_order: 'warn', duplicate_ack: 'info', lost_segment: 'gap' }

export default function Indicators({ id, report, flow, setFlow, onDrill }) {
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  const [only, setOnly] = useState('all')

  useEffect(() => {
    setData(null); setErr(''); setOnly('all')
    getIndicators(id, flow).then(setData).catch((e) => setErr(e.message))
  }, [id, flow])

  const events = useMemo(() => (data ? data.events.filter((e) => only === 'all' || e.tags.split(',').includes(only)) : []), [data, only])

  const countOpt = useMemo(() => !data ? {} : ({
    grid: { left: 170, right: 30, top: 10, bottom: 25 }, tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    xAxis: { type: 'value' }, yAxis: { type: 'category', data: INDICATOR_KEYS.map((k) => INDICATORS[k].label), inverse: true },
    series: [{ type: 'bar', barMaxWidth: 22, data: INDICATOR_KEYS.map((k) => ({ value: data.counts[k] || 0, itemStyle: { color: INDICATORS[k].color } })) }],
  }), [data])

  const timelineOpt = useMemo(() => {
    if (!data) return {}
    const series = INDICATOR_KEYS.map((k) => ({
      name: INDICATORS[k].label, type: 'scatter', symbol: INDICATORS[k].symbol, symbolRotate: INDICATORS[k].rotate || 0, symbolSize: INDICATORS[k].size,
      itemStyle: { color: INDICATORS[k].color },
      data: data.events.filter((e) => e.tags.split(',').includes(k)).map((e) => [e.rel_time, INDICATORS[k].label, e.packet_no, e.flow]),
    })).filter((s) => s.data.length)
    return {
      grid: { left: 170, right: 20, top: 56, bottom: 60 },
      tooltip: { trigger: 'item', formatter: (p) => `${p.seriesName}<br>packet #${p.data[2]} · flow #${p.data[3]}<br>t = ${p.data[0].toFixed(4)} s` },
      xAxis: { type: 'value', name: 'time (s)', nameLocation: 'middle', nameGap: 28 }, yAxis: { type: 'category', data: INDICATOR_KEYS.map((k) => INDICATORS[k].label), inverse: true },
      dataZoom: [{ type: 'inside', xAxisIndex: 0 }, { type: 'slider', xAxisIndex: 0, height: 18, bottom: 6 }], series,
    }
  }, [data])

  const byFlowOpt = useMemo(() => {
    if (!data?.by_flow?.length) return null
    const f = data.by_flow
    return {
      grid: { left: 60, right: 20, top: 56, bottom: 40 }, legend: { top: 0 }, tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      xAxis: { type: 'category', data: f.map((r) => `#${r.flow}`), name: 'flow' }, yAxis: { type: 'value', name: 'packets' },
      series: INDICATOR_KEYS.filter((k) => f.some((r) => r[k])).map((k) => ({ name: INDICATORS[k].label, type: 'bar', stack: 'x', data: f.map((r) => r[k] || 0), itemStyle: { color: INDICATORS[k].color } })),
    }
  }, [data])

  const cols = [
    { key: 'packet_no', label: 'Packet', num: true }, { key: 'flow', label: 'Flow', num: true },
    { key: 'rel_time', label: 'Time (s)', num: true, render: (v) => v?.toFixed(4) },
    { key: 'direction', label: 'Dir' }, { key: 'tags', label: 'Indicator', render: (v) => <TagBadges tags={v} /> },
    { key: 'seq', label: 'Seq', num: true }, { key: 'ack', label: 'Ack', num: true }, { key: 'flags', label: 'Flags' },
    { key: 'wireshark_message', label: 'Wireshark message' },
  ]

  return (
    <div className="stack">
      <div className="toolbar">
        <b>Scope:</b><FlowSelect flows={report.flows} value={flow} onChange={setFlow} allowAll />
        {flow != null && <button className="btn" onClick={() => onDrill(flow)}>Open flow drill-down →</button>}
      </div>
      {err && <div className="err">{err}</div>}
      {!data && !err && <Card><Empty>Loading…</Empty></Card>}
      {data && (
        <>
          <div className="stats">
            <Stat label="Retransmissions" value={fmtNum((data.counts.retransmission || 0) + (data.counts.fast_retransmission || 0))}
                  sub={`${data.counts.fast_retransmission || 0} fast · ${data.counts.spurious_retransmission || 0} spurious`} tone="bad" />
            <Stat label="Duplicate ACKs" value={fmtNum(data.counts.duplicate_ack)} tone="info" />
            <Stat label="Out-of-order" value={fmtNum(data.counts.out_of_order)} tone="warn" />
            <Stat label="Sequence gaps" value={fmtNum((data.counts.lost_segment || 0) + (data.counts.ack_lost_segment || 0))} tone="gap" />
            <Stat label="Flagged packets" value={fmtNum(data.flagged_packets)} sub={flow == null ? 'whole capture' : `flow #${flow}`} />
          </div>
          {data.flagged_packets === 0 ? <Card><Empty>✅ Wireshark flagged no TCP anomalies {flow == null ? 'in this capture' : 'in this flow'}.</Empty></Card> : (
            <>
              <div className="grid cols-2">
                <Card title="Indicators by type"><Chart option={countOpt} height={290} /></Card>
                <Card title="When they occurred"><Chart option={timelineOpt} height={290} /></Card>
              </div>
              {byFlowOpt && <Card title="Indicators per flow">
                <Chart option={byFlowOpt} height={280} onClick={(p) => onDrill(Number(String(data.by_flow[p.dataIndex].flow)))} /></Card>}
              <Card title="Flagged packets" sub={data.events.length < data.flagged_packets ? `showing first ${fmtNum(data.events.length)} of ${fmtNum(data.flagged_packets)}` : 'Click a row to open its flow'}
                    actions={<select value={only} onChange={(e) => setOnly(e.target.value)}>
                      <option value="all">All indicators</option>
                      {INDICATOR_KEYS.filter((k) => data.counts[k]).map((k) => <option key={k} value={k}>{INDICATORS[k].label} ({data.counts[k]})</option>)}
                    </select>}>
                <DataTable rows={events} columns={cols} pageSize={15} defaultSort={{ key: 'packet_no', dir: 'asc' }} onRowClick={(r) => onDrill(r.flow)} />
              </Card>
            </>
          )}
        </>
      )}
    </div>
  )
}
