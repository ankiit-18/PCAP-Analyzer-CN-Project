import { useEffect, useState } from 'react'
import { getCongestion } from '../api.js'
import { ChartCard } from '../components/GenericChart.jsx'
import { Basis } from '../components/Spec.jsx'
import { Card, DataTable, Empty, FlowSelect } from '../components/ui.jsx'
import { fmtBytes, fmtMs, fmtNum } from '../lib.js'

const tone = (a) => (/congestion|loss/i.test(a) ? 'bad' : /reordering|flow-control|RTT variation/i.test(a) ? 'warn' : 'ok')

export default function Congestion({ id, report, flow, setFlow }) {
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    setD(null); setErr('')
    getCongestion(id, flow).then(setD).catch((e) => setErr(e.message))
  }, [id, flow])
  const yn = (v) => (v == null ? 'Unknown' : v ? 'Yes' : 'No')
  return (
    <div className="stack">
      <div className="toolbar"><b>Scope:</b><FlowSelect flows={report.flows} value={flow} onChange={setFlow} allowAll /></div>
      {err && <div className="err">{err}</div>}
      {!d && !err && <Card><Empty>Loading…</Empty></Card>}
      {d && (
        <>
          <Card title="Assessment per flow">
            <DataTable rows={d.flows} pageSize={8} defaultSort={{ key: 'retransmissions', dir: 'desc' }} columns={[
              { key: 'flow', label: 'Flow', num: true }, { key: 'client', label: 'Client' }, { key: 'server', label: 'Server' },
              { key: 'assessment', label: 'Assessment', wrap: true, render: (v) => <span className={`assess ${tone(v)}`}>{v}</span> },
              { key: 'evidence', label: 'Evidence', wrap: true, render: (v) => <ul className="evidence">{(v || []).map((e, i) => <li key={i}><Basis basis={e.basis} /> {e.text}</li>)}{!(v || []).length && <li>No indicators observed</li>}</ul> },
            ]} />
          </Card>
          {d.charts.length > 0 ? <div className="grid cols-2">{d.charts.map((c) => <ChartCard key={c.id} spec={c} height={300} />)}</div> : <Card><Empty>No timeline data for this scope.</Empty></Card>}
          <Card title="Indicators by flow">
            <DataTable rows={d.flows} pageSize={10} columns={[
              { key: 'flow', label: 'Flow', num: true }, { key: 'data_packets', label: 'Data pkts', num: true, render: fmtNum }, { key: 'retransmission_pct', label: 'Retrans %', num: true, render: (v) => (v == null ? '–' : `${v.toFixed(1)}%`) },
              { key: 'retransmissions', label: 'Retrans', num: true }, { key: 'fast_retransmissions', label: 'Fast', num: true }, { key: 'spurious_retransmissions', label: 'Spurious', num: true },
              { key: 'dup_acks', label: 'Dup ACKs', num: true }, { key: 'out_of_order', label: 'Out-of-order', num: true }, { key: 'lost_segments', label: 'Seq gaps', num: true },
              { key: 'rtt_min_ms', label: 'RTT min', num: true, render: (v) => fmtMs(v) }, { key: 'rtt_p95_ms', label: 'RTT p95', num: true, render: (v) => fmtMs(v) },
              { key: 'bytes_in_flight_max', label: 'Max bytes in flight', num: true, render: (v) => (v == null ? 'n/a' : fmtBytes(v)) },
              { key: 'ecn_negotiated', label: 'ECN negotiated', render: yn }, { key: 'ce_marks', label: 'CE marks', num: true }, { key: 'ece_packets', label: 'ECE', num: true },
              { key: 'peak_packets_per_10ms', label: 'Peak pkts/10 ms', num: true, render: (v) => (v == null ? 'n/a' : v) }, { key: 'burstiness', label: 'Burstiness', num: true, render: (v) => (v == null ? 'n/a' : `${v.toFixed(1)}×`) },
            ]} />
          </Card>
          {d.ecn_events.length > 0 && (
            <Card title="ECN events">
              <DataTable rows={d.ecn_events} pageSize={8} columns={[{ key: 'packet_no', label: 'Packet', num: true }, { key: 'rel_time', label: 'Time (s)', num: true, render: (v) => v?.toFixed(4) }, { key: 'flow', label: 'Flow', num: true }, { key: 'kind', label: 'Event' }]} />
            </Card>
          )}
        </>
      )}
    </div>
  )
}
