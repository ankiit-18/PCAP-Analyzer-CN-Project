import { useMemo, useState } from 'react'
import { Card, DataTable } from '../components/ui.jsx'
import { fmtBps, fmtBytes, fmtMs, fmtNum, fmtNum1, fmtSec } from '../lib.js'

export default function Flows({ report, onIndicators, onDrill }) {
  const [onlyIssues, setOnlyIssues] = useState(false)
  const [more, setMore] = useState(false)
  const rows = useMemo(() => (onlyIssues ? report.flows.filter((f) => f.issues > 0) : report.flows), [report.flows, onlyIssues])
  const issue = (v) => (v ? <b style={{ color: 'var(--bad)' }}>{v}</b> : 0)
  const columns = [
    ...(more ? [
      { key: 'payload_bytes', label: 'Payload', num: true, render: fmtBytes }, { key: 'packets_per_s', label: 'Pkts/s', num: true, render: fmtNum1 }, { key: 'avg_packet_size', label: 'Avg pkt', num: true, render: (v) => `${fmtNum1(v)} B` },
      { key: 'pkts_c2s', label: 'Pkts c→s', num: true }, { key: 'pkts_s2c', label: 'Pkts s→c', num: true }, { key: 'bytes_c2s', label: 'Bytes c→s', num: true, render: fmtBytes }, { key: 'bytes_s2c', label: 'Bytes s→c', num: true, render: fmtBytes },
      { key: 'payload_c2s', label: 'Payload c→s', num: true, render: fmtBytes }, { key: 'payload_s2c', label: 'Payload s→c', num: true, render: fmtBytes },
      { key: 'throughput_c2s_bps', label: 'Thr c→s', num: true, render: fmtBps }, { key: 'throughput_s2c_bps', label: 'Thr s→c', num: true, render: fmtBps },
      { key: 'fast_retransmissions', label: 'Fast retx', num: true }, { key: 'spurious_retransmissions', label: 'Spurious retx', num: true }, { key: 'lost_segments', label: 'Lost-seg flags', num: true },
      { key: 'ack_lost_segments', label: 'ACK-lost-seg', num: true }, { key: 'zero_windows', label: 'Zero win', num: true }, { key: 'resets', label: 'RST', num: true }, { key: 'rtt_std_ms', label: 'RTT std', num: true, render: (v) => fmtMs(v) },
    ] : []),
    { key: 'actions', label: '', render: (_, r) => (
      <span style={{ display: 'flex', gap: 6 }}>
        <button className="btn small" onClick={(e) => { e.stopPropagation(); onIndicators(r.flow) }}>Indicators</button>
        <button className="btn small" onClick={(e) => { e.stopPropagation(); onDrill(r.flow) }}>Drill-down</button>
      </span>) },
    { key: 'flow', label: 'Flow', num: true },
    { key: 'client', label: 'Client', render: (v, r) => (r.role_known ? v : `${v} ?`) }, { key: 'server', label: 'Server' },
    { key: 'packets', label: 'Packets', num: true, render: fmtNum },
    { key: 'bytes', label: 'Bytes', num: true, render: fmtBytes },
    { key: 'duration_s', label: 'Duration', num: true, render: (v) => fmtSec(v) },
    { key: 'throughput_bps', label: 'Throughput', num: true, render: fmtBps },
    { key: 'retransmissions', label: 'Retrans.', num: true, render: issue },
    { key: 'dup_acks', label: 'Dup ACKs', num: true },
    { key: 'out_of_order', label: 'Out-of-order', num: true, render: issue },
    { key: 'seq_gaps', label: 'Seq gaps', num: true, render: issue },
    { key: 'handshake_rtt_ms', label: 'Handshake RTT', num: true, render: (v) => fmtMs(v) },
    { key: 'rtt_avg_ms', label: 'RTT avg', num: true, render: (v) => fmtMs(v) },
    { key: 'rtt_samples', label: 'RTT samples', num: true },
  ]
  return (
    <Card title="TCP flows"
          actions={<span style={{ display: 'flex', gap: 14 }}>
            <label className="check"><input type="checkbox" checked={more} onChange={(e) => setMore(e.target.checked)} /> all columns (payload, directional, …)</label>
            <label className="check"><input type="checkbox" checked={onlyIssues} onChange={(e) => setOnlyIssues(e.target.checked)} /> only flows with issues</label></span>}>
      <DataTable rows={rows} columns={columns} pageSize={15} defaultSort={{ key: 'bytes', dir: 'desc' }} onRowClick={(r) => onDrill(r.flow)}
                 empty="No TCP flows in this capture." />
    </Card>
  )
}
