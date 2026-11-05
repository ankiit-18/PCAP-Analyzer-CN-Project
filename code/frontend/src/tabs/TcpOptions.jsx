import { useEffect, useState } from 'react'
import { getTcpOptions } from '../api.js'
import { Card, DataTable, Empty, FlowSelect } from '../components/ui.jsx'
import { fmtNum } from '../lib.js'

const yn = (v) => (v == null ? <span className="muted" title="The handshake was not captured, so the negotiation result is unknown">Unknown</span> : v ? 'Yes' : 'No')
const val = (v) => (v == null ? '–' : v)

export default function TcpOptions({ id, report, flow, setFlow }) {
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    setD(null); setErr('')
    getTcpOptions(id, flow).then(setD).catch((e) => setErr(e.message))
  }, [id, flow])
  return (
    <div className="stack">
      <div className="toolbar"><b>Scope:</b><FlowSelect flows={report.flows} value={flow} onChange={setFlow} allowAll /></div>
      {err && <div className="err">{err}</div>}
      {!d && !err && <Card><Empty>Loading…</Empty></Card>}
      {d && (
        <>
          <Card title="Negotiated options per flow">
            <DataTable rows={d.flows} pageSize={12} defaultSort={{ key: 'flow', dir: 'asc' }} columns={[
              { key: 'flow', label: 'Flow', num: true }, { key: 'client', label: 'Client' }, { key: 'server', label: 'Server' },
              { key: 'handshake_captured', label: 'Handshake captured', render: (v) => (v ? 'Yes' : 'No') },
              { key: 'client_mss', label: 'Client MSS', num: true, render: val }, { key: 'server_mss', label: 'Server MSS', num: true, render: val },
              { key: 'wscale_negotiated', label: 'Window scale', render: yn }, { key: 'sack_negotiated', label: 'SACK', render: yn },
              { key: 'timestamps_negotiated', label: 'Timestamps', render: yn }, { key: 'ecn_negotiated', label: 'ECN', render: yn },
              { key: 'sack_block_packets', label: 'SACK blocks seen later', num: true, render: fmtNum }, { key: 'timestamp_packets_later', label: 'Timestamps seen later', num: true, render: fmtNum },
              { key: 'ce_marks', label: 'CE marks', num: true },
            ]} />
          </Card>
          <Card title="Options by flow and direction">
            <DataTable rows={d.by_direction} pageSize={12} defaultSort={{ key: 'flow', dir: 'asc' }} columns={[
              { key: 'flow', label: 'Flow', num: true }, { key: 'direction', label: 'Direction (sender)' }, { key: 'handshake_packet_seen', label: 'SYN captured', render: (v) => (v ? 'Yes' : 'No') },
              { key: 'mss', label: 'MSS', num: true, render: val }, { key: 'wscale_shift', label: 'WScale shift', num: true, render: val }, { key: 'wscale_factor', label: 'Factor', num: true, render: val },
              { key: 'sack_permitted', label: 'SACK permitted', render: yn }, { key: 'timestamps', label: 'Timestamps', render: yn }, { key: 'syn_ece', label: 'SYN ECE', render: yn }, { key: 'syn_cwr', label: 'SYN CWR', render: yn },
              { key: 'window_scale_status', label: 'Window scale status' },
              { key: 'sack_block_packets', label: 'SACK blocks (later)', num: true }, { key: 'timestamp_packets_later', label: 'Timestamps (later)', num: true },
              { key: 'mss_later_packets', label: 'MSS (later)', num: true }, { key: 'ece_packets', label: 'ECE pkts', num: true }, { key: 'cwr_packets', label: 'CWR pkts', num: true },
            ]} />
          </Card>
        </>
      )}
    </div>
  )
}
