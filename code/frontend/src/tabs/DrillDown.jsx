import { useEffect, useState } from 'react'
import { getFlow, getPackets } from '../api.js'
import { Card, DataTable, Empty, FlowSelect, Stat, TagBadges } from '../components/ui.jsx'
import { fmtBps, fmtBytes, fmtMs, fmtNum, fmtSec } from '../lib.js'

const PAGE = 100

function PacketTable({ id, flow }) {
  const [flaggedOnly, setFlaggedOnly] = useState(false)
  const [offset, setOffset] = useState(0)
  const [data, setData] = useState(null)
  useEffect(() => { setOffset(0) }, [flow, flaggedOnly])
  useEffect(() => {
    let live = true
    setData(null)
    getPackets(id, flow, { offset, limit: PAGE, flaggedOnly }).then((d) => live && setData(d))
    return () => { live = false }
  }, [id, flow, offset, flaggedOnly])

  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE)) : 1
  return (
    <Card title="Packet table"
          actions={<label className="check"><input type="checkbox" checked={flaggedOnly} onChange={(e) => setFlaggedOnly(e.target.checked)} /> flagged packets only</label>}>
      {!data ? <Empty>Loading…</Empty> : (
        <>
          <div className="tablewrap">
            <table className="dt">
              <thead><tr>
                <th className="num">#</th><th className="num">Time (s)</th><th>Timestamp (UTC)</th><th>Dir</th><th>Source</th><th>Destination</th><th>Flags</th>
                <th className="num">Seq</th><th className="num">Ack</th><th className="num">Payload</th><th className="num">Window</th><th className="num">RTT</th><th>Acks pkt</th><th>Indicators</th><th>Wireshark message</th>
              </tr></thead>
              <tbody>
                {data.rows.map((r) => (
                  <tr key={r.packet_no} className={r.tags ? 'flagged' : ''}>
                    <td className="num">{r.packet_no}</td><td className="num">{r.time_s?.toFixed(6)}</td>
                    <td className="mono">{new Date(r.epoch * 1000).toISOString().replace('T', ' ').replace('Z', '')}</td>
                    <td>{r.direction}</td><td>{r.src}:{r.sport}</td><td>{r.dst}:{r.dport}</td><td>{r.flags}</td>
                    <td className="num">{r.seq}</td><td className="num">{r.ack}</td><td className="num">{r.payload}</td><td className="num">{r.window}</td>
                    <td className="num">{r.ack_rtt != null ? fmtMs(r.ack_rtt * 1000, 3) : '–'}</td><td>{r.acks_frame != null ? `#${r.acks_frame}` : ''}</td>
                    <td><TagBadges tags={r.tags} /></td><td>{r.wireshark_message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!data.rows.length && <Empty>No packets.</Empty>}
          </div>
          <div className="pager">
            <span>{fmtNum(data.total)} packets</span>
            <button className="btn small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>‹ Prev</button>
            <span>Page {offset / PAGE + 1} / {pages}</span>
            <button className="btn small" disabled={offset + PAGE >= data.total} onClick={() => setOffset(offset + PAGE)}>Next ›</button>
          </div>
        </>
      )}
    </Card>
  )
}

export default function DrillDown({ id, report, flow, setFlow }) {
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')

  // default to the flow with the most issues
  useEffect(() => {
    if (flow == null && report.flows.length) setFlow([...report.flows].sort((a, b) => b.issues - a.issues || b.packets - a.packets)[0].flow)
  }, [flow, report.flows, setFlow])

  useEffect(() => {
    if (flow == null) return
    setD(null); setErr('')
    getFlow(id, flow).then(setD).catch((e) => setErr(e.message))
  }, [id, flow])

  const fl = d?.flow
  const flagged = d?.findings || []
  return (
    <div className="stack">
      <div className="toolbar">
        <b>Flow:</b><FlowSelect flows={report.flows} value={flow} onChange={setFlow} />
      </div>
      {!report.flows.length && <Card><Empty>No TCP flows in this capture.</Empty></Card>}
      {err && <div className="err">{err}</div>}
      {!d && !err && flow != null && <Card><Empty>Loading flow…</Empty></Card>}
      {d && (
        <>
          <Card title={`Flow #${fl.flow}: ${fl.client} ⇄ ${fl.server}`}>
            <div className="stats">
              <Stat label="Packets" value={fmtNum(fl.packets)} /><Stat label="Bytes" value={fmtBytes(fl.bytes)} />
              <Stat label="Duration" value={fmtSec(fl.duration_s)} /><Stat label="Throughput" value={fmtBps(fl.throughput_bps)} />
              <Stat label="Retransmissions" value={fmtNum(fl.retransmissions)} tone="bad" /><Stat label="Duplicate ACKs" value={fmtNum(fl.dup_acks)} tone="info" />
              <Stat label="Out-of-order" value={fmtNum(fl.out_of_order)} tone="warn" /><Stat label="Sequence gaps" value={fmtNum(fl.seq_gaps)} tone="gap" />
              <Stat label="RTT avg" value={fmtMs(fl.rtt_avg_ms)} sub={fl.rtt_samples ? `${fl.rtt_samples} samples · handshake ${fmtMs(fl.handshake_rtt_ms)}` : 'no samples'} />
            </div>
          </Card>

          <Card title="Flagged packets in this flow" sub={flagged.length ? `${flagged.length} packet${flagged.length === 1 ? '' : 's'}` : ''}>
              {flagged.length ? (
                <DataTable rows={flagged} pageSize={8} searchable={false} columns={[
                  { key: 'packet_no', label: 'Packet', num: true }, { key: 'rel_time', label: 'Time (s)', num: true, render: (v) => v?.toFixed(4) },
                  { key: 'direction', label: 'Dir' }, { key: 'tags', label: 'Indicator', render: (v) => <TagBadges tags={v} /> },
                  { key: 'seq', label: 'Seq', num: true }, { key: 'wireshark_message', label: 'Wireshark message' },
                ]} />
              ) : <Empty>✅ No anomalies flagged in this flow.</Empty>}
            </Card>

          <PacketTable id={id} flow={flow} />
        </>
      )}
    </div>
  )
}
