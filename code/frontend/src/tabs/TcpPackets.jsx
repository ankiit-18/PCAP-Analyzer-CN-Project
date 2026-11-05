import { useEffect, useState } from 'react'
import { getTcpPackets } from '../api.js'
import { DecodeDrawer } from '../components/PacketInspector.jsx'
import { Card, Empty, FlowSelect, TagBadges } from '../components/ui.jsx'
import { CONDITIONS, fmtMs } from '../lib.js'

const PAGE = 100

/** TCP packet inspection: filter by flow and by conditions (retransmissions, duplicate ACKs, zero-window, out-of-order, ...). */
export default function TcpPackets({ id, report, flow, setFlow }) {
  const [conds, setConds] = useState([])
  const [offset, setOffset] = useState(0)
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')
  const [decode, setDecode] = useState(null)
  useEffect(() => { setOffset(0) }, [flow, conds])
  useEffect(() => {
    let live = true
    setD(null); setErr('')
    getTcpPackets(id, { flow, conds, offset, limit: PAGE }).then((x) => live && setD(x)).catch((e) => live && setErr(e.message))
    return () => { live = false }
  }, [id, flow, conds, offset])
  const toggle = (c) => setConds((s) => (s.includes(c) ? s.filter((x) => x !== c) : [...s, c]))
  const pages = d ? Math.max(1, Math.ceil(d.total / PAGE)) : 1
  return (
    <div className="stack">
      <div className="toolbar"><b>Flow:</b><FlowSelect flows={report.flows} value={flow} onChange={setFlow} allowAll /></div>
      <Card title="Packet inspection"
            actions={<button className="btn small" onClick={() => setConds([])} disabled={!conds.length}>Clear conditions</button>}>
        <div className="chips" style={{ marginBottom: 12 }}>
          {CONDITIONS.map(([k, l]) => <button key={k} className={`chip ${conds.includes(k) ? 'on' : ''}`} onClick={() => toggle(k)}>{l}</button>)}
        </div>
        {err && <div className="err">{err}</div>}
        {!d && !err ? <Empty>Loading…</Empty> : d && (
          <>
            <div className="muted" style={{ marginBottom: 6 }}>{d.total.toLocaleString()} packets</div>
            <div className="tablewrap">
              <table className="dt">
                <thead><tr><th className="num">#</th><th className="num">Time (s)</th><th className="num">Flow</th><th>Source</th><th>Destination</th><th>Dir</th><th>Flags</th><th className="num">Seq</th><th className="num">Ack</th>
                  <th className="num">Payload</th><th className="num">Window (raw)</th><th className="num">Effective window</th><th className="num">RTT</th><th>Options</th><th>Indicators</th><th>Wireshark message</th></tr></thead>
                <tbody>
                  {d.rows.map((r) => (
                    <tr key={r.packet_no} className={`clickable ${r.tags ? 'flagged' : ''}`} onClick={() => setDecode(r.packet_no)}>
                      <td className="num">{r.packet_no}</td><td className="num">{r.time_s?.toFixed(6)}</td><td className="num">{r.flow}</td><td>{r.src}:{r.sport}</td><td>{r.dst}:{r.dport}</td>
                      <td>{r.direction === 'fwd' ? 'c→s' : 's→c'}</td><td>{r.flags}</td><td className="num">{r.seq}</td><td className="num">{r.ack}</td><td className="num">{r.payload}</td>
                      <td className="num">{r.window}</td><td className="num" title={r.win_status}>{r.effective_window}</td>
                      <td className="num">{r.ack_rtt != null ? fmtMs(r.ack_rtt * 1000, 3) : '–'}</td><td className="mono">{r.options}</td><td><TagBadges tags={r.tags} /></td><td>{r.wireshark_message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!d.rows.length && <Empty>No packets match.</Empty>}
            </div>
            <div className="pager">
              <button className="btn small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>‹ Prev</button>
              <span>Page {offset / PAGE + 1} / {pages}</span>
              <button className="btn small" disabled={offset + PAGE >= d.total} onClick={() => setOffset(offset + PAGE)}>Next ›</button>
            </div>
          </>
        )}
      </Card>
      <DecodeDrawer id={id} no={decode} onClose={() => setDecode(null)} />
    </div>
  )
}
