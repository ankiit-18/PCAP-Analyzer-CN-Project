import { useMemo, useState } from 'react'
import Chart from '../components/Chart.jsx'
import { Card, DataTable, Section, Stat } from '../components/ui.jsx'
import { fmtBps, fmtBytes, fmtNum, fmtNum1, fmtSec } from '../lib.js'

function Fact({ label, value, sub, tip, na }) {
  return na ? (
    <div className="stat na"><div className="label">{label}</div><div className="value">Not available</div><div className="sub">{na}</div></div>
  ) : (
    <Stat label={<>{label}</>} value={value} sub={sub} />
  )
}

const NICE = { frame: 'Frame', eth: 'Ethernet', ip: 'IPv4', ipv6: 'IPv6', arp: 'ARP', tcp: 'TCP', udp: 'UDP', icmp: 'ICMP', icmpv6: 'ICMPv6', data: 'Raw data', tls: 'TLS', http: 'HTTP', dns: 'DNS', dhcp: 'DHCP', vlan: 'VLAN' }
const LAYER = ['Capture', 'Link', 'Network', 'Transport', 'Application', 'Payload', 'Detail']

/** Protocol hierarchy as an indented, collapsible tree with guide lines, a layer label and a share bar. */
function ProtocolTree({ rows }) {
  const [open, setOpen] = useState(() => new Set(rows.map((r, i) => i).filter((i) => rows[i].depth < 3)))
  const hasKids = (i) => i + 1 < rows.length && rows[i + 1].depth > rows[i].depth
  const visible = useMemo(() => {
    const out = []; let hide = Infinity
    rows.forEach((r, i) => {
      if (r.depth > hide) return
      hide = Infinity
      out.push(i)
      if (hasKids(i) && !open.has(i)) hide = r.depth
    })
    return out
  }, [rows, open])
  const toggle = (i) => setOpen((s) => { const n = new Set(s); n.has(i) ? n.delete(i) : n.add(i); return n })
  return (
    <>
      <div className="toolbar" style={{ marginBottom: 8 }}>
        <button className="btn small" onClick={() => setOpen(new Set(rows.map((_, i) => i)))}>Expand all</button>
        <button className="btn small" onClick={() => setOpen(new Set(rows.map((_, i) => i).filter((i) => rows[i].depth < 2)))}>Collapse</button>
      </div>
      <div className="tablewrap ptree" style={{ maxHeight: 420 }}>
        <table className="dt">
          <thead><tr><th>Protocol</th><th>Layer</th><th className="num">Packets</th><th>Share of capture</th><th className="num">Bytes</th></tr></thead>
          <tbody>
            {visible.map((i) => {
              const r = rows[i]
              return (
                <tr key={i}>
                  <td>
                    <span className="tnode">
                      {Array.from({ length: r.depth }).map((_, k) => <span key={k} className="tguide" />)}
                      {hasKids(i) ? <button className="tchev" onClick={() => toggle(i)} aria-label="toggle">{open.has(i) ? '▾' : '▸'}</button> : <span className="tleaf">└</span>}
                      <b>{NICE[r.protocol] || r.protocol.toUpperCase()}</b>
                      {NICE[r.protocol] && NICE[r.protocol].toLowerCase() !== r.protocol && <span className="muted mono"> {r.protocol}</span>}
                    </span>
                  </td>
                  <td className="muted">{LAYER[Math.min(r.depth, LAYER.length - 1)]}</td>
                  <td className="num">{fmtNum(r.frames)}</td>
                  <td><div className="hbar"><div className="track"><i style={{ width: `${r.pct_frames}%` }} /></div><span className="mono pct">{r.pct_frames}%</span></div></td>
                  <td className="num">{fmtBytes(r.bytes)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </>
  )
}

export function Warnings({ items }) {
  if (!items?.length) return null
  const partial = items.filter((w) => w.code === 'partial_analysis')
  const rest = items.filter((w) => w.code !== 'partial_analysis')
  return (
    <>
      {partial.map((w) => <div key={w.code} className="banner"><b>Partial analysis.</b> {w.message.replace(/^Partial analysis: /, '')}</div>)}
      {rest.length > 0 && <div className={`banner ${rest.some((w) => w.level === 'error') ? 'error' : 'info'}`}><ul>{rest.map((w) => <li key={w.code}>{w.message}</li>)}</ul></div>}
    </>
  )
}

export default function OverviewPage({ id, ov, onOpen }) {
  const c = ov.capture
  const zeroDur = !c.duration_s
  const rateNa = zeroDur ? 'The capture spans zero time (all packets share one timestamp).' : null
  const hier = ov.hierarchy
  const others = ov.distribution.filter((p) => !p.page)

  const distOpt = useMemo(() => {
    const rows = ov.distribution.slice(0, 25)            // every protocol in the capture (all layers), biggest first
    return {
      grid: { left: 110, right: 30, top: 10, bottom: 24, containLabel: true }, tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, valueFormatter: (v) => fmtNum(v) },
      xAxis: { type: 'value', name: 'packets' }, yAxis: { type: 'category', inverse: true, data: rows.map((r) => NICE[r.protocol] || r.protocol.toUpperCase()) },
      series: [{ type: 'bar', barMaxWidth: 20, data: rows.map((r) => ({ value: r.packets, itemStyle: { color: r.page ? '#4f46e5' : '#94a3b8' } })) }],
    }
  }, [ov.distribution])

  const Card2 = ({ p }) => (
    <button className="pcard" onClick={() => onOpen(p.key)}>
      <div className="ph"><span className="pn">{p.label}{p.heuristic ? <span className="badge" style={{ background: '#a16207', marginLeft: 6 }} title="Found with Wireshark's RTP heuristic">heuristic</span> : null}</span>
        <span className="pp">{p.pct_packets}% of analysed packets{ov.analysis_metadata?.partial ? ' · partial' : ''}</span></div>
      <ul>{p.lines.map((l) => <li key={l}>{l}</li>)}</ul>
      <div className="pbar"><i style={{ width: `${Math.min(100, p.pct_packets)}%` }} /></div>
      <div className="go">Open {p.label} analysis →</div>
    </button>
  )

  return (
    <div className="stack">
      <Warnings items={ov.warnings} />
      <Section title="Capture" sub={c.filename}>
        <div className="stats">
          <Fact label="File" value={<span style={{ fontSize: 15, wordBreak: 'break-all' }}>{c.filename}</span>} sub={`${fmtBytes(c.file_size)} on disk`} />
          <Fact label="Format" value={c.format.toUpperCase()} />
          <Fact label="Capture duration" value={fmtSec(c.duration_s)} />
          <Fact label="Total packets" value={fmtNum(c.packets)} />
          <Fact label="Total bytes" value={fmtBytes(c.bytes)} sub={`${fmtNum(c.bytes)} B on the wire`} />
          <Fact label="Average packet size" value={`${fmtNum1(c.avg_packet_size)} B`} />
          <Fact label="Packet rate" value={`${fmtNum1(c.packet_rate)} pkt/s`} na={rateNa} />
          <Fact label="Throughput" value={fmtBps(c.throughput_bps)} na={rateNa} />
          <Fact label="Protocols detected" value={fmtNum(c.protocol_count)} />
          <Fact label="Endpoints" value={c.endpoint_count == null ? '–' : fmtNum(c.endpoint_count)} />
          <Fact label="Conversations" value={fmtNum(c.conversation_count)} />
        </div>
      </Section>

      {ov.insights.length > 0 && (
        <Section title="Highlights">
          <div className="insights">
            {ov.insights.map((i) => i.page ? (
              <button key={i.text} className={`insight ${i.tone}`} onClick={() => onOpen(i.page)}><span>{i.text}</span><span className="go">→</span></button>
            ) : (
              <div key={i.text} className={`insight static ${i.tone}`}><span>{i.text}</span></div>
            ))}
          </div>
        </Section>
      )}

      <div className="grid cols-2">
        <Card title="Protocol distribution">
          <ProtocolTree rows={hier} />
        </Card>
        <Card title="Packets per protocol"><Chart option={distOpt} height={420} /></Card>
      </div>

      <Section title="Protocols with a detail page">
        <div className="pcards">{ov.protocols.map((p) => <Card2 key={p.key} p={p} />)}</div>
        {!ov.protocols.length && <div className="note">None of TCP, UDP, DNS, TLS, QUIC or ARP appear in this capture.</div>}
      </Section>

      <Section title="All other protocols" sub={`${others.length} protocols · counted here, no detail page`}>
        <DataTable rows={others} pageSize={12} defaultSort={{ key: 'packets', dir: 'desc' }} searchable columns={[
          { key: 'protocol', label: 'Protocol', render: (v) => <b>{NICE[v] || v.toUpperCase()}</b> },
          { key: 'packets', label: 'Packets', num: true, render: fmtNum },
          { key: 'pct_packets', label: 'Share', num: true, render: (v) => `${v}%` },
          { key: 'bytes', label: 'Bytes', num: true, render: fmtBytes },
          { key: 'summary', label: 'Summary', render: (v) => (v?.length ? v.join(' · ') : '') },
        ]} />
      </Section>

      {ov.endpoints?.length > 0 && (
        <Card title="Endpoint summary">
          <div className="tablewrap"><table className="dt"><thead><tr><th>Address</th><th className="num">Packets</th><th className="num">Bytes</th><th className="num">Sent</th><th className="num">Received</th></tr></thead>
            <tbody>{ov.endpoints.map((e) => <tr key={e.endpoint}><td>{e.endpoint}</td><td className="num">{fmtNum(e.packets)}</td><td className="num">{fmtBytes(e.bytes)}</td><td className="num">{fmtBytes(e.tx_bytes)}</td><td className="num">{fmtBytes(e.rx_bytes)}</td></tr>)}</tbody></table></div>
        </Card>
      )}
      {ov.ip && (
        <div>
          <button className="pcard ipcard" onClick={() => onOpen('ip')}>
            <div className="ph"><span className="pn">IP Analysis</span><span className="pp">network layer</span></div>
            <div>{ov.ip.summary}</div>
            <div className="go">Open IP analysis: endpoints, conversations, TTL, fragmentation, traffic direction →</div>
          </button>
        </div>
      )}
    </div>
  )
}
