import { useEffect, useState } from 'react'
import { getIpAddress } from '../api.js'
import { ChartCard } from '../components/GenericChart.jsx'
import { Card, DataTable, Empty } from '../components/ui.jsx'
import { fmtBps, fmtBytes, fmtNum, fmtSec } from '../lib.js'

/** Everything about one IP address (opened from the Top Talkers table). */
export default function IpInspector({ id, addr, onClose, onNavigate }) {
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    if (!addr) return
    setD(null); setErr('')
    getIpAddress(id, addr).then(setD).catch((e) => setErr(e.message))
  }, [id, addr])
  if (!addr) return null
  const tbl = (rows, cols, pageSize = 8) => <DataTable rows={rows} columns={cols} pageSize={pageSize} searchable={false} />
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" style={{ width: 'min(900px, 96vw)', overflow: 'auto' }}>
        <header>
          <h3>{addr}</h3>
          {d && <span className="muted">{d.family} · {d.category}</span>}
          <button className="btn small" style={{ marginLeft: 'auto' }} onClick={onClose}>Close ✕</button>
        </header>
        <div style={{ padding: 16 }} className="stack">
          {err && <div className="err">{err}</div>}
          {!d && !err && <Empty>Loading…</Empty>}
          {d && (
            <>
              <div className="stats">
                <div className="stat"><div className="label">Sent</div><div className="value">{fmtNum(d.packets_sent)} pkts</div><div className="sub">{fmtBytes(d.bytes_sent)}</div></div>
                <div className="stat"><div className="label">Received</div><div className="value">{fmtNum(d.packets_received)} pkts</div><div className="sub">{fmtBytes(d.bytes_received)}</div></div>
                <div className="stat"><div className="label">First / last seen</div><div className="value" style={{ fontSize: 16 }}>{fmtSec(d.first_seen_s)} → {fmtSec(d.last_seen_s)}</div></div>
              </div>
              {d.traffic && <ChartCard spec={d.traffic} height={240} />}
              <Card title="Protocol breakdown">{tbl(d.protocols, [{ key: 'l4', label: 'Protocol' }, { key: 'packets', label: 'Packets', num: true, render: fmtNum }, { key: 'bytes', label: 'Bytes', num: true, render: fmtBytes }])}</Card>
              <Card title="Ports / services seen">
                {tbl(d.services, [{ key: 'l4', label: 'Proto' }, { key: 'server_port', label: 'Port' }, { key: 'packets', label: 'Packets', num: true, render: fmtNum }, { key: 'bytes', label: 'Bytes', num: true, render: fmtBytes }])}
              </Card>
              <Card title="Top peers">{tbl(d.peers, [{ key: 'peer', label: 'Peer' }, { key: 'packets', label: 'Packets', num: true, render: fmtNum }, { key: 'bytes', label: 'Bytes', num: true, render: fmtBytes }])}</Card>
              <Card title="Conversations of this address">
                <DataTable rows={d.conversations} pageSize={8} searchable={false} onRowClick={(r) => r.page && onNavigate(r.page, { flow: r.flow })}
                  columns={[{ key: 'ip_a', label: 'A' }, { key: 'port_a', label: 'Port' }, { key: 'ip_b', label: 'B' }, { key: 'port_b', label: 'Port' }, { key: 'l4', label: 'Proto' },
                    { key: 'packets', label: 'Packets', num: true, render: fmtNum }, { key: 'bytes', label: 'Bytes', num: true, render: fmtBytes }, { key: 'throughput_bps', label: 'Throughput', num: true, render: fmtBps }]} />
              </Card>
            </>
          )}
        </div>
      </aside>
    </>
  )
}
