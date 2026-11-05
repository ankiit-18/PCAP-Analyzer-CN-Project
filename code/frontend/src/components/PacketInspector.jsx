import { useEffect, useMemo, useState } from 'react'
import { decodePacket, getProtocolPackets } from '../api.js'
import { Card, Empty } from './ui.jsx'
import { fmtBytes, fmtSec, formatter } from '../lib.js'

/** Slide-over with the full Wireshark dissection of one packet (tshark -V -x). */
export function DecodeDrawer({ id, no, onClose }) {
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    if (no == null) return
    setD(null); setErr('')
    decodePacket(id, no).then(setD).catch((e) => setErr(e.message))
  }, [id, no])
  if (no == null) return null
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer">
        <header>
          <h3>Packet #{no} – Wireshark decode</h3>
          <button className="btn small" style={{ marginLeft: 'auto' }} onClick={onClose}>Close ✕</button>
        </header>
        {err && <div className="err" style={{ margin: 16 }}>{err}</div>}
        {!d && !err && <Empty>Running tshark…</Empty>}
        {d && <pre className="mono">{d.text}{d.truncated ? '\n… (output truncated)' : ''}</pre>}
      </aside>
    </>
  )
}

const DEFAULT_COLS = [
  { key: 'packet_no', label: '#', num: true }, { key: 'time_s', label: 'Time', num: true, fmt: 'sec' }, { key: 'src', label: 'Source' }, { key: 'dst', label: 'Destination' },
  { key: 'length', label: 'Length', num: true, fmt: 'bytes' }, { key: 'info', label: 'Info' },
]

function FilterBar({ spec, values, setValues, onApply, onClear }) {
  return (
    <form className="filters" onSubmit={(e) => { e.preventDefault(); onApply() }}>
      {spec.map((f) => (
        <label key={f.key}>{f.label}
          {f.type === 'select' ? (
            <select value={values[f.key] || ''} onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}><option value="">any</option>{f.options.map((o) => <option key={o} value={o}>{o}</option>)}</select>
          ) : f.type === 'bool' ? (
            <input type="checkbox" checked={!!values[f.key]} onChange={(e) => setValues({ ...values, [f.key]: e.target.checked })} />
          ) : (
            <input type={f.type === 'number' ? 'number' : 'text'} value={values[f.key] || ''} onChange={(e) => setValues({ ...values, [f.key]: e.target.value })} />
          )}
        </label>
      ))}
      <button className="btn small" type="submit">Apply</button>
      <button className="btn small" type="button" onClick={onClear}>Clear</button>
    </form>
  )
}

/** Server-paged packet list for one protocol, with search, optional field filters and click-to-decode. */
export function PacketInspector({ id, protoKey, filters, onOpen }) {
  const [q, setQ] = useState('')
  const [vals, setVals] = useState({})
  const [applied, setApplied] = useState({ q: '', vals: {} })
  const [offset, setOffset] = useState(0)
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  const PAGE = 100

  useEffect(() => { setOffset(0) }, [applied, protoKey])
  useEffect(() => {
    let live = true
    setData(null); setErr('')
    getProtocolPackets(id, protoKey, { offset, limit: PAGE, q: applied.q, filters: applied.vals }).then((d) => live && setData(d)).catch((e) => live && setErr(e.message))
    return () => { live = false }
  }, [id, protoKey, offset, applied])

  const cols = useMemo(() => data?.columns || DEFAULT_COLS, [data])
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE)) : 1
  const cell = (c, r) => {
    const v = r[c.key]
    if (c.key === 'src' && r.sport) return `${v}:${r.sport}`
    if (c.key === 'dst' && r.dport) return `${v}:${r.dport}`
    if (typeof v === 'boolean') return v ? 'yes' : ''
    return c.fmt ? formatter(c.fmt)(v) : (v ?? '')
  }
  return (
    <Card title="Packet inspection">
      {filters?.length > 0 && <FilterBar spec={filters} values={vals} setValues={setVals} onApply={() => setApplied({ q, vals })} onClear={() => { setVals({}); setQ(''); setApplied({ q: '', vals: {} }) }} />}
      <form className="toolbar" onSubmit={(e) => { e.preventDefault(); setApplied({ q, vals }) }}>
        <input type="search" placeholder="Search address, protocol or info…" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 280 }} />
        <button className="btn small" type="submit">Search</button>
        <span className="muted">{data ? `${data.total.toLocaleString()} packets` : ''}</span>
      </form>
      {err && <div className="err">{err}</div>}
      {!data && !err ? <Empty>Loading…</Empty> : data && (
        <>
          <div className="tablewrap">
            <table className="dt">
              <thead><tr>{cols.map((c) => <th key={c.key} className={c.num ? 'num' : ''}>{c.label}</th>)}</tr></thead>
              <tbody>
                {data.rows.map((r) => (
                  <tr key={r.packet_no} className="clickable" onClick={() => onOpen(r.packet_no)}>
                    {cols.map((c) => <td key={c.key} className={c.num ? 'num' : ''}>{cell(c, r)}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
            {!data.rows.length && <Empty>No packets match.</Empty>}
          </div>
          <div className="pager">
            <button className="btn small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>‹ Prev</button>
            <span>Page {offset / PAGE + 1} / {pages}</span>
            <button className="btn small" disabled={offset + PAGE >= data.total} onClick={() => setOffset(offset + PAGE)}>Next ›</button>
          </div>
        </>
      )}
    </Card>
  )
}
