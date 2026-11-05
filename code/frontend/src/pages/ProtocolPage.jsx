import { useEffect, useMemo, useState } from 'react'
import { getProtocol } from '../api.js'
import { ChartCard } from '../components/GenericChart.jsx'
import { DecodeDrawer, PacketInspector } from '../components/PacketInspector.jsx'
import { MetricGrid, SpecTable } from '../components/Spec.jsx'
import { Card, Empty, Section } from '../components/ui.jsx'
import IpInspector from './IpInspector.jsx'

/** Generic detail page for any protocol described by the backend. `sections` (when present) defines the tabs; otherwise a default layout is used. */
export default function ProtocolPage({ id, pkey, onNavigate }) {
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')
  const [tab, setTab] = useState(0)
  const [decodeNo, setDecodeNo] = useState(null)
  const [ipAddr, setIpAddr] = useState(null)

  useEffect(() => {
    setD(null); setErr(''); setTab(0)
    getProtocol(id, pkey).then(setD).catch((e) => setErr(e.message))
  }, [id, pkey])

  const sections = useMemo(() => {
    if (!d) return []
    if (d.sections) return d.sections
    return [{ id: 'summary', title: 'Summary & charts', metrics: 'all', charts: d.charts.map((c) => c.id) }, ...d.tables.map((t) => ({ id: t.id, title: t.title, tables: [t.id] }))]
  }, [d])

  if (err) return <div className="err">{err}</div>
  if (!d) return <Card><Empty>Loading {pkey}…</Empty></Card>

  const charts = Object.fromEntries(d.charts.map((c) => [c.id, c]))
  const tables = Object.fromEntries(d.tables.map((t) => [t.id, t]))
  const onRow = (spec, row) => {
    if (pkey === 'ip' && spec.id === 'endpoints') return setIpAddr(row.endpoint)
    if (row.page) return onNavigate(row.page, { flow: row.flow })        // IP conversation -> its TCP / UDP / ICMP page
    if (row[spec.click] != null) setDecodeNo(row[spec.click])
  }
  const tabs = [...sections.map((s) => s.title), 'Packet Inspection']
  const cur = sections[tab]
  const metricsOf = (s) => (s.metrics === 'all' ? d.metrics : d.metrics.filter((m) => s.metrics?.includes(m.label)))

  return (
    <div className="stack">
      <Card>
        <div style={{ fontSize: 15 }}>{d.summary}</div>
      </Card>

      <div className="subtabs">{tabs.map((t, i) => <button key={t} className={`tab ${tab === i ? 'active' : ''}`} onClick={() => setTab(i)}>{t}</button>)}</div>

      {cur && (
        <>
          {cur.metrics && (
            <Section title="Key metrics" sub={`${d.metrics.filter((m) => m.available).length} measured · ${d.metrics.filter((m) => !m.available).length} not available`}>
              <MetricGrid metrics={metricsOf(cur)} />
            </Section>
          )}
          {cur.charts?.some((c) => charts[c]) && <div className="grid cols-2">{cur.charts.filter((c) => charts[c]).map((c) => <ChartCard key={c} spec={charts[c]} />)}</div>}
          {cur.tables?.filter((t) => tables[t]).map((t) => <SpecTable key={t} spec={tables[t]} onRow={onRow} />)}
        </>
      )}
      {tab === sections.length && <PacketInspector id={id} protoKey={pkey} filters={d.packet_filters} onOpen={setDecodeNo} />}
      <DecodeDrawer id={id} no={decodeNo} onClose={() => setDecodeNo(null)} />
      {pkey === 'ip' && <IpInspector id={id} addr={ipAddr} onClose={() => setIpAddr(null)} onNavigate={(p, o) => { setIpAddr(null); onNavigate(p, o) }} />}
    </div>
  )
}
