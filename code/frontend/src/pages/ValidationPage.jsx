import { useEffect, useState } from 'react'
import { getValidation } from '../api.js'
import { Basis } from '../components/Spec.jsx'
import { Card, DataTable, Empty, Section } from '../components/ui.jsx'
import { fmtNum } from '../lib.js'

/** Engine values vs independent tshark measurements. */
export default function ValidationPage({ id }) {
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => { getValidation(id).then(setD).catch((e) => setErr(e.message)) }, [id])
  if (err) return <div className="err">{err}</div>
  if (!d) return <Card><Empty>Re-measuring with tshark…</Empty></Card>
  const s = d.summary
  return (
    <div className="stack">
      <Card>
        <div style={{ fontSize: 15 }}><b>{s.matching} of {s.checked}</b> checks match the Wireshark/TShark reference{s.differing ? `; ${s.differing} differ` : ''}. Scope: {d.scope}.</div>
      </Card>
      <Card title="Cross-validation table">
        <DataTable rows={d.rows} pageSize={40} columns={[
          { key: 'area', label: 'Area' }, { key: 'metric', label: 'Metric' }, { key: 'engine', label: 'Engine', num: true, render: fmtNum },
          { key: 'tshark', label: 'Wireshark / tshark', num: true, render: (v) => (v == null ? 'n/a' : fmtNum(v)) },
          { key: 'difference', label: 'Difference', num: true, render: (v) => (v == null ? '–' : v === 0 ? '0' : <b style={{ color: 'var(--bad)' }}>{v > 0 ? `+${v}` : v}</b>) },
          { key: 'status', label: 'Status', render: (v) => <span style={{ color: v === 'match' ? 'var(--ok)' : v === 'differs' ? 'var(--bad)' : 'var(--muted)' }}>{v}</span> },
          { key: 'basis', label: 'Engine value is', render: (v) => <Basis basis={v === 'aggregated' ? null : v} /> || v }, { key: 'note', label: 'Note' },
        ]} />
      </Card>
    </div>
  )
}
