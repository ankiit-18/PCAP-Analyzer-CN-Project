import { useMemo } from 'react'
import { BASIS_LABEL, formatter } from '../lib.js'
import { Card, DataTable } from './ui.jsx'

export const Basis = ({ basis }) => (basis ? <span className={`basis ${basis}`} title={BASIS_LABEL[basis]}>{basis}</span> : null)

/** One metric from the engine: measured -> value; not calculable -> "Not available" + reason (never 0). */
export function MetricCard({ m }) {
  if (!m.available) {
    return (
      <div className="stat na" title={m.reason}>
        <div className="label">{m.label}</div>
        <div className="value">Not available</div>
        <div className="sub">{m.reason}</div>
      </div>
    )
  }
  return (
    <div className="stat">
      <div className="label">{m.label}</div>
      <div className="value">{formatter(m.fmt)(m.value)}</div>
      {m.sub && <div className="sub">{m.sub}</div>}
      <Basis basis={m.basis} />
    </div>
  )
}

export const MetricGrid = ({ metrics }) => <div className="stats">{metrics.map((m) => <MetricCard key={m.label} m={m} />)}</div>

/** A table described by the backend ({columns:[{key,label,fmt,num}], rows, total, click}). */
export function SpecTable({ spec, onRow }) {
  const columns = useMemo(() => spec.columns.map((c) => ({ key: c.key, label: c.label, num: c.num, render: c.fmt === 'text' ? undefined : (v) => formatter(c.fmt)(v) })), [spec])
  return (
    <Card title={spec.title} sub={spec.total > spec.rows.length ? `showing first ${spec.rows.length.toLocaleString()} of ${spec.total.toLocaleString()}` : `${spec.total.toLocaleString()} rows`}>
      <DataTable rows={spec.rows} columns={columns} pageSize={15} onRowClick={spec.click && onRow ? (r) => onRow(spec, r) : undefined} empty="No rows." />
    </Card>
  )
}
