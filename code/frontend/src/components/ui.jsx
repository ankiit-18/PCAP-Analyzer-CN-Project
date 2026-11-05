import { useEffect, useMemo, useState } from 'react'
import { INDICATORS, flowLabel } from '../lib.js'

export function useDark() {
  const q = '(prefers-color-scheme: dark)'
  const [dark, setDark] = useState(() => window.matchMedia(q).matches)
  useEffect(() => {
    const m = window.matchMedia(q)
    const h = (e) => setDark(e.matches)
    m.addEventListener('change', h)
    return () => m.removeEventListener('change', h)
  }, [])
  return dark
}

export const Card = ({ title, sub, actions, children }) => (
  <section className="card">
    {(title || actions) && (
      <div className="card-head">
        <div><h3>{title}</h3>{sub && <div className="sub">{sub}</div>}</div>
        {actions}
      </div>
    )}
    {children}
  </section>
)

export const Stat = ({ label, value, sub, tone }) => (
  <div className={`stat ${tone ? 'accent-' + tone : ''}`}>
    <div className="label">{label}</div>
    <div className="value">{value}</div>
    {sub && <div className="sub">{sub}</div>}
  </div>
)

export const TagBadges = ({ tags }) =>
  (tags || '').split(',').filter(Boolean).map((t) => (
    <span key={t} className="badge" style={{ background: INDICATORS[t]?.color || '#666' }} title={INDICATORS[t]?.hint}>
      {INDICATORS[t]?.label || t}
    </span>
  ))

export const Empty = ({ children }) => <div className="empty">{children}</div>

// Flow scope picker used by the RTT / Indicators / Drill-down tabs
export function FlowSelect({ flows, value, onChange, allowAll = false }) {
  const sorted = useMemo(() => [...flows].sort((a, b) => b.issues - a.issues || b.packets - a.packets).slice(0, 1500), [flows])
  return (
    <select className="flowselect" value={value ?? ''} onChange={(e) => onChange(e.target.value === '' ? null : Number(e.target.value))}>
      {allowAll && <option value="">All flows ({flows.length})</option>}
      {sorted.map((f) => (
        <option key={f.flow} value={f.flow}>{flowLabel(f)} · {f.packets} pkts · {f.issues} issue{f.issues === 1 ? '' : 's'}</option>
      ))}
    </select>
  )
}

/** Client-side sortable / searchable / paged table. */
export function DataTable({ columns, rows, pageSize = 15, defaultSort, searchable = true, onRowClick, rowClass, empty = 'No rows.' }) {
  const [sort, setSort] = useState(defaultSort || null)
  const [q, setQ] = useState('')
  const [page, setPage] = useState(0)

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase()
    return s ? rows.filter((r) => columns.some((c) => String(r[c.key] ?? '').toLowerCase().includes(s))) : rows
  }, [rows, q, columns])

  const sorted = useMemo(() => {
    if (!sort) return filtered
    const { key, dir } = sort
    return [...filtered].sort((a, b) => {
      const x = a[key], y = b[key]
      if (x == null) return 1
      if (y == null) return -1
      return (typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y))) * (dir === 'asc' ? 1 : -1)
    })
  }, [filtered, sort])

  useEffect(() => setPage(0), [q, rows])
  const pages = Math.max(1, Math.ceil(sorted.length / pageSize))
  const view = sorted.slice(page * pageSize, (page + 1) * pageSize)

  return (
    <div>
      {searchable && (
        <div className="toolbar">
          <input type="search" placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} />
          <span className="muted">{sorted.length.toLocaleString()} row{sorted.length === 1 ? '' : 's'}</span>
        </div>
      )}
      <div className="tablewrap">
        <table className="dt">
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c.key} className={`${c.num ? 'num' : ''} sortable`}
                    onClick={() => setSort((s) => (s?.key === c.key ? { key: c.key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key: c.key, dir: c.num ? 'desc' : 'asc' }))}>
                  {c.label}{sort?.key === c.key ? (sort.dir === 'asc' ? ' ▲' : ' ▼') : ''}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {view.map((r, i) => (
              <tr key={i} className={`${onRowClick ? 'clickable' : ''} ${rowClass ? rowClass(r) : ''}`} onClick={onRowClick ? () => onRowClick(r) : undefined}>
                {columns.map((c) => <td key={c.key} className={`${c.num ? 'num' : ''} ${c.wrap ? 'wrap' : ''}`}>{c.render ? c.render(r[c.key], r) : (r[c.key] ?? '–')}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
        {!view.length && <Empty>{empty}</Empty>}
      </div>
      {pages > 1 && (
        <div className="pager">
          <button className="btn small" disabled={page === 0} onClick={() => setPage(page - 1)}>‹ Prev</button>
          <span>Page {page + 1} / {pages}</span>
          <button className="btn small" disabled={page >= pages - 1} onClick={() => setPage(page + 1)}>Next ›</button>
        </div>
      )}
    </div>
  )
}

/** Collapsible section (open by default). */
export function Section({ title, sub, defaultOpen = true, children }) {
  return (
    <details className="card section" open={defaultOpen}>
      <summary><h3>{title}</h3>{sub && <span className="sub">{sub}</span>}</summary>
      <div className="section-body">{children}</div>
    </details>
  )
}
