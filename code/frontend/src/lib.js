export const fmtNum = (n) => (n == null || Number.isNaN(n) ? '–' : Number(n).toLocaleString())

export function fmtBytes(n) {
  if (n == null || Number.isNaN(n)) return '–'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++ }
  return `${i ? n.toFixed(1) : Math.round(n)} ${u[i]}`
}

export function fmtBps(n) {
  if (n == null || Number.isNaN(n)) return '–'
  const u = ['bps', 'Kbps', 'Mbps', 'Gbps']
  let i = 0
  while (Math.abs(n) >= 1000 && i < u.length - 1) { n /= 1000; i++ }
  return `${n.toFixed(i ? 2 : 0)} ${u[i]}`
}

export const fmtMs = (n, d = 2) => (n == null || Number.isNaN(n) ? '–' : `${Number(n).toFixed(d)} ms`)
export const fmtSec = (n, d = 3) => (n == null || Number.isNaN(n) ? '–' : `${Number(n).toFixed(d)} s`)

// Wireshark TCP-analysis indicators (tshark fields tcp.analysis.*)
export const X_PATH = 'path://M4.5,0L10,5.5L15.5,0L20,4.5L14.5,10L20,15.5L15.5,20L10,14.5L4.5,20L0,15.5L5.5,10L0,4.5Z'
export const INDICATORS = {
  retransmission: { label: 'Retransmission', color: '#e5484d', symbol: X_PATH, size: 11, hint: 'Sequence range seen before' },
  fast_retransmission: { label: 'Fast retransmission', color: '#b4232a', symbol: X_PATH, size: 11, hint: 'Retransmission after ≥3 duplicate ACKs' },
  spurious_retransmission: { label: 'Spurious retransmission', color: '#a0612b', symbol: 'rect', size: 9, hint: 'Retransmission of data already ACKed' },
  out_of_order: { label: 'Out-of-order', color: '#f08c00', symbol: 'diamond', size: 12, hint: 'Segment arrives behind a higher sequence' },
  duplicate_ack: { label: 'Duplicate ACK', color: '#3b82f6', symbol: 'triangle', rotate: 180, size: 10, hint: 'Repeated ACK number' },
  lost_segment: { label: 'Sequence gap', color: '#8b5cf6', symbol: 'triangle', size: 12, hint: '"Previous segment not captured" – possible loss (inferred)' },
  ack_lost_segment: { label: 'ACK of uncaptured data', color: '#a855f7', symbol: 'pin', size: 12, hint: 'ACK for data that was never captured' },
}
export const INDICATOR_KEYS = Object.keys(INDICATORS)
// further Wireshark flow-control flags (used by the Flow Control tab / packet filters)
export const CONDITIONS = [
  ['retransmission', 'Retransmissions'], ['dup_ack', 'Duplicate ACKs'], ['out_of_order', 'Out-of-order'], ['lost_segment', 'Sequence gaps'],
  ['zero_window', 'Zero-window'], ['zero_window_probe', 'Zero-window probes'], ['window_update', 'Window updates'], ['window_full', 'Window full'], ['ecn', 'ECN (ECE/CWR/CE)'],
]
export const BASIS_LABEL = { observed: 'Observed (dissected by tshark)', derived: 'Derived (calculated by the engine)', inferred: 'Inferred (interpretation, not proof)' }

export const flowLabel = (f) => `#${f.flow}  ${f.client} → ${f.server}`

export const fmtNum1 = (n) => (n == null || Number.isNaN(n) ? '–' : Number(n).toLocaleString(undefined, { maximumFractionDigits: 1 }))
export const fmtPct = (n) => (n == null || Number.isNaN(n) ? '–' : `${Number(n).toFixed(n < 10 ? 2 : 1)}%`)
export const fmtDate = (s) => (s == null ? '–' : new Date(s * 1000).toISOString().replace('T', ' ').replace('Z', ' UTC'))

// formatter lookup used by the generic (server-described) tables, metrics and charts
export function formatter(fmt) {
  return ({
    num: fmtNum, num1: fmtNum1, bytes: fmtBytes, bps: fmtBps, ms: (v) => fmtMs(v), sec: (v) => fmtSec(v), pct: fmtPct, time: fmtDate,
  })[fmt] || ((v) => (v == null || v === '' ? '–' : String(v)))
}

export const PALETTE = ['#4f46e5', '#22c1c3', '#f08c00', '#e5484d', '#16a34a', '#8b5cf6', '#0ea5e9', '#d946ef', '#84cc16', '#f43f5e', '#14b8a6', '#a16207']
