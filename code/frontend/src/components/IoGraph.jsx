import { useEffect, useState } from 'react'
import { getProtocolIo } from '../api.js'
import { Card, Empty } from './ui.jsx'
import { ChartCard } from './GenericChart.jsx'
import { fmtBps, fmtBytes, fmtNum } from '../lib.js'

const INTERVALS = [['', 'Automatic'], ['0.001', '1 ms'], ['0.01', '10 ms'], ['0.1', '100 ms'], ['1', '1 s'], ['10', '10 s'], ['60', '1 min'], ['600', '10 min']]
const MEASURES = [['packets', 'Packets / s'], ['bytes', 'Bytes / s'], ['bits', 'Bits / s']]
const SPLITS = [['none', 'Nothing (one line)'], ['app', 'Application protocol'], ['conversation', 'Conversation (top 6)']]
const fmtIv = (s) => (s == null ? '–' : s < 1 ? `${s * 1000} ms` : s < 60 ? `${s} s` : `${s / 60} min`)

// defined outside IoGraph so it is not re-created (and the <select> remounted) on every render
function Select({ label, value, set, options }) {
  return (
    <label className="muted" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>{label}
      <select value={value} onChange={(e) => set(e.target.value)}>{options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
    </label>
  )
}

/** Wireshark-style I/O graph for one protocol: choose the interval, the measure and how the traffic is split into lines. */
export default function IoGraph({ id, pkey }) {
  const [interval, setInterval_] = useState('')
  const [measure, setMeasure] = useState('packets')
  const [split, setSplit] = useState('none')
  const [d, setD] = useState(null)
  const [err, setErr] = useState('')
  useEffect(() => {
    setErr('')
    getProtocolIo(id, pkey, { interval: interval || null, measure, split }).then(setD).catch((e) => setErr(e.message))
  }, [id, pkey, interval, measure, split])

  const fmtPeak = (v) => (d.measure === 'bits' ? fmtBps(v) : d.measure === 'bytes' ? `${fmtBytes(v)}/s` : `${fmtNum(v)} pkts/s`)
  return (
    <div className="stack">
      <Card title="I/O graph" sub="Traffic per second over time, like Wireshark's I/O Graphs. Derived from frame length and capture time.">
        <div className="toolbar" style={{ flexWrap: 'wrap', gap: 16 }}>
          <Select label="Interval" value={interval} set={setInterval_} options={INTERVALS} />
          <Select label="Measure" value={measure} set={setMeasure} options={MEASURES} />
          <Select label="Split by" value={split} set={setSplit} options={SPLITS} />
        </div>
        {err && <div className="err">{err}</div>}
        {d && d.chart && (
          <div className="muted" style={{ margin: '8px 0', fontSize: 13 }}>
            Interval {fmtIv(d.interval_s)}{d.auto ? ' (automatic)' : ''} · {fmtNum(d.bins)} intervals · {fmtNum(d.packets)} packets · peak <b>{fmtPeak(d.peak)}</b> at t = {d.peak_at_s.toFixed(3)} s · average {fmtPeak(d.average)}
            {d.widened && <> · <b>interval widened from {fmtIv(d.requested_interval_s)}</b> so the browser is not flooded with points</>}
          </div>
        )}
        {d && !d.chart && <Empty>No packets to plot.</Empty>}
        {!d && !err && <Empty>Loading…</Empty>}
      </Card>
      {d && d.chart && <ChartCard spec={d.chart} height={380} />}
    </div>
  )
}
