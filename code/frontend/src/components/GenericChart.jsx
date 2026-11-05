import { useMemo } from 'react'
import Chart from './Chart.jsx'
import { PALETTE, formatter } from '../lib.js'

const UNIT_FMT = { bytes: 'bytes', bps: 'bps', ms: 'ms' }

/** Renders a chart described by the backend: {type: bar|barh|pie|line|scatter, labels|x|series[].points, unit}. */
export function GenericChart({ spec, height = 280 }) {
  const option = useMemo(() => {
    const f = formatter(UNIT_FMT[spec.unit] || 'num')
    const colorOf = (i) => PALETTE[i % PALETTE.length]
    const tipFmt = { valueFormatter: (v) => f(v) }
    if (spec.type === 'pie') {
      return {
        tooltip: { trigger: 'item', ...tipFmt }, legend: { type: 'scroll', bottom: 0 },
        series: [{ type: 'pie', radius: ['42%', '70%'], center: ['50%', '45%'], label: { show: false },
          data: spec.labels.map((l, i) => ({ name: l, value: spec.series[0].data[i], itemStyle: { color: colorOf(i) } })) }],
      }
    }
    if (spec.type === 'line' || spec.type === 'scatter') {
      const scatter = spec.type === 'scatter'
      return {
        grid: { left: 74, right: 20, top: spec.series.length > 1 ? 40 : 16, bottom: 62 },
        tooltip: scatter ? { trigger: 'item', formatter: (p) => `${p.seriesName}<br>t = ${Number(p.data[0]).toFixed(4)} s<br>${f(p.data[1])}` } : { trigger: 'axis', ...tipFmt },
        xAxis: { type: 'value', name: spec.xLabel, nameLocation: 'middle', nameGap: 28, scale: scatter },
        yAxis: { type: 'value', name: spec.yLabel, axisLabel: { formatter: (v) => f(v) }, scale: scatter },
        legend: spec.series.length > 1 ? { top: 0 } : { show: false },
        dataZoom: [{ type: 'inside' }, { type: 'slider', height: 16, bottom: 6 }],
        series: spec.series.map((s, i) => ({
          name: s.name, type: scatter ? 'scatter' : 'line', showSymbol: scatter, symbolSize: 5, areaStyle: scatter ? undefined : { opacity: 0.12 },
          lineStyle: { width: 1.5, color: colorOf(i) }, itemStyle: { color: colorOf(i) },
          data: s.points || spec.x.map((x, j) => [x, s.data[j]]),
        })),
      }
    }
    const horizontal = spec.type === 'barh'
    const cat = { type: 'category', data: spec.labels, ...(horizontal ? { inverse: true } : { axisLabel: { interval: 0, rotate: spec.labels.length > 6 ? 30 : 0, hideOverlap: true } }), name: horizontal ? undefined : spec.xLabel, nameLocation: 'middle', nameGap: 42 }
    const val = { type: 'value', name: horizontal ? undefined : spec.yLabel, axisLabel: { formatter: (v) => f(v) } }
    return {
      grid: { left: horizontal ? 150 : 56, right: 24, top: spec.series.length > 1 ? 40 : 14, bottom: horizontal ? 24 : (spec.labels.length > 6 ? 70 : 50), containLabel: horizontal },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, ...tipFmt },
      legend: spec.series.length > 1 ? { top: 0 } : { show: false },
      xAxis: horizontal ? val : cat, yAxis: horizontal ? cat : val,
      series: spec.series.map((s, i) => ({ name: s.name, type: 'bar', barMaxWidth: 36, data: s.data, itemStyle: { color: colorOf(i) } })),
    }
  }, [spec])
  return <Chart option={option} height={height} />
}

export function ChartCard({ spec, height }) {
  return (
    <section className="card">
      <div className="card-head"><div><h3>{spec.title}</h3></div></div>
      <GenericChart spec={spec} height={height} />
    </section>
  )
}
