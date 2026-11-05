import { useEffect, useRef } from 'react'
import * as echarts from 'echarts'
import { useDark } from './ui.jsx'

// Thin ECharts wrapper: theme-aware, resizes with its container.
export default function Chart({ option, height = 320, onClick }) {
  const el = useRef(null)
  const chart = useRef(null)
  const dark = useDark()

  useEffect(() => {
    chart.current = echarts.init(el.current)
    const ro = new ResizeObserver(() => chart.current?.resize())
    ro.observe(el.current)
    return () => { ro.disconnect(); chart.current?.dispose(); chart.current = null }
  }, [])

  useEffect(() => {
    const text = dark ? '#e6e8ee' : '#1f2430'
    const muted = dark ? '#8b93a7' : '#6b7385'
    const line = dark ? '#2a3040' : '#e3e6ee'
    const style = (o) => ({ axisLine: { lineStyle: { color: line } }, axisLabel: { color: muted }, nameTextStyle: { color: muted },
      splitLine: { lineStyle: { color: line, opacity: 0.6 } }, ...o })
    const fix = (a) => (Array.isArray(a) ? a.map((x) => style(x)) : a ? style(a) : a)
    chart.current.setOption({
      animation: false, backgroundColor: 'transparent', textStyle: { color: text },
      legend: { top: 0, textStyle: { color: muted }, type: 'scroll' },
      tooltip: { backgroundColor: dark ? '#232a38' : '#fff', borderColor: line, textStyle: { color: text } },
      ...option, xAxis: fix(option.xAxis), yAxis: fix(option.yAxis),
    }, true)
  }, [option, dark])

  useEffect(() => {
    if (!onClick) return
    chart.current.off('click')
    chart.current.on('click', onClick)
  }, [onClick])

  return <div ref={el} style={{ height, width: '100%' }} />
}
