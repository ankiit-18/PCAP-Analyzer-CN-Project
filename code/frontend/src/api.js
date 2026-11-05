const BASE = import.meta.env.VITE_API_BASE || ''

async function req(path, opts) {
  const r = await fetch(BASE + path, opts)
  if (!r.ok) {
    let msg = `Request failed (${r.status})`
    try { msg = (await r.json()).detail || msg } catch { /* not json */ }
    throw new Error(msg)
  }
  return r.json()
}

// XHR instead of fetch so we can report upload progress
export function uploadFile(file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', BASE + '/api/upload')
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress?.(e.loaded / e.total)
    xhr.onload = () => {
      let body = {}
      try { body = JSON.parse(xhr.responseText) } catch { /* ignore */ }
      xhr.status >= 200 && xhr.status < 300 ? resolve(body) : reject(new Error(body.detail || `Upload failed (${xhr.status})`))
    }
    xhr.onerror = () => reject(new Error('Cannot reach the backend. Is it running on port 8000?'))
    const fd = new FormData()
    fd.append('file', file)
    xhr.send(fd)
  })
}

export const health = () => req('/api/health')
export const analyze = (id) => req(`/api/analyze/${id}`, { method: 'POST' })
export const getReport = (id) => req(`/api/reports/${id}`)
export const getIndicators = (id, flow) => req(`/api/reports/${id}/indicators${flow == null ? '' : `?flow=${flow}`}`)
export const getFlow = (id, flow) => req(`/api/reports/${id}/flows/${flow}`)
export const getPackets = (id, flow, { offset = 0, limit = 100, flaggedOnly = false } = {}) =>
  req(`/api/reports/${id}/flows/${flow}/packets?offset=${offset}&limit=${limit}&flagged_only=${flaggedOnly}`)
export const deleteReport = (id) => req(`/api/reports/${id}`, { method: 'DELETE' })

// ---- overview-first pages (protocol detail) ----
export const getOverview = (id) => req(`/api/reports/${id}/overview`)
export const getProtocol = (id, key) => req(`/api/reports/${id}/protocols/${encodeURIComponent(key)}`)
export const getProtocolPackets = (id, key, { offset = 0, limit = 100, q = '', filters = {} } = {}) => {
  const f = Object.entries(filters).filter(([, v]) => v !== '' && v != null && v !== false).map(([k, v]) => `&f_${k}=${encodeURIComponent(v === true ? '1' : v)}`).join('')
  return req(`/api/reports/${id}/protocols/${encodeURIComponent(key)}/packets?offset=${offset}&limit=${limit}&q=${encodeURIComponent(q)}${f}`)
}
export const decodePacket = (id, no) => req(`/api/reports/${id}/packets/${no}/decode`)

// ---- TCP deep analysis, IP, validation, export ----
const fq = (flow) => (flow == null ? '' : `?flow=${flow}`)
export const getTcpRtt = (id, flow) => req(`/api/reports/${id}/tcp/rtt${fq(flow)}`)
export const getFlowControl = (id, flow) => req(`/api/reports/${id}/tcp/flow-control${fq(flow)}`)
export const getCongestion = (id, flow) => req(`/api/reports/${id}/tcp/congestion${fq(flow)}`)
export const getTcpOptions = (id, flow) => req(`/api/reports/${id}/tcp/options${fq(flow)}`)
export const getTcpPackets = (id, { flow = null, conds = [], offset = 0, limit = 100 } = {}) =>
  req(`/api/reports/${id}/tcp/packets?offset=${offset}&limit=${limit}${flow == null ? '' : `&flow=${flow}`}${conds.map((c) => `&cond=${c}`).join('')}`)
export const getIpAddress = (id, addr) => req(`/api/reports/${id}/ip/${encodeURIComponent(addr)}`)
export const getValidation = (id) => req(`/api/reports/${id}/validation`)
export const exportUrl = (id) => `${BASE}/api/reports/${id}/export?download=1`
