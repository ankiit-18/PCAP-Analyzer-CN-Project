import Overview from '../tabs/Overview.jsx'
import Flows from '../tabs/Flows.jsx'
import Rtt from '../tabs/Rtt.jsx'
import FlowControl from '../tabs/FlowControl.jsx'
import Congestion from '../tabs/Congestion.jsx'
import TcpOptions from '../tabs/TcpOptions.jsx'
import Indicators from '../tabs/Indicators.jsx'
import DrillDown from '../tabs/DrillDown.jsx'
import TcpPackets from '../tabs/TcpPackets.jsx'

export const TCP_TABS = [['summary', 'Summary'], ['flows', 'Flows'], ['rtt', 'RTT Analysis'], ['flowcontrol', 'Flow Control'], ['congestion', 'Congestion Indicators'],
  ['options', 'TCP Options'], ['indicators', 'Retransmissions & Loss'], ['drill', 'Flow Drill-down'], ['packets', 'Packet Inspection']]

/** TCP analysis: the stage-2 tabs (Summary, Flows, Indicators, Drill-down) plus RTT methods, flow control, congestion indicators, options and packet inspection. */
export default function TcpPage({ id, report, flow, setFlow, sub, setSub }) {
  const open = (f, t) => { setFlow(f); setSub(t) }
  return (
    <div>
      <div className="subtabs">
        {TCP_TABS.map(([k, l]) => <button key={k} className={`tab ${sub === k ? 'active' : ''}`} onClick={() => setSub(k)}>{l}</button>)}
      </div>
      {sub === 'summary' && <Overview report={report} onOpenFlow={(f) => open(f, 'drill')} />}
      {sub === 'flows' && <Flows report={report} onIndicators={(f) => open(f, 'indicators')} onDrill={(f) => open(f, 'drill')} />}
      {sub === 'rtt' && <Rtt id={id} report={report} flow={flow} setFlow={setFlow} />}
      {sub === 'flowcontrol' && <FlowControl id={id} report={report} flow={flow} setFlow={setFlow} />}
      {sub === 'congestion' && <Congestion id={id} report={report} flow={flow} setFlow={setFlow} />}
      {sub === 'options' && <TcpOptions id={id} report={report} flow={flow} setFlow={setFlow} />}
      {sub === 'indicators' && <Indicators id={id} report={report} flow={flow} setFlow={setFlow} onDrill={(f) => open(f, 'drill')} />}
      {sub === 'drill' && <DrillDown id={id} report={report} flow={flow} setFlow={setFlow} />}
      {sub === 'packets' && <TcpPackets id={id} report={report} flow={flow} setFlow={setFlow} />}
    </div>
  )
}
