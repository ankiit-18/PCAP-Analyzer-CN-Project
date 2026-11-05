# PCAP Analyzer

Upload a `.pcap` / `.pcapng`, click **Analyze**, get an overview first and detail pages on click. All analysis comes from **TShark**; Python groups, aggregates and calculates.

## Requirements
Python 3.10+, Node 18+, and **TShark** on the PATH (`brew install wireshark` · `sudo apt install tshark`).

## Run
```bash
cd code && ./start.sh        # Windows: start.bat
```
Open http://127.0.0.1:8000 and drop `samples/protocols_mix.pcap`. (`PORT=9000 ./start.sh` changes the port.)

Dev mode: `cd backend && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && uvicorn main:app --port 8000`, then `cd frontend && npm install && npm run dev`.

## What you get
- **Overview:** capture facts, protocol distribution and chart for **all** protocols, cards for protocols with a page, other protocols listed (no page).
- **Detail pages:** TCP, UDP, DNS, TLS, QUIC, ARP and IP Analysis, each with metrics, charts, tables and packet inspection (click a packet for its full Wireshark decode).
- **TCP tabs:** Summary, Flows, RTT Analysis, Flow Control, Congestion Indicators, TCP Options, Retransmissions & Loss, Flow Drill-down, Packet Inspection.
- Metrics that cannot be calculated show "Not available" with the reason, never 0.

## Configuration (env vars, all off by default; 0 = no limit)
`MAX_PCAP_SIZE_MB` · `MAX_ANALYSIS_SECONDS` · `MAX_EXTRACTED_PACKETS` (results beyond it are labelled partial) · `CAPTURE_TTL_HOURS` (default 24).
Memory is the practical limit: about 3–5 KB of RAM per packet.

## Layout
- `backend/engine/` shared TShark analysis package (used by the API and both notebooks) · `backend/main.py` API · `backend/tests/`
- `frontend/` React + ECharts
- `notebook/` two notebooks using the same engine (`python3 notebook/_build_notebooks.py` regenerates them)
- `samples/` test captures and their generators

## Tests
```bash
cd backend && pip install -r requirements-dev.txt && pytest      # 48 tests
```

## Notes
A capture shows one vantage point: a retransmission or a missing packet is not proof of loss or congestion. Reports are kept in memory, so restarting the backend drops them.
