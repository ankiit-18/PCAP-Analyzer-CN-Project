"""Generates the two notebooks from shared cell templates. Run:  python3 _build_notebooks.py   (needs nbformat)

Both notebooks import the SAME `engine` package as the backend API - there is no analysis code in the notebooks.
  PCAP_Analysis_Tshark.ipynb  - guided walkthrough with plots
  PCAP_Analysis_Engine.ipynb  - engine / API view: unified report schema, limits, tables, validation, export (no plots)
"""
import os

import nbformat as nbf

HERE = os.path.dirname(os.path.abspath(__file__))

SETUP = '''
import os, sys, shutil, subprocess, json, warnings
warnings.filterwarnings("ignore")

IN_COLAB = "google.colab" in sys.modules

# 1) TShark (Colab needs it installed once; locally: brew install wireshark / sudo apt install tshark)
if not shutil.which("tshark") and IN_COLAB:
    subprocess.run("apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y tshark > /dev/null", shell=True)
print("tshark:", shutil.which("tshark") or "NOT FOUND - install it first")

# 2) the shared analysis engine (the same package the backend uses)
def _find_engine():
    for base in ("../backend", "backend", "."):
        if os.path.isdir(os.path.join(base, "engine")):
            return os.path.abspath(base)
if _find_engine() is None and IN_COLAB:
    from google.colab import files
    print("Upload engine.zip  (create it with:  cd code/backend && zip -r engine.zip engine)")
    up = files.upload()
    subprocess.run(["unzip", "-oq", next(iter(up))], check=True)
path = _find_engine()
assert path, "engine/ package not found. Run this notebook from the repository (notebook/ folder) or upload engine.zip."
sys.path.insert(0, path)

import numpy as np, pandas as pd, matplotlib.pyplot as plt
import engine
from engine import tcp_views
pd.set_option("display.max_columns", 40, "display.width", 200, "display.max_colwidth", 80)
'''

HELPERS = '''
# ---- tiny display helpers (presentation only - no analysis happens here) -----------------------------------------
def fmt(v, kind):
    if v is None: return "-"
    if kind == "bytes":
        for u in ("B", "KB", "MB", "GB"):
            if abs(v) < 1024: return f"{v:,.1f} {u}" if u != "B" else f"{int(v)} B"
            v /= 1024
    if kind == "bps":
        for u in ("bps", "Kbps", "Mbps", "Gbps"):
            if abs(v) < 1000: return f"{v:,.1f} {u}"
            v /= 1000
    if kind == "ms": return f"{v:,.2f} ms"
    if kind == "sec": return f"{v:,.3f} s"
    if kind == "pct": return f"{v:.2f}%"
    return f"{v:,.2f}" if isinstance(v, float) else f"{v:,}" if isinstance(v, int) else str(v)

def metrics_table(detail):
    """Metrics as a table. Unavailable metrics say WHY - they are never shown as 0."""
    rows = [{"metric": m["label"], "value": fmt(m["value"], m["fmt"]) if m["available"] else "NOT AVAILABLE", "basis": m.get("basis", ""),
             "note": m.get("reason", "") if not m["available"] else m.get("sub", "")} for m in detail["metrics"]]
    return pd.DataFrame(rows)

def table_df(detail, table_id=None, n=15):
    t = next((t for t in detail["tables"] if table_id in (None, t["id"])), None)
    if t is None: return None
    df = pd.DataFrame(t["rows"]); cols = [c["key"] for c in t["columns"] if c["key"] in df.columns]
    return df[cols].rename(columns={c["key"]: c["label"] for c in t["columns"]}).head(n)

def plot_spec(spec, height=3.0):
    """Render a chart description produced by the engine (bar / barh / pie / line / scatter)."""
    t = spec["type"]; fig, ax = plt.subplots(figsize=(8.5, height))
    try:
        if t == "barh":
            ax.barh(range(len(spec["labels"])), spec["series"][0]["data"]); ax.set_yticks(range(len(spec["labels"]))); ax.set_yticklabels(spec["labels"]); ax.invert_yaxis()
        elif t == "bar":
            n = len(spec["series"]); w = 0.8 / n; idx = np.arange(len(spec["labels"]))
            for i, s in enumerate(spec["series"]):
                ax.bar(idx - 0.4 + w * (i + 0.5), s["data"], w, label=s["name"])
            ax.set_xticks(idx); ax.set_xticklabels(spec["labels"], rotation=30, ha="right")
            if n > 1: ax.legend(fontsize=8)
        elif t == "pie":
            ax.pie(spec["series"][0]["data"], labels=spec["labels"], autopct="%1.0f%%", startangle=90); ax.axis("equal")
        else:
            for s in spec["series"]:
                pts = s.get("points") or list(zip(spec["x"], s["data"]))
                x, y = [p[0] for p in pts], [p[1] for p in pts]
                (ax.scatter(x, y, s=10, label=s["name"]) if t == "scatter" else ax.plot(x, y, label=s["name"]))
            if len(spec["series"]) > 1: ax.legend(fontsize=8)
        ax.set_title(spec["title"] or ""); ax.set_xlabel(spec.get("xLabel", "")); ax.set_ylabel(spec.get("yLabel", "")); ax.grid(alpha=.3)
        plt.tight_layout(); plt.show()
    except Exception as e:
        plt.close(fig); print("(chart skipped:", e, ")")

def protocol_section(key, charts=None, tables=True, plots=True, n=10):
    """Summary + metrics + (charts) + tables for one protocol page of the engine. Prints a clear message if the protocol is absent."""
    d = rep.protocol(key)
    if d is None:
        print(f"No {key.upper().replace('X:', '')} traffic detected in this capture."); return
    print(d["summary"]); display(metrics_table(d))
    if plots:
        for c in d["charts"]:
            if charts is None or c["id"] in charts: plot_spec(c)
    if tables:
        for t in d["tables"]:
            print(f"\\n{t['title']}  ({t['total']:,} rows)"); display(table_df(d, t["id"], n))
    for note in d.get("notes", []): print("  note:", note)
'''

LOAD = '''
#@markdown Capture to analyse. In Colab leave this empty to get an upload prompt; locally set the path.
PCAP_PATH = "../samples/protocols_mix.pcap"  #@param {type:"string"}
MAX_PCAP_SIZE_MB = 100            # same defaults as the backend (env vars MAX_PCAP_SIZE_MB / MAX_ANALYSIS_SECONDS / MAX_EXTRACTED_PACKETS)
MAX_ANALYSIS_SECONDS = 300
MAX_EXTRACTED_PACKETS = 500_000   # 0 = unlimited; above this, packet-level metrics are labelled PARTIAL

if IN_COLAB and not os.path.exists(PCAP_PATH):
    from google.colab import files
    up = files.upload(); PCAP_PATH = next(iter(up))

limits = engine.Limits(max_pcap_size_mb=MAX_PCAP_SIZE_MB, max_analysis_seconds=MAX_ANALYSIS_SECONDS, max_extracted_packets=MAX_EXTRACTED_PACKETS)
try:
    rep = engine.analyze(PCAP_PATH, limits)                       # validates first (magic number, size, empty file) and raises a readable error
except engine.EngineError as e:
    raise SystemExit(f"ERROR: {e}")
md = rep.metadata
print(f"OK {rep.meta['file']} ({rep.meta['format']}, {rep.meta['file_size_bytes'] / 1e6:.2f} MB) - {md['packets_processed']:,} of {md['total_packets']:,} packets analysed "
      f"in {md['elapsed_s']}s  [{md['analysis_scope'].upper()} analysis]")
print("engine", md["engine_version"], "|", md["tshark_version"])
for w in rep.warnings: print(f"[{w['level']}] {w['message']}")
'''


def build(kind):
    plots = kind == "tshark"
    nb, cells = nbf.v4.new_notebook(), []
    md = lambda s: cells.append(nbf.v4.new_markdown_cell(s.strip()))
    code = lambda s: cells.append(nbf.v4.new_code_cell(s.strip()))

    if plots:
        md("""# PCAP Network Analysis - walkthrough
Uses the **shared analysis engine** (`backend/engine`, TShark-based) - exactly the code behind the dashboard API. This notebook only displays results.

**Run:** `Runtime → Run all` (Colab) or run top to bottom locally from the `notebook/` folder. Colab: it installs tshark and asks for `engine.zip` + your capture.

*Basis of every number:* **observed** = dissected by tshark · **derived** = calculated by the engine · **inferred** = cautious interpretation (never proof).""")
    else:
        md("""# PCAP Network Analysis - engine / API view
The same engine the backend API uses, driven programmatically: unified report schema, limits and partial-analysis reporting, per-protocol tables, Wireshark cross-validation and JSON export (no plots - see `PCAP_Analysis_Tshark.ipynb` for the visual walkthrough).""")

    md("## 1. Environment and TShark version")
    code(SETUP)
    code(HELPERS)
    code("from engine.tshark import Tshark\nts = Tshark(engine.Limits()); ts.require()\nprint(ts.version)\nprint('engine', engine.ENGINE_VERSION)")

    md("## 2. Load, validate and run the analysis\nInvalid, empty, too-large or unsupported files stop here with a readable message. If the capture exceeds `MAX_EXTRACTED_PACKETS` the packet-level results are labelled **partial**.")
    code(LOAD)

    md("## 3. Overview and protocol distribution")
    code('''s = rep.summary
overview = pd.DataFrame([("file", rep.meta["file"]), ("format", rep.meta["format"]), ("duration", fmt(s["duration_s"], "sec")), ("packets", f"{s['packets']:,}"), ("bytes", fmt(s["bytes"], "bytes")),
                         ("average packet size", fmt(s["avg_packet_size"], "bytes")), ("packet rate", f"{s['avg_pps']:,.1f} pkt/s" if s["avg_pps"] else "NOT AVAILABLE (zero duration)"),
                         ("throughput", fmt(s["avg_throughput_bps"], "bps") if s["avg_throughput_bps"] else "NOT AVAILABLE (zero duration)"),
                         ("protocols detected", len(rep.detected)), ("TCP flows", s["tcp_flows"])], columns=["capture", "value"])
display(overview)
print("Protocol hierarchy (tshark -z io,phs)"); display(rep.hierarchy[["tree", "frames", "bytes", "pct_frames"]])
print("Detected protocols"); display(pd.DataFrame(rep.detected)[["label", "packets", "pct_packets", "bytes"]])''' + ('''
d = pd.DataFrame(rep.detected).set_index("label")["packets"]
d.sort_values().plot.barh(figsize=(7, 3), title="Packets per detected protocol"); plt.tight_layout(); plt.show()''' if plots else ""))

    md("## 4. IP analysis (IPv4 + IPv6)\nEndpoints, top talkers, transport conversations (canonical IP pair + ports + protocol), header analysis, traffic over time.")
    code('protocol_section("ip", charts=["toptalk_b", "ipcat", "ipttl", "ipdscp", "iptime"], tables=True, plots=%s, n=8)' % plots)

    md("## 5. TCP - flows and indicators")
    code('''if rep.tcp.flows.empty:
    print("No TCP traffic in this capture.")
else:
    print({k: rep.tcp.summary[k] for k in ("tcp_flows", "retransmissions", "fast_retransmissions", "spurious_retransmissions", "out_of_order", "dup_acks", "seq_gaps", "zero_windows", "flows_with_issues")})
    cols = ["flow", "client", "server", "packets", "bytes", "payload_bytes", "duration_s", "throughput_bps", "packets_per_s", "avg_packet_size", "pkts_c2s", "pkts_s2c",
            "retransmissions", "fast_retransmissions", "spurious_retransmissions", "out_of_order", "dup_acks", "lost_segments", "handshake_rtt_ms", "rtt_samples", "rtt_avg_ms"]
    display(rep.tcp.flows[cols].round(3).head(15))
    print("Flagged packets (Wireshark tcp.analysis.*)"); display(rep.tcp.findings.head(15))''')

    md("## 6. TCP - RTT analysis\nThree **separate** methods (never combined): ACK-based `tcp.analysis.ack_rtt` (observed), TCP timestamp-echo (derived), initial handshake `tcp.analysis.initial_rtt` (observed).")
    code('''r = tcp_views.rtt(rep)
for m in r["methods"]:
    st = m["stats_ms"]
    print(f"{m['label']:28s} [{m['basis']}]", "-> " + (f"n={st['count']}  min={st['min']:.2f}  avg={st['avg']:.2f}  std={st['std']:.2f}  p95={st['p95']:.2f}  max={st['max']:.2f} ms" if st else "NOT AVAILABLE: " + m["reason"]))
display(pd.DataFrame(r["per_flow"]).round(3).head(10))''' + ('''
for m in r["methods"]:
    if m["available"]:
        pts = np.array([[p[0], p[1]] for p in m["points"]]); plt.scatter(pts[:, 0], pts[:, 1], s=8, label=m["label"])
plt.xlabel("time (s)"); plt.ylabel("RTT (ms)"); plt.title("RTT over time (methods kept separate)"); plt.legend(fontsize=8); plt.grid(alpha=.3); plt.show()''' if plots else ""))

    md("## 7. TCP - flow control (advertised receive window, NOT cwnd)\nEffective window = advertised 16-bit window × 2^(negotiated shift); not applied to SYN, only when both SYNs carried the option; each direction separately. If the handshake is missing the scale is *uncertain*.")
    code('''fc = tcp_views.flow_control(rep)
display(pd.DataFrame(fc["directions"])[["flow", "direction", "scale_status", "scale_shift", "window_min", "window_avg", "window_max", "zero_window_engine", "zero_window_wireshark", "zero_window_probes", "window_updates", "window_full"]].round(1).head(12) if fc["directions"] else "No TCP flows.")
print(fc["note"])''' + ('''
if rep.tcp.window_dir is not None and len(rep.tcp.window_dir):
    f0 = int(rep.tcp.window_dir.sort_values("zero_window_wireshark", ascending=False).iloc[0]["flow"])
    s = tcp_views.flow_control(rep, f0)["series"]
    for role, v in s.items():
        if v["effective"]: plt.step([p[0] for p in v["effective"]], [p[1] for p in v["effective"]], where="post", label=f"{v['direction']} ({v['status']})")
    plt.xlabel("time (s)"); plt.ylabel("window (bytes)"); plt.title(f"Effective receive window, flow {f0}"); plt.legend(fontsize=8); plt.grid(alpha=.3); plt.show()''' if plots else ""))

    md("## 8. TCP - congestion indicators (inferred)\n**The sender's cwnd is not visible in a capture** and is never reported. Assessments are cautious interpretations; retransmissions and duplicate ACKs alone do not prove congestion.")
    code('''cg = tcp_views.congestion(rep)
print(cg["caveat"])
if cg["flows"]:
    df = pd.DataFrame(cg["flows"])
    display(df[["flow", "assessment", "retransmissions", "dup_acks", "out_of_order", "zero_windows", "rtt_min_ms", "rtt_p95_ms", "ce_marks", "ecn_negotiated"]].round(2).head(12))
    worst = df.sort_values("retransmissions", ascending=False).iloc[0]
    print(f"\\nEvidence for flow {int(worst['flow'])}:"); [print(f"  [{e['basis']}] {e['text']}") for e in worst["evidence"]]''' + ('''
for c in cg["charts"][:2]:
    plot_spec(c)''' if plots else ""))

    md("## 9. TCP - options\nNegotiated (SYN / SYN-ACK) vs observed later. Unknown when the handshake was not captured.")
    code('''op = tcp_views.options(rep)
display(pd.DataFrame(op["flows"]).head(12) if op["flows"] else "No TCP flows.")
print(op["note"])''')

    md("## 10. UDP"); code('protocol_section("udp", charts=["udp_traffic", "udp_size"], plots=%s, n=8)' % plots)
    md("## 11. DNS"); code('protocol_section("dns", charts=["dns_qtype", "dns_lat"], plots=%s, n=10)' % plots)
    md("## 12. TLS (metadata only - payload is encrypted)"); code('protocol_section("tls", charts=["tls_ver", "tls_cipher"], plots=%s, n=8)' % plots)
    md("## 13. QUIC and ARP\nDetail pages exist for TCP, UDP, DNS, TLS, QUIC, ARP and IP. QUIC and ARP use the generic protocol view (identified by tshark's dissector, never by port).")
    code('''for k in ("x:quic", "x:arp"):
    protocol_section(k, plots=False, n=5)''')
    md("## 14. Every other protocol (overview only)\nThese are counted but have no detail page: the table below is what the dashboard overview lists.")
    code('''allp = pd.DataFrame([{"protocol": p, "packets": int(g["frames"].sum()), "bytes": int(g["bytes"].sum())} for p, g in rep.hierarchy[rep.hierarchy.protocol != "frame"].groupby("protocol")])
allp["share_%"] = (100 * allp["packets"] / rep.summary["packets"]).round(2)
display(allp.sort_values("packets", ascending=False).reset_index(drop=True))''')

    md("## 15. Wireshark / TShark cross-validation\nRe-measures key values with independent tshark commands. **dissected** = counted from a tshark flag · **aggregated** = grouped by the engine · **derived** = calculated by the engine (no direct Wireshark equivalent).")
    code('''v = engine.cross_validate(rep)
display(pd.DataFrame(v["rows"])[["area", "metric", "engine", "tshark", "difference", "status", "basis", "note"]])
print(v["summary"], "| scope:", v["scope"])
print("\\nWhy values can differ:"); [print(" -", e) for e in v["explanations"]]''')

    if not plots:
        md("## 16. Unified report schema\n`engine.to_dict(report)` is JSON-safe (no DataFrames, NaN/inf -> null) and is what the API exports.")
        code('''data = engine.to_dict(rep)
print("top-level keys:", list(data))
print("analysis_metadata:", json.dumps(data["analysis_metadata"], indent=2)[:600])
json.dumps(data, allow_nan=False)  # strict JSON must not raise
print("strict JSON OK -", len(json.dumps(data)) // 1024, "KB")''')

    md("## %s. JSON export" % ("17" if not plots else "16"))
    code('''out = "pcap_report.json"
with open(out, "w") as f:
    json.dump(engine.to_dict(rep), f, indent=1)
print("written", out, f"({os.path.getsize(out) / 1024:.0f} KB)")
if IN_COLAB:
    from google.colab import files; files.download(out)''')

    nb.cells = cells
    nb.metadata = {"kernelspec": {"name": "python3", "display_name": "Python 3"}, "language_info": {"name": "python"}}
    name = "PCAP_Analysis_Tshark.ipynb" if plots else "PCAP_Analysis_Engine.ipynb"
    nbf.write(nb, os.path.join(HERE, name))
    print("wrote", name, len(cells), "cells")


if __name__ == "__main__":
    build("tshark")
    build("engine")
