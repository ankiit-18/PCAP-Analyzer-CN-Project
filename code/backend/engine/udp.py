"""UDP analysis. UDP has no ACKs, sequence numbers, retransmissions, congestion control or window flow control - none of those are
invented here. Timing is reported as generic *packet inter-arrival variation*; protocol-specific jitter exists only for RTP."""
from __future__ import annotations

import numpy as np
import pandas as pd

from .base import BASE_PROTOS
from .charts import chart, clean, counts_chart, histogram, metric, over_time, table, traffic_chart
from .context import Context
from .util import pl, stats


def _app(chain: pd.Series) -> pd.Series:
    cache = {c: next((p.upper() for p in reversed(c.split(":")) if p not in BASE_PROTOS), "") for c in chain.unique()}
    return chain.map(cache)


def conversations(u: pd.DataFrame) -> pd.DataFrame:
    """One row per udp.stream = canonical bidirectional 5-tuple (IP pair + port pair + UDP). Direction is relative to the first datagram."""
    u = u.sort_values(["udp_stream", "time"]).copy()
    u["ia"] = u.groupby("udp_stream")["time"].diff() * 1000
    first = u.groupby("udp_stream")[["src", "sport", "dst", "dport"]].first()
    fs, fp = u["udp_stream"].map(first["src"]), u["udp_stream"].map(first["sport"])
    u["fwd"] = (u["src"] == fs) & (u["sport"] == fp)
    g = u.groupby("udp_stream", sort=True)
    c = pd.DataFrame({"flow": g.size().index.astype(int)}).set_index("flow")
    c["source"] = [f"{r.src}:{r.sport}" for r in first.itertuples()]
    c["destination"] = [f"{r.dst}:{r.dport}" for r in first.itertuples()]
    c["app"] = g["app"].agg(lambda s: next((a for a in s if a), "")).to_numpy()
    c["packets"] = g.size().to_numpy()
    c["bytes"] = g["length"].sum().to_numpy().astype(int)
    c["payload_bytes"] = g["payload"].sum().to_numpy()
    c["pkts_fwd"] = u[u["fwd"]].groupby("udp_stream").size().reindex(first.index).fillna(0).astype(int).to_numpy()
    c["pkts_rev"] = c["packets"] - c["pkts_fwd"]
    c["bytes_fwd"] = u[u["fwd"]].groupby("udp_stream")["length"].sum().reindex(first.index).fillna(0).astype(int).to_numpy()
    c["bytes_rev"] = c["bytes"] - c["bytes_fwd"]
    c["start_s"] = g["rel_time"].min().to_numpy()
    c["duration_s"] = (g["time"].max() - g["time"].min()).to_numpy()
    d = c["duration_s"].to_numpy()
    c["throughput_bps"] = np.where(d > 0, c["bytes"] * 8 / np.where(d > 0, d, 1), np.nan)
    c["packets_per_s"] = np.where(d > 0, c["packets"] / np.where(d > 0, d, 1), np.nan)
    c["size_min"], c["size_avg"], c["size_max"] = g["length"].min().to_numpy(), g["length"].mean().to_numpy(), g["length"].max().to_numpy()
    ia = g["ia"]
    c["iat_mean_ms"], c["iat_std_ms"], c["iat_max_ms"] = ia.mean().to_numpy(), ia.std(ddof=0).to_numpy(), ia.max().to_numpy()
    c["one_way"] = c["pkts_rev"] == 0
    c["first_no"] = g["no"].min().to_numpy()
    return c.reset_index().sort_values("bytes", ascending=False), u


def analyze(ctx: Context) -> tuple[dict, pd.DataFrame]:
    u = ctx.packets[ctx.packets["is_udp"]].copy()
    u["payload"] = (u["udp_len"] - 8).clip(lower=0)
    u["app"] = _app(u["protocols"])
    conv, u = conversations(u)
    srv = u.assign(port=u[["sport", "dport"]].min(axis=1)).query("port > 0")
    metrics = [
        metric("Datagrams", int(len(u)), basis="observed"), metric("Total bytes", int(u["length"].sum()), fmt="bytes", tip="Frame bytes of all UDP packets."),
        metric("Payload bytes", float(u["payload"].sum()), fmt="bytes", tip="UDP length minus the 8-byte header.", why="UDP length not available."),
        metric("UDP conversations", int(len(conv)), tip="Canonical bidirectional 5-tuple (tshark udp.stream)."),
        metric("Packet size min / avg / max", f"{int(u['length'].min())} / {u['length'].mean():.0f} / {int(u['length'].max())} B", fmt="text"),
    ]
    charts = {c["id"]: c for c in clean([
        traffic_chart(ctx.ts, ctx.path, "udp", ctx.duration, "udp_traffic", "UDP traffic over time"),
        over_time("udp_bytes", "UDP bytes by application", u["rel_time"], weights=u["length"].to_numpy(), split=u["app"].replace("", "unrecognised"), unit="bytes", name="bytes"),
        counts_chart("udp_ports", "Top service ports (packets)", srv["port"].astype(str), "barh", tip="Lower port of each datagram's pair, used as the service port."),
        chart("udp_topflows", "Top conversations by bytes", "barh", list((conv["source"] + " → " + conv["destination"]).head(10)), [{"name": "bytes", "data": [int(x) for x in conv["bytes"].head(10)]}], unit="bytes"),
        counts_chart("udp_apps", "Application protocols over UDP", u["app"], "pie", tip="Wireshark dissector for each datagram; unrecognised traffic is left out."),
        histogram("udp_size", "Packet size distribution (bytes on the wire)", u["length"], unit="bytes", x_label="bytes"),
        histogram("udp_payload", "Payload size distribution", u["payload"], unit="bytes", x_label="bytes"),
    ])}
    tables = {"conversations": table("conversations", "UDP conversations", conv, [
        ("flow", "Flow", "num", True), ("source", "Source", "text", False), ("destination", "Destination", "text", False), ("app", "App", "text", False),
        ("packets", "Packets", "num", True), ("bytes", "Bytes", "bytes", True), ("payload_bytes", "Payload", "bytes", True), ("pkts_fwd", "→ pkts", "num", True),
        ("pkts_rev", "← pkts", "num", True), ("bytes_fwd", "→ bytes", "bytes", True), ("bytes_rev", "← bytes", "bytes", True), ("duration_s", "Duration", "sec", True),
        ("throughput_bps", "Throughput", "bps", True), ("packets_per_s", "Pkts/s", "num1", True), ("size_min", "Min size", "bytes", True), ("size_avg", "Avg size", "bytes", True),
        ("size_max", "Max size", "bytes", True), ("iat_mean_ms", "IAT mean", "ms", True), ("iat_std_ms", "IAT std", "ms", True), ("iat_max_ms", "IAT max", "ms", True)],
        tip="One row per canonical bidirectional 5-tuple. → = same direction as the first datagram. IAT = inter-arrival time. Click a row to inspect its first datagram.", click="first_no")}
    sections = [{"id": "summary", "title": "Summary", "metrics": "all", "charts": ["udp_traffic", "udp_apps"]},
                {"id": "conversations", "title": "Conversations", "tables": ["conversations"]},
                {"id": "traffic", "title": "Traffic Analysis", "charts": ["udp_bytes", "udp_ports", "udp_topflows", "udp_size", "udp_payload"]}]
    detail = {
        "key": "udp", "label": "UDP", "filter": "udp",
        "summary": f"{len(u):,} UDP datagrams in {len(conv):,} conversations.",
        "card": [pl(len(u), "datagram"), pl(len(conv), "conversation"), f"avg payload {u['payload'].mean():.0f} B"],
        "insight": {"text": f"UDP carries {100 * u['length'].sum() / max(ctx.totals.get('bytes') or 1, 1):.1f}% of all bytes ({pl(len(conv), 'conversation')})", "tone": "info"},
        "metrics": metrics, "charts": list(charts.values()), "tables": list(tables.values()), "sections": sections,
        "notes": ["Metrics that need sequence numbers, ACKs or handshakes are shown as unavailable instead of 0 or an estimate.",
                  "Inter-arrival variation is generic timing. Application-specific jitter is only computed for RTP (see the RTP page)."],
        "packet_columns": [{"key": k, "label": l, "fmt": f, "num": n} for k, l, f, n in [("no", "#", "num", True), ("rel_time", "Time", "sec", True), ("src", "Source", "text", False),
                           ("sport", "Port", "text", False), ("dst", "Destination", "text", False), ("dport", "Port", "text", False), ("length", "Length", "bytes", True),
                           ("payload", "Payload", "bytes", True), ("app", "App", "text", False)]],
    }
    pk = u.assign(info=u["app"].replace("", "UDP") + " len=" + u["payload"].fillna(0).astype(int).astype(str))
    return detail, pk
