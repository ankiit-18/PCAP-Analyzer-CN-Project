"""Generic view for any dissected protocol without a dedicated analyzer (ARP, NTP, SSH, FTP, SMTP, MQTT, QUIC, SCTP, ...).
Identification comes from tshark's dissector chain (frame.protocols), never from port numbers."""
from __future__ import annotations

import pandas as pd

from .base import load_base
from .charts import clean, counts_chart, metric, over_time, table
from .context import Context
from .util import pl


def analyze(ctx: Context, token: str, label: str) -> tuple[dict, pd.DataFrame]:
    df = load_base(ctx, token)
    key = df["stream"].where(df["stream"] != "", df["src"].fillna("") + " ⇄ " + df["dst"].fillna(""))
    rows = []
    for k, g in df.groupby(key, sort=False):
        f = g.iloc[0]
        rows.append({"conversation": f"{f['src']}:{f['sport']} ⇄ {f['dst']}:{f['dport']}" if f["sport"] else str(k), "packets": len(g), "bytes": int(g["length"].sum()),
                     "start_s": float(g["rel_time"].min()), "duration_s": float(g["time"].max() - g["time"].min()), "first_no": int(g["no"].min())})
    conv = pd.DataFrame(rows, columns=["conversation", "packets", "bytes", "start_s", "duration_s", "first_no"]).sort_values("bytes", ascending=False)
    total = max(ctx.totals.get("packets") or len(ctx.packets), 1)
    metrics = [metric("Packets", int(len(df)), basis="observed"), metric("Bytes", int(df["length"].sum()), fmt="bytes"), metric("Conversations", int(len(conv))),
               metric("Hosts", int(pd.concat([df["src"], df["dst"]]).replace("", pd.NA).dropna().nunique())), metric("Share of all packets", 100 * len(df) / total, fmt="pct"),
               metric("Protocol-specific metrics", None, why=f"No dedicated analyzer for {label} yet; showing generic traffic statistics from the dissector.")]
    charts = {c["id"]: c for c in clean([over_time("gen_time", f"{label} packets over time", df["rel_time"]), counts_chart("gen_info", "Most common packet summaries", df["info"], "barh", top=10)])}
    tables = {"conversations": table("conversations", "Conversations", conv, [("conversation", "Conversation", "text", False), ("packets", "Packets", "num", True), ("bytes", "Bytes", "bytes", True),
              ("start_s", "Start (s)", "sec", True), ("duration_s", "Duration", "sec", True)], click="first_no")} if len(conv) else {}
    sections = [{"id": "summary", "title": "Summary", "metrics": "all", "charts": ["gen_time", "gen_info"]}] + ([{"id": "conv", "title": "Conversations", "tables": ["conversations"]}] if tables else [])
    detail = {"key": f"x:{token}", "label": label, "filter": token, "summary": f"{pl(len(df), label + ' packet')} ({int(df['length'].sum()):,} bytes) in {pl(len(conv), 'conversation')}.",
              "card": [pl(len(df), "packet")], "metrics": metrics, "charts": list(charts.values()), "tables": list(tables.values()), "sections": sections,
              "notes": ["Identified by the tshark dissector. Encrypted payloads (for example QUIC or SSH) show metadata only."]}
    return detail, df
