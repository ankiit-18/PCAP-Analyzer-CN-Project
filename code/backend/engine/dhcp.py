"""DHCPv4: message types, DORA progress and timing per transaction ID, leases."""
from __future__ import annotations

import pandas as pd

from .base import load_base
from .charts import clean, counts_chart, metric, over_time, table
from .context import Context
from .util import numeric, first, pl, stats

DHCP_TYPES = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}


def _nz(s: pd.Series):
    s = s.replace("", pd.NA).dropna()
    return s.iloc[0] if len(s) else ""


def analyze(ctx: Context) -> tuple[dict, pd.DataFrame]:
    df = load_base(ctx, "dhcp", [("xid", "dhcp.id"), ("mtype", "dhcp.option.dhcp"), ("mac", "dhcp.hw.mac_addr"), ("yiaddr", "dhcp.ip.your"), ("host", "dhcp.option.hostname"),
                                 ("reqip", "dhcp.option.requested_ip_address"), ("server", "dhcp.option.dhcp_server_id"), ("lease", "dhcp.option.ip_address_lease_time")])
    df["mtype_name"] = numeric(df["mtype"]).map(lambda v: DHCP_TYPES.get(int(v), f"type {int(v)}") if v == v else "")
    rows = []
    for xid, g in df.groupby("xid", sort=False):
        g = g.sort_values("time")
        types = set(g["mtype_name"])
        ack, offer = g[g["mtype_name"] == "ACK"], g[g["mtype_name"] == "Offer"]
        ip = _nz(ack["yiaddr"]) or _nz(offer["yiaddr"])
        outcome = ("Completed (DORA)" if {"Discover", "Offer", "Request", "ACK"} <= types else "Rejected (NAK)" if "NAK" in types else
                   "Renewal/ACK" if "ACK" in types else "No offer" if types == {"Discover"} else "Incomplete")
        t = lambda n: (g[g["mtype_name"] == n]["time"].min() if n in types else None)
        rows.append({"xid": xid, "client_mac": _nz(g["mac"]), "hostname": _nz(g["host"]), "requested_ip": _nz(g["reqip"]), "assigned_ip": ip, "server": _nz(g["server"]),
                     "sequence": " → ".join(g["mtype_name"]), "outcome": outcome, "duration_ms": (g["time"].max() - g["time"].min()) * 1000 if len(g) > 1 else None,
                     "offer_delay_ms": (t("Offer") - t("Discover")) * 1000 if t("Offer") is not None and t("Discover") is not None else None,
                     "lease_s": float(numeric(ack["lease"]).dropna().iloc[0]) if len(ack) and numeric(ack["lease"]).notna().any() else None,
                     "first_no": int(g["no"].min()), "start_s": float(g["rel_time"].min())})
    tx = pd.DataFrame(rows, columns=["xid", "client_mac", "hostname", "requested_ip", "assigned_ip", "server", "sequence", "outcome", "duration_ms", "offer_delay_ms", "lease_s", "first_no", "start_s"])
    done = int(tx["outcome"].isin(["Completed (DORA)", "Renewal/ACK"]).sum())
    nak, noffer = int((df["mtype_name"] == "NAK").sum()), int((tx["outcome"] == "No offer").sum())
    dur, off = stats(tx["duration_ms"]), stats(tx["offer_delay_ms"])
    leases = tx[tx["assigned_ip"] != ""]
    metrics = [
        metric("DHCP messages", int(len(df)), basis="observed"), metric("Transactions (xid)", int(len(tx)), tip="Messages sharing a transaction ID."),
        metric("Completed leases", done, tip="Transactions ending in an ACK (full DORA = Discover, Offer, Request, ACK)."),
        metric("Discovers without offer", noffer, tip="No server answered (or the capture missed the Offer)."), metric("NAKs", nak, tip="The server refused the request."),
        metric("Declines", int((df["mtype_name"] == "Decline").sum())), metric("Clients (MAC)", int(df["mac"].replace("", pd.NA).dropna().nunique())),
        metric("DHCP servers", int(df[df["mtype_name"].isin(["Offer", "ACK", "NAK"])]["src"].nunique())),
        metric("Discover → Offer time", off["avg"] if off else None, fmt="ms", tip="Average time between Discover and Offer (timestamps).", why="No Discover/Offer pairs."),
        metric("Whole exchange time", dur["avg"] if dur else None, fmt="ms", tip="First to last message of a transaction (average).", why="No multi-message transactions."),
    ]
    charts = {c["id"]: c for c in clean([over_time("dhcp_time", "DHCP messages over time", df["rel_time"]),
                                         counts_chart("dhcp_types", "Message types", df["mtype_name"], "bar", tip="Discover → Offer → Request → ACK is the normal sequence (DORA)."),
                                         counts_chart("dhcp_out", "Transaction outcomes", tx["outcome"], "pie")])}
    tables = {"transactions": table("transactions", "DHCP transactions (DORA progress)", tx, [
        ("xid", "XID", "text", False), ("client_mac", "Client MAC", "text", False), ("hostname", "Hostname", "text", False), ("requested_ip", "Requested IP", "text", False),
        ("assigned_ip", "Assigned IP", "text", False), ("server", "Server ID", "text", False), ("sequence", "Sequence", "text", False), ("outcome", "Outcome", "text", False),
        ("offer_delay_ms", "Offer delay", "ms", True), ("duration_ms", "Duration", "ms", True), ("lease_s", "Lease (s)", "num", True), ("start_s", "Start (s)", "sec", True)],
        tip="Click a row to inspect the first message.", click="first_no"),
        "leases": table("leases", "Leases", leases, [("client_mac", "Client MAC", "text", False), ("hostname", "Hostname", "text", False), ("assigned_ip", "Assigned IP", "text", False),
                                                    ("server", "Server ID", "text", False), ("lease_s", "Lease (s)", "num", True), ("outcome", "Outcome", "text", False)])}
    sections = [{"id": "summary", "title": "Summary", "metrics": "all", "charts": ["dhcp_types", "dhcp_out", "dhcp_time"]},
                {"id": "dora", "title": "Transactions", "tables": ["transactions"]}, {"id": "leases", "title": "Leases", "tables": ["leases"]}]
    detail = {
        "key": "dhcp", "label": "DHCP", "filter": "dhcp",
        "summary": f"{pl(len(df), 'DHCP message')} in {pl(len(tx), 'transaction')}; {done} completed, {nak} NAK, {noffer} without offer.",
        "card": [pl(len(tx), "transaction"), f"{done} completed", f"{nak} NAK · {noffer} no offer"],
        "insight": {"text": f"DHCP: {done}/{len(tx)} leases completed" + (f", {nak} NAK" if nak else "") + (f", {noffer} no offer" if noffer else ""), "tone": "bad" if (nak or noffer) else "ok"},
        "metrics": metrics, "charts": list(charts.values()), "tables": list(tables.values()), "sections": sections, "notes": ["DHCPv6 is not analysed separately in this version."],
    }
    return detail, df
