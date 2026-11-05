"""TLS metadata visible on the wire. Application data is encrypted and never inspected (no keys). TLS 1.3 and Encrypted ClientHello can hide
much of the handshake - what is not visible is reported as unavailable, not guessed."""
from __future__ import annotations

import pandas as pd

from .base import load_base
from .charts import chart, clean, counts_chart, histogram, metric, over_time, table
from .context import Context
from .util import pl, stats, to_int, values

TLS_VER = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
CIPHERS = {0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
           0xC030: "ECDHE-RSA-AES256-GCM-SHA384", 0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256", 0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384", 0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
           0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305", 0x009C: "RSA-AES128-GCM-SHA256", 0x009D: "RSA-AES256-GCM-SHA384", 0x002F: "RSA-AES128-CBC-SHA", 0x0035: "RSA-AES256-CBC-SHA"}
ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked",
          45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
          71: "insufficient_security", 80: "internal_error", 90: "user_canceled", 112: "unrecognized_name"}
CONTENT = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "Application data"}
ECH_EXT = 65037      # encrypted_client_hello (0xfe0d)


def _ver(v):
    return TLS_VER.get(v, f"0x{v:04x}") if v is not None else ""


def analyze(ctx: Context) -> tuple[dict, pd.DataFrame]:
    df = load_base(ctx, "tls", [("htype", "tls.handshake.type"), ("sni", "tls.handshake.extensions_server_name"), ("ver", "tls.handshake.version"),
                                ("sver", "tls.handshake.extensions.supported_version"), ("cipher", "tls.handshake.ciphersuite"), ("alpn", "tls.handshake.extensions_alpn_str"),
                                ("exts", "tls.handshake.extension.type"), ("alert", "tls.alert_message.desc"), ("alevel", "tls.alert_message.level"),
                                ("ctype", "tls.record.content_type"), ("san", "x509ce.dNSName"), ("utc", "x509af.utcTime")])
    conns, alerts, ctypes = {}, [], []
    offered_ver, offered_ciph = [], []
    for x in df.itertuples():
        key = x.stream or f"pkt{x.no}"
        c = conns.setdefault(key, {"stream": key, "client": None, "server": None, "sni": "", "alpn_offered": "", "alpn": "", "version": "", "cipher": "", "offered_versions": "",
                                   "ech": False, "ch_time": None, "sh_time": None, "ch_no": None, "alert": "", "appdata": 0, "ccs": False, "cert": "", "cert_seen": False})
        types = [to_int(v) for v in values(x.htype)]
        cts = [to_int(v) for v in values(x.ctype)]
        if 1 in types:                                                       # ClientHello
            c.update(client=f"{x.src}:{x.sport}", server=f"{x.dst}:{x.dport}", ch_time=x.time, ch_no=x.no)
            c["sni"] = c["sni"] or next(iter(values(x.sni)), "")
            c["alpn_offered"] = ", ".join(values(x.alpn))
            sv = [to_int(v) for v in values(x.sver)]
            c["offered_versions"] = ", ".join(_ver(v) for v in sv if v is not None)
            offered_ver += [_ver(v) for v in sv if v is not None]
            offered_ciph += [CIPHERS.get(to_int(v), f"0x{to_int(v):04x}") for v in values(x.cipher) if to_int(v) is not None]
            c["ech"] = ECH_EXT in [to_int(v) for v in values(x.exts)]
        if 2 in types:                                                       # ServerHello
            sv = [to_int(v) for v in values(x.sver)] or [to_int(v) for v in values(x.ver)]
            c["version"] = _ver(sv[0]) if sv else c["version"]
            ci = to_int(x.cipher)
            c["cipher"] = (CIPHERS.get(ci, f"0x{ci:04x}") if ci is not None else c["cipher"])
            c["alpn"] = ", ".join(values(x.alpn)) or c["alpn"]
            c["sh_time"] = x.time
        if 11 in types:                                                      # Certificate (cleartext only up to TLS 1.2)
            c["cert_seen"] = True
            san = values(x.san)[:3]
            utc = values(x.utc)[:2]
            c["cert"] = ", ".join(san) + (f"  (valid {utc[0]} → {utc[1]})" if len(utc) == 2 else "")
        al = [to_int(v) for v in values(x.alert)]
        if al:
            lv = to_int(x.alevel)
            c["alert"] = ALERTS.get(al[0], f"alert {al[0]}")
            alerts.append({"no": x.no, "time_s": x.rel_time, "src": x.src, "dst": x.dst, "alert": c["alert"], "level": "fatal" if lv == 2 else "warning"})
        ctypes += [CONTENT.get(v, f"type {v}") for v in cts if v is not None]
        if 20 in cts:
            c["ccs"] = True
        if 23 in cts:
            c["appdata"] += 1
    cols = ["stream", "client", "server", "sni", "alpn_offered", "alpn", "version", "cipher", "offered_versions", "ech", "ch_time", "sh_time", "ch_no", "alert", "appdata", "ccs", "cert", "cert_seen"]
    conn = pd.DataFrame([v for v in conns.values() if v["ch_no"] is not None], columns=cols)
    conn["handshake_ms"] = (conn["sh_time"] - conn["ch_time"]) * 1000
    conn["status"] = conn.apply(lambda r: f"Alert: {r['alert']}" if r["alert"] else
                                ("Completed (ServerHello + later records)" if pd.notna(r["sh_time"]) and (r["ccs"] or r["appdata"]) else
                                 "ServerHello seen" if pd.notna(r["sh_time"]) else "ClientHello only"), axis=1) if len(conn) else []
    conn["click"] = conn["ch_no"]
    ok = conn[conn["sh_time"].notna()]
    hs = stats(conn["handshake_ms"])
    fatal = sum(1 for a in alerts if a["level"] == "fatal")
    n_ech = int(conn["ech"].sum()) if len(conn) else 0
    metrics = [
        metric("TLS connections (ClientHello)", int(len(conn)), basis="observed"), metric("ServerHello seen", int(len(ok)), tip="ClientHello answered by a ServerHello.", basis="observed"),
        metric("Alerts", int(len(alerts)), sub=f"{fatal} fatal", tip="Visible TLS alert records (alerts are encrypted in TLS 1.3 after the handshake keys are set).", basis="observed"),
        metric("Handshake time min", hs["min"] if hs else None, fmt="ms", tip="ClientHello → ServerHello (timestamps of the two packets at the capture point).", why="No ClientHello/ServerHello pairs."),
        metric("Handshake time average", hs["avg"] if hs else None, fmt="ms", why="No ClientHello/ServerHello pairs."), metric("Handshake time max", hs["max"] if hs else None, fmt="ms", why="No ClientHello/ServerHello pairs."),
        metric("Server names visible (SNI)", int(conn["sni"].replace("", pd.NA).dropna().nunique()), tip="Hostnames sent in clear text in the ClientHello."),
        metric("Encrypted application-data records", int(sum(1 for c in ctypes if c == "Application data")), tip="Record count only - the content is encrypted and not inspected."),
    ]
    vc = ok["version"].replace("", pd.NA).dropna()
    charts = {c["id"]: c for c in clean([
        over_time("tls_time", "TLS packets over time", df["rel_time"]),
        counts_chart("tls_ver", "Negotiated TLS version", vc, "pie", tip="From the ServerHello (supported_versions extension for TLS 1.3)."),
        counts_chart("tls_overs", "Versions offered by clients", pd.Series(offered_ver, dtype=str), "bar", tip="supported_versions extension of the ClientHello (empty for clients that only send the legacy version field)."),
        counts_chart("tls_cipher", "Negotiated cipher suite", ok["cipher"].replace("", pd.NA).dropna(), "barh"),
        counts_chart("tls_ociph", "Cipher suites offered by clients (top)", pd.Series(offered_ciph, dtype=str), "barh", top=10),
        counts_chart("tls_sni", "Top server names (SNI)", conn["sni"], "barh"), counts_chart("tls_alpn", "ALPN (negotiated)", conn["alpn"].replace("", pd.NA).dropna(), "pie"),
        counts_chart("tls_alpno", "ALPN (offered)", conn["alpn_offered"], "bar"),
        counts_chart("tls_rec", "TLS record types", pd.Series(ctypes, dtype=str), "bar", tip="Handshake / Alert / ChangeCipherSpec / Application data record counts."),
        histogram("tls_hs", "Handshake time distribution", conn["handshake_ms"], unit="ms", x_label="ms"),
    ])}
    tables = {"connections": table("connections", "TLS handshakes", conn, [
        ("stream", "Stream", "text", False), ("client", "Client", "text", False), ("server", "Server", "text", False), ("sni", "SNI", "text", False), ("version", "Version", "text", False),
        ("cipher", "Cipher suite", "text", False), ("alpn", "ALPN", "text", False), ("handshake_ms", "Handshake", "ms", True), ("cert", "Certificate", "text", False),
        ("appdata", "App-data pkts", "num", True), ("status", "Status", "text", False)], tip="One row per TCP connection that carried a ClientHello. Click a row to inspect the ClientHello.", click="click")}
    if alerts:
        tables["alerts"] = table("alerts", "TLS alerts", pd.DataFrame(alerts), [("no", "Packet", "num", True), ("time_s", "Time (s)", "sec", True), ("src", "From", "text", False),
                                 ("dst", "To", "text", False), ("alert", "Alert", "text", False), ("level", "Level", "text", False)], click="no")
    sections = [{"id": "summary", "title": "Summary", "metrics": "all", "charts": ["tls_time", "tls_ver", "tls_rec"]},
                {"id": "handshakes", "title": "Handshakes", "charts": ["tls_hs"], "tables": ["connections", "alerts"]},
                {"id": "versions", "title": "Versions/Cipher Suites", "charts": ["tls_ver", "tls_overs", "tls_cipher", "tls_ociph"]},
                {"id": "sni", "title": "SNI/ALPN", "charts": ["tls_sni", "tls_alpn", "tls_alpno"]}]
    top_ver = vc.value_counts().index[0] if len(vc) else None
    detail = {
        "key": "tls", "label": "TLS", "filter": "tls",
        "summary": f"{pl(len(conn), 'TLS connection')}, {len(ok)} with a ServerHello" + (f", mostly {top_ver}" if top_ver else "") + f", {pl(len(alerts), 'alert')}. Payload is encrypted.",
        "card": [pl(len(conn), "handshake"), top_ver or "version n/a", pl(len(alerts), "alert")],
        "insight": {"text": f"{pl(len(conn), 'TLS handshake')}" + (f", {pl(len(alerts), 'alert')}" if alerts else ""), "tone": "bad" if fatal else "info"},
        "metrics": metrics, "charts": list(charts.values()), "tables": list(tables.values()), "sections": sections,
        "notes": ["HTTPS/TLS application data is encrypted: only handshake metadata (SNI, versions, cipher suites, ALPN, certificates up to TLS 1.2) is visible.",
                  "TLS 1.3 encrypts most of the handshake after ServerHello, and Encrypted ClientHello can hide the server name.",
                  "No decryption keys are used; encrypted content is never inspected."],
    }
    return detail, df
