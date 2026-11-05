"""Generate samples/protocols_mix.pcap: multi_flow.pcap (TCP) + DNS, HTTP, TLS, ICMP/ICMPv6, DHCP, RTP, NTP, ARP, UDP.
Needs scapy (pip install scapy). Run make_multi_flow_sample.py first."""
import os
import random
import struct

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP, IPerror, UDPerror
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.ntp import NTP
from scapy.layers.rtp import RTP
from scapy.packet import Raw
from scapy.utils import rdpcap, wrpcap

random.seed(7)
HERE = os.path.dirname(os.path.abspath(__file__))
pk = list(rdpcap(os.path.join(HERE, "multi_flow.pcap")))
T0 = 1700000000.0
C = "192.168.1.10"
CM = "aa:bb:cc:00:00:10"


def add(t, p):
    p.time = T0 + t
    pk.append(p)


# ---------------------------------------------------------------- DNS
def dns(t, qname, qtype="A", ans=None, rcode=0, lat=0.02, ident=None, server="8.8.8.8", sport=None):
    ident = ident or random.randint(1000, 60000)
    sport = sport or random.randint(40000, 60000)
    add(t, Ether() / IP(src=C, dst=server) / UDP(sport=sport, dport=53) / DNS(id=ident, rd=1, qd=DNSQR(qname=qname, qtype=qtype)))
    if lat is not None:
        r = DNS(id=ident, qr=1, ra=1, rcode=rcode, qd=DNSQR(qname=qname, qtype=qtype))
        if ans:
            r.an = DNSRR(rrname=qname, type=qtype, ttl=300, rdata=ans)
            r.ancount = 1
        add(t + lat, Ether() / IP(src=server, dst=C) / UDP(sport=53, dport=sport) / r)


dns(0.00, "example.com", "A", "93.184.216.34", lat=0.025)
dns(0.40, "www.google.com", "A", "142.250.80.4", lat=0.012)
dns(0.80, "www.google.com", "AAAA", "2607:f8b0:4004:c07::68", lat=0.015)
dns(1.20, "does-not-exist.example", "A", None, rcode=3, lat=0.030)
dns(1.60, "timeout.example", "A", lat=None)
dns(2.00, "slow.example.org", "A", "198.51.100.7", lat=0.250)
dns(2.40, "example.com", "A", "93.184.216.34", lat=0.018)
dns(2.80, "lost-again.example", "A", lat=None)


# ---------------------------------------------------------------- HTTP (plain text over TCP 80)
def http_flow(t0, server, cport, requests, rtt=0.03):
    cs, ss = 5000, 9000
    add(t0, Ether() / IP(src=C, dst=server) / TCP(sport=cport, dport=80, flags="S", seq=cs))
    add(t0 + rtt, Ether() / IP(src=server, dst=C) / TCP(sport=80, dport=cport, flags="SA", seq=ss, ack=cs + 1))
    add(t0 + rtt + 0.0002, Ether() / IP(src=C, dst=server) / TCP(sport=cport, dport=80, flags="A", seq=cs + 1, ack=ss + 1))
    cs, ss, t = cs + 1, ss + 1, t0 + rtt + 0.01
    for method, uri, code, phrase, ctype, body, think in requests:
        req = f"{method} {uri} HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: demo-agent/1.0\r\n\r\n".encode()
        add(t, Ether() / IP(src=C, dst=server) / TCP(sport=cport, dport=80, flags="PA", seq=cs, ack=ss) / Raw(req))
        cs += len(req)
        add(t + rtt * 0.5, Ether() / IP(src=server, dst=C) / TCP(sport=80, dport=cport, flags="A", seq=ss, ack=cs))
        resp = (f"HTTP/1.1 {code} {phrase}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\nServer: nginx\r\n\r\n").encode() + body
        add(t + think, Ether() / IP(src=server, dst=C) / TCP(sport=80, dport=cport, flags="PA", seq=ss, ack=cs) / Raw(resp))
        ss += len(resp)
        add(t + think + rtt * 0.5, Ether() / IP(src=C, dst=server) / TCP(sport=cport, dport=80, flags="A", seq=cs, ack=ss))
        t += think + 0.1
    add(t, Ether() / IP(src=C, dst=server) / TCP(sport=cport, dport=80, flags="FA", seq=cs, ack=ss))
    add(t + rtt, Ether() / IP(src=server, dst=C) / TCP(sport=80, dport=cport, flags="FA", seq=ss, ack=cs + 1))
    add(t + rtt + 0.0002, Ether() / IP(src=C, dst=server) / TCP(sport=cport, dport=80, flags="A", seq=cs + 1, ack=ss + 1))


http_flow(0.20, "203.0.113.20", 51001, [
    ("GET", "/index.html", 200, "OK", "text/html", b"<html>" + b"a" * 480 + b"</html>", 0.08),
    ("GET", "/static/app.js", 200, "OK", "application/javascript", b"x" * 900, 0.05),
    ("GET", "/missing.png", 404, "Not Found", "text/html", b"<h1>404</h1>", 0.04),
    ("POST", "/api/order", 500, "Internal Server Error", "application/json", b'{"error":"boom"}', 0.35),
])
http_flow(1.50, "203.0.113.21", 51002, [("GET", "/health", 200, "OK", "text/plain", b"ok", 0.02)])


# ---------------------------------------------------------------- TLS (hand-built records)
def u16(n): return struct.pack(">H", n)
def u24(n): return struct.pack(">I", n)[1:]


def client_hello(sni, ech=False):
    name = sni.encode()
    ext_sni = u16(0) + u16(len(name) + 5) + u16(len(name) + 3) + b"\x00" + u16(len(name)) + name
    ext_ver = u16(0x2B) + u16(3) + b"\x02\x03\x04"
    alpn_list = b"\x02h2" + b"\x08http/1.1"
    ext_alpn = u16(0x10) + u16(len(alpn_list) + 2) + u16(len(alpn_list)) + alpn_list
    ext_ech = (u16(0xFE0D) + u16(12) + os.urandom(12)) if ech else b""
    exts = ext_sni + ext_ver + ext_alpn + ext_ech
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + u16(6) + u16(0x1301) + u16(0xC02F) + u16(0xC030) + b"\x01\x00" + u16(len(exts)) + exts
    hs = b"\x01" + u24(len(body)) + body
    return b"\x16\x03\x01" + u16(len(hs)) + hs


def server_hello(cipher, tls13):
    alpn = b"\x02h2"
    exts = ((u16(0x2B) + u16(2) + u16(0x0304)) if tls13 else b"") + u16(0x10) + u16(len(alpn) + 2) + u16(len(alpn)) + alpn
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + u16(cipher) + b"\x00" + u16(len(exts)) + exts
    hs = b"\x02" + u24(len(body)) + body
    return b"\x16\x03\x03" + u16(len(hs)) + hs


import base64
CERT_DER = base64.b64decode("MIIBkzCCATigAwIBAgIUObI83SvwI2QgH6BIoJCa/YyMb/owCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPbWFpbC5nb29nbGUuY29tMB4XDTI2MTEwNDE0MDQ0N1oXDTI3MTEwNDE0MDQ0N1owGjEYMBYGA1UEAwwPbWFpbC5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEePGFTNKyPLzT0+S2ffRxv0rC9GnUX6NLW7COL/GJqQurOJrmm5NkfsVdKEdvJtNcxobr+uBAM/jHRbhGuWpsoqNcMFowHQYDVR0OBBYEFGs2BZTj2DQj36izeNpPMLZO/b9vMA8GA1UdEwEB/wQFMAMBAf8wKAYDVR0RBCEwH4IPbWFpbC5nb29nbGUuY29tggwqLmdvb2dsZS5jb20wCgYIKoZIzj0EAwIDSQAwRgIhANjN7fgwnqB5XLOkNAJA5PU5g763Z6XZC0FevppDeVppAiEAvv1Vq/2fxhYFKbf7ix6YrYHEh+fShL+hFUzCgOvjSuQ=")


def certificate_record():
    cert = u24(len(CERT_DER)) + CERT_DER
    body = u24(len(cert)) + cert
    hs = b"\x0b" + u24(len(body)) + body
    return b"\x16\x03\x03" + u16(len(hs)) + hs


def appdata(n): return b"\x17\x03\x03" + u16(n) + os.urandom(n)


def tls_flow(t0, server, cport, sni, cipher, tls13, rtt=0.04, alert=False, nrec=6, ech=False):
    cs, ss = 7000, 3000
    add(t0, Ether() / IP(src=C, dst=server) / TCP(sport=cport, dport=443, flags="S", seq=cs))
    add(t0 + rtt, Ether() / IP(src=server, dst=C) / TCP(sport=443, dport=cport, flags="SA", seq=ss, ack=cs + 1))
    add(t0 + rtt + 0.0002, Ether() / IP(src=C, dst=server) / TCP(sport=cport, dport=443, flags="A", seq=cs + 1, ack=ss + 1))
    cs, ss, t = cs + 1, ss + 1, t0 + rtt + 0.005
    ch = client_hello(sni, ech)
    add(t, Ether() / IP(src=C, dst=server) / TCP(sport=cport, dport=443, flags="PA", seq=cs, ack=ss) / Raw(ch)); cs += len(ch)
    if alert:
        al = b"\x15\x03\x03\x00\x02\x02\x28"
        add(t + rtt, Ether() / IP(src=server, dst=C) / TCP(sport=443, dport=cport, flags="PA", seq=ss, ack=cs) / Raw(al)); ss += len(al)
        add(t + rtt + 0.001, Ether() / IP(src=server, dst=C) / TCP(sport=443, dport=cport, flags="FA", seq=ss, ack=cs))
        return
    sh = server_hello(cipher, tls13) + (b"" if tls13 else certificate_record())     # TLS 1.2: certificate is sent in the clear
    add(t + rtt + 0.004, Ether() / IP(src=server, dst=C) / TCP(sport=443, dport=cport, flags="PA", seq=ss, ack=cs) / Raw(sh)); ss += len(sh)
    t += rtt + 0.02
    for i in range(nrec):
        d = appdata(random.randint(200, 1200))
        src, dst, sp, dp = (C, server, cport, 443) if i % 2 == 0 else (server, C, 443, cport)
        sq, ak = (cs, ss) if i % 2 == 0 else (ss, cs)
        add(t + i * 0.01, Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags="PA", seq=sq, ack=ak) / Raw(d))
        if i % 2 == 0: cs += len(d)
        else: ss += len(d)


tls_flow(0.50, "151.101.65.69", 52001, "www.wikipedia.org", 0x1301, True)
tls_flow(0.90, "172.217.5.110", 52002, "mail.google.com", 0xC02F, False, rtt=0.06)
tls_flow(1.30, "104.16.1.1", 52003, "legacy.example.net", 0, False, alert=True)
tls_flow(1.70, "151.101.65.69", 52004, "www.wikipedia.org", 0x1301, True, rtt=0.035)
tls_flow(1.95, "104.16.9.9", 52005, "public-name.example", 0x1301, True, rtt=0.03, ech=True)


# ---------------------------------------------------------------- ICMP / ICMPv6
for i in range(6):
    add(0.3 + i * 0.5, Ether() / IP(src=C, dst="1.1.1.1") / ICMP(type=8, id=77, seq=i) / Raw(b"p" * 32))
    if i != 3:   # echo #3 unanswered
        add(0.3 + i * 0.5 + 0.018 + 0.002 * i, Ether() / IP(src="1.1.1.1", dst=C) / ICMP(type=0, id=77, seq=i) / Raw(b"p" * 32))
add(3.4, Ether() / IP(src="10.255.0.1", dst=C) / ICMP(type=3, code=3) / IPerror(src=C, dst="10.0.0.77", proto=17) / UDPerror(sport=40000, dport=9999))
add(3.5, Ether() / IP(src="10.255.0.2", dst=C) / ICMP(type=11, code=0) / IPerror(src=C, dst="8.8.4.4", proto=17) / UDPerror(sport=40001, dport=33434))
add(3.6, Ether() / IP(src="10.255.0.1", dst=C) / ICMP(type=3, code=1) / IPerror(src=C, dst="10.0.0.78", proto=6) / UDPerror(sport=40002, dport=80))
for i in range(3):
    add(0.7 + i * 0.4, Ether() / IPv6(src="2001:db8::10", dst="2001:db8::1") / ICMPv6EchoRequest(id=5, seq=i))
    if i != 2:
        add(0.7 + i * 0.4 + 0.004, Ether() / IPv6(src="2001:db8::1", dst="2001:db8::10") / ICMPv6EchoReply(id=5, seq=i))


# ---------------------------------------------------------------- DHCP
def dora(t, mac, xid, ip, host, complete=True, nak=False):
    m = bytes.fromhex(mac.replace(":", ""))
    b = lambda **k: BOOTP(chaddr=m + b"\x00" * 10, xid=xid, **k)
    add(t, Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / b() /
        DHCP(options=[("message-type", "discover"), ("hostname", host), "end"]))
    if not complete:
        return
    add(t + 0.01, Ether() / IP(src="192.168.1.1", dst="255.255.255.255") / UDP(sport=67, dport=68) / b(op=2, yiaddr=ip) /
        DHCP(options=[("message-type", "offer"), ("server_id", "192.168.1.1"), ("lease_time", 3600), "end"]))
    add(t + 0.02, Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / b() /
        DHCP(options=[("message-type", "request"), ("requested_addr", ip), ("server_id", "192.168.1.1"), ("hostname", host), "end"]))
    add(t + 0.03, Ether() / IP(src="192.168.1.1", dst="255.255.255.255") / UDP(sport=67, dport=68) / b(op=2, yiaddr=ip) /
        DHCP(options=[("message-type", "nak" if nak else "ack"), ("server_id", "192.168.1.1"), ("lease_time", 3600), "end"]))


dora(0.05, "aa:bb:cc:00:00:01", 0x1111, "192.168.1.101", "laptop-ankit")
dora(0.25, "aa:bb:cc:00:00:02", 0x2222, "192.168.1.102", "phone")
dora(0.60, "aa:bb:cc:00:00:03", 0x3333, "192.168.1.103", "printer", nak=True)
dora(1.00, "aa:bb:cc:00:00:04", 0x4444, "192.168.1.104", "ghost", complete=False)


# ---------------------------------------------------------------- RTP (bare UDP, needs heuristic detection) + other UDP + NTP + ARP
seq, ts = 1000, 160000
for i in range(100):
    if i == 40:
        seq += 1                      # one lost RTP packet
    add(0.10 + i * 0.020 + random.uniform(-0.003, 0.003), Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / UDP(sport=16384, dport=16386) /
        RTP(version=2, payload_type=0, sequence=seq, timestamp=ts, sourcesync=0xABCDEF01) / Raw(b"\x7f" * 160))
    seq += 1
    ts += 160
add(0.5, Ether() / IP(src=C, dst="129.6.15.28") / UDP(sport=50123, dport=123) / NTP(version=4, mode=3))
add(0.52, Ether() / IP(src="129.6.15.28", dst=C) / UDP(sport=123, dport=50123) / NTP(version=4, mode=4, stratum=1))
add(0.01, Ether(src=CM, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=CM, psrc=C, pdst="192.168.1.1"))
add(0.011, Ether(src="aa:bb:cc:00:00:01", dst=CM) / ARP(op=2, hwsrc="aa:bb:cc:00:00:01", psrc="192.168.1.1", hwdst=CM, pdst=C))

pk.sort(key=lambda p: float(p.time))
wrpcap(os.path.join(HERE, "protocols_mix.pcap"), pk)
print("wrote protocols_mix.pcap", len(pk), "packets")
