"""Generate samples/tcp_features.pcap: TCP options (MSS, window scale, SACK, timestamps), window scaling, zero window + probe + window update,
SACK blocks, a retransmission, ECN (negotiation + CE marks + ECE echo), a mid-stream flow (no handshake) and a plain flow. Needs scapy."""
import os

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

HERE = os.path.dirname(os.path.abspath(__file__))
pk = []
C, S = "10.1.1.1", "10.1.1.2"


def add(t, src, dst, sp, dp, flags, seq, ack, win, n=0, opts=None, tos=0):
    p = Ether() / IP(src=src, dst=dst, tos=tos, id=len(pk) + 1) / TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack, window=win, options=opts or []) / Raw(b"x" * n)
    p.time = 1700000000.0 + t
    pk.append(p)


def ts(t, base):
    return base + int(t * 1000)


# ------------------------------------------------------------------------------------ flow A: options + window + loss + ECN
cp, sp = 40001, 8443
def c(t, flags, seq, ack, win, n=0, tsecr=0, extra=None, tos=0):
    add(t, C, S, cp, sp, flags, seq, ack, win, n, [("NOP", None), ("NOP", None), ("Timestamp", (ts(t, 1000), tsecr))] + (extra or []), tos)
def s(t, flags, seq, ack, win, n=0, tsecr=0, tos=0):
    add(t, S, C, sp, cp, flags, seq, ack, win, n, [("NOP", None), ("NOP", None), ("Timestamp", (ts(t, 5000), tsecr))], tos)

add(0.000, C, S, cp, sp, "SEC", 100, 0, 8192, 0, [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1000, 0)), ("NOP", None), ("WScale", 7)])
add(0.030, S, C, sp, cp, "SAE", 9000, 101, 65535, 0, [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (5030, 1000)), ("NOP", None), ("WScale", 8)])
c(0.0302, "A", 101, 9001, 500, tsecr=5030)
c(0.040, "PA", 101, 9001, 500, n=100, tsecr=5030)
s(0.070, "A", 9001, 201, 256, tsecr=ts(0.040, 1000))
last_srv = 5030
seg_t = {i: 0.080 + 0.005 * (i - 1) for i in range(1, 13)}
SEQ = lambda i: 9001 + 1000 * (i - 1)
for i in (1, 2, 3):
    s(seg_t[i], "PA", SEQ(i), 201, 256, n=1000, tsecr=ts(0.040, 1000))
    c(seg_t[i] + 0.0002, "A", 201, SEQ(i) + 1000, 480 - 10 * i, tsecr=ts(seg_t[i], 5000))
# segment 4 is lost before the capture point; 5..8 arrive -> duplicate ACKs with SACK blocks
for k, i in enumerate((5, 6, 7, 8)):
    s(seg_t[i], "PA", SEQ(i), 201, 256, n=1000, tsecr=ts(0.040, 1000))
    c(seg_t[i] + 0.0002, "A", 201, SEQ(4), 440, tsecr=ts(seg_t[3], 5000), extra=[("SAck", (SEQ(5), SEQ(i) + 1000))])
s(0.250, "PA", SEQ(4), 201, 256, n=1000, tsecr=ts(0.040, 1000))                       # retransmission of segment 4 (200 ms late)
c(0.2502, "A", 201, SEQ(8) + 1000, 0, tsecr=ts(0.250, 5000))                          # cumulative ACK, window = 0  -> zero window
s(0.450, "A", SEQ(9) - 1, 201, 256, n=1, tsecr=ts(0.040, 1000))                       # zero-window probe (1 byte)
c(0.4502, "A", 201, SEQ(9), 0, tsecr=ts(0.450, 5000))                                  # probe ACK, still zero
c(0.600, "A", 201, SEQ(9), 500, tsecr=ts(0.450, 5000))                                 # window update
for k, i in enumerate((9, 10, 11, 12)):
    t = 0.610 + 0.005 * k
    s(t, "PA", SEQ(i), 201, 256, n=1000, tsecr=ts(0.040, 1000), tos=3 if i in (10, 11) else 0)    # CE-marked segments
    c(t + 0.0002, "AE" if i in (10, 11) else "A", 201, SEQ(i) + 1000, 480, tsecr=ts(t, 5000))
    if i == 12:
        c(t + 0.0302, "AC", 201, SEQ(i) + 1000, 480, tsecr=ts(t, 5000))              # CWR from the sender side is shown on the client packet
c(0.700, "FA", 201, SEQ(13), 480, tsecr=ts(0.640, 5000))
s(0.730, "FA", SEQ(13), 202, 256, tsecr=ts(0.700, 1000))
c(0.7302, "A", 202, SEQ(13) + 1, 480, tsecr=ts(0.730, 5000))

# ------------------------------------------------------------------------------------ flow B: mid-stream (handshake not captured)
cp2, sp2 = 40002, 8080
for i in range(12):
    t = 1.0 + i * 0.01
    add(t, S, C, sp2, cp2, "PA", 70000 + i * 1000, 500, 1000, 1000)
    add(t + 0.0003, C, S, cp2, sp2, "A", 500, 70000 + (i + 1) * 1000, 1000)

# ------------------------------------------------------------------------------------ flow C: plain flow, no options
cp3, sp3 = 40003, 80
add(1.5, C, S, cp3, sp3, "S", 300, 0, 65535)
add(1.53, S, C, sp3, cp3, "SA", 800, 301, 65535)
add(1.5302, C, S, cp3, sp3, "A", 301, 801, 65535)
for i in range(20):
    t = 1.54 + i * 0.004
    add(t, S, C, sp3, cp3, "PA", 801 + i * 1000, 301, 65535, 1000)
    add(t + 0.0002, C, S, cp3, sp3, "A", 301, 801 + (i + 1) * 1000, 65535)

pk.sort(key=lambda p: float(p.time))
wrpcap(os.path.join(HERE, "tcp_features.pcap"), pk)
print("wrote tcp_features.pcap", len(pk), "packets")
