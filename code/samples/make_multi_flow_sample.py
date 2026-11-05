"""Generate samples/multi_flow.pcap - several TCP flows with known behaviour (needs: pip install scapy).
 flow A: clean bulk download           flow B: loss before capture point + retransmission + dup-ACKs
 flow C: reordering                    flow D: short request/response (slow RTT)   + DNS and UDP noise"""
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

pk, ipid = [], [1000]
MSS = 1000
CLIENT = "192.168.1.10"


def add(t, p):
    p.time = 1700000000.0 + t
    pk.append(p)


def seg(src, dst, sp, dp, flags, seq, ack, n=0, dup_id=None):
    ipid[0] += 1
    return Ether() / IP(src=src, dst=dst, id=dup_id or ipid[0]) / TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack, window=64000) / Raw(b"x" * n)


def flow(server, cport, sport, t0, rtt, nseg, loss=(), swap=(), retx_delay=0.25, gap_before_first=0.0):
    """Client downloads from server. `loss` = segment numbers lost before the capture point (retransmitted later).
    `swap` = (i, i+1) segment pairs delivered in swapped order."""
    cs, ss = 100, 9000
    add(t0, seg(CLIENT, server, cport, sport, "S", cs, 0))
    add(t0 + rtt, seg(server, CLIENT, sport, cport, "SA", ss, cs + 1))
    add(t0 + rtt + 0.0002, seg(CLIENT, server, cport, sport, "A", cs + 1, ss + 1))
    add(t0 + rtt + 0.001, seg(CLIENT, server, cport, sport, "PA", cs + 1, ss + 1, 200))          # request
    t = t0 + 2 * rtt + 0.002
    order = list(range(1, nseg + 1))
    for a, b in swap:
        order[a - 1], order[b - 1] = order[b - 1], order[a - 1]
    acked, pending_lost = 0, []
    for k, i in enumerate(order):
        tt = t + k * 0.004
        s = ss + 1 + (i - 1) * MSS
        if i in loss:
            pending_lost.append(i)
            continue
        add(tt, seg(server, CLIENT, sport, cport, "A", s, cs + 201, MSS))
        if pending_lost:                                           # receiver is missing a segment -> duplicate ACKs
            need = ss + 1 + (pending_lost[0] - 1) * MSS
            add(tt + rtt * 0.5, seg(CLIENT, server, cport, sport, "A", cs + 201, need))
        elif k % 2 == 1:
            add(tt + rtt * 0.5, seg(CLIENT, server, cport, sport, "A", cs + 201, s + MSS))
    tend = t + len(order) * 0.004
    for i in pending_lost:
        s = ss + 1 + (i - 1) * MSS
        add(tend + retx_delay, seg(server, CLIENT, sport, cport, "A", s, cs + 201, MSS))
        add(tend + retx_delay + rtt * 0.5, seg(CLIENT, server, cport, sport, "A", cs + 201, ss + 1 + nseg * MSS))
    last = tend + (retx_delay + rtt if pending_lost else rtt)
    add(last, seg(CLIENT, server, cport, sport, "FA", cs + 201, ss + 1 + nseg * MSS))
    add(last + rtt, seg(server, CLIENT, sport, cport, "FA", ss + 1 + nseg * MSS, cs + 202))
    add(last + rtt + 0.0002, seg(CLIENT, server, cport, sport, "A", cs + 202, ss + 2 + nseg * MSS))


add(0.00, Ether() / IP(src=CLIENT, dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(id=1, rd=1, qd=DNSQR(qname="example.com")))
add(0.02, Ether() / IP(src="8.8.8.8", dst=CLIENT) / UDP(sport=53, dport=5353) / DNS(id=1, qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="93.184.216.34")))
flow("93.184.216.34", 50001, 443, 0.05, 0.030, 60)                                  # A clean
flow("151.101.1.69", 50002, 80, 0.30, 0.045, 50, loss=(12, 13, 30), retx_delay=0.30)  # B loss + retransmissions
flow("104.18.2.10", 50003, 443, 0.60, 0.020, 40, swap=((10, 11), (25, 26)))        # C reordering
flow("172.217.5.110", 50004, 8080, 1.10, 0.120, 6)                                  # D slow RTT
for i in range(30):
    add(0.2 + i * 0.05, Ether() / IP(src=CLIENT, dst="10.0.0.99") / UDP(sport=40000, dport=5004) / Raw(b"r" * 160))
pk.sort(key=lambda p: p.time)
wrpcap("multi_flow.pcap", pk)
print("wrote multi_flow.pcap", len(pk), "packets")
