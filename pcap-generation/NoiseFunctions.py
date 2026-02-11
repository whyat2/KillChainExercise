from tcpStuff import tcp_ack, tcp_handshake, tcp_send
import random
from pcapDetails import noise_ip, ip, times
from datetime import timedelta

def ts(offset):
    return times.noise_start + timedelta(seconds=offset)

for dst_ip, label, dst_mac in noise_ip:
    sport = random.randint(40000, 60000)
    c_seq, s_seq = tcp_handshake(
        pkts, ts, i,
        src_mac, dst_mac,
        src_ip, dst_ip,
        sport, 443
    )
    i += 3

    payload = b"\x16\x03\x01" + bytes(random.randint(150, 300))
    c_seq = tcp_send(
        pkts, ts, i,
        src_mac, dst_mac,
        src_ip, dst_ip,
        sport, 443,
        c_seq, s_seq,
        payload
    )
    i += 1

    tcp_ack(
        pkts, ts, i,
        dst_mac, src_mac,
        dst_ip, src_ip,
        443, sport,
        s_seq, c_seq
    )
    i += 1