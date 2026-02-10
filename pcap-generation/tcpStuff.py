from scapy.all import *
from datetime import datetime, timedelta
import random

def tcp_handshake(pkts, ts, i,
                  src_mac, dst_mac,
                  src_ip, dst_ip,
                  sport, dport,
                  c_seq=1000, s_seq=5000):

    # SYN
    syn = (
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=dport, flags="S", seq=c_seq)
    )
    syn.time = ts(i).timestamp()
    pkts.append(syn)

    # SYN-ACK
    synack = (
        Ether(src=dst_mac, dst=src_mac) /
        IP(src=dst_ip, dst=src_ip) /
        TCP(sport=dport, dport=sport,
            flags="SA",
            seq=s_seq,
            ack=c_seq + 1)
    )
    synack.time = ts(i+1).timestamp()
    pkts.append(synack)

    # ACK
    ack = (
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=dport,
            flags="A",
            seq=c_seq + 1,
            ack=s_seq + 1)
    )
    ack.time = ts(i+2).timestamp()
    pkts.append(ack)

    return c_seq + 1, s_seq + 1

def tcp_send(pkts, ts, i,
             src_mac, dst_mac,
             src_ip, dst_ip,
             sport, dport,
             seq, ack,
             payload):

    pkt = (
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=dport,
            flags="PA",
            seq=seq,
            ack=ack) /
        Raw(load=payload)
    )
    pkt.time = ts(i).timestamp()
    pkts.append(pkt)

    return seq + len(payload)

def tcp_ack(pkts, ts, i,
            src_mac, dst_mac,
            src_ip, dst_ip,
            sport, dport,
            seq, ack):

    pkt = (
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=dport,
            flags="A",
            seq=seq,
            ack=ack)
    )
    pkt.time = ts(i).timestamp()
    pkts.append(pkt)
