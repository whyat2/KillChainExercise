from tcpStuff import tcp_ack, tcp_handshake, tcp_send
import random
from pcapDetails import noise_ip, ip, time
from datetime import timedelta

src_mac = ip.victim_mac
src_ip = ip.victim_ip


def noiseAddition(pkts):
    x = time.noise_start
    for dst_ip, label, dst_mac in noise_ip:
        def ts(offset):
            return x + offset
        i = 0
        sport = random.randint(40000, 60000)
        c_seq, s_seq = tcp_handshake(
            pkts, ts, i,
            src_mac, dst_mac,
            src_ip, dst_ip,
            sport, 25
        )
        i = 3

        victim_name = "John Bob"
        victim_email = "John.Bob@victim.local"

        smtp_payloads = [
            f"EHLO support.{label}.com\r\n",
            f"MAIL FROM:<newsletter@{label}.com>\r\n",
            f"RCPT TO:<{victim_email}>\r\n",
            b"DATA\r\n",
            f"""From: News Department <newsletter@{label}>
                To: {victim_name} <{victim_email}>
                Subject: Invoice Reminder - Action Required
                MIME-Version: 1.0
                Content-Type: text/plain; charset="UTF-8"
                Hello John Bob,

                [unsuspicious message here]
                .\r\n""".encode(),

            b"QUIT\r\n"
        ]
        
        for cmd in smtp_payloads:
            c_seq = tcp_send(
                pkts, ts, i,
                ip.victim_mac, ip.server_mac,
                ip.victim_ip, ip.mail_server_ip,
                sport, 25,
                c_seq, s_seq,
                cmd
            )
            i += 1

            tcp_ack(
                pkts, ts, i,
                ip.server_mac, ip.victim_mac,
                ip.mail_server_ip, ip.victim_ip,
                sport, 1025,
                s_seq, c_seq
            )
            i += 1
        x = x + 10