import datetime


# This file contains parameters that can be used to modify noise/story


from dataclasses import dataclass, field
from datetime import datetime, timedelta
import time as time_lib

@dataclass
class ip:
    # Core systems
    victim_ip: str = "10.0.0.25"
    mail_server_ip: str = "10.0.0.5"
    web_server_ip: str = "203.0.113.50"
    c2_ip: str = "198.51.100.77"

    # MAC addresses
    victim_mac: str = "00:11:22:33:44:55"
    server_mac: str = "66:77:88:99:aa:bb"

    # Noise / benign traffic
    google: str = "142.250.72.206"
    outlook: str = "52.109.76.25"
    office_cdn: str = "13.107.6.152"
    microsoft: str = "20.190.160.132"


@dataclass
class time:
    # These are set automatically after initialization
    start_attack: datetime = time_lib.mktime(time_lib.strptime("2022-09-15 15:00:42", "%Y-%m-%d %H:%M:%S"))
    exfiltrate: datetime = time_lib.mktime(time_lib.strptime("2022-09-15 15:09:57", "%Y-%m-%d %H:%M:%S"))
    noise_start: datetime = time_lib.mktime(time_lib.strptime("2022-09-15 15:00:25", "%Y-%m-%d %H:%M:%S"))
    #noise_end: datetime = time_lib.mktime(time_lib.strptime("2026-02-12 16:45:00", "%Y-%m-%d %H:%M:%S"))

noise_ip = [
    ("142.250.72.206", "google", "77:88:99:aa:bb:cc"),
    ("52.109.76.25",   "outlook", "88:99:aa:bb:cc:dd"),
    ("13.107.6.152",   "amazon", "44:55:66:77:88:99"),
    ("20.190.160.132", "microsoft", "55:66:77:88:99:aa")
]

domains = [
    "www.google.com",
    "powerpoint tips",
    "how to use powerpoint",
    "docs.google.com",
    "www.microsoft.com",
    "login.microsoftonline.com",
    "outlook.office365.com",
    "graph.microsoft.com",
    "cdn.office.net"
]

