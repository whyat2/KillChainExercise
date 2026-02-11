import datetime


# This file contains parameters that can be used to modify noise/story


ip = {
    "victim_ip": "10.0.0.25",
    "mail_server_ip": "10.0.0.5",
    "web_server_ip": "203.0.113.50",
    "c2_ip": "198.51.100.77",
    "victim_mac": "00:11:22:33:44:55",
    "server_mac": "66:77:88:99:aa:bb",

# For Noise
    "google": "142.250.72.206",
    "outlook": "52.109.76.25",
    "office_cdn": "13.107.6.152",
    "microsoft": "20.190.160.132"
}
noise_ip = [
    ("142.250.72.206", "google", "77:88:99:aa:bb:cc"),
    ("52.109.76.25",   "outlook", "88:99:aa:bb:cc:dd"),
    ("13.107.6.152",   "officecdn", "44:55:66:77:88:99"),
    ("20.190.160.132", "microsoft", "55:66:77:88:99:aa")
]
times = {
    "start_attack": datetime.now(),
    "exfiltrate": datetime.now() + 100,
    "noise_start": datetime.now() - 100,
    "noise_end": datetime.now() + 200,
} # fix with actual dates

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

