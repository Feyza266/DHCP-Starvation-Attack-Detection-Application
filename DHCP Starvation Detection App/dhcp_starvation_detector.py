import time
import json
from datetime import datetime
from collections import deque
from scapy.all import sniff, BOOTP, DHCP


WINDOW_SECONDS = 5
DISCOVER_THRESHOLD = 5
UNIQUE_MAC_THRESHOLD = 1
LOG_FILE = "dhcp_starvation_alerts.jsonl"
INTERFACE = "enp0s8"


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_msg_type(pkt):
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            return opt[1]
    return None

def mac_from_bootp(pkt):
    return ":".join(f"{b:02x}" for b in pkt[BOOTP].chaddr[:6])

events = deque()

def handle_packet(pkt):
    print("[DEBUG] packet received")

    if BOOTP not in pkt or DHCP not in pkt:
        return

    msg_type = get_msg_type(pkt)
    print(f"[DEBUG] DHCP msg_type = {msg_type}")

    if msg_type != 1:
        return

    ts = time.time()
    mac = mac_from_bootp(pkt)
    events.append((ts, mac))

    
    while events and events[0][0] < ts - WINDOW_SECONDS:
        events.popleft()

    discover_count = len(events)
    unique_macs = len(set(m for _, m in events))

    print(f"[+] DISCOVER seen | total={discover_count} | unique_mac={unique_macs}")

    if discover_count >= DISCOVER_THRESHOLD and unique_macs >= UNIQUE_MAC_THRESHOLD:
        print("\n[!!!] DHCP STARVATION ATTACK DETECTED !!!\n")

        alert = {
            "timestamp": now(),
            "alert": "DHCP_STARVATION_POSSIBLE",
            "discover_count": discover_count,
            "unique_macs": unique_macs
        }

        print(json.dumps(alert, indent=2))

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(alert) + "\n")

print("[*] DHCP Starvation Detector started")
print(f"[*] Window={WINDOW_SECONDS}s | Discover>={DISCOVER_THRESHOLD} | UniqueMAC>={UNIQUE_MAC_THRESHOLD}")

sniff(
    iface=INTERFACE,
    prn=handle_packet,
    store=False
)
