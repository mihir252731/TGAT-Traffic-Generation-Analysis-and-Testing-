
from scapy.all import IP, TCP, UDP, ICMP, send, get_if_list
import time

from datetime import datetime

def log_action(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("log.txt", "a") as f:
        f.write(f"[{timestamp}] {message}\n")


def get_default_iface():
    interfaces = get_if_list()
    return interfaces[0] if interfaces else "lo"

def generate_traffic(dst, protocol='TCP', packet_size=100, count=10, delay=0.1):
    data = "X" * packet_size
    iface = get_default_iface()
    for _ in range(count):
        if protocol.upper() == 'TCP':
            pkt = IP(dst=dst)/TCP(dport=80)/data
        elif protocol.upper() == 'UDP':
            pkt = IP(dst=dst)/UDP(dport=80)/data
        elif protocol.upper() == 'ICMP':
            pkt = IP(dst=dst)/ICMP()/data
        else:
            return
        send(pkt, iface=iface, verbose=False)
        time.sleep(delay)
    log_action(f"Sent {count} {protocol} packets to {dst} using interface {iface}")
