# from scapy.all import sniff, IP, TCP, UDP
# import json
# from datetime import datetime

# # Load rules
# with open("config.json", "r") as f:
#     rules = json.load(f)

# log_file = "logs/blocked_traffic.log"

# def log_block(packet, reason):
#     with open(log_file, "a") as log:
#         log.write(f"[{datetime.now()}] BLOCKED: {packet[IP].src} → {packet[IP].dst}, Reason: {reason}\n")

# def packet_filter(packet):
#     if IP in packet:
#         src_ip = packet[IP].src
#         dst_ip = packet[IP].dst

#         # Check IP block
#         if src_ip in rules["blocked_ips"]:
#             log_block(packet, f"Blocked IP {src_ip}")
#             return

#         # Check port block
#         if TCP in packet or UDP in packet:
#             sport = packet.sport
#             dport = packet.dport
#             if sport in rules["blocked_ports"] or dport in rules["blocked_ports"]:
#                 log_block(packet, f"Blocked Port {sport}->{dport}")
#                 return

#         # Check protocol
#         if packet.haslayer(TCP):
#             proto = "TCP"
#         elif packet.haslayer(UDP):
#             proto = "UDP"
#         else:
#             proto = "OTHER"
        
#         if proto not in rules["allowed_protocols"]:
#             log_block(packet, f"Protocol {proto} not allowed")

# # Start sniffing
# print("🔐 Personal Firewall is running...")
# sniff(prn=packet_filter, store=0)



from scapy.all import sniff, IP, TCP, UDP
import json
from datetime import datetime
import os

# Make sure the logs folder exists to avoid errors
os.makedirs("logs", exist_ok=True)

# Load rules from config.json
with open("config.json", "r") as f:
    rules = json.load(f)

log_file = "logs/blocked_traffic.log"

def log_block(packet, reason):
    """
    Logs blocked packets with timestamp, source, destination, and reason.
    """
    with open(log_file, "a") as log:
        log.write(f"[{datetime.now()}] BLOCKED: {packet[IP].src} → {packet[IP].dst}, Reason: {reason}\n")
    print(f"🚫 BLOCKED: {packet[IP].src} → {packet[IP].dst} | Reason: {reason}")

def packet_filter(packet):
    """
    Checks packets against firewall rules:
    - Blocked IPs
    - Blocked Ports
    - Allowed Protocols (TCP, UDP)
    Logs and drops blocked packets.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # 1) Check if source IP is blocked
        if src_ip in rules.get("blocked_ips", []):
            log_block(packet, f"Blocked IP {src_ip}")
            return  # Packet blocked, stop processing

        # 2) Check if source or destination port is blocked (only if TCP or UDP)
        if TCP in packet or UDP in packet:
            sport = packet.sport
            dport = packet.dport
            if sport in rules.get("blocked_ports", []) or dport in rules.get("blocked_ports", []):
                log_block(packet, f"Blocked Port {sport}->{dport}")
                return  # Packet blocked

        # 3) Check protocol allowed
        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        else:
            proto = "OTHER"

        if proto not in rules.get("allowed_protocols", []):
            log_block(packet, f"Protocol {proto} not allowed")
            return  # Packet blocked

# Start sniffing network packets
print("🔐 Personal Firewall is running...")
sniff(prn=packet_filter, store=0)
