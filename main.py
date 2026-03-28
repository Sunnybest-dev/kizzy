from database import init_db, insert_threat
from scapy.all import *
from datetime import datetime
import socket
from alert import send_alert

# 🔧 SYSTEM SETUP
LOCAL_IP = socket.gethostbyname(socket.gethostname())
print(f"Local IP: {LOCAL_IP}")

init_db()

# 🔥 CONFIG
PORT_SCAN_THRESHOLD = 5
TIME_WINDOW = 10
ALERT_COOLDOWN = 30

# 🔥 GLOBAL TRACKERS
suspicious_ips = {}
last_alert_time = {}
blacklist = set()
login_attempts = {}
traffic_count = {}
connection_tracker = {}
packet_sizes = {}

# 🔧 LOG FUNCTION
def log_threat(threat_type, ip):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    insert_threat(threat_type, ip, timestamp)
    print(f"[LOGGED] {threat_type} from {ip}")

    send_alert(threat_type, ip)  # 👈 move it here

# 🚨 PORT SCAN DETECTION
def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = datetime.now()

        if src_ip not in suspicious_ips:
            suspicious_ips[src_ip] = []

        suspicious_ips[src_ip].append((dst_port, current_time))

        suspicious_ips[src_ip] = [
            p for p in suspicious_ips[src_ip]
            if (current_time - p[1]).seconds < TIME_WINDOW
        ]

        ports_accessed = set(p[0] for p in suspicious_ips[src_ip])

        if len(ports_accessed) >= PORT_SCAN_THRESHOLD:

            # COOL DOWN
            if src_ip in last_alert_time:
                if (current_time - last_alert_time[src_ip]).seconds < ALERT_COOLDOWN:
                    return

            print(f"[ALERT] Port Scan from {src_ip}")
            log_threat("Port Scan", src_ip)

            blacklist.add(src_ip)
            print(f"[BLOCKED] {src_ip} added to blacklist")

            send_alert("Port Scan", src_ip)

            last_alert_time[src_ip] = current_time
            suspicious_ips[src_ip] = []

# 🔐 BRUTE FORCE DETECTION
def detect_bruteforce(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        dst_port = packet[TCP].dport

        if dst_port in [22, 21, 80, 443]:
            src_ip = packet[IP].src
            current_time = datetime.now()

            if src_ip not in login_attempts:
                login_attempts[src_ip] = []

            login_attempts[src_ip].append(current_time)

            login_attempts[src_ip] = [
                t for t in login_attempts[src_ip]
                if (current_time - t).seconds < 60
            ]

            if len(login_attempts[src_ip]) >= 5:
                print(f"[ALERT] Brute Force from {src_ip}")
                log_threat("Brute Force", src_ip)
                send_alert("Brute Force", src_ip)
                login_attempts[src_ip] = []

# 🌊 DDoS / FLOOD DETECTION
def detect_flood(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_time = datetime.now()

        if src_ip not in traffic_count:
            traffic_count[src_ip] = []

        traffic_count[src_ip].append(current_time)

        traffic_count[src_ip] = [
            t for t in traffic_count[src_ip]
            if (current_time - t).seconds < 5
        ]

        if len(traffic_count[src_ip]) > 30:
            print(f"[ALERT] DDoS Attack from {src_ip}")
            log_threat("DDoS", src_ip)
            send_alert("DDoS", src_ip)
            traffic_count[src_ip] = []

# ⚠️ SUSPICIOUS PORT DETECTION
def detect_suspicious_ports(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        port = packet[TCP].dport
        src_ip = packet[IP].src

        risky_ports = [23, 445, 3389]

        if port in risky_ports:
            print(f"[ALERT] Suspicious Port {port} from {src_ip}")
            log_threat("Suspicious Port", src_ip)
            send_alert("Suspicious Port", src_ip)

# ⚡ RAPID CONNECTION DETECTION
def detect_rapid_connections(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_time = datetime.now()

        if src_ip not in connection_tracker:
            connection_tracker[src_ip] = []

        connection_tracker[src_ip].append(current_time)

        connection_tracker[src_ip] = [
            t for t in connection_tracker[src_ip]
            if (current_time - t).seconds < 2
        ]

        if len(connection_tracker[src_ip]) > 15:
            print(f"[ALERT] Rapid Connections from {src_ip}")
            log_threat("Rapid Traffic", src_ip)
            send_alert("Rapid Traffic", src_ip)
            connection_tracker[src_ip] = []

# 🤖 ANOMALY DETECTION
def detect_anomaly(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        size = len(packet)

        if src_ip not in packet_sizes:
            packet_sizes[src_ip] = []

        packet_sizes[src_ip].append(size)

        if len(packet_sizes[src_ip]) > 10:
            avg = sum(packet_sizes[src_ip]) / len(packet_sizes[src_ip])

            if size > avg * 3:
                print(f"[ALERT] Anomaly from {src_ip}")
                log_threat("Anomaly", src_ip)
                send_alert("Anomaly", src_ip)

            packet_sizes[src_ip] = []

# 🎯 MAIN PACKET HANDLER
def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Only process incoming traffic
        if dst_ip != LOCAL_IP:
            return

        if src_ip in blacklist:
            print(f"[BLOCKED TRAFFIC] from {src_ip}")
            return

    detect_port_scan(packet)
    detect_bruteforce(packet)
    detect_flood(packet)
    detect_suspicious_ports(packet)
    detect_rapid_connections(packet)
    detect_anomaly(packet)

# 🚀 START SYSTEM
if __name__ == "__main__":
    print("Starting Network Monitoring...")
    sniff(prn=packet_callback, store=0, filter="tcp")