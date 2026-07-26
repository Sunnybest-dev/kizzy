from database import init_db, insert_threat
from alert import send_alert
from datetime import datetime
import socket
import struct
import threading
import psutil
import time
import os

LOCAL_IP = socket.gethostbyname(socket.gethostname())
print(f"Local IP: {LOCAL_IP}")

init_db()

# ── CONFIG ─────────────────────────────────────────────────────────────────────
PORT_SCAN_THRESHOLD = 5
TIME_WINDOW = 10
ALERT_COOLDOWN = 30
RISKY_PORTS = [23, 445, 3389, 4444, 8080]

# ── TRACKERS ───────────────────────────────────────────────────────────────────
suspicious_ips = {}
last_alert_time = {}
blacklist = set()
login_attempts = {}
traffic_count = {}
connection_tracker = {}
packet_sizes = {}
seen_connections = set()

# ── HELPERS ────────────────────────────────────────────────────────────────────
def log_threat(threat_type, ip):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    insert_threat(threat_type, ip, timestamp)
    print(f"[LOGGED] {threat_type} from {ip}")
    send_alert(threat_type, ip)

def cooldown_ok(ip):
    now = datetime.now()
    if ip in last_alert_time:
        if (now - last_alert_time[ip]).seconds < ALERT_COOLDOWN:
            return False
    last_alert_time[ip] = now
    return True

# ── RAW SOCKET DETECTIONS ──────────────────────────────────────────────────────
def parse_packet(data):
    ip_header = data[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    protocol = iph[6]
    size = len(data)
    return src_ip, dst_ip, protocol, size

def parse_tcp(data):
    tcp_header = data[20:40]
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
    src_port = tcph[0]
    dst_port = tcph[1]
    return src_port, dst_port

def detect_port_scan(src_ip, dst_port):
    now = datetime.now()
    if src_ip not in suspicious_ips:
        suspicious_ips[src_ip] = []
    suspicious_ips[src_ip].append((dst_port, now))
    suspicious_ips[src_ip] = [p for p in suspicious_ips[src_ip] if (now - p[1]).seconds < TIME_WINDOW]
    ports = set(p[0] for p in suspicious_ips[src_ip])
    if len(ports) >= PORT_SCAN_THRESHOLD and cooldown_ok(src_ip):
        log_threat("Port Scan", src_ip)
        blacklist.add(src_ip)
        suspicious_ips[src_ip] = []

def detect_bruteforce(src_ip, dst_port):
    if dst_port in [22, 21, 80, 443, 3389]:
        now = datetime.now()
        if src_ip not in login_attempts:
            login_attempts[src_ip] = []
        login_attempts[src_ip].append(now)
        login_attempts[src_ip] = [t for t in login_attempts[src_ip] if (now - t).seconds < 60]
        if len(login_attempts[src_ip]) >= 5 and cooldown_ok(src_ip):
            log_threat("Brute Force", src_ip)
            login_attempts[src_ip] = []

def detect_flood(src_ip):
    now = datetime.now()
    if src_ip not in traffic_count:
        traffic_count[src_ip] = []
    traffic_count[src_ip].append(now)
    traffic_count[src_ip] = [t for t in traffic_count[src_ip] if (now - t).seconds < 5]
    if len(traffic_count[src_ip]) > 30 and cooldown_ok(src_ip):
        log_threat("DDoS", src_ip)
        traffic_count[src_ip] = []

def detect_suspicious_port(src_ip, dst_port):
    if dst_port in RISKY_PORTS and cooldown_ok(src_ip):
        log_threat("Suspicious Port", src_ip)

def detect_anomaly(src_ip, size):
    if src_ip not in packet_sizes:
        packet_sizes[src_ip] = []
    packet_sizes[src_ip].append(size)
    if len(packet_sizes[src_ip]) > 10:
        avg = sum(packet_sizes[src_ip]) / len(packet_sizes[src_ip])
        if size > avg * 3 and cooldown_ok(src_ip):
            log_threat("Anomaly", src_ip)
        packet_sizes[src_ip] = []

# ── RAW SOCKET SNIFFER ─────────────────────────────────────────────────────────
def raw_socket_monitor():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.bind((LOCAL_IP, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        print("[RAW SOCKET] Monitoring started...")

        while True:
            data, addr = s.recvfrom(65535)
            try:
                src_ip, dst_ip, protocol, size = parse_packet(data)
                if dst_ip != LOCAL_IP:
                    continue
                if src_ip in blacklist:
                    print(f"[BLOCKED] {src_ip}")
                    continue
                src_port, dst_port = parse_tcp(data)
                detect_port_scan(src_ip, dst_port)
                detect_bruteforce(src_ip, dst_port)
                detect_flood(src_ip)
                detect_suspicious_port(src_ip, dst_port)
                detect_anomaly(src_ip, size)
            except:
                continue
    except PermissionError:
        print("[RAW SOCKET] No admin rights - switching to psutil monitor")
        psutil_monitor()
    except Exception as e:
        print(f"[RAW SOCKET ERROR] {e} - switching to psutil monitor")
        psutil_monitor()

# ── PSUTIL MONITOR (FALLBACK) ──────────────────────────────────────────────────
def psutil_monitor():
    print("[PSUTIL] Connection monitoring started...")
    while True:
        try:
            connections = psutil.net_connections(kind='inet')
            now = datetime.now()

            ip_ports = {}
            for conn in connections:
                if conn.raddr and conn.status == 'ESTABLISHED':
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    local_port = conn.laddr.port if conn.laddr else 0

                    if remote_ip not in ip_ports:
                        ip_ports[remote_ip] = set()
                    ip_ports[remote_ip].add(remote_port)

                    # Suspicious port
                    if remote_port in RISKY_PORTS and cooldown_ok(remote_ip):
                        log_threat("Suspicious Port", remote_ip)

                    # Brute force
                    if local_port in [22, 21, 80, 443, 3389]:
                        if remote_ip not in login_attempts:
                            login_attempts[remote_ip] = []
                        login_attempts[remote_ip].append(now)
                        login_attempts[remote_ip] = [t for t in login_attempts[remote_ip] if (now - t).seconds < 60]
                        if len(login_attempts[remote_ip]) >= 5 and cooldown_ok(remote_ip):
                            log_threat("Brute Force", remote_ip)
                            login_attempts[remote_ip] = []

            # Port scan detection
            for ip, ports in ip_ports.items():
                if len(ports) >= PORT_SCAN_THRESHOLD and cooldown_ok(ip):
                    log_threat("Port Scan", ip)

            # Rapid connections
            all_ips = [c.raddr.ip for c in connections if c.raddr]
            for ip in set(all_ips):
                count = all_ips.count(ip)
                if count > 10 and cooldown_ok(ip):
                    log_threat("Rapid Traffic", ip)

        except Exception as e:
            print(f"[PSUTIL ERROR] {e}")

        time.sleep(3)

# ── START ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Starting NetGuard Network Monitoring...")
    t = threading.Thread(target=raw_socket_monitor, daemon=True)
    t.start()
    t.join()
