# from scapy.all import IP, TCP, send
# import random
# import time

# def simulate_port_scan(target_ip="127.0.0.1"):
#     print("Starting simulated port scan...")

#     for port in range(1, 50):  # simulate scanning ports 1–50
#         packet = IP(dst=target_ip)/TCP(dport=port)
#         send(packet, verbose=0)
#         time.sleep(0.1)  # small delay

#     print("Simulation complete!")

# if __name__ == "__main__":
#     simulate_port_scan()