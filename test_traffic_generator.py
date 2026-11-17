"""Safe Local Traffic Generator for Authorized Lab Testing.

Simulates benign and malicious traffic safely against 127.0.0.1 loopback interface
or sends synthetic flows into the live SOC system without external network exposure.
"""

import time
import sys
import argparse
from scapy.all import IP, TCP, UDP, send, conf

# Restrict Scapy to loopback / local testing
conf.verb = 0


def generate_benign_traffic(count: int = 10, target_ip: str = "127.0.0.1"):
    """Simulate normal web browsing traffic (HTTP / HTTPS)."""
    print(f"[+] Generating {count} benign simulated packets to {target_ip}...")
    for i in range(count):
        port = 80 if i % 2 == 0 else 443
        p1 = IP(src="127.0.0.1", dst=target_ip) / TCP(sport=50000 + i, dport=port, flags="S", window=65535)
        p2 = IP(src=target_ip, dst="127.0.0.1") / TCP(sport=port, dport=50000 + i, flags="SA", window=28960)
        p3 = IP(src="127.0.0.1", dst=target_ip) / TCP(sport=50000 + i, dport=port, flags="PA") / b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        send([p1, p2, p3], verbose=False)
        time.sleep(0.05)
    print("✓ Benign traffic transmission complete.")


import socket

def generate_port_scan(target_ip: str = "127.0.0.1", ports_count: int = 25):
    """Simulate a fast SYN port scan across multiple destination ports."""
    print(f"[!] Simulating authorized SYN port scan on {target_ip} ({ports_count} ports)...")
    base_port = 20
    
    # 1. Dispatch Scapy SYN probes
    for i in range(ports_count):
        port = base_port + i
        try:
            pkt = IP(src=target_ip, dst=target_ip) / TCP(sport=44000 + i, dport=port, flags="S")
            send(pkt, verbose=False)
        except Exception:
            pass
        time.sleep(0.015)

    # 2. Dispatch non-blocking socket SYN attempts to guarantee Npcap capture on Windows
    for i in range(ports_count):
        port = base_port + i
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        try:
            s.connect((target_ip, port))
        except (BlockingIOError, ConnectionRefusedError, OSError):
            pass
        finally:
            s.close()
        time.sleep(0.015)

    print(f"✓ Port scan simulation complete ({ports_count} distinct ports targeted). Check SOC Threat Alerts dashboard.")


def generate_syn_flood(target_ip: str = "127.0.0.1", target_port: int = 80, count: int = 50):
    """Simulate a high-volume burst of SYN packets to test abnormal connection detection."""
    print(f"[!] Simulating authorized SYN burst on {target_ip}:{target_port} ({count} packets)...")
    for i in range(count):
        pkt = IP(src="127.0.0.1", dst=target_ip) / TCP(sport=30000 + (i % 500), dport=target_port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.005)
    print("✓ SYN burst simulation complete. Check SOC Threat Alerts dashboard.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberSOC IDS Local Test Traffic Generator")
    parser.add_argument("--mode", choices=["benign", "portscan", "synflood", "all"], default="all")
    parser.add_argument("--target", default="127.0.0.1", help="Target test IP (Defaults to 127.0.0.1 loopback)")

    args = parser.parse_args()

    print("=" * 60)
    print("  CYBERSOC IDS - SAFE LOCAL TRAFFIC GENERATOR")
    print("  Target:", args.target)
    print("=" * 60)

    if args.mode in ["benign", "all"]:
        generate_benign_traffic(15, args.target)
        time.sleep(1)

    if args.mode in ["portscan", "all"]:
        generate_port_scan(args.target, 20)
        time.sleep(1)

    if args.mode in ["synflood", "all"]:
        generate_syn_flood(args.target, 80, 50)

    print("\n[+] Done. Open the React SOC dashboard at http://127.0.0.1:8000 to view live telemetry.")
