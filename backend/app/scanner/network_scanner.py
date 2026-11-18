"""Authorized Network Inventory and Security Port Scanner Module.

Performs host discovery on authorized local subnets, TCP connect port scanning,
and service banner identification without spoofing or fabricating results.
"""

import socket
import subprocess
import threading
import time
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from datetime import datetime

from backend.app.database.connection import SessionLocal
from backend.app.database.models import ScanHistory, DiscoveredHost, SystemLog

# Standard high-value TCP ports to audit
COMMON_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443
]

PORT_SERVICE_MAP = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted Remote Shell)",
    25: "SMTP (Mail Transfer)",
    53: "DNS (Domain Name Service)",
    80: "HTTP (Web Server)",
    110: "POP3 (Post Office Protocol)",
    135: "Microsoft RPC Endpoint Mapper",
    139: "NetBIOS Session Service",
    143: "IMAP (Internet Message Access)",
    443: "HTTPS (Encrypted Web Server)",
    445: "SMB / Microsoft Directory Service",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database Listener",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop Protocol)",
    5432: "PostgreSQL Database",
    5900: "VNC (Remote Desktop)",
    8000: "CyberSOC / Python App Server",
    8080: "HTTP-Alt / Web Proxy",
    8443: "HTTPS-Alt / Management Console"
}


def is_target_authorized(target_ip_or_cidr: str, allow_override: bool = False) -> bool:
    """Verify target is strictly localhost, private LAN, or explicitly authorized."""
    if allow_override:
        return True
    try:
        # Check single IP
        ip = ipaddress.ip_address(target_ip_or_cidr.strip())
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass

    try:
        # Check network CIDR
        net = ipaddress.ip_network(target_ip_or_cidr.strip(), strict=False)
        return net.is_private or net.is_loopback
    except ValueError:
        pass

    # Hostname check
    if target_ip_or_cidr.lower() in ["localhost", "127.0.0.1", "::1"]:
        return True

    return False


def get_windows_arp_table() -> Dict[str, str]:
    """Extract genuine local IP to MAC address mappings from Windows ARP cache."""
    arp_map = {}
    try:
        res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    ip_match = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parts[0])
                    mac_match = re.match(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$", parts[1])
                    if ip_match and mac_match:
                        arp_map[parts[0]] = parts[1].replace("-", ":").upper()
    except Exception:
        pass
    return arp_map


def ping_host_socket(ip_str: str, timeout_sec: float = 0.4) -> Optional[Dict[str, Any]]:
    """Test if a host is active by checking standard ports (TCP ping)."""
    t0 = time.time()
    mac_map = get_windows_arp_table()

    # Fast probe on 80, 443, 135, 445, 22, 53
    test_ports = [80, 443, 135, 445, 22, 53, 8000]
    for port in test_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_sec)
        try:
            res = s.connect_ex((ip_str, port))
            if res == 0:
                s.close()
                latency = round((time.time() - t0) * 1000, 2)
                hostname = None
                try:
                    hostname = socket.gethostbyaddr(ip_str)[0]
                except Exception:
                    pass
                return {
                    "ip": ip_str,
                    "is_alive": True,
                    "latency_ms": latency,
                    "hostname": hostname,
                    "mac": mac_map.get(ip_str, "N/A"),
                    "confirmed_by": f"TCP Port {port} Open"
                }
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    # Fallback to ICMP ping via system ping
    try:
        cmd = ["ping", "-n", "1", "-w", "300", ip_str]
        ping_res = subprocess.run(cmd, capture_output=True, text=True, timeout=1.0)
        if ping_res.returncode == 0 and "TTL=" in ping_res.stdout.upper():
            latency = 1.0
            match = re.search(r"time[<=](\d+)ms", ping_res.stdout, re.IGNORECASE)
            if match:
                latency = float(match.group(1))
            hostname = None
            try:
                hostname = socket.gethostbyaddr(ip_str)[0]
            except Exception:
                pass
            return {
                "ip": ip_str,
                "is_alive": True,
                "latency_ms": latency,
                "hostname": hostname,
                "mac": mac_map.get(ip_str, "N/A"),
                "confirmed_by": "ICMP Echo Reply"
            }
    except Exception:
        pass

    return None


def grab_service_banner(ip_str: str, port: int, timeout_sec: float = 0.8) -> str:
    """Safely inspect server response banner."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_sec)
    try:
        s.connect((ip_str, port))
        if port in [80, 8080, 8000]:
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip_str.encode() + b"\r\n\r\n")
        elif port == 21:
            pass  # FTP sends banner on connect
        elif port == 22:
            pass  # SSH sends identification string on connect
        else:
            s.sendall(b"\r\n")
        
        banner = s.recv(256).decode(errors="ignore").strip()
        lines = banner.split("\n")
        return lines[0].strip() if lines else banner[:60]
    except Exception:
        return PORT_SERVICE_MAP.get(port, "Unknown Service")
    finally:
        s.close()


def scan_single_port(ip_str: str, port: int, timeout_sec: float = 0.5) -> Optional[Dict[str, Any]]:
    """Scan an individual TCP port on target host using TCP connect method."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_sec)
    t0 = time.time()
    try:
        code = s.connect_ex((ip_str, port))
        latency = round((time.time() - t0) * 1000, 2)
        if code == 0:
            s.close()
            banner = grab_service_banner(ip_str, port, timeout_sec=0.6)
            return {
                "port": port,
                "protocol": "TCP",
                "state": "OPEN",
                "service": PORT_SERVICE_MAP.get(port, f"TCP/{port}"),
                "banner": banner,
                "latency_ms": latency
            }
        elif code in [10061, 111]:  # WSAECONNREFUSED / Connection Refused
            s.close()
            return {
                "port": port,
                "protocol": "TCP",
                "state": "CLOSED",
                "service": PORT_SERVICE_MAP.get(port, f"TCP/{port}"),
                "banner": "None",
                "latency_ms": latency
            }
        else:
            s.close()
            return {
                "port": port,
                "protocol": "TCP",
                "state": "FILTERED",
                "service": PORT_SERVICE_MAP.get(port, f"TCP/{port}"),
                "banner": "Firewall Filtered",
                "latency_ms": latency
            }
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


class NetworkSecurityScanner:
    """Coordinates host discovery and TCP port scans against authorized targets."""

    def __init__(self):
        self.is_scanning = False
        self._lock = threading.Lock()

    def discover_subnet_hosts(self, target_subnet: str = "127.0.0.1/32", max_threads: int = 20) -> Dict[str, Any]:
        """Perform host discovery across an authorized subnet."""
        if not is_target_authorized(target_subnet):
            raise ValueError(f"Target '{target_subnet}' is outside authorized private/lab network boundaries.")

        start_time = datetime.utcnow()
        active_hosts = []

        try:
            net = ipaddress.ip_network(target_subnet, strict=False)
            hosts_to_test = [str(ip) for ip in net.hosts()]
            if not hosts_to_test and net.num_addresses == 1:
                hosts_to_test = [str(net.network_address)]
            # Limit scan range for performance safety (max 64 hosts in a single sweep)
            hosts_to_test = hosts_to_test[:64]
        except Exception as e:
            raise ValueError(f"Invalid subnet specification '{target_subnet}': {e}")

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_ip = {executor.submit(ping_host_socket, ip): ip for ip in hosts_to_test}
            for future in as_completed(future_to_ip):
                res = future.result()
                if res:
                    active_hosts.append(res)

        active_hosts.sort(key=lambda h: ipaddress.ip_address(h["ip"]))

        # Record scan in SQLite database
        db = SessionLocal()
        try:
            scan_rec = ScanHistory(
                target=target_subnet,
                scan_type="HOST_DISCOVERY",
                hosts_found=len(active_hosts),
                open_ports_count=0,
                status="COMPLETED",
                summary_json={"hosts": active_hosts, "total_probed": len(hosts_to_test)}
            )
            db.add(scan_rec)
            db.commit()
            db.refresh(scan_rec)

            for h in active_hosts:
                host_rec = DiscoveredHost(
                    scan_id=scan_rec.id,
                    ip=h["ip"],
                    mac=h.get("mac"),
                    hostname=h.get("hostname"),
                    is_alive=True,
                    latency_ms=h.get("latency_ms", 0.0),
                    open_ports_json=[]
                )
                db.add(host_rec)
            db.commit()

            # Add System Log
            db.add(SystemLog(
                source="NETWORK_SCANNER",
                level="INFO",
                message=f"Subnet discovery completed for {target_subnet}. Discovered {len(active_hosts)} active hosts."
            ))
            db.commit()

            return {
                "scan_id": scan_rec.id,
                "target": target_subnet,
                "status": "COMPLETED",
                "hosts_found": len(active_hosts),
                "probed_count": len(hosts_to_test),
                "duration_seconds": round((datetime.utcnow() - start_time).total_seconds(), 2),
                "hosts": active_hosts
            }
        finally:
            db.close()

    def scan_target_ports(
        self,
        target_ip: str,
        ports: Optional[List[int]] = None,
        max_threads: int = 15
    ) -> Dict[str, Any]:
        """Perform authorized TCP connect scan against a target host."""
        if not is_target_authorized(target_ip):
            raise ValueError(f"Target '{target_ip}' is not an authorized test host.")

        # Resolve hostname if string provided
        try:
            resolved_ip = socket.gethostbyname(target_ip.strip())
        except Exception:
            resolved_ip = target_ip.strip()

        ports_to_scan = ports or COMMON_TCP_PORTS
        start_time = datetime.utcnow()
        results = []

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {
                executor.submit(scan_single_port, resolved_ip, p): p 
                for p in ports_to_scan
            }
            for future in as_completed(future_to_port):
                res = future.result()
                if res:
                    results.append(res)

        results.sort(key=lambda r: r["port"])
        open_ports = [r for r in results if r["state"] == "OPEN"]
        closed_ports = [r for r in results if r["state"] == "CLOSED"]
        filtered_ports = [r for r in results if r["state"] == "FILTERED"]

        # Record in SQLite database
        db = SessionLocal()
        try:
            scan_rec = ScanHistory(
                target=f"{target_ip} ({resolved_ip})",
                scan_type="TCP_PORT_SCAN",
                hosts_found=1 if open_ports or closed_ports else 0,
                open_ports_count=len(open_ports),
                status="COMPLETED",
                summary_json={
                    "open": open_ports,
                    "closed_count": len(closed_ports),
                    "filtered_count": len(filtered_ports),
                    "total_scanned": len(ports_to_scan)
                }
            )
            db.add(scan_rec)
            db.commit()
            db.refresh(scan_rec)

            # Update or create DiscoveredHost record
            existing_host = db.query(DiscoveredHost).filter(DiscoveredHost.ip == resolved_ip).first()
            if existing_host:
                existing_host.open_ports_json = open_ports
                existing_host.timestamp = datetime.utcnow()
            else:
                hostname = None
                try:
                    hostname = socket.gethostbyaddr(resolved_ip)[0]
                except Exception:
                    pass
                mac_map = get_windows_arp_table()
                db.add(DiscoveredHost(
                    scan_id=scan_rec.id,
                    ip=resolved_ip,
                    mac=mac_map.get(resolved_ip, "N/A"),
                    hostname=hostname,
                    is_alive=True,
                    latency_ms=open_ports[0]["latency_ms"] if open_ports else 0.0,
                    open_ports_json=open_ports
                ))
            
            db.add(SystemLog(
                source="PORT_SCANNER",
                level="INFO",
                message=f"TCP Port scan completed for {target_ip}. Found {len(open_ports)} OPEN ports out of {len(ports_to_scan)} tested."
            ))
            db.commit()

            return {
                "scan_id": scan_rec.id,
                "target": target_ip,
                "resolved_ip": resolved_ip,
                "status": "COMPLETED",
                "open_ports_count": len(open_ports),
                "closed_ports_count": len(closed_ports),
                "filtered_ports_count": len(filtered_ports),
                "total_scanned": len(ports_to_scan),
                "duration_seconds": round((datetime.utcnow() - start_time).total_seconds(), 2),
                "open_ports": open_ports,
                "all_results": results
            }
        finally:
            db.close()


# Global Singleton Scanner Instance
network_scanner = NetworkSecurityScanner()
