"""Port Scanning Rule-Based Detection Engine.

Tracks connection attempts per source IP using a sliding time window.
Alerts when the count of distinct targeted destination ports exceeds the threshold.
"""

import time
from collections import defaultdict
from typing import Dict, Set, List, Optional, Any
from backend.app.config import settings


class PortScanDetector:
    """Detects horizontal and vertical port scanning activity."""

    def __init__(self, threshold: int = 15, window_seconds: float = 5.0):
        self.threshold = threshold
        self.window_seconds = window_seconds
        # Structure: src_ip -> list of (timestamp, dst_port, dst_ip)
        self.history: Dict[str, List[tuple]] = defaultdict(list)
        # Suppress duplicate alerts for same IP within 10 seconds
        self.last_alert_time: Dict[str, float] = {}

    def process_packet(
        self, src_ip: str, dst_ip: str, dst_port: int, protocol: str, tcp_flags: Dict[str, bool]
    ) -> Optional[Dict[str, Any]]:
        """Evaluate packet for port scanning behavior."""
        if protocol != "TCP" or not dst_port:
            return None

        # Focus on SYN packets without ACK (classic SYN scan probe)
        is_syn = tcp_flags.get("S", False) and not tcp_flags.get("A", False)
        if not is_syn:
            return None

        now = time.time()
        cutoff = now - self.window_seconds

        # Prune old entries for this src_ip
        recent = [entry for entry in self.history[src_ip] if entry[0] >= cutoff]
        recent.append((now, dst_port, dst_ip))
        self.history[src_ip] = recent

        # Count distinct destination ports
        distinct_ports = {entry[1] for entry in recent}

        if len(distinct_ports) >= self.threshold:
            # Check alert cooldown
            last_alert = self.last_alert_time.get(src_ip, 0.0)
            if (now - last_alert) >= 8.0:
                self.last_alert_time[src_ip] = now
                return {
                    "rule_name": "PORT_SCAN_DETECTED",
                    "title": "Port Scanning Activity Detected",
                    "description": f"Host {src_ip} scanned {len(distinct_ports)} ports within {self.window_seconds}s.",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": "TCP",
                    "severity": "HIGH",
                    "detection_type": "RULE_BASED",
                    "details": {
                        "scanned_ports_sample": sorted(list(distinct_ports))[:10],
                        "total_unique_ports": len(distinct_ports),
                        "window_seconds": self.window_seconds
                    },
                    "timestamp": now
                }

        return None
