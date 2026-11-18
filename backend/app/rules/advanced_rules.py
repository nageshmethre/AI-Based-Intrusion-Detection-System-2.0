"""Advanced Deterministic Intrusion Detection Rules.

Covers:
- Distributed Denial-of-Service (DDoS) multi-source flood indicators
- Stealth TCP scans (NULL scan, XMAS scan, SYN-FIN scan)
- Botnet C2 periodic beaconing indicators
- Unusual high-volume burst anomalies
"""

import time
from collections import defaultdict
from typing import Dict, List, Optional, Any


class AdvancedRuleEngine:
    """Evaluates advanced packet and flow-level indicators."""

    def __init__(self):
        # DDoS multi-source tracking: dst_ip:port -> list of (timestamp, src_ip)
        self.ddos_history: Dict[str, List[tuple]] = defaultdict(list)
        self.ddos_last_alert: Dict[str, float] = {}

        # Botnet beacon tracking: (src_ip, dst_ip) -> list of timestamps
        self.beacon_history: Dict[tuple, List[float]] = defaultdict(list)
        self.beacon_last_alert: Dict[tuple, float] = {}

        # Stealth scan alert suppression: src_ip -> timestamp
        self.stealth_last_alert: Dict[str, float] = {}

    def check_stealth_scan(
        self, src_ip: str, dst_ip: str, dst_port: int, protocol: str, tcp_flags: Dict[str, bool]
    ) -> Optional[Dict[str, Any]]:
        """Identify stealth port scanning techniques (NULL, XMAS, SYN-FIN scans)."""
        if protocol != "TCP":
            return None

        now = time.time()
        f = tcp_flags.get("F", False)
        s = tcp_flags.get("S", False)
        r = tcp_flags.get("R", False)
        p = tcp_flags.get("P", False)
        a = tcp_flags.get("A", False)
        u = tcp_flags.get("U", False)

        stealth_type = None
        # NULL Scan: No flags set
        if not (f or s or r or p or a or u):
            stealth_type = "TCP NULL Stealth Scan"
        # XMAS Scan: FIN + PSH + URG flags set
        elif f and p and u and not (s or r or a):
            stealth_type = "TCP XMAS Tree Stealth Scan"
        # SYN-FIN Scan: Conflicting flags
        elif s and f:
            stealth_type = "TCP SYN-FIN Anomalous Probe"

        if stealth_type:
            last = self.stealth_last_alert.get(src_ip, 0.0)
            if (now - last) >= 10.0:
                self.stealth_last_alert[src_ip] = now
                return {
                    "rule_name": "STEALTH_SCAN_DETECTED",
                    "title": f"Stealth Reconnaissance: {stealth_type}",
                    "description": f"Source {src_ip} sent anomalous TCP probe ({stealth_type}) to port {dst_port}.",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": "TCP",
                    "severity": "HIGH",
                    "detection_type": "RULE_BASED",
                    "threat_category": "PortScan",
                    "details": {
                        "stealth_type": stealth_type,
                        "tcp_flags": tcp_flags
                    },
                    "timestamp": now
                }
        return None

    def check_ddos_distributed(
        self, src_ip: str, dst_ip: str, dst_port: int, window_sec: float = 5.0, min_unique_sources: int = 5, min_packets: int = 40
    ) -> Optional[Dict[str, Any]]:
        """Identify multi-source distributed traffic bursts targeting a single destination service."""
        target_key = f"{dst_ip}:{dst_port}"
        now = time.time()
        cutoff = now - window_sec

        recent = [entry for entry in self.ddos_history[target_key] if entry[0] >= cutoff]
        recent.append((now, src_ip))
        self.ddos_history[target_key] = recent

        unique_sources = {entry[1] for entry in recent}

        if len(unique_sources) >= min_unique_sources and len(recent) >= min_packets:
            last = self.ddos_last_alert.get(target_key, 0.0)
            if (now - last) >= 12.0:
                self.ddos_last_alert[target_key] = now
                return {
                    "rule_name": "DDOS_DISTRIBUTED_FLOOD_SUSPECTED",
                    "title": "DDoS-Like Distributed Traffic Surge Suspected",
                    "description": f"Target {target_key} received {len(recent)} packets from {len(unique_sources)} distinct source IPs in {window_sec}s.",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": "TCP",
                    "severity": "CRITICAL",
                    "detection_type": "RULE_BASED",
                    "threat_category": "DDoS",
                    "details": {
                        "distinct_sources_count": len(unique_sources),
                        "total_packets_window": len(recent),
                        "sources_sample": list(unique_sources)[:8],
                        "window_seconds": window_sec
                    },
                    "timestamp": now
                }
        return None

    def check_botnet_beaconing(
        self, src_ip: str, dst_ip: str, dst_port: int, interval_tolerance: float = 0.5
    ) -> Optional[Dict[str, Any]]:
        """Identify repetitive periodic beaconing intervals characteristic of Botnet C2 communication."""
        if src_ip in ["127.0.0.1", "::1"] or dst_ip in ["127.0.0.1", "::1"]:
            return None

        pair = (src_ip, dst_ip)
        now = time.time()
        timestamps = self.beacon_history[pair]
        timestamps.append(now)

        # Keep last 10 connection timestamps
        if len(timestamps) > 10:
            timestamps.pop(0)

        if len(timestamps) >= 6:
            # Calculate intervals
            intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
            avg_interval = sum(intervals) / len(intervals)
            # Low variance in interval indicates programmatic beaconing (1s to 60s)
            if 1.0 <= avg_interval <= 60.0:
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                std_dev = variance ** 0.5
                if std_dev <= interval_tolerance:
                    last = self.beacon_last_alert.get(pair, 0.0)
                    if (now - last) >= 60.0:
                        self.beacon_last_alert[pair] = now
                        return {
                            "rule_name": "BOTNET_BEACON_DETECTED",
                            "title": "Potential Botnet C2 Periodic Beaconing Detected",
                            "description": f"Regular periodic connection interval ({avg_interval:.2f}s +/- {std_dev:.2f}s) between {src_ip} and {dst_ip}:{dst_port}.",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "protocol": "TCP",
                            "severity": "HIGH",
                            "detection_type": "RULE_BASED",
                            "threat_category": "Botnet",
                            "details": {
                                "average_interval_seconds": round(avg_interval, 2),
                                "jitter_std_dev": round(std_dev, 3),
                                "samples_count": len(timestamps)
                            },
                            "timestamp": now
                        }
        return None
