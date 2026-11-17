"""Abnormal Connection and SYN Flood Detection Rule Engine."""

import time
from collections import defaultdict
from typing import Dict, List, Optional, Any
from backend.app.config import settings


class AbnormalConnectionDetector:
    """Detects SYN floods and anomalous connection bursts."""

    def __init__(self, syn_threshold: int = 40, window_seconds: float = 3.0):
        self.syn_threshold = syn_threshold
        self.window_seconds = window_seconds
        # Structure: dst_ip -> list of timestamps
        self.syn_history: Dict[str, List[float]] = defaultdict(list)
        self.last_alert_time: Dict[str, float] = {}

    def process_packet(
        self, src_ip: str, dst_ip: str, dst_port: int, protocol: str, tcp_flags: Dict[str, bool]
    ) -> Optional[Dict[str, Any]]:
        """Check for SYN flood indicators."""
        if protocol != "TCP":
            return None

        is_syn = tcp_flags.get("S", False) and not tcp_flags.get("A", False)
        if not is_syn:
            return None

        now = time.time()
        cutoff = now - self.window_seconds

        # Prune older entries
        recent = [ts for ts in self.syn_history[dst_ip] if ts >= cutoff]
        recent.append(now)
        self.syn_history[dst_ip] = recent

        if len(recent) >= self.syn_threshold:
            last_alert = self.last_alert_time.get(dst_ip, 0.0)
            if (now - last_alert) >= 8.0:
                self.last_alert_time[dst_ip] = now
                return {
                    "rule_name": "SYN_FLOOD_SUSPECTED",
                    "title": "High-Volume SYN Flood Suspected",
                    "description": f"Target {dst_ip}:{dst_port} received {len(recent)} SYN packets in {self.window_seconds}s.",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": "TCP",
                    "severity": "CRITICAL",
                    "detection_type": "RULE_BASED",
                    "details": {
                        "syn_count": len(recent),
                        "window_seconds": self.window_seconds
                    },
                    "timestamp": now
                }

        return None
