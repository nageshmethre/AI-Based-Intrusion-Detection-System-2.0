"""SSH Authentication Failure & Brute Force Monitor.

Monitors authorized authentication logs (e.g., auth.log, OpenSSH logs, or Event Logs)
for repeated failed authentication attempts from single IP addresses.
"""

import re
import time
from collections import defaultdict
from typing import Dict, List, Optional, Any
from backend.app.config import settings


class SSHAuthMonitor:
    """Monitors and alerts on SSH brute-force attempts from authentication logs."""

    def __init__(self, failure_threshold: int = 5, window_seconds: float = 60.0):
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds
        # Structure: ip -> list of timestamps
        self.failures_by_ip: Dict[str, List[float]] = defaultdict(list)
        self.last_alert_time: Dict[str, float] = {}

        # Standard OpenSSH / Syslog failed password regex
        # e.g.: "Failed password for root from 192.168.1.50 port 55432 ssh2"
        # or "Failed password for invalid user admin from 10.0.0.99 port 44321 ssh2"
        self.ssh_failed_pattern = re.compile(
            r"Failed (?:password|publickey) for (?:invalid user |user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        )

    def parse_log_line(self, log_line: str, timestamp: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Parses an authentication log line and tracks failure attempts."""
        match = self.ssh_failed_pattern.search(log_line)
        if not match:
            return None

        username = match.group(1)
        src_ip = match.group(2)
        now = timestamp or time.time()
        cutoff = now - self.window_seconds

        recent = [t for t in self.failures_by_ip[src_ip] if t >= cutoff]
        recent.append(now)
        self.failures_by_ip[src_ip] = recent

        if len(recent) >= self.failure_threshold:
            last_alert = self.last_alert_time.get(src_ip, 0.0)
            if (now - last_alert) >= 30.0:  # Suppress repeat alert for 30s
                self.last_alert_time[src_ip] = now
                return {
                    "rule_name": "SSH_BRUTE_FORCE",
                    "title": "SSH Brute-Force Authentication Attempt Detected",
                    "description": f"Source {src_ip} accumulated {len(recent)} failed SSH logins targeting user '{username}'.",
                    "src_ip": src_ip,
                    "dst_ip": "LOCAL_SYSTEM",
                    "dst_port": 22,
                    "protocol": "TCP",
                    "severity": "CRITICAL" if len(recent) >= 10 else "HIGH",
                    "detection_type": "RULE_BASED",
                    "details": {
                        "failed_attempts": len(recent),
                        "targeted_username": username,
                        "window_seconds": self.window_seconds,
                        "raw_sample": log_line.strip()
                    },
                    "timestamp": now
                }

        return None

    def record_direct_failure(self, src_ip: str, username: str = "root") -> Optional[Dict[str, Any]]:
        """Direct programmatic failure record."""
        log_sample = f"Failed password for {username} from {src_ip} port 22 ssh2"
        return self.parse_log_line(log_sample)
