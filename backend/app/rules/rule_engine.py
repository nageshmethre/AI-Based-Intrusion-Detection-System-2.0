"""Unified Rule-Based Threat Detection Engine."""

import logging
from typing import Dict, List, Optional, Any
from backend.app.config import settings
from backend.app.rules.port_scan import PortScanDetector
from backend.app.rules.abnormal_conn import AbnormalConnectionDetector
from backend.app.rules.ssh_monitor import SSHAuthMonitor

logger = logging.getLogger("RuleEngine")


class RuleBasedDetectionEngine:
    """Coordinates all deterministic signature and threshold-based security rules."""

    def __init__(self):
        self.port_scan_detector = PortScanDetector(
            threshold=settings.PORT_SCAN_THRESHOLD,
            window_seconds=settings.PORT_SCAN_WINDOW_SECONDS
        )
        self.abnormal_conn_detector = AbnormalConnectionDetector(
            syn_threshold=settings.SYN_FLOOD_THRESHOLD,
            window_seconds=3.0
        )
        self.ssh_monitor = SSHAuthMonitor(
            failure_threshold=settings.SSH_FAILURE_THRESHOLD,
            window_seconds=60.0
        )

    def evaluate_packet(self, packet_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate raw packet against packet-level rules."""
        alerts = []

        src_ip = packet_dict.get("src_ip", "")
        dst_ip = packet_dict.get("dst_ip", "")
        dst_port = packet_dict.get("dst_port", 0)
        protocol = packet_dict.get("protocol", "")
        tcp_flags = packet_dict.get("tcp_flags", {})

        # 1. Port scan check
        ps_alert = self.port_scan_detector.process_packet(src_ip, dst_ip, dst_port, protocol, tcp_flags)
        if ps_alert:
            alerts.append(ps_alert)

        # 2. Abnormal connection / SYN flood check
        syn_alert = self.abnormal_conn_detector.process_packet(src_ip, dst_ip, dst_port, protocol, tcp_flags)
        if syn_alert:
            alerts.append(syn_alert)

        return alerts

    def evaluate_auth_log(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Evaluate an authentication log line."""
        return self.ssh_monitor.parse_log_line(log_line)
