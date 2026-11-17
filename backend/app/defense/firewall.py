"""Active Defense & IPS (Intrusion Prevention System) Engine.

Executes real-time firewall blocking against verified malicious attacker IPs
using Windows Advanced Firewall rules (netsh advfirewall), with automated
isolation timers and manual override capabilities.
"""

import subprocess
import logging
import threading
import time
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger("active_defense")


class ActiveDefenseManager:
    """Manages host firewall blocking rules and isolation states."""

    def __init__(self):
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        self.auto_block_enabled: bool = False
        self.default_block_duration: int = 300  # 5 minutes default
        self._lock = threading.Lock()
        self._start_expiration_worker()

    def _start_expiration_worker(self):
        """Background thread that automatically unblocks IPs once their timeout expires."""
        def worker():
            while True:
                time.sleep(5)
                self.sweep_expired_blocks()

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def block_ip(
        self,
        ip: str,
        reason: str = "High-confidence attack detected",
        duration_seconds: Optional[int] = None,
        auto_blocked: bool = False,
        threat_category: str = "Attack"
    ) -> Dict[str, Any]:
        """Block an attacker IP address at the host firewall level."""
        # Sanitize IP to avoid loopback blocking or invalid inputs
        if ip in ["127.0.0.1", "::1", "localhost", "0.0.0.0"]:
            logger.warning(f"Prevented blocking loopback address {ip}")
            return {
                "success": False,
                "message": f"Cannot block loopback or local host address {ip}."
            }

        duration = duration_seconds if duration_seconds is not None else self.default_block_duration
        rule_name = f"CyberSOC_IPS_Block_{ip.replace(':', '_').replace('.', '_')}"

        with self._lock:
            # 1. Execute Windows Firewall netsh command
            firewall_executed = False
            try:
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                    "enable=yes",
                    f"description=CyberSOC Active Defense: Blocked due to {threat_category}"
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0 or "Ok." in res.stdout:
                    firewall_executed = True
                    logger.info(f"[IPS ACTIVE DEFENSE] Blocked IP {ip} via Windows Firewall rule {rule_name}")
                else:
                    logger.warning(f"Netsh firewall returned non-zero (non-admin or simulated): {res.stderr.strip() or res.stdout.strip()}")
            except Exception as e:
                logger.warning(f"Could not execute netsh command: {e}")

            # 2. Record in internal blocklist state
            block_record = {
                "ip": ip,
                "rule_name": rule_name,
                "reason": reason,
                "threat_category": threat_category,
                "blocked_at": datetime.now().isoformat(),
                "blocked_timestamp": time.time(),
                "duration_seconds": duration,
                "expires_at": datetime.fromtimestamp(time.time() + duration).isoformat() if duration > 0 else "NEVER",
                "auto_blocked": auto_blocked,
                "firewall_active": firewall_executed,
                "status": "BLOCKED"
            }
            self.blocked_ips[ip] = block_record

            return {
                "success": True,
                "message": f"Attacker IP {ip} successfully isolated by IPS.",
                "record": block_record
            }

    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        """Unblock an IP address and remove the firewall rule."""
        with self._lock:
            if ip not in self.blocked_ips:
                return {"success": False, "message": f"IP {ip} is not in the active blocklist."}

            record = self.blocked_ips.pop(ip)
            rule_name = record.get("rule_name")

            # Remove Windows firewall rule
            try:
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                logger.info(f"[IPS ACTIVE DEFENSE] Unblocked IP {ip} (rule {rule_name} removed).")
            except Exception as e:
                logger.warning(f"Could not delete netsh rule {rule_name}: {e}")

            return {
                "success": True,
                "message": f"IP {ip} unblocked successfully and host access restored."
            }

    def sweep_expired_blocks(self):
        """Remove rules whose duration has expired."""
        now = time.time()
        expired_ips = []
        with self._lock:
            for ip, record in list(self.blocked_ips.items()):
                dur = record.get("duration_seconds", 0)
                if dur > 0 and (now - record.get("blocked_timestamp", now)) >= dur:
                    expired_ips.append(ip)

        for ip in expired_ips:
            logger.info(f"Auto-unblocking expired IP {ip}")
            self.unblock_ip(ip)

    def list_blocked_ips(self) -> List[Dict[str, Any]]:
        """Return all active blocked IPs with remaining seconds."""
        now = time.time()
        with self._lock:
            results = []
            for ip, record in self.blocked_ips.items():
                dur = record.get("duration_seconds", 0)
                elapsed = now - record.get("blocked_timestamp", now)
                remaining = max(0, int(dur - elapsed)) if dur > 0 else -1
                item = dict(record)
                item["remaining_seconds"] = remaining
                results.append(item)
            return sorted(results, key=lambda x: x["blocked_timestamp"], reverse=True)


# Global singleton instance
active_defense_manager = ActiveDefenseManager()
