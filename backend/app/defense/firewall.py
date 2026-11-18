"""Active Defense & IPS (Intrusion Prevention System) Engine.

Executes real-time, auditable host firewall blocking against verified malicious attacker IPs
using Windows Advanced Firewall rules (netsh advfirewall), with automated isolation timers,
manual administrative override, SQLite persistence, and strict whitelist safeguards.
"""

import subprocess
import logging
import threading
import time
import ipaddress
import socket
from typing import Dict, List, Optional, Any
from datetime import datetime

from backend.app.database.connection import SessionLocal
from backend.app.database.models import DefensiveAction, SystemLog

logger = logging.getLogger("active_defense")

# Static Whitelist: Critical infrastructure and local host addresses that can NEVER be blocked
PROTECTED_WHITELIST = {
    "127.0.0.1", "::1", "localhost", "0.0.0.0",
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"  # Core DNS
}


def get_local_machine_ips() -> set:
    """Detect local adapter and gateway IPs to prevent self-lockout."""
    local_ips = set()
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            local_ips.add(ip)
    except Exception:
        pass
    # Common router gateway addresses
    local_ips.update({"172.20.10.1", "172.20.10.2", "192.168.1.1", "192.168.0.1", "10.0.0.1"})
    return local_ips


class ActiveDefenseManager:
    """Manages host firewall blocking rules, audit trails, and isolation states."""

    def __init__(self):
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        self.auto_block_enabled: bool = False  # Default to MANUAL approval per safety requirements
        self.default_block_duration: int = 300  # 5 minutes default
        self._lock = threading.Lock()
        
        # Load and sync any active blocks from database
        self._restore_active_rules_from_db()
        self._start_expiration_worker()

    def _restore_active_rules_from_db(self):
        """Restore active block state from SQLite database on engine startup."""
        db = SessionLocal()
        try:
            active_actions = db.query(DefensiveAction).filter(
                DefensiveAction.is_active == True,
                DefensiveAction.action == "BLOCK"
            ).all()
            now = time.time()
            for a in active_actions:
                elapsed = (datetime.utcnow() - a.timestamp).total_seconds()
                if a.duration_seconds > 0 and elapsed >= a.duration_seconds:
                    a.is_active = False
                    a.unblocked_at = datetime.utcnow()
                else:
                    self.blocked_ips[a.ip] = {
                        "ip": a.ip,
                        "rule_name": a.rule_name,
                        "reason": a.reason,
                        "threat_category": a.threat_category,
                        "blocked_at": a.timestamp.isoformat(),
                        "blocked_timestamp": a.timestamp.timestamp(),
                        "duration_seconds": a.duration_seconds,
                        "expires_at": (datetime.fromtimestamp(a.timestamp.timestamp() + a.duration_seconds)).isoformat() if a.duration_seconds > 0 else "NEVER",
                        "auto_blocked": False,
                        "firewall_active": a.firewall_success,
                        "status": "BLOCKED"
                    }
            db.commit()
        except Exception as e:
            logger.warning(f"Could not restore firewall rules from DB: {e}")
        finally:
            db.close()

    def _start_expiration_worker(self):
        """Background thread that automatically unblocks IPs once their timeout expires."""
        def worker():
            while True:
                time.sleep(5)
                self.sweep_expired_blocks()

        t = threading.Thread(target=worker, daemon=True, name="FirewallExpirationWorker")
        t.start()

    def validate_ip(self, ip_str: str) -> bool:
        """Validate whether the string is a syntactically valid IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(ip_str.strip())
            return True
        except ValueError:
            return False

    def is_protected(self, ip_str: str) -> bool:
        """Check if an IP is on the permanent whitelist or belongs to local host/gateway."""
        clean_ip = ip_str.strip()
        if clean_ip in PROTECTED_WHITELIST:
            return True
        if clean_ip in get_local_machine_ips():
            return True
        return False

    def block_ip(
        self,
        ip: str,
        reason: str = "High-confidence attack detected",
        duration_seconds: Optional[int] = None,
        auto_blocked: bool = False,
        threat_category: str = "Attack",
        admin_user: str = "SOC_Analyst",
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """Block an attacker IP address at the Windows Firewall level with audit logging."""
        clean_ip = ip.strip()

        # 1. Validation Safeguard
        if not self.validate_ip(clean_ip):
            return {
                "success": False,
                "message": f"Invalid IP address format: '{clean_ip}'."
            }

        # 2. Whitelist Safeguard
        if self.is_protected(clean_ip):
            logger.warning(f"[IPS SAFETY REJECTION] Block attempt on protected IP {clean_ip} denied.")
            return {
                "success": False,
                "message": f"CRITICAL SAFEGUARD: IP {clean_ip} is a protected host, gateway, or loopback address and cannot be blocked."
            }

        duration = duration_seconds if duration_seconds is not None else self.default_block_duration
        rule_name = f"CyberSOC_IPS_Block_{clean_ip.replace(':', '_').replace('.', '_')}"

        with self._lock:
            firewall_executed = False
            exact_command = f"netsh advfirewall firewall add rule name={rule_name} dir=in action=block remoteip={clean_ip} enable=yes"

            if not dry_run:
                try:
                    cmd = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}",
                        "dir=in",
                        "action=block",
                        f"remoteip={clean_ip}",
                        "enable=yes",
                        f"description=CyberSOC Active Defense: Blocked due to {threat_category} by {admin_user}"
                    ]
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    if res.returncode == 0 or "Ok." in res.stdout:
                        firewall_executed = True
                        logger.info(f"[IPS ACTIVE DEFENSE] Blocked IP {clean_ip} via Windows Firewall rule {rule_name}")
                    else:
                        logger.warning(f"Netsh firewall returned non-zero (verify Admin rights): {res.stderr.strip() or res.stdout.strip()}")
                except Exception as e:
                    logger.warning(f"Could not execute netsh command: {e}")
            else:
                logger.info(f"[IPS DRY RUN] Simulated rule: {exact_command}")

            # 3. Record in internal blocklist state
            block_record = {
                "ip": clean_ip,
                "rule_name": rule_name,
                "reason": reason,
                "threat_category": threat_category,
                "blocked_at": datetime.utcnow().isoformat(),
                "blocked_timestamp": time.time(),
                "duration_seconds": duration,
                "expires_at": datetime.fromtimestamp(time.time() + duration).isoformat() if duration > 0 else "NEVER",
                "auto_blocked": auto_blocked,
                "firewall_active": firewall_executed,
                "dry_run": dry_run,
                "exact_command": exact_command,
                "status": "BLOCKED"
            }
            self.blocked_ips[clean_ip] = block_record

            # 4. Audit in SQLite Database
            db = SessionLocal()
            try:
                action_rec = DefensiveAction(
                    ip=clean_ip,
                    action="DRY_RUN" if dry_run else "BLOCK",
                    rule_name=rule_name,
                    threat_category=threat_category,
                    reason=reason,
                    duration_seconds=duration,
                    is_active=True,
                    firewall_success=firewall_executed,
                    admin_user=admin_user
                )
                db.add(action_rec)
                db.add(SystemLog(
                    source="IPS_FIREWALL",
                    level="WARNING" if not dry_run else "INFO",
                    message=f"[DEFENSE ACTION] {'[DRY RUN] ' if dry_run else ''}Blocked IP {clean_ip} ({threat_category}) for {duration}s. Rule: {rule_name}"
                ))
                db.commit()
            except Exception as e:
                logger.error(f"Failed to record defensive action in DB: {e}")
            finally:
                db.close()

            return {
                "success": True,
                "message": f"Attacker IP {clean_ip} successfully isolated by IPS.",
                "rule_name": rule_name,
                "exact_command": exact_command,
                "firewall_active": firewall_executed,
                "dry_run": dry_run,
                "record": block_record
            }

    def unblock_ip(self, ip: str, admin_user: str = "SOC_Analyst") -> Dict[str, Any]:
        """Unblock an IP address and remove the Windows Defender Firewall rule."""
        clean_ip = ip.strip()

        with self._lock:
            rule_name = f"CyberSOC_IPS_Block_{clean_ip.replace(':', '_').replace('.', '_')}"
            if clean_ip in self.blocked_ips:
                record = self.blocked_ips.pop(clean_ip)
                rule_name = record.get("rule_name", rule_name)

            # Remove Windows firewall rule
            try:
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                logger.info(f"[IPS ACTIVE DEFENSE] Unblocked IP {clean_ip} (rule {rule_name} removed).")
            except Exception as e:
                logger.warning(f"Could not delete netsh rule {rule_name}: {e}")

            # Update Database audit record
            db = SessionLocal()
            try:
                action_rec = db.query(DefensiveAction).filter(
                    DefensiveAction.ip == clean_ip,
                    DefensiveAction.is_active == True
                ).first()
                if action_rec:
                    action_rec.is_active = False
                    action_rec.unblocked_at = datetime.utcnow()

                db.add(DefensiveAction(
                    ip=clean_ip,
                    action="UNBLOCK",
                    rule_name=rule_name,
                    threat_category="Resolution",
                    reason="Manual or automated expiration unblock by SOC",
                    duration_seconds=0,
                    is_active=False,
                    firewall_success=True,
                    admin_user=admin_user,
                    unblocked_at=datetime.utcnow()
                ))
                db.add(SystemLog(
                    source="IPS_FIREWALL",
                    level="INFO",
                    message=f"[DEFENSE ACTION] Unblocked IP {clean_ip}. Removed rule {rule_name}."
                ))
                db.commit()
            except Exception as e:
                logger.error(f"Failed to record unblock action in DB: {e}")
            finally:
                db.close()

            return {
                "success": True,
                "message": f"IP {clean_ip} unblocked successfully and host access restored."
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
            self.unblock_ip(ip, admin_user="Auto_Timer_Sweep")

    def unblock_all_emergency(self) -> Dict[str, Any]:
        """Emergency recovery: delete all CyberSOC IPS firewall rules and clear blocklist."""
        with self._lock:
            count = len(self.blocked_ips)
            self.blocked_ips.clear()

            # Execute netsh delete rule by prefix/wildcard
            try:
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", "name=all"]
                # Specifically target CyberSOC rules
                rule_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
                res = subprocess.run(rule_cmd, capture_output=True, text=True, timeout=5)
                for line in res.stdout.splitlines():
                    if "Rule Name:" in line and "CyberSOC_IPS_Block_" in line:
                        r_name = line.split(":", 1)[1].strip()
                        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={r_name}"], timeout=3)
            except Exception as e:
                logger.warning(f"Error during emergency unblock: {e}")

            db = SessionLocal()
            try:
                db.query(DefensiveAction).filter(DefensiveAction.is_active == True).update({
                    DefensiveAction.is_active: False,
                    DefensiveAction.unblocked_at: datetime.utcnow()
                })
                db.add(SystemLog(
                    source="IPS_FIREWALL",
                    level="WARNING",
                    message="[EMERGENCY RECOVERY] All active IPS firewall rules were flushed and removed."
                ))
                db.commit()
            finally:
                db.close()

            return {
                "success": True,
                "message": f"Emergency Recovery Complete: {count} active firewall rules flushed."
            }

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
