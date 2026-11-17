"""Real-Time Threat Notification Dispatcher.

Supports webhook integration for Discord, Telegram, Slack, and custom SIEM webhooks
with an interactive test dispatch mode for evaluation demonstrations.
"""

import json
import urllib.request
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("soc_notifications")


class NotificationDispatcher:
    """Dispatches high-priority incident notifications to external channels."""

    def __init__(self):
        self.webhook_url: Optional[str] = None
        self.enabled: bool = False
        self.alert_on_severity: str = "CRITICAL"  # CRITICAL or HIGH

    def configure(self, webhook_url: str, enabled: bool = True, alert_on_severity: str = "CRITICAL"):
        self.webhook_url = webhook_url
        self.enabled = enabled
        self.alert_on_severity = alert_on_severity

    def send_alert(self, alert_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Send formatted threat notification to external webhook."""
        if not self.enabled or not self.webhook_url:
            return {"status": "SKIPPED", "message": "Webhook alerts disabled or URL not configured."}

        title = alert_dict.get("title", "Threat Detected")
        severity = alert_dict.get("severity", "HIGH")
        src_ip = alert_dict.get("src_ip", "Unknown")
        category = alert_dict.get("threat_category", "Attack")
        desc = alert_dict.get("description", "")

        # Format Discord / Slack compatible payload
        payload = {
            "content": f"🚨 **[CyberSOC IDS Alert - {severity}]** {title}",
            "embeds": [
                {
                    "title": f"Security Incident: {category}",
                    "description": desc,
                    "color": 15158332 if severity == "CRITICAL" else 15105570,
                    "fields": [
                        {"name": "Attacker IP", "value": src_ip, "inline": True},
                        {"name": "Severity", "value": severity, "inline": True},
                        {"name": "Engine", "value": alert_dict.get("detection_type", "AI/Rule"), "inline": True}
                    ],
                    "footer": {"text": "CyberSOC Real-Time Threat Defense System"}
                }
            ]
        }

        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "CyberSOC-Notifier/2.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                logger.info(f"Webhook notification dispatched (status {resp.status})")
                return {"status": "SENT", "http_code": resp.status}
        except Exception as e:
            logger.warning(f"Failed to deliver webhook notification: {e}")
            return {"status": "FAILED", "error": str(e)}


# Global instance
notification_dispatcher = NotificationDispatcher()
