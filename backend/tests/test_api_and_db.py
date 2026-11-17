"""Phase 5 FastAPI Backend & SQLite Database Verification Test."""

import sys
from pathlib import Path
import httpx

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.database.connection import init_db, SessionLocal
from backend.app.database.models import NetworkEvent, ThreatAlert, SystemLog
from backend.app.main import app


def test_sqlite_db_and_tables():
    print("Testing SQLite database initialization and CRUD operations...")
    init_db()
    db = SessionLocal()
    try:
        # Create test event
        event = NetworkEvent(
            src_ip="192.168.1.15",
            dst_ip="10.0.0.8",
            src_port=49152,
            dst_port=80,
            protocol="TCP",
            flow_duration=250000.0,
            total_packets=10,
            total_bytes=1500,
            prediction="BENIGN",
            confidence=0.98,
            is_malicious=False,
            severity="INFO"
        )
        db.add(event)

        # Create test alert
        alert = ThreatAlert(
            title="Suspicious SYN Scan",
            description="Host attempted connection to 25 target ports.",
            src_ip="192.168.1.99",
            dst_ip="10.0.0.8",
            dst_port=22,
            protocol="TCP",
            detection_type="RULE_BASED",
            threat_category="PortScan",
            severity="HIGH",
            confidence=1.0,
            status="OPEN"
        )
        db.add(alert)

        # Create test log
        log = SystemLog(source="TEST_SUITE", level="INFO", message="Phase 5 DB test record")
        db.add(log)
        db.commit()

        # Query back
        ev_count = db.query(NetworkEvent).count()
        al_count = db.query(ThreatAlert).count()
        assert ev_count >= 1, "NetworkEvent table empty"
        assert al_count >= 1, "ThreatAlert table empty"
        print(f"✓ SQLite persistence validated: {ev_count} events, {al_count} alerts logged")
    finally:
        db.close()


import asyncio

async def async_test_fastapi_endpoints():
    print("Testing FastAPI REST endpoints with httpx.AsyncClient...")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Health & Root HTML
        r_health = await client.get("/api/health")
        assert r_health.status_code == 200
        assert r_health.json()["status"] == "ONLINE"
        print("✓ Health endpoint '/api/health' responsive (Status: ONLINE)")

        r_root = await client.get("/")
        assert r_root.status_code == 200
        print("✓ Frontend root '/' successfully served")

        # 2. Overview
        r_over = await client.get("/api/overview")
        assert r_over.status_code == 200
        data_over = r_over.json()
        assert "total_packets_or_flows" in data_over
        assert "severity_breakdown" in data_over
        assert "protocol_distribution" in data_over
        assert "recent_alerts" in data_over
        print("✓ '/api/overview' returned valid SOC metrics")

        # 3. Monitoring Events
        r_events = await client.get("/api/monitoring/events?limit=10")
        assert r_events.status_code == 200
        assert "items" in r_events.json()
        print("✓ '/api/monitoring/events' returned paginated flow events")

        # 4. Threat Alerts
        r_alerts = await client.get("/api/threats/alerts?limit=10")
        assert r_alerts.status_code == 200
        items = r_alerts.json()["items"]
        assert len(items) > 0
        alert_id = items[0]["id"]
        print(f"✓ '/api/threats/alerts' returned alerts (target alert ID {alert_id})")

        # 5. Patch Alert Status
        r_patch = await client.patch(f"/api/threats/alerts/{alert_id}", json={"status": "RESOLVED"})
        assert r_patch.status_code == 200
        assert r_patch.json()["new_status"] == "RESOLVED"
        print(f"✓ Alert {alert_id} successfully marked as RESOLVED")

        # 6. Model Metrics
        r_metrics = await client.get("/api/model/metrics")
        assert r_metrics.status_code == 200
        assert "accuracy" in r_metrics.json()
        assert "confusion_matrix" in r_metrics.json()
        print(f"✓ '/api/model/metrics' loaded: Model Accuracy = {r_metrics.json()['accuracy'] * 100:.1f}%")

        # 7. Log Ingestion (SSH Brute Force simulation)
        from backend.app.main import app_state
        from backend.app.rules.rule_engine import RuleBasedDetectionEngine
        if not app_state.rule_engine:
            app_state.rule_engine = RuleBasedDetectionEngine()

        for _ in range(5):
            r_ingest = await client.post(
                "/api/logs/ingest",
                json={"log_line": "Nov 14 14:10:00 server sshd[999]: Failed password for invalid user root from 198.51.100.22 port 48123 ssh2"}
            )
            assert r_ingest.status_code == 200

        assert r_ingest.json()["alert_triggered"] is True
        print("✓ '/api/logs/ingest' processed and triggered rule-based SSH Brute-Force alert")

        # 8. Settings
        r_settings = await client.get("/api/settings")
        assert r_settings.status_code == 200
        assert "available_interfaces" in r_settings.json()
        print(f"✓ '/api/settings' validated: {len(r_settings.json()['available_interfaces'])} network interfaces detected")


def test_fastapi_endpoints():
    asyncio.run(async_test_fastapi_endpoints())


if __name__ == "__main__":
    test_sqlite_db_and_tables()
    test_fastapi_endpoints()
    print("\n--- Phase 5 Verification Passed Successfully! ---")
