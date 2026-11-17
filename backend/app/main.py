"""FastAPI Main Application Entry Point.

Orchestrates packet capture, flow aggregation, AI detection engine,
rule-based threat detection, SQLite persistence, and WebSocket real-time feeds.
"""

import asyncio
import logging
import time
from typing import Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from backend.app.config import settings, BASE_DIR
from backend.app.database.connection import init_db, SessionLocal
from backend.app.database.models import NetworkEvent, ThreatAlert, SystemLog
from backend.app.ml.detector import AIDetectionEngine
from backend.app.rules.rule_engine import RuleBasedDetectionEngine
from backend.app.capture.flow import FlowAggregator
from backend.app.capture.sniffer import PacketSniffer
from backend.app.api.routes import router as api_router
from backend.app.api.websockets import ws_router, ws_manager
from backend.app.defense.firewall import active_defense_manager
from backend.app.notifications.webhook import notification_dispatcher

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("SOC_Core")


class SOCApplicationState:
    """Singleton holder for application services."""
    def __init__(self):
        self.ai_engine: Optional[AIDetectionEngine] = None
        self.rule_engine: Optional[RuleBasedDetectionEngine] = None
        self.flow_aggregator: Optional[FlowAggregator] = None
        self.sniffer: Optional[PacketSniffer] = None
        self.pulse_task: Optional[asyncio.Task] = None


app_state = SOCApplicationState()


def handle_completed_flow(flow_dict: dict):
    """Callback invoked when a network flow completes or expires."""
    try:
        # 1. Run AI Inference
        ai_res = app_state.ai_engine.predict_flow(flow_dict)
        
        # 2. Persist to Database
        db = SessionLocal()
        try:
            event_obj = NetworkEvent(
                src_ip=flow_dict.get("src_ip", "0.0.0.0"),
                dst_ip=flow_dict.get("dst_ip", "0.0.0.0"),
                src_port=int(flow_dict.get("src_port", 0)),
                dst_port=int(flow_dict.get("dst_port", 0)),
                protocol=flow_dict.get("protocol", "TCP"),
                flow_duration=float(flow_dict.get("flow_duration", 0.0)),
                total_packets=int(flow_dict.get("total_packets", 0)),
                total_bytes=int(flow_dict.get("total_bytes", 0)),
                bytes_per_sec=float(flow_dict.get("flow_bytes_per_sec", 0.0)),
                packets_per_sec=float(flow_dict.get("flow_pkts_per_sec", 0.0)),
                prediction=ai_res["prediction"],
                confidence=ai_res["confidence"],
                is_malicious=ai_res["is_malicious"],
                severity=ai_res["severity"]
            )
            db.add(event_obj)

            alert_dict = None
            if ai_res.get("is_threat_alert", False):
                threat_alert = ThreatAlert(
                    title=f"AI Confirmed Threat: {ai_res['prediction']}",
                    description=f"High-confidence {ai_res['prediction']} flow ({ai_res['confidence']*100:.1f}%, margin: {ai_res.get('probability_margin', 0)*100:.1f}%) from {event_obj.src_ip} to {event_obj.dst_ip}:{event_obj.dst_port}.",
                    src_ip=event_obj.src_ip,
                    dst_ip=event_obj.dst_ip,
                    dst_port=event_obj.dst_port,
                    protocol=event_obj.protocol,
                    detection_type="MACHINE_LEARNING",
                    threat_category=ai_res["prediction"],
                    severity=ai_res["severity"],
                    confidence=ai_res["confidence"],
                    status="OPEN",
                    details_json={
                        "probabilities": ai_res.get("probabilities"),
                        "probability_margin": ai_res.get("probability_margin"),
                        "status": ai_res.get("status")
                    }
                )
                db.add(threat_alert)
                db.commit()
                db.refresh(threat_alert)
                
                alert_dict = {
                    "id": threat_alert.id,
                    "timestamp": threat_alert.timestamp.isoformat(),
                    "title": threat_alert.title,
                    "description": threat_alert.description,
                    "src_ip": threat_alert.src_ip,
                    "dst_ip": threat_alert.dst_ip,
                    "dst_port": threat_alert.dst_port,
                    "protocol": threat_alert.protocol,
                    "detection_type": threat_alert.detection_type,
                    "threat_category": threat_alert.threat_category,
                    "severity": threat_alert.severity,
                    "confidence": threat_alert.confidence,
                    "status": threat_alert.status
                }
            else:
                db.commit()

            db.refresh(event_obj)

            # 3. Broadcast to WebSockets
            event_dict = {
                "id": event_obj.id,
                "timestamp": event_obj.timestamp.isoformat(),
                "src_ip": event_obj.src_ip,
                "dst_ip": event_obj.dst_ip,
                "src_port": event_obj.src_port,
                "dst_port": event_obj.dst_port,
                "protocol": event_obj.protocol,
                "prediction": event_obj.prediction,
                "confidence": event_obj.confidence,
                "is_malicious": event_obj.is_malicious,
                "severity": event_obj.severity,
                "total_packets": event_obj.total_packets,
                "total_bytes": event_obj.total_bytes
            }
            ws_manager.dispatch_from_thread("NEW_EVENT", event_dict)

            if alert_dict:
                ws_manager.dispatch_from_thread("NEW_ALERT", alert_dict)
                # Active Defense Auto-Block & Webhook Notification
                if active_defense_manager.auto_block_enabled and alert_dict.get("severity") in ["CRITICAL", "HIGH"]:
                    active_defense_manager.block_ip(
                        ip=alert_dict["src_ip"],
                        reason=f"Automated IPS Defense: {alert_dict['title']}",
                        threat_category=alert_dict.get("threat_category", "Attack"),
                        auto_blocked=True
                    )
                if notification_dispatcher.enabled:
                    notification_dispatcher.send_alert(alert_dict)

        finally:
            db.close()

    except Exception as e:
        logger.error(f"Error processing completed flow: {e}")


def handle_live_packet(packet_dict: dict):
    """Callback for individual packets to evaluate fast rule-based detections."""
    if not app_state.rule_engine:
        return

    rule_alerts = app_state.rule_engine.evaluate_packet(packet_dict)
    if rule_alerts:
        db = SessionLocal()
        try:
            for ra in rule_alerts:
                alert_obj = ThreatAlert(
                    title=ra["title"],
                    description=ra["description"],
                    src_ip=ra["src_ip"],
                    dst_ip=ra["dst_ip"],
                    dst_port=ra.get("dst_port"),
                    protocol=ra.get("protocol"),
                    detection_type=ra["detection_type"],
                    threat_category="PortScan" if "PORT" in ra["rule_name"] else "DoS",
                    severity=ra["severity"],
                    confidence=1.0,
                    status="OPEN",
                    details_json=ra.get("details")
                )
                db.add(alert_obj)
                db.commit()
                db.refresh(alert_obj)

                alert_dict = {
                    "id": alert_obj.id,
                    "timestamp": alert_obj.timestamp.isoformat(),
                    "title": alert_obj.title,
                    "description": alert_obj.description,
                    "src_ip": alert_obj.src_ip,
                    "dst_ip": alert_obj.dst_ip,
                    "dst_port": alert_obj.dst_port,
                    "protocol": alert_obj.protocol,
                    "detection_type": alert_obj.detection_type,
                    "threat_category": alert_obj.threat_category,
                    "severity": alert_obj.severity,
                    "confidence": alert_obj.confidence,
                    "status": alert_obj.status
                }
                ws_manager.dispatch_from_thread("NEW_ALERT", alert_dict)
                # Active Defense Auto-Block & Webhook Notification
                if active_defense_manager.auto_block_enabled and alert_dict.get("severity") in ["CRITICAL", "HIGH"]:
                    active_defense_manager.block_ip(
                        ip=alert_dict["src_ip"],
                        reason=f"Automated IPS Defense: {alert_dict['title']}",
                        threat_category=alert_dict.get("threat_category", "Attack"),
                        auto_blocked=True
                    )
                if notification_dispatcher.enabled:
                    notification_dispatcher.send_alert(alert_dict)
        finally:
            db.close()


async def traffic_pulse_broadcaster():
    """Broadcasts 1-second pulse telemetry for live throughput charts."""
    prev_packets = 0
    prev_bytes = 0

    while True:
        await asyncio.sleep(1.0)
        if app_state.sniffer:
            metrics = app_state.sniffer.get_metrics()
            curr_packets = metrics["total_packets"]
            curr_bytes = metrics["total_bytes"]

            pps = max(0, curr_packets - prev_packets)
            bps = max(0, curr_bytes - prev_bytes)

            prev_packets = curr_packets
            prev_bytes = curr_bytes

            pulse_data = {
                "timestamp": time.strftime("%H:%M:%S"),
                "packets_per_sec": pps,
                "bytes_per_sec": bps,
                "total_packets": curr_packets,
                "total_bytes": curr_bytes,
                "interface": metrics.get("interface_display", metrics.get("interface", "DEFAULT")),
                "interface_display": metrics.get("interface_display", metrics.get("interface", "DEFAULT")),
                "interface_id": metrics.get("interface", "DEFAULT"),
                "is_running": metrics.get("is_running", True),
                "active_flows": metrics["active_flows"],
                "completed_flows": metrics["completed_flows"],
                "tcp_packets": metrics["tcp_packets"],
                "udp_packets": metrics["udp_packets"],
                "icmp_packets": metrics["icmp_packets"]
            }
            await ws_manager.broadcast_json({
                "type": "TRAFFIC_PULSE",
                "data": pulse_data
            })


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan setup and teardown."""
    logger.info("Initializing SOC Detection Engine and Database...")
    init_db()

    # Register event loop with WS manager
    loop = asyncio.get_running_loop()
    ws_manager.set_loop(loop)

    # Instantiate Engines
    app_state.ai_engine = AIDetectionEngine()
    app_state.rule_engine = RuleBasedDetectionEngine()
    app_state.flow_aggregator = FlowAggregator(
        flow_timeout=settings.FLOW_TIMEOUT,
        on_flow_complete=handle_completed_flow
    )
    app_state.sniffer = PacketSniffer(
        interface=settings.NETWORK_INTERFACE,
        flow_aggregator=app_state.flow_aggregator,
        packet_callback=handle_live_packet
    )

    # Start Sniffer Service
    app_state.sniffer.start()

    # Start live telemetry pulse task
    app_state.pulse_task = asyncio.create_task(traffic_pulse_broadcaster())

    # Log operational start
    db = SessionLocal()
    try:
        db.add(SystemLog(source="SOC_SYSTEM", level="INFO", message="SOC Intrusion Detection Engine started successfully."))
        db.commit()
    finally:
        db.close()

    logger.info("SOC Detection Engine is fully operational.")

    yield

    # Shutdown
    logger.info("Shutting down SOC Detection Services...")
    if app_state.pulse_task:
        app_state.pulse_task.cancel()
    if app_state.sniffer:
        app_state.sniffer.stop()


app = FastAPI(
    title="AI-Based SOC Intrusion Detection System",
    description="Real-time Network Threat Detection API combining Random Forest ML & Rule-Based Analytics",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Routers
app.include_router(api_router)
app.include_router(ws_router)


@app.get("/api/health")
def health():
    return {
        "service": "AI-Based Network Intrusion Detection SOC System",
        "status": "ONLINE",
        "version": "1.0.0"
    }


# Mount frontend production build if available
frontend_dist = BASE_DIR / "frontend" / "dist"
if frontend_dist.exists():
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
else:
    @app.get("/")
    def root():
        return {
            "service": "AI-Based Network Intrusion Detection SOC System",
            "status": "ONLINE",
            "docs": "/docs",
            "version": "1.0.0"
        }
