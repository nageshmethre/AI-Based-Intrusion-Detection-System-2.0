"""FastAPI REST API Endpoints for the SOC Dashboard."""

import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from pydantic import BaseModel

from backend.app.database.connection import get_db, SessionLocal
from backend.app.database.models import NetworkEvent, ThreatAlert, SystemLog
from backend.app.config import settings
from backend.app.ml.train import train_model
from backend.app.ml.dataset_importer import scan_raw_dataset_files, process_authentic_cicids2017
from backend.app.capture.sniffer import list_available_interfaces
from backend.app.defense.firewall import active_defense_manager
from backend.app.intelligence.geoip import get_ip_intel
from backend.app.ml.explainer import explain_flow_prediction
from backend.app.reports.exporter import generate_executive_html_report
from backend.app.notifications.webhook import notification_dispatcher
from backend.app.scanner.web_scanner import audit_website
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/api")


# Pydantic schemas
class WebScanRequest(BaseModel):
    target_url: str
    check_exposures: Optional[bool] = True
    test_waf: Optional[bool] = True


class WebScanRecordAlertRequest(BaseModel):
    title: str
    severity: str
    description: str
    target_url: str
    category: Optional[str] = "Web Application Attack"
    evidence: Optional[str] = ""
    remediation: Optional[str] = ""


class AlertStatusUpdate(BaseModel):
    status: str  # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE


class BlockIpRequest(BaseModel):
    ip: str
    reason: Optional[str] = "Manual isolation by SOC analyst"
    duration_seconds: Optional[int] = 300
    threat_category: Optional[str] = "Attack"


class UnblockIpRequest(BaseModel):
    ip: str


class WebhookConfigRequest(BaseModel):
    webhook_url: str
    enabled: Optional[bool] = True
    alert_on_severity: Optional[str] = "CRITICAL"


class LogIngestRequest(BaseModel):
    log_line: str
    source: Optional[str] = "AUTH_LOG"


class RetrainRequest(BaseModel):
    use_authentic: Optional[bool] = True
    n_estimators: Optional[int] = 100
    max_depth: Optional[int] = 22


class DatasetProcessRequest(BaseModel):
    chunk_size: Optional[int] = 50000
    max_samples_per_class: Optional[int] = 15000


class SettingsUpdateRequest(BaseModel):
    network_interface: Optional[str] = None
    flow_timeout: Optional[float] = None
    anomaly_threshold: Optional[float] = None
    ml_alert_confidence_threshold: Optional[float] = None
    ml_probability_margin_threshold: Optional[float] = None
    port_scan_threshold: Optional[int] = None
    sniffer_running: Optional[bool] = None


@router.get("/overview")
def get_soc_overview(db: Session = Depends(get_db)):
    """Summary metrics, attack distributions, and recent alerts for the SOC Overview."""
    # Counts
    total_events = db.query(func.count(NetworkEvent.id)).scalar() or 0
    malicious_events = db.query(func.count(NetworkEvent.id)).filter(NetworkEvent.is_malicious == True).scalar() or 0
    normal_events = total_events - malicious_events
    total_alerts = db.query(func.count(ThreatAlert.id)).scalar() or 0
    open_alerts = db.query(func.count(ThreatAlert.id)).filter(ThreatAlert.status == "OPEN").scalar() or 0

    # Severity distribution
    sev_rows = db.query(ThreatAlert.severity, func.count(ThreatAlert.id)).group_by(ThreatAlert.severity).all()
    severity_breakdown = {s: 0 for s in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]}
    for sev, cnt in sev_rows:
        severity_breakdown[sev] = cnt

    # Protocol distribution
    proto_rows = db.query(NetworkEvent.protocol, func.count(NetworkEvent.id)).group_by(NetworkEvent.protocol).all()
    protocol_distribution = {p: cnt for p, cnt in proto_rows}

    # Attack category distribution
    attack_rows = db.query(ThreatAlert.threat_category, func.count(ThreatAlert.id)).group_by(ThreatAlert.threat_category).all()
    attack_distribution = {cat: cnt for cat, cnt in attack_rows}

    # Top Source IPs
    top_ip_rows = (
        db.query(NetworkEvent.src_ip, func.count(NetworkEvent.id).label("cnt"))
        .group_by(NetworkEvent.src_ip)
        .order_by(desc("cnt"))
        .limit(5)
        .all()
    )
    top_source_ips = [
        {
            "ip": ip,
            "count": cnt,
            "percentage": round((cnt / total_events * 100), 1) if total_events > 0 else 0.0
        }
        for ip, cnt in top_ip_rows
    ]

    # Top Destination Ports
    port_names = {
        443: "443 (HTTPS)",
        53: "53 (DNS)",
        80: "80 (HTTP)",
        22: "22 (SSH)",
        3389: "3389 (RDP)",
        21: "21 (FTP)",
        23: "23 (Telnet)",
        8080: "8080 (Proxy)",
        5222: "5222 (XMPP)"
    }
    top_port_rows = (
        db.query(NetworkEvent.dst_port, func.count(NetworkEvent.id).label("cnt"))
        .filter(NetworkEvent.dst_port > 0)
        .group_by(NetworkEvent.dst_port)
        .order_by(desc("cnt"))
        .limit(5)
        .all()
    )
    top_dest_ports = [
        {
            "port": p,
            "label": port_names.get(p, f"{p} (Custom)"),
            "count": cnt,
            "percentage": round((cnt / total_events * 100), 1) if total_events > 0 else 0.0
        }
        for p, cnt in top_port_rows
    ]

    # Recent Threat Geolocation Sources for Threat Map
    threat_ips = (
        db.query(ThreatAlert.src_ip, ThreatAlert.threat_category, ThreatAlert.severity)
        .order_by(desc(ThreatAlert.timestamp))
        .limit(10)
        .all()
    )
    threat_map_nodes = []
    seen_ips = set()
    for src_ip, cat, sev in threat_ips:
        if src_ip in seen_ips:
            continue
        seen_ips.add(src_ip)
        intel = get_ip_intel(src_ip)
        threat_map_nodes.append({
            "ip": src_ip,
            "category": cat,
            "severity": sev,
            "country": intel.get("country", "Unknown"),
            "city": intel.get("city", "Unknown"),
            "lat": intel.get("lat", 20.0),
            "lon": intel.get("lon", 0.0),
            "is_malicious": True
        })

    # Recent Alerts
    recent_alerts_objs = db.query(ThreatAlert).order_by(desc(ThreatAlert.timestamp)).limit(6).all()
    recent_alerts = [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat(),
            "title": a.title,
            "description": a.description,
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "dst_port": a.dst_port,
            "protocol": a.protocol,
            "detection_type": a.detection_type,
            "threat_category": a.threat_category,
            "severity": a.severity,
            "confidence": a.confidence,
            "status": a.status
        }
        for a in recent_alerts_objs
    ]

    # Recent Events
    recent_events_objs = db.query(NetworkEvent).order_by(desc(NetworkEvent.timestamp)).limit(6).all()
    recent_events = [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "src_port": e.src_port,
            "dst_port": e.dst_port,
            "protocol": e.protocol,
            "prediction": e.prediction,
            "confidence": e.confidence,
            "is_malicious": e.is_malicious,
            "severity": e.severity,
            "total_packets": e.total_packets,
            "total_bytes": e.total_bytes
        }
        for e in recent_events_objs
    ]

    return {
        "total_packets_or_flows": total_events,
        "normal_traffic": normal_events,
        "suspicious_traffic": malicious_events,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "severity_breakdown": severity_breakdown,
        "protocol_distribution": protocol_distribution,
        "attack_distribution": attack_distribution,
        "top_source_ips": top_source_ips,
        "top_dest_ports": top_dest_ports,
        "threat_map_nodes": threat_map_nodes,
        "traffic_flow_stats": {
            "total_flows": total_events,
            "normal": normal_events,
            "suspicious": malicious_events,
            "dos": attack_distribution.get("DoS", 0),
            "portscan": attack_distribution.get("PortScan", 0),
            "bruteforce": attack_distribution.get("BruteForce", 0),
            "botnet": attack_distribution.get("Botnet", 0),
            "active_alerts": open_alerts
        },
        "recent_alerts": recent_alerts,
        "recent_events": recent_events
    }


@router.get("/monitoring/events")
def list_network_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    is_malicious: Optional[bool] = None,
    protocol: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Paginated list of network flow events."""
    query = db.query(NetworkEvent)
    if is_malicious is not None:
        query = query.filter(NetworkEvent.is_malicious == is_malicious)
    if protocol:
        query = query.filter(NetworkEvent.protocol == protocol.upper())

    total = query.count()
    events = query.order_by(desc(NetworkEvent.timestamp)).offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "src_ip": e.src_ip,
                "dst_ip": e.dst_ip,
                "src_port": e.src_port,
                "dst_port": e.dst_port,
                "protocol": e.protocol,
                "flow_duration_us": e.flow_duration,
                "total_packets": e.total_packets,
                "total_bytes": e.total_bytes,
                "prediction": e.prediction,
                "confidence": e.confidence,
                "is_malicious": e.is_malicious,
                "severity": e.severity
            }
            for e in events
        ]
    }


@router.get("/threats/alerts")
def list_threat_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    detection_type: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Paginated list of threat alerts with filtering options."""
    query = db.query(ThreatAlert)
    if severity:
        query = query.filter(ThreatAlert.severity == severity.upper())
    if status:
        query = query.filter(ThreatAlert.status == status.upper())
    if detection_type:
        query = query.filter(ThreatAlert.detection_type == detection_type.upper())

    total = query.count()
    alerts = query.order_by(desc(ThreatAlert.timestamp)).offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "id": a.id,
                "timestamp": a.timestamp.isoformat(),
                "title": a.title,
                "description": a.description,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "dst_port": a.dst_port,
                "protocol": a.protocol,
                "detection_type": a.detection_type,
                "threat_category": a.threat_category,
                "severity": a.severity,
                "confidence": a.confidence,
                "status": a.status,
                "details": a.details_json
            }
            for a in alerts
        ]
    }


@router.patch("/threats/alerts/{alert_id}")
def update_alert_status(alert_id: int, payload: AlertStatusUpdate, db: Session = Depends(get_db)):
    """Update resolution status of a threat alert."""
    alert = db.query(ThreatAlert).filter(ThreatAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = payload.status.upper()
    db.commit()
    db.refresh(alert)
    return {"status": "SUCCESS", "alert_id": alert.id, "new_status": alert.status}


@router.get("/model/metrics")
def get_model_performance():
    """Retrieve model evaluation metrics, confusion matrix, and feature importances."""
    metrics_file = Path(settings.METRICS_PATH)
    if not metrics_file.exists():
        raise HTTPException(status_code=404, detail="Model metrics file not found. Please train model first.")

    with open(metrics_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


@router.post("/model/retrain")
def trigger_model_retrain(
    background_tasks: BackgroundTasks,
    payload: Optional[RetrainRequest] = None
):
    """Trigger background model retraining on authentic or augmented dataset."""
    use_auth = payload.use_authentic if payload else True
    n_est = payload.n_estimators if payload else 100
    max_d = payload.max_depth if payload else 22

    background_tasks.add_task(
        train_model,
        use_authentic=use_auth,
        n_estimators=n_est,
        max_depth=max_d
    )
    return {
        "status": "STARTED",
        "message": f"Model retraining initiated in background (use_authentic={use_auth}).",
        "parameters": {"n_estimators": n_est, "max_depth": max_d, "use_authentic": use_auth}
    }


@router.get("/dataset/status")
def get_dataset_status():
    """Retrieve official dataset scan status, detected raw CSVs, and processed files."""
    return scan_raw_dataset_files()


@router.post("/dataset/process")
def trigger_dataset_processing(
    background_tasks: BackgroundTasks,
    payload: Optional[DatasetProcessRequest] = None
):
    """Trigger chunk-based compilation and sanitization of raw authentic CIC-IDS2017 CSVs."""
    chunk_sz = payload.chunk_size if payload else 50000
    max_samples = payload.max_samples_per_class if payload else 15000

    def run_import():
        try:
            process_authentic_cicids2017(chunk_size=chunk_sz, max_samples_per_class=max_samples)
        except Exception as e:
            print(f"Error during dataset processing task: {e}")

    background_tasks.add_task(run_import)
    return {
        "status": "STARTED",
        "message": "Chunk-based authentic dataset compilation initiated in background."
    }


@router.get("/system/status")
def get_detailed_system_status(db: Session = Depends(get_db)):
    """Comprehensive real-time project status across all architectural layers."""
    from backend.app.main import app_state, ws_manager

    # 1. DB stats
    total_events = db.query(func.count(NetworkEvent.id)).scalar() or 0
    total_alerts = db.query(func.count(ThreatAlert.id)).scalar() or 0
    total_logs = db.query(func.count(SystemLog.id)).scalar() or 0
    db_file = Path(settings.DATABASE_URL.replace("sqlite:///", ""))
    db_size_mb = round(db_file.stat().st_size / (1024 * 1024), 2) if db_file.exists() else 0

    # 2. Sniffer stats
    sniffer_metrics = app_state.sniffer.get_metrics() if app_state.sniffer else {}
    active_iface = app_state.sniffer.interface if app_state.sniffer else settings.NETWORK_INTERFACE

    # 3. Model stats
    model_loaded = app_state.ai_engine.model is not None if app_state.ai_engine else False
    metrics_file = Path(settings.METRICS_PATH)
    metrics_data = {}
    if metrics_file.exists():
        try:
            with open(metrics_file, "r", encoding="utf-8") as f:
                metrics_data = json.load(f)
        except Exception:
            metrics_data = {}

    # 4. Dataset stats
    ds_status = scan_raw_dataset_files()

    return {
        "backend": {
            "status": "ONLINE",
            "version": "1.0.0",
            "framework": "FastAPI + Uvicorn",
            "environment": "Windows 11 Host",
            "database_url": settings.DATABASE_URL
        },
        "frontend": {
            "status": "READY",
            "framework": "React 18 + Tailwind CSS + Recharts",
            "build": "Production (Vite)",
            "websocket_url": "/ws/soc"
        },
        "packet_capture": {
            "is_running": sniffer_metrics.get("is_running", False),
            "interface_id": sniffer_metrics.get("interface", "DEFAULT"),
            "interface_display": sniffer_metrics.get("interface_display", active_iface or "DEFAULT"),
            "total_packets": sniffer_metrics.get("total_packets", 0),
            "tcp_packets": sniffer_metrics.get("tcp_packets", 0),
            "udp_packets": sniffer_metrics.get("udp_packets", 0),
            "active_flows": sniffer_metrics.get("active_flows", 0),
            "completed_flows": sniffer_metrics.get("completed_flows", 0)
        },
        "ai_detection_engine": {
            "status": "LOADED" if model_loaded else "NOT_LOADED",
            "model_type": metrics_data.get("model_type", "Random Forest Classifier"),
            "dataset_trained_on": metrics_data.get("dataset", "CIC-IDS2017"),
            "is_authentic_unb": metrics_data.get("is_authentic_unb", False),
            "accuracy": metrics_data.get("accuracy", 0.0),
            "macro_f1": metrics_data.get("macro_f1", 0.0),
            "macro_fpr": metrics_data.get("false_positive_rate", 0.0),
            "classes": metrics_data.get("classes", []),
            "alert_confidence_threshold": app_state.ai_engine.alert_confidence_threshold if app_state.ai_engine else 0.80,
            "margin_threshold": app_state.ai_engine.margin_threshold if app_state.ai_engine else 0.25,
            "training_date": metrics_data.get("training_date", metrics_data.get("timestamp"))
        },
        "dataset_provenance": {
            "raw_files_detected": ds_status.get("raw_files_count", 0),
            "has_processed_authentic": ds_status.get("has_processed_authentic", False),
            "official_source": ds_status.get("official_info", {}).get("institution", ""),
            "manifest": ds_status.get("manifest", {})
        },
        "database": {
            "engine": "SQLite 3 (WAL mode)",
            "size_mb": db_size_mb,
            "total_network_events": total_events,
            "total_threat_alerts": total_alerts,
            "total_system_logs": total_logs
        },
        "websocket": {
            "endpoint": "/ws/soc",
            "active_connections": len(ws_manager.active_connections),
            "status": "BROADCASTING"
        }
    }


@router.get("/logs")
def list_system_logs(
    limit: int = Query(100, ge=1, le=500),
    level: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieve security audit and operational logs."""
    query = db.query(SystemLog)
    if level:
        query = query.filter(SystemLog.level == level.upper())
    logs = query.order_by(desc(SystemLog.timestamp)).limit(limit).all()

    return [
        {
            "id": l.id,
            "timestamp": l.timestamp.isoformat(),
            "source": l.source,
            "level": l.level,
            "message": l.message
        }
        for l in logs
    ]


@router.get("/logs/download")
def download_system_logs(db: Session = Depends(get_db)):
    """Download forensic security audit logs as a text file."""
    from fastapi.responses import Response
    logs = db.query(SystemLog).order_by(desc(SystemLog.timestamp)).limit(1000).all()
    output_lines = [
        "==================================================================",
        "          CYBERSOC IDS / IPS FORENSIC AUDIT LOG EXPORT",
        f"          Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "==================================================================",
        ""
    ]
    for l in logs:
        output_lines.append(f"[{l.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] [{l.level:<7}] [{l.source:<12}] {l.message}")
    
    content = "\n".join(output_lines)
    return Response(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=cybersoc_security_audit.log"}
    )


@router.post("/logs/ingest")
def ingest_auth_log(payload: LogIngestRequest, db: Session = Depends(get_db)):
    """Ingest external syslog/auth log line for SSH brute force detection."""
    from backend.app.main import app_state

    # Save to SystemLog table
    sys_log = SystemLog(source=payload.source or "AUTH_LOG", level="INFO", message=payload.log_line)
    db.add(sys_log)
    db.commit()

    # Pass to rule engine
    alert_created = None
    if app_state.rule_engine:
        alert = app_state.rule_engine.evaluate_auth_log(payload.log_line)
        if alert:
            threat = ThreatAlert(
                title=alert["title"],
                description=alert["description"],
                src_ip=alert["src_ip"],
                dst_ip=alert["dst_ip"],
                dst_port=alert["dst_port"],
                protocol=alert["protocol"],
                detection_type=alert["detection_type"],
                threat_category="BruteForce",
                severity=alert["severity"],
                confidence=1.0,
                status="OPEN",
                details_json=alert.get("details")
            )
            db.add(threat)
            db.commit()
            db.refresh(threat)
            alert_created = alert["title"]

    return {
        "status": "INGESTED",
        "alert_triggered": alert_created is not None,
        "alert_title": alert_created
    }


@router.get("/settings")
def get_system_settings():
    """Retrieve system settings, available interfaces, and sniffer state."""
    from backend.app.main import app_state

    interfaces = list_available_interfaces()
    sniffer_metrics = app_state.sniffer.get_metrics() if app_state.sniffer else {}
    active_iface_id = app_state.sniffer.interface if (app_state.sniffer and app_state.sniffer.interface) else (settings.NETWORK_INTERFACE or "DEFAULT")

    return {
        "network_interface": active_iface_id,
        "interface_display": sniffer_metrics.get("interface_display", active_iface_id),
        "available_interfaces": interfaces,
        "sniffer_status": sniffer_metrics,
        "flow_timeout": settings.FLOW_TIMEOUT,
        "anomaly_threshold": settings.ANOMALY_THRESHOLD,
        "ml_alert_confidence_threshold": app_state.ai_engine.alert_confidence_threshold if app_state.ai_engine else settings.ML_ALERT_CONFIDENCE_THRESHOLD,
        "ml_probability_margin_threshold": app_state.ai_engine.margin_threshold if app_state.ai_engine else settings.ML_PROBABILITY_MARGIN_THRESHOLD,
        "port_scan_threshold": settings.PORT_SCAN_THRESHOLD,
        "port_scan_window_seconds": settings.PORT_SCAN_WINDOW_SECONDS,
        "syn_flood_threshold": settings.SYN_FLOOD_THRESHOLD,
        "ssh_failure_threshold": settings.SSH_FAILURE_THRESHOLD
    }


@router.post("/settings")
def update_system_settings(payload: SettingsUpdateRequest):
    """Update operational parameters and sniffer state."""
    from backend.app.main import app_state

    if payload.network_interface is not None:
        new_iface = None if payload.network_interface == "DEFAULT" else payload.network_interface
        settings.NETWORK_INTERFACE = new_iface
        if app_state.sniffer:
            app_state.sniffer.switch_interface(new_iface)

    if payload.ml_alert_confidence_threshold is not None:
        settings.ML_ALERT_CONFIDENCE_THRESHOLD = payload.ml_alert_confidence_threshold
        if app_state.ai_engine:
            app_state.ai_engine.alert_confidence_threshold = payload.ml_alert_confidence_threshold

    if payload.ml_probability_margin_threshold is not None:
        settings.ML_PROBABILITY_MARGIN_THRESHOLD = payload.ml_probability_margin_threshold
        if app_state.ai_engine:
            app_state.ai_engine.margin_threshold = payload.ml_probability_margin_threshold

    if payload.flow_timeout is not None:
        settings.FLOW_TIMEOUT = payload.flow_timeout
        if app_state.flow_aggregator:
            app_state.flow_aggregator.flow_timeout = payload.flow_timeout

    if payload.anomaly_threshold is not None:
        settings.ANOMALY_THRESHOLD = payload.anomaly_threshold

    if payload.port_scan_threshold is not None:
        settings.PORT_SCAN_THRESHOLD = payload.port_scan_threshold
        if app_state.rule_engine:
            app_state.rule_engine.port_scan_detector.threshold = payload.port_scan_threshold

    # Toggle sniffer
    if payload.sniffer_running is not None and app_state.sniffer:
        if payload.sniffer_running and not app_state.sniffer.is_running:
            app_state.sniffer.start()
        elif not payload.sniffer_running and app_state.sniffer.is_running:
            app_state.sniffer.stop()

    return {"status": "UPDATED", "settings": get_system_settings()}


# ==========================================
# 1. Active Defense & IPS Firewall Endpoints
# ==========================================

@router.get("/defense/blocked-ips")
def get_blocked_ips():
    """Retrieve all attacker IPs currently isolated by Windows Firewall."""
    return {
        "auto_block_enabled": active_defense_manager.auto_block_enabled,
        "default_duration": active_defense_manager.default_block_duration,
        "blocked_ips": active_defense_manager.list_blocked_ips()
    }


@router.post("/defense/block")
def block_attacker_ip(payload: BlockIpRequest):
    """Manually isolate an attacker IP address at the host firewall level."""
    res = active_defense_manager.block_ip(
        ip=payload.ip,
        reason=payload.reason or "Manual block by SOC operator",
        duration_seconds=payload.duration_seconds,
        threat_category=payload.threat_category or "Threat"
    )
    return res


@router.post("/defense/unblock")
def unblock_attacker_ip(payload: UnblockIpRequest):
    """Remove firewall isolation rule for an IP address."""
    return active_defense_manager.unblock_ip(payload.ip)


@router.post("/defense/toggle-auto-block")
def toggle_auto_block(enabled: bool = Query(...)):
    """Toggle automated firewall isolation for high-confidence threats."""
    active_defense_manager.auto_block_enabled = enabled
    return {
        "status": "UPDATED",
        "auto_block_enabled": active_defense_manager.auto_block_enabled
    }


# ==========================================
# 2. Threat Intelligence & GeoIP Resolver
# ==========================================

@router.get("/intel/ip/{ip}")
def get_threat_intelligence(ip: str):
    """Enrich IP address with country, city, ISP/ASN, and reputation score."""
    return get_ip_intel(ip)


# ==========================================
# 3. AI Explainability (XAI)
# ==========================================

@router.get("/ml/explain/{alert_id}")
def explain_alert(alert_id: int, db: Session = Depends(get_db)):
    """Explain why the Random Forest model flagged a specific alert as an attack."""
    alert = db.query(ThreatAlert).filter(ThreatAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Match corresponding flow record if available
    event = (
        db.query(NetworkEvent)
        .filter(
            NetworkEvent.src_ip == alert.src_ip,
            NetworkEvent.dst_ip == alert.dst_ip
        )
        .order_by(desc(NetworkEvent.id))
        .first()
    )

    flow_dict = {}
    if event:
        flow_dict = {
            "flow_duration": event.flow_duration,
            "flow_pkts_per_sec": event.packets_per_sec,
            "flow_bytes_per_sec": event.bytes_per_sec,
            "total_fwd_packets": event.total_packets,
            "prediction": event.prediction,
            "confidence": event.confidence
        }
    else:
        flow_dict = {
            "flow_duration": 1200.0 if alert.threat_category == "PortScan" else 4500000.0,
            "flow_pkts_per_sec": 850.0 if alert.threat_category == "DoS" else 30.0,
            "syn_flag_cnt": 15.0 if alert.threat_category == "PortScan" else 1.0,
            "prediction": alert.threat_category,
            "confidence": alert.confidence
        }

    ai_res = {
        "prediction": alert.threat_category,
        "confidence": alert.confidence,
        "probabilities": alert.details_json if isinstance(alert.details_json, dict) else {}
    }

    explanation = explain_flow_prediction(flow_dict, ai_res)
    explanation["alert_id"] = alert.id
    explanation["alert_title"] = alert.title
    explanation["src_ip"] = alert.src_ip
    explanation["dst_ip"] = alert.dst_ip
    explanation["dst_port"] = alert.dst_port
    return explanation


# ==========================================
# 4. Executive Incident Report Exporter
# ==========================================

@router.get("/reports/incident-summary", response_class=HTMLResponse)
def export_incident_report(db: Session = Depends(get_db)):
    """Generate printable HTML & PDF forensic audit report."""
    metrics_file = Path(settings.METRICS_PATH)
    metrics_data = {}
    if metrics_file.exists():
        try:
            with open(metrics_file, "r", encoding="utf-8") as f:
                metrics_data = json.load(f)
        except Exception:
            metrics_data = {}

    html_content = generate_executive_html_report(db, metrics_data)
    return HTMLResponse(content=html_content)


# ==========================================
# 5. Real-Time Webhook Notifications
# ==========================================

@router.post("/notifications/config")
def configure_notifications(payload: WebhookConfigRequest):
    """Configure external webhook for Discord / Telegram / Slack alerts."""
    notification_dispatcher.configure(
        webhook_url=payload.webhook_url,
        enabled=payload.enabled if payload.enabled is not None else True,
        alert_on_severity=payload.alert_on_severity or "CRITICAL"
    )
    return {
        "status": "CONFIGURED",
        "enabled": notification_dispatcher.enabled,
        "alert_on_severity": notification_dispatcher.alert_on_severity
    }


@router.post("/notifications/test")
def test_notification():
    """Send test alert to configured webhook or return live preview."""
    sample_alert = {
        "title": "Test SOC Intrusion Alert: PortScan Simulation",
        "severity": "HIGH",
        "src_ip": "198.51.100.23",
        "threat_category": "PortScan",
        "description": "Simulated multi-port horizontal sweep probe detected across 20 ports.",
        "detection_type": "RULE_BASED"
    }
    if notification_dispatcher.enabled and notification_dispatcher.webhook_url:
        return notification_dispatcher.send_alert(sample_alert)
    return {
        "status": "SIMULATED",
        "message": "Webhook test simulated successfully (set webhook_url in Settings to deliver to live Discord/Telegram).",
        "payload": sample_alert
    }


# ==========================================
# 6. Web Application Attack Scanner & Auditor
# ==========================================

@router.post("/scanner/audit")
def run_web_security_audit(req: WebScanRequest):
    """Conduct defensive web attack scanning, OWASP security header audit and exposure testing."""
    if not req.target_url or not req.target_url.strip():
        raise HTTPException(status_code=400, detail="Target URL cannot be empty")
    
    result = audit_website(
        target_url=req.target_url.strip(),
        check_exposures=req.check_exposures if req.check_exposures is not None else True,
        test_waf=req.test_waf if req.test_waf is not None else True
    )
    return result


@router.post("/scanner/record-alert")
def record_web_scan_alert(req: WebScanRecordAlertRequest, db: Session = Depends(get_db)):
    """Record a critical finding from web attack scanning directly into the SOC Threat Alert database."""
    from urllib.parse import urlparse
    import socket

    parsed = urlparse(req.target_url)
    hostname = parsed.hostname or "127.0.0.1"
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except Exception:
        resolved_ip = "127.0.0.1"

    alert = ThreatAlert(
        title=req.title,
        severity=req.severity.upper() if req.severity else "HIGH",
        status="OPEN",
        src_ip=resolved_ip,
        dst_ip=settings.HOST,
        dst_port=parsed.port or (443 if parsed.scheme == "https" else 80),
        threat_category=req.category or "Web Attack",
        detection_type="RULE_BASED",
        confidence=0.95,
        description=req.description,
        details_json={
            "target_url": req.target_url,
            "evidence": req.evidence,
            "remediation": req.remediation,
            "origin": "CyberSOC Web Attack Scanner"
        }
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    # Dispatch notification if critical/high
    notification_dispatcher.send_alert({
        "title": alert.title,
        "severity": alert.severity,
        "src_ip": alert.src_ip,
        "threat_category": alert.threat_category,
        "description": alert.description,
        "detection_type": alert.detection_type
    })

    return {
        "success": True,
        "message": f"Security finding recorded as Threat Alert #{alert.id}",
        "alert_id": alert.id
    }


