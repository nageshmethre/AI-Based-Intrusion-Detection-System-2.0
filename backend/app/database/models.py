"""SQLAlchemy ORM models for SQLite database."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, JSON
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class NetworkEvent(Base):
    """Network flow events captured and analyzed."""
    __tablename__ = "network_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip = Column(String(45), index=True, nullable=False)
    dst_ip = Column(String(45), index=True, nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, index=True, nullable=False)
    protocol = Column(String(10), index=True, nullable=False)
    
    # Traffic metrics
    flow_duration = Column(Float, default=0.0)
    total_packets = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    bytes_per_sec = Column(Float, default=0.0)
    packets_per_sec = Column(Float, default=0.0)

    # ML Analysis
    prediction = Column(String(50), index=True, default="BENIGN")
    confidence = Column(Float, default=0.0)
    is_malicious = Column(Boolean, index=True, default=False)
    severity = Column(String(20), index=True, default="INFO")
    
    # Raw feature dump / explainability
    features_json = Column(JSON, nullable=True)


class ThreatAlert(Base):
    """Security alerts triggered by ML model or deterministic rules."""
    __tablename__ = "threat_alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    
    # Attacker / Target
    src_ip = Column(String(45), index=True, nullable=False)
    dst_ip = Column(String(45), index=True, nullable=False)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)

    # Classification
    detection_type = Column(String(30), index=True, nullable=False)  # MACHINE_LEARNING or RULE_BASED
    threat_category = Column(String(50), index=True, nullable=False) # PortScan, DoS, BruteForce, Botnet, etc.
    severity = Column(String(20), index=True, nullable=False)        # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, default=1.0)
    
    # Remediation / SOC workflow
    status = Column(String(20), index=True, default="OPEN")         # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    details_json = Column(JSON, nullable=True)


class SystemLog(Base):
    """Security and operational audit logs."""
    __tablename__ = "system_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String(50), default="SYSTEM")
    level = Column(String(20), default="INFO")
    message = Column(Text, nullable=False)


class DefensiveAction(Base):
    """Audit log of all Windows Defender Firewall defensive actions (blocks & unblocks)."""
    __tablename__ = "defensive_actions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ip = Column(String(45), index=True, nullable=False)
    action = Column(String(20), nullable=False)  # BLOCK, UNBLOCK, DRY_RUN
    rule_name = Column(String(100), nullable=False)
    threat_category = Column(String(50), default="General Attack")
    reason = Column(Text, nullable=False)
    duration_seconds = Column(Integer, default=300)
    is_active = Column(Boolean, default=True)
    firewall_success = Column(Boolean, default=False)
    admin_user = Column(String(50), default="SOC_Analyst")
    unblocked_at = Column(DateTime, nullable=True)


class ScanHistory(Base):
    """History of authorized network inventory and vulnerability port scans."""
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    target = Column(String(100), nullable=False)
    scan_type = Column(String(50), nullable=False)  # HOST_DISCOVERY, TCP_PORT_SCAN, SYN_SCAN
    hosts_found = Column(Integer, default=0)
    open_ports_count = Column(Integer, default=0)
    status = Column(String(20), default="COMPLETED")
    summary_json = Column(JSON, nullable=True)


class DiscoveredHost(Base):
    """Inventory of discovered local network hosts and their open ports."""
    __tablename__ = "discovered_hosts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    scan_id = Column(Integer, index=True, nullable=True)
    ip = Column(String(45), index=True, nullable=False)
    mac = Column(String(30), nullable=True)
    hostname = Column(String(100), nullable=True)
    is_alive = Column(Boolean, default=True)
    latency_ms = Column(Float, default=0.0)
    open_ports_json = Column(JSON, nullable=True)  # List of {port, service, banner, state}
