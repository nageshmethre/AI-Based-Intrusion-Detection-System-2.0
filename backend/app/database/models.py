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
