"""SOC Executive Incident Report Exporter.

Generates comprehensive, audit-ready HTML & printable forensic incident reports
summarizing network inspection sessions, AI model evaluations, threat classifications,
and active defense firewall mitigations.
"""

from datetime import datetime
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from backend.app.database.models import NetworkEvent, ThreatAlert, SystemLog
from backend.app.defense.firewall import active_defense_manager


def generate_executive_html_report(db: Session, metrics_data: Dict[str, Any]) -> str:
    """Generate professional printable HTML audit report."""
    total_events = db.query(func.count(NetworkEvent.id)).scalar() or 0
    malicious_events = db.query(func.count(NetworkEvent.id)).filter(NetworkEvent.is_malicious == True).scalar() or 0
    total_alerts = db.query(func.count(ThreatAlert.id)).scalar() or 0
    critical_alerts = db.query(func.count(ThreatAlert.id)).filter(ThreatAlert.severity == "CRITICAL").scalar() or 0
    high_alerts = db.query(func.count(ThreatAlert.id)).filter(ThreatAlert.severity == "HIGH").scalar() or 0

    # Top Attacker IPs
    top_attackers = (
        db.query(ThreatAlert.src_ip, func.count(ThreatAlert.id).label("cnt"))
        .group_by(ThreatAlert.src_ip)
        .order_by(desc("cnt"))
        .limit(5)
        .all()
    )

    # Recent Alerts
    recent_threats = (
        db.query(ThreatAlert)
        .order_by(desc(ThreatAlert.id))
        .limit(10)
        .all()
    )

    # Active Blocked IPs from Defense Manager
    blocked_ips = active_defense_manager.list_blocked_ips()

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CyberSOC IDS - Executive Incident Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 40px; }}
        .header {{ border-bottom: 2px solid #1e293b; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: flex-end; }}
        .title {{ font-size: 24px; font-weight: bold; color: #38bdf8; text-transform: uppercase; letter-spacing: 1px; }}
        .subtitle {{ font-size: 13px; color: #94a3b8; margin-top: 4px; }}
        .meta {{ text-align: right; font-size: 12px; color: #64748b; font-family: monospace; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 30px; }}
        .card {{ background: #131b2e; border: 1px solid #1e293b; border-radius: 10px; padding: 18px; }}
        .card-label {{ font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: bold; }}
        .card-val {{ font-size: 26px; font-weight: bold; font-family: monospace; color: #fff; margin-top: 6px; }}
        .card-sub {{ font-size: 11px; color: #64748b; margin-top: 4px; }}
        h2 {{ font-size: 16px; text-transform: uppercase; letter-spacing: 0.5px; color: #f8fafc; border-bottom: 1px solid #1e293b; padding-bottom: 8px; margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }}
        th {{ background: #1e293b; color: #94a3b8; text-align: left; padding: 10px 12px; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #1e293b; font-family: monospace; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: bold; }}
        .badge-crit {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }}
        .badge-ips {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }}
        .print-btn {{ background: #2563eb; color: #fff; border: none; padding: 10px 20px; border-radius: 6px; font-weight: bold; cursor: pointer; float: right; margin-bottom: 20px; }}
        @media print {{
            .print-btn {{ display: none; }}
            body {{ background: #fff; color: #000; padding: 0; }}
            .card {{ border: 1px solid #ccc; background: #fafafa; }}
            .card-val {{ color: #000; }}
            th {{ background: #eee; color: #000; }}
            td {{ color: #000; border-bottom: 1px solid #eee; }}
        }}
    </style>
</head>
<body>
    <button class="print-btn" onclick="window.print()">Print / Save as PDF</button>

    <div class="header">
        <div>
            <div class="title">CyberSOC IDS & IPS - Incident Forensic Audit Report</div>
            <div class="subtitle">Real-Time Threat Detection, AI Evaluation & Active Host Defense Summary</div>
        </div>
        <div class="meta">
            Generated: {now_str}<br>
            Environment: Windows 11 Enterprise Host<br>
            Engine: Random Forest + Rule Correlator
        </div>
    </div>

    <!-- Executive Overview Metrics -->
    <div class="grid">
        <div class="card">
            <div class="card-label">Total Flows Inspected</div>
            <div class="card-val" style="color: #38bdf8;">{total_events:,}</div>
            <div class="card-sub">Bidirectional 5-tuple sessions</div>
        </div>
        <div class="card">
            <div class="card-label">Anomalous / Attack Flows</div>
            <div class="card-val" style="color: #f87171;">{malicious_events:,}</div>
            <div class="card-sub">{((malicious_events / max(total_events, 1)) * 100):.2f}% of monitored traffic</div>
        </div>
        <div class="card">
            <div class="card-label">Security Incidents Triggered</div>
            <div class="card-val" style="color: #fb923c;">{total_alerts:,}</div>
            <div class="card-sub">{critical_alerts} Critical / {high_alerts} High</div>
        </div>
        <div class="card">
            <div class="card-label">AI Model Test Accuracy</div>
            <div class="card-val" style="color: #34d399;">{((metrics_data.get('accuracy', 0.0)) * 100):.2f}%</div>
            <div class="card-sub">Macro F1: {((metrics_data.get('macro_f1', 0.0)) * 100):.2f}% | FPR: {((metrics_data.get('false_positive_rate', 0.0)) * 100):.3f}%</div>
        </div>
    </div>

    <!-- Active Defense & Isolated IPs -->
    <h2>1. Active Defense & IPS Mitigations (Firewall Isolation)</h2>
    <p style="font-size: 12px; color: #94a3b8;">Attacking hosts actively blocked via Windows Firewall netsh rules:</p>
    <table>
        <thead>
            <tr>
                <th>Attacker IP</th>
                <th>Isolation Reason</th>
                <th>Threat Category</th>
                <th>Blocked At</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {"".join(f'''<tr>
                <td><strong>{b["ip"]}</strong></td>
                <td>{b["reason"]}</td>
                <td>{b["threat_category"]}</td>
                <td>{b["blocked_at"][:19]}</td>
                <td><span class="badge badge-ips">FIREWALL BLOCKED</span></td>
            </tr>''' for b in blocked_ips) if blocked_ips else '<tr><td colspan="5" style="text-align: center; color: #64748b;">No hosts currently isolated by IPS.</td></tr>'}
        </tbody>
    </table>

    <!-- Top Attacker IPs -->
    <h2>2. Top Attacking Source Hosts</h2>
    <table>
        <thead>
            <tr>
                <th>Source IP Address</th>
                <th>Total Incident Alerts Generated</th>
                <th>Threat Profile</th>
                <th>Action Recommended</th>
            </tr>
        </thead>
        <tbody>
            {"".join(f'''<tr>
                <td><strong>{a[0]}</strong></td>
                <td>{a[1]} incidents</td>
                <td>High-Volume Threat Vector</td>
                <td><span class="badge badge-crit">ISOLATE / BLOCK</span></td>
            </tr>''' for a in top_attackers) if top_attackers else '<tr><td colspan="4" style="text-align: center; color: #64748b;">No attacking IPs logged.</td></tr>'}
        </tbody>
    </table>

    <!-- Recent Incident Alerts -->
    <h2>3. Verified Security Incident Log (Sample)</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Threat Title</th>
                <th>Source IP</th>
                <th>Destination</th>
                <th>Engine</th>
                <th>Severity</th>
            </tr>
        </thead>
        <tbody>
            {"".join(f'''<tr>
                <td>#{t.id}</td>
                <td>{t.timestamp.strftime("%H:%M:%S")}</td>
                <td><strong>{t.title}</strong></td>
                <td>{t.src_ip}</td>
                <td>{t.dst_ip}:{t.dst_port} ({t.protocol})</td>
                <td>{t.detection_type}</td>
                <td><span class="badge {'badge-crit' if t.severity == 'CRITICAL' else 'badge-high'}">{t.severity}</span></td>
            </tr>''' for t in recent_threats) if recent_threats else '<tr><td colspan="7" style="text-align: center; color: #64748b;">No recent alerts.</td></tr>'}
        </tbody>
    </table>

    <div style="margin-top: 50px; border-top: 1px solid #1e293b; padding-top: 15px; font-size: 11px; color: #64748b; text-align: center;">
        CyberSOC Real-Time AI Intrusion Detection System &bull; MCA Major Academic Project &bull; Verified Evaluation Report
    </div>
</body>
</html>
"""
    return html
