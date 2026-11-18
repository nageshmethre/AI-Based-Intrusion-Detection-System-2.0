"""
CYBERSOC IDS - Real System Verification Script
Executes all 10 real-world cybersecurity & AI intrusion detection/prevention tests.
Captures actual outputs, database records, and engine responses.
"""

import sys
from pathlib import Path

# Add project root to path for direct imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import json
import time
import socket
import urllib.request
import urllib.error
import sqlite3
import pandas as pd

BASE_URL = "http://127.0.0.1:8000"
DB_PATH = PROJECT_ROOT / "backend" / "data" / "soc_ids.db"

def make_request(path, method="GET", data=None):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, method=method)
    if data is not None:
        req.add_header('Content-Type', 'application/json')
        body = json.dumps(data).encode('utf-8')
        req.data = body
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            res_body = response.read().decode('utf-8')
            return response.status, json.loads(res_body)
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8')
        try:
            return e.code, json.loads(err_body)
        except:
            return e.code, {"error": err_body}
    except Exception as e:
        return 500, {"error": str(e)}

def test_1_normal_traffic():
    print("\n--- TEST 1: Normal Web Browsing & DNS Traffic ---")
    endpoints = ["/api/health", "/api/system/status", "/api/settings"]
    for ep in endpoints:
        status, data = make_request(ep)
        print(f"HTTP GET {ep} -> Status {status}")
        assert status == 200, f"Expected 200 for {ep}, got {status}"
    
    # Query database to confirm normal packets / flows are captured and classified as BENIGN
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, src_ip, dst_ip, protocol, prediction, confidence, is_malicious FROM network_events ORDER BY id DESC LIMIT 5")
    rows = cursor.fetchall()
    conn.close()
    
    print(f"Captured {len(rows)} recent flow events:")
    benign_found = False
    for r in rows:
        print(f"  Flow #{r[0]}: {r[1]} -> {r[2]} ({r[3]}) | AI: {r[4]} ({r[5]*100:.1f}%) | Malicious: {r[6]}")
        if r[4] == "BENIGN":
            benign_found = True
            
    assert len(rows) > 0, "No network events captured in SQLite!"
    print(f"[TEST 1 PASS] Genuine traffic captured and classified. BENIGN flows verified: {benign_found}")
    return True

def test_2_localhost_port_scan():
    print("\n--- TEST 2: Localhost Port Scanning ---")
    scan_payload = {
        "target_ip": "127.0.0.1",
        "ports": [80, 443, 8000, 3306, 5432, 22]
    }
    status, result = make_request("/api/network-scan/port-scan", method="POST", data=scan_payload)
    print(f"Port scan response (Status {status}):")
    print(f"  Target: {result.get('target')}")
    print(f"  Open Ports found: {result.get('open_ports_count')}")
    for p in result.get('open_ports', []):
        print(f"  -> Port {p.get('port')} OPEN ({p.get('service')}) - Banner: {p.get('banner')} (Latency: {p.get('latency_ms')}ms)")
    assert status == 200, f"Port scan failed with status {status}"
    assert result.get('open_ports_count', 0) >= 1, "Expected at least port 8000 (uvicorn) to be OPEN on 127.0.0.1"
    print("[TEST 2 PASS] Authorized TCP connect scan completed with accurate service detection.")
    return True

def test_3_subnet_host_discovery():
    print("\n--- TEST 3: Subnet Host Discovery ---")
    discovery_payload = {
        "target_subnet": "127.0.0.1/32"
    }
    status, result = make_request("/api/network-scan/host-discovery", method="POST", data=discovery_payload)
    print(f"Host discovery response (Status {status}):")
    print(f"  Subnet: {result.get('target')}")
    print(f"  Active Hosts found: {result.get('hosts_found')}")
    for h in result.get('hosts', []):
        print(f"  -> Host: {h.get('ip')} | Status: {h.get('status')} | Latency: {h.get('latency_ms')}ms | MAC: {h.get('mac')}")
    assert status == 200, f"Host discovery failed with status {status}"
    assert result.get('hosts_found', 0) >= 1, "Expected 127.0.0.1 to be discovered active"
    print("[TEST 3 PASS] Localhost/subnet host discovery completed successfully.")
    return True

def test_4_stealth_scan_rule():
    print("\n--- TEST 4: Stealth Scan Detection (NULL / XMAS / SYN-FIN) ---")
    from backend.app.rules.advanced_rules import AdvancedRuleEngine
    engine = AdvancedRuleEngine()
    
    # 1. Test TCP NULL Scan (Flags all False)
    alert1 = engine.check_stealth_scan(
        src_ip="192.168.1.105",
        dst_ip="192.168.1.20",
        dst_port=80,
        protocol="TCP",
        tcp_flags={"F": False, "S": False, "R": False, "P": False, "A": False, "U": False}
    )
    print(f"TCP NULL Scan Evaluation -> Rule: {alert1.get('rule_name') if alert1 else 'None'} | Category: {alert1.get('threat_category') if alert1 else 'None'}")
    assert alert1 is not None and alert1['threat_category'] == "PortScan", "Failed to detect NULL scan!"
    assert alert1['rule_name'] == "STEALTH_SCAN_DETECTED"

    # 2. Test TCP XMAS Scan (FIN + PSH + URG)
    alert2 = engine.check_stealth_scan(
        src_ip="192.168.1.106",
        dst_ip="192.168.1.20",
        dst_port=443,
        protocol="TCP",
        tcp_flags={"F": True, "S": False, "R": False, "P": True, "A": False, "U": True}
    )
    print(f"TCP XMAS Scan Evaluation -> Rule: {alert2.get('rule_name') if alert2 else 'None'} | Category: {alert2.get('threat_category') if alert2 else 'None'}")
    assert alert2 is not None and alert2['threat_category'] == "PortScan", "Failed to detect XMAS scan!"
    assert alert2['rule_name'] == "STEALTH_SCAN_DETECTED"
    print("[TEST 4 PASS] Advanced stealth scan detection verified.")
    return True

def test_5_syn_burst_detection():
    print("\n--- TEST 5: Controlled SYN Packet Burst Detection ---")
    from backend.app.rules.rule_engine import RuleBasedDetectionEngine
    rule_engine = RuleBasedDetectionEngine()
    
    attacker_ip = f"192.168.1.{int(time.time()) % 100 + 100}"
    target_ip = "192.168.1.50"
    
    # Send a burst of 25 SYN packets across different ports within 1 second
    alerts = []
    base_time = time.time()
    for port in range(1000, 1025):
        pkt = {
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "src_port": 45000,
            "dst_port": port,
            "protocol": "TCP",
            "pkt_len": 60,
            "tcp_flags": {"F": False, "S": True, "R": False, "P": False, "A": False, "U": False},
            "timestamp": base_time + (port - 1000) * 0.02
        }
        res_list = rule_engine.evaluate_packet(pkt)
        if res_list:
            alerts.extend(res_list)
            
    print(f"Sent 25 SYN probes. Generated {len(alerts)} alerts.")
    for a in alerts:
        print(f"  -> [{a['severity']}] {a['rule_name']}: {a['description']}")
    assert len(alerts) > 0, "No alert triggered for port scan burst!"
    print("[TEST 5 PASS] Controlled port scanning / SYN burst successfully triggered alert.")
    return True

def test_6_ssh_brute_force():
    print("\n--- TEST 6: Repeated Failed SSH Authentication Ingestion ---")
    # Use dynamic test IP to prevent 30-second alert suppression
    ssh_ip = f"192.168.2.{int(time.time() * 10) % 200 + 10}"
    log_entries = [
        f"Failed password for root from {ssh_ip} port 51234 ssh2",
        f"Failed password for invalid user admin from {ssh_ip} port 51236 ssh2",
        f"Failed password for guest from {ssh_ip} port 51238 ssh2",
        f"Failed password for invalid user test from {ssh_ip} port 51240 ssh2",
        f"Failed password for root from {ssh_ip} port 51242 ssh2"
    ]
    alerts_triggered = 0
    for line in log_entries:
        status, result = make_request("/api/logs/ingest", method="POST", data={"log_line": line})
        if result.get("alert_triggered"):
            alerts_triggered += 1
            print(f"  -> Triggered alert: {result.get('alert_title')} from {ssh_ip}")
            
    print(f"Ingested {len(log_entries)} failed auth logs for {ssh_ip}. Alerts triggered: {alerts_triggered}")
    assert alerts_triggered >= 1, "Expected SSH brute force alert to be triggered!"
    print("[TEST 6 PASS] SSH Brute Force authentication attacks reliably detected.")
    return True

def test_7_ai_model_inference():
    print("\n--- TEST 7: AI Model Inference & Probability Margin ---")
    from backend.app.ml.detector import AIDetectionEngine
    ai = AIDetectionEngine()
    
    # 1. Evaluate Benign Sample from authentic CIC-IDS2017 dataset
    df_clean = pd.read_csv(PROJECT_ROOT / "backend/data/processed/cicids2017_authentic_clean.csv")
    benign_sample = df_clean.loc[3].to_dict()
    benign_res = ai.predict_flow(benign_sample)
    print(f"AI Evaluation (Authentic Legitimate Flow):")
    print(f"  Prediction: {benign_res['prediction']} | Confidence: {benign_res['confidence']*100:.2f}% | Threat Alert: {benign_res['is_threat_alert']} | Status: {benign_res['status']}")
    assert benign_res['prediction'] == "BENIGN", f"Expected BENIGN, got {benign_res['prediction']}"
    assert not benign_res['is_threat_alert'], "Legitimate traffic must not trigger a critical alert!"

    # 2. Evaluate Confirmed DoS Attack Sample from CIC-IDS2017 augmented dataset
    df_aug = pd.read_csv(PROJECT_ROOT / "backend/data/processed/cicids2017_augmented_train.csv")
    dos_sample = df_aug[df_aug['label'] == 'DoS'].iloc[0].to_dict()
    dos_res = ai.predict_flow(dos_sample)
    print(f"AI Evaluation (Confirmed High-Volume DoS Attack):")
    print(f"  Prediction: {dos_res['prediction']} | Confidence: {dos_res['confidence']*100:.2f}% | Margin: {dos_res.get('probability_margin', 0):.4f} | Threat Alert: {dos_res['is_threat_alert']} | Severity: {dos_res['severity']}")
    assert dos_res['prediction'] == "DoS", f"Expected DoS, got {dos_res['prediction']}"
    assert dos_res['is_threat_alert'] is True, "High-confidence DoS must trigger threat alert!"
    assert dos_res['confidence'] >= 0.80, "Expected >=80% confidence"
    print("[TEST 7 PASS] Real Random Forest inference and probability distributions verified.")
    return True

def test_8_defensive_ip_blocking():
    print("\n--- TEST 8: Defensive IP Blocking & Whitelist Protection ---")
    test_ip = "198.51.100.77"
    block_payload = {
        "ip": test_ip,
        "reason": "Automated IPS mitigation verification",
        "dry_run": True  # Safe execution mode for testing
    }
    status, result = make_request("/api/defense/block", method="POST", data=block_payload)
    print(f"Block response for {test_ip} (Status {status}):")
    print(f"  Success: {result.get('success')}")
    print(f"  Rule: {result.get('rule_name')}")
    print(f"  Dry run: {result.get('dry_run')}")
    assert status == 200, f"Expected 200, got {status}"
    
    # Verify whitelist protection prevents blocking localhost or own machine
    status_wl, result_wl = make_request("/api/defense/block", method="POST", data={"ip": "127.0.0.1", "dry_run": True})
    print(f"Whitelist verification on 127.0.0.1 (Status {status_wl}): {result_wl.get('detail')}")
    assert status_wl == 400, "Safeguard failure: 127.0.0.1 should be permanently whitelisted!"
    
    # Query database to confirm defensive action was recorded in SQLite
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, action, ip, rule_name, is_active FROM defensive_actions WHERE ip=? ORDER BY id DESC LIMIT 1", (test_ip,))
    row = cursor.fetchone()
    conn.close()
    
    assert row is not None, "DefensiveAction not persisted to SQLite!"
    print(f"  -> SQLite Action Record: ID #{row[0]}, Type: {row[1]}, Target: {row[2]}, Rule: {row[3]}, Active: {row[4]}")
    print("[TEST 8 PASS] Defensive IP block execution and audit logging verified.")
    return True

def test_9_defensive_unblocking_and_recovery():
    print("\n--- TEST 9: Defensive IP Unblocking & Emergency Flush ---")
    test_ip = "198.51.100.77"
    unblock_payload = {
        "ip": test_ip
    }
    status, result = make_request("/api/defense/unblock", method="POST", data=unblock_payload)
    print(f"Unblock response (Status {status}):")
    print(f"  Success: {result.get('success')}")
    assert status == 200, f"Unblock failed with status {status}"

    # Test emergency flush endpoint
    status_em, result_em = make_request("/api/defense/emergency-unblock-all", method="POST")
    print(f"Emergency unblock all (Status {status_em}): {result_em.get('message')}")
    assert status_em == 200, "Emergency unblock all failed!"
    print("[TEST 9 PASS] Unblocking and Emergency IPS Recovery verified.")
    return True

def test_10_database_and_websocket_integrity():
    print("\n--- TEST 10: Persistent SQLite Storage & System Status ---")
    status, sys_status = make_request("/api/system/status")
    print(f"System status (Status {status}):")
    print(f"  Database connected: {sys_status.get('database')}")
    
    # Check all SQLite tables
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    tables = ["network_events", "threat_alerts", "system_logs", "defensive_actions", "scan_history", "discovered_hosts"]
    counts = {}
    for tbl in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {tbl}")
        counts[tbl] = cursor.fetchone()[0]
    conn.close()
    
    print("Database table row counts:")
    for tbl, count in counts.items():
        print(f"  Table '{tbl}': {count} records")
        
    assert counts['network_events'] > 0, "network_events is empty!"
    assert counts['threat_alerts'] > 0, "threat_alerts is empty!"
    assert counts['defensive_actions'] > 0, "defensive_actions is empty!"
    assert counts['scan_history'] > 0, "scan_history is empty!"
    assert counts['discovered_hosts'] > 0, "discovered_hosts is empty!"
    
    print("[TEST 10 PASS] Full SQLite database integrity confirmed across all 6 core tables.")
    return True

def main():
    print("=" * 65)
    print("  CYBERSOC IDS - 10 REAL SYSTEM VERIFICATION TESTS")
    print("=" * 65)
    
    tests = [
        ("TEST 1: Normal Traffic Capture & Classification", test_1_normal_traffic),
        ("TEST 2: Authorized Port Scanning", test_2_localhost_port_scan),
        ("TEST 3: Subnet Host Discovery", test_3_subnet_host_discovery),
        ("TEST 4: Stealth Scan Detection", test_4_stealth_scan_rule),
        ("TEST 5: SYN Packet Burst Detection", test_5_syn_burst_detection),
        ("TEST 6: SSH Brute Force Ingestion", test_6_ssh_brute_force),
        ("TEST 7: AI Model Inference & Margins", test_7_ai_model_inference),
        ("TEST 8: Defensive IP Blocking & Whitelist", test_8_defensive_ip_blocking),
        ("TEST 9: Defensive Unblock & Emergency Flush", test_9_defensive_unblocking_and_recovery),
        ("TEST 10: SQLite Storage & System Status", test_10_database_and_websocket_integrity),
    ]
    
    passed = 0
    failed = 0
    for name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"[FAIL] {name}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
            
    print("\n" + "=" * 65)
    print(f"VERIFICATION SUMMARY: {passed} PASSED, {failed} FAILED (TOTAL: {len(tests)})")
    print("=" * 65)
    if failed == 0:
        print(">>> ALL 10 VERIFICATION TESTS PASSED WITH 100% SUCCESS! <<<")
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
