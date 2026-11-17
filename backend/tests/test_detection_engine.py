"""Phase 4 AI Detection Engine & Rule Verification Test."""

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.ml.detector import AIDetectionEngine
from backend.app.rules.port_scan import PortScanDetector
from backend.app.rules.abnormal_conn import AbnormalConnectionDetector
from backend.app.rules.ssh_monitor import SSHAuthMonitor
from backend.app.rules.rule_engine import RuleBasedDetectionEngine
from backend.app.ml.schema import LABEL_BENIGN, LABEL_PORTSCAN, LABEL_DOS
from backend.app.capture.flow import NetworkFlow


def test_ai_detector():
    print("Testing AI Detection Engine with trained Random Forest model...")
    engine = AIDetectionEngine()
    assert engine.is_loaded, "AI Detection Engine failed to load artifacts"

    # Simulate realistic Benign web browsing flow using NetworkFlow aggregator
    now = time.time()
    benign_flow_obj = NetworkFlow("192.168.1.100", 55432, "142.250.190.46", 443, "TCP", now)
    benign_flow_obj.add_packet(True, 60, 32, {"S": True}, 65535, now)
    benign_flow_obj.add_packet(False, 60, 32, {"S": True, "A": True}, 28960, now + 0.02)
    benign_flow_obj.add_packet(True, 450, 32, {"A": True, "P": True}, 65535, now + 0.03)
    benign_flow_obj.add_packet(False, 1460, 32, {"A": True, "P": True}, 28960, now + 0.05)
    benign_flow_obj.add_packet(False, 1460, 32, {"A": True}, 28960, now + 0.06)
    benign_flow_obj.add_packet(True, 54, 32, {"F": True, "A": True}, 65535, now + 0.10)
    
    benign_features = benign_flow_obj.to_feature_dict()
    pred_benign = engine.predict_flow(benign_features)
    assert "prediction" in pred_benign
    assert "confidence" in pred_benign
    assert "probabilities" in pred_benign
    print(f"✓ Benign sample evaluated -> Prediction: {pred_benign['prediction']}, Confidence: {pred_benign['confidence'] * 100:.1f}%, Severity: {pred_benign['severity']}")

    # Simulate PortScan flow: single SYN probe
    scan_flow_obj = NetworkFlow("192.168.1.200", 41234, "10.0.0.1", 22, "TCP", now)
    scan_flow_obj.add_packet(True, 0, 32, {"S": True}, 1024, now)
    scan_flow_obj.add_packet(False, 0, 32, {"R": True}, 0, now + 0.001)

    scan_features = scan_flow_obj.to_feature_dict()
    pred_scan = engine.predict_flow(scan_features)
    print("PortScan prediction output:", pred_scan)
    assert pred_scan["prediction"] == LABEL_PORTSCAN
    assert pred_scan["is_malicious"] is True
    print(f"✓ Malicious PortScan sample evaluated -> Prediction: {pred_scan['prediction']}, Confidence: {pred_scan['confidence'] * 100:.1f}%, Severity: {pred_scan['severity']}")


def test_rule_based_port_scan():
    print("Testing Port Scan rule detector...")
    detector = PortScanDetector(threshold=5, window_seconds=3.0)
    alert = None
    attacker_ip = "192.168.1.77"

    # Send 5 SYN probes to 5 distinct ports
    for p in [21, 22, 23, 80, 443]:
        alert = detector.process_packet(
            src_ip=attacker_ip,
            dst_ip="10.0.0.1",
            dst_port=p,
            protocol="TCP",
            tcp_flags={"S": True}
        )

    assert alert is not None, "Port scan detector failed to trigger alert"
    assert alert["rule_name"] == "PORT_SCAN_DETECTED"
    assert alert["severity"] == "HIGH"
    assert alert["src_ip"] == attacker_ip
    print("✓ Port scan rule alert triggered accurately!")


def test_rule_based_syn_flood():
    print("Testing SYN Flood rule detector...")
    detector = AbnormalConnectionDetector(syn_threshold=10, window_seconds=2.0)
    alert = None
    target_ip = "10.0.0.5"

    for _ in range(12):
        res = detector.process_packet(
            src_ip="192.168.1.88",
            dst_ip=target_ip,
            dst_port=80,
            protocol="TCP",
            tcp_flags={"S": True}
        )
        if res:
            alert = res

    assert alert is not None, "SYN flood detector failed to trigger alert"
    assert alert["rule_name"] == "SYN_FLOOD_SUSPECTED"
    assert alert["severity"] == "CRITICAL"
    print("✓ SYN flood rule alert triggered accurately!")


def test_ssh_auth_failure_monitor():
    print("Testing SSH Authentication Failure Monitor...")
    monitor = SSHAuthMonitor(failure_threshold=3, window_seconds=10.0)
    alert = None
    bad_actor_ip = "10.10.10.99"

    for _ in range(4):
        log_sample = f"Nov 14 14:00:01 soc-host sshd[1234]: Failed password for root from {bad_actor_ip} port 43212 ssh2"
        res = monitor.parse_log_line(log_sample)
        if res:
            alert = res

    assert alert is not None, "SSH monitor failed to trigger alert"
    assert alert["rule_name"] == "SSH_BRUTE_FORCE"
    assert alert["src_ip"] == bad_actor_ip
    print("✓ SSH brute-force rule alert triggered accurately!")


if __name__ == "__main__":
    test_ai_detector()
    test_rule_based_port_scan()
    test_rule_based_syn_flood()
    test_ssh_auth_failure_monitor()
    print("\n--- Phase 4 Verification Passed Successfully! ---")
