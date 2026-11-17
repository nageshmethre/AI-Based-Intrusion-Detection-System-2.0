"""Comprehensive Master Test Suite for AI-Based Network Intrusion Detection System."""

import sys
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

TEST_SUITES = [
    ("Phase 1: Environment & Dependencies", PROJECT_ROOT / "backend" / "tests" / "test_environment.py"),
    ("Phase 2: ML Pipeline & CIC-IDS2017 Model", PROJECT_ROOT / "backend" / "tests" / "test_ml_pipeline.py"),
    ("Phase 3: Network Capture & Flow Aggregation", PROJECT_ROOT / "backend" / "tests" / "test_capture_and_flows.py"),
    ("Phase 4: AI Detection & Rule Engines", PROJECT_ROOT / "backend" / "tests" / "test_detection_engine.py"),
    ("Phase 5: FastAPI REST API & SQLite DB", PROJECT_ROOT / "backend" / "tests" / "test_api_and_db.py"),
    ("Phase 7: Real-Time WebSockets Manager", PROJECT_ROOT / "backend" / "tests" / "test_websockets.py"),
]

def run_all():
    print("=" * 70)
    print("  AI-BASED NETWORK INTRUSION DETECTION SYSTEM - TEST SUITE")
    print("=" * 70)

    total = len(TEST_SUITES)
    passed = 0

    for idx, (name, path) in enumerate(TEST_SUITES, 1):
        print(f"\n[{idx}/{total}] Running: {name}")
        print("-" * 50)
        res = subprocess.run([sys.executable, str(path)], cwd=str(PROJECT_ROOT))
        if res.returncode == 0:
            passed += 1
            print(f"✓ {name}: PASSED")
        else:
            print(f"✗ {name}: FAILED (Code {res.returncode})")

    print("\n" + "=" * 70)
    print(f"  TEST SUMMARY: {passed}/{total} Test Suites Passed ({passed/total*100:.1f}%)")
    print("=" * 70)

    if passed != total:
        sys.exit(1)

if __name__ == "__main__":
    run_all()
