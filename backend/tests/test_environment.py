"""Phase 1 Environment & Dependency Verification Test."""

import sys
import os
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def test_python_version():
    assert sys.version_info >= (3, 10), f"Python 3.10+ required, found {sys.version}"

def test_dependencies_importable():
    import fastapi
    import uvicorn
    import scapy
    import pandas
    import numpy
    import sklearn
    import joblib
    import sqlalchemy
    import websockets
    import pydantic
    assert True

def test_config_and_directories():
    from backend.app.config import settings, BASE_DIR, DATA_DIR, MODELS_DIR, LOGS_DIR
    assert BASE_DIR.exists()
    assert DATA_DIR.exists()
    assert MODELS_DIR.exists()
    assert LOGS_DIR.exists()
    assert settings.PORT == 8000
    assert "sqlite" in settings.DATABASE_URL

def test_scapy_interfaces():
    from scapy.all import get_if_list
    interfaces = get_if_list()
    assert isinstance(interfaces, list)
    assert len(interfaces) > 0, "No network interfaces discovered by Scapy"

if __name__ == "__main__":
    print("Testing Python Version...")
    test_python_version()
    print("✓ Python version OK:", sys.version.split()[0])

    print("Testing Dependencies...")
    test_dependencies_importable()
    print("✓ All required Python packages import successfully")

    print("Testing Config & Directories...")
    test_config_and_directories()
    print("✓ Config loaded and target directories validated")

    print("Testing Network Interfaces (Scapy)...")
    test_scapy_interfaces()
    print("✓ Scapy detected valid local network interfaces")

    print("\n--- Phase 1 Verification Passed Successfully! ---")
