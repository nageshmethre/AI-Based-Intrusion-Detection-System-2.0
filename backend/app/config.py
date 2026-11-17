import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = BASE_DIR / "backend"
DATA_DIR = BACKEND_DIR / "data"
MODELS_DIR = BACKEND_DIR / "saved_models"
LOGS_DIR = BACKEND_DIR / "logs"

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
(DATA_DIR / "raw").mkdir(parents=True, exist_ok=True)
(DATA_DIR / "processed").mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)


class Settings(BaseSettings):
    # Server
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    DEBUG: bool = True

    # Database
    DATABASE_URL: str = f"sqlite:///{DATA_DIR / 'soc_ids.db'}"

    # Packet Capture & Flow Aggregation
    NETWORK_INTERFACE: Optional[str] = None  # None selects default Scapy iface
    PROMISCUOUS_MODE: bool = True
    FLOW_TIMEOUT: float = 5.0  # seconds before flow is flushed as complete
    FLOW_SWEEP_INTERVAL: float = 1.0  # seconds between inactive flow flushes

    # Machine Learning
    MODEL_PATH: str = str(MODELS_DIR / "random_forest_cicids2017.joblib")
    SCALER_PATH: str = str(MODELS_DIR / "feature_scaler.joblib")
    METRICS_PATH: str = str(MODELS_DIR / "model_metrics.json")
    ANOMALY_THRESHOLD: float = 0.80  # Conservative probability threshold for confirmed alert
    ML_ALERT_CONFIDENCE_THRESHOLD: float = 0.80  # Minimum confidence required for confirmed ML alert
    ML_PROBABILITY_MARGIN_THRESHOLD: float = 0.25  # Minimum margin between attack prob and BENIGN prob
    ML_CANDIDATE_THRESHOLD: float = 0.60  # Threshold for logging informational suspicious candidate

    # Rule-based Thresholds
    PORT_SCAN_THRESHOLD: int = 15  # Unique target ports within window
    PORT_SCAN_WINDOW_SECONDS: float = 5.0
    SYN_FLOOD_THRESHOLD: int = 50  # Unanswered SYNs in window
    SSH_FAILURE_THRESHOLD: int = 5  # Failed attempts within window

    class Config:
        env_file = str(BASE_DIR / ".env")
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()
