"""Phase 2 Machine Learning Pipeline Verification Test."""

import sys
import os
from pathlib import Path
import json

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import settings, MODELS_DIR
from backend.app.ml.schema import FLOW_FEATURES, LABEL_BENIGN, LABEL_PORTSCAN
from backend.app.ml.preprocessor import FlowPreprocessor
from backend.app.ml.train import train_model
import joblib


def test_preprocessor_robustness():
    print("Testing Preprocessor handling of edge cases (NaN, Inf, missing)...")
    preprocessor = FlowPreprocessor()
    
    # Dummy flow dict with missing features and extreme values
    raw_flow = {
        "destination_port": 80,
        "flow_duration": float("inf"),
        "total_fwd_packets": float("nan"),
        "flow_bytes_per_sec": 1e12,
        # Other 36 features missing
    }
    
    # Train dummy scaler
    import pandas as pd
    df_dummy = pd.DataFrame([{f: 1.0 for f in FLOW_FEATURES}])
    preprocessor.fit(df_dummy)
    
    scaled = preprocessor.transform(raw_flow)
    assert scaled.shape == (1, len(FLOW_FEATURES))
    assert not pd.isna(scaled).any()
    print("✓ Preprocessor successfully sanitized and scaled incomplete flow")


def test_model_training_and_artifacts():
    print("Executing model training pipeline...")
    result = train_model()
    
    model_path = Path(settings.MODEL_PATH)
    scaler_path = Path(settings.SCALER_PATH)
    metrics_path = Path(settings.METRICS_PATH)
    
    assert model_path.exists(), f"Model artifact missing: {model_path}"
    assert scaler_path.exists(), f"Scaler artifact missing: {scaler_path}"
    assert metrics_path.exists(), f"Metrics artifact missing: {metrics_path}"
    
    # Verify model load
    loaded_model = joblib.load(model_path)
    loaded_scaler = FlowPreprocessor.load(scaler_path)
    
    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = json.load(f)
        
    assert metrics["accuracy"] >= 0.90, f"Expected accuracy >= 0.90, got {metrics['accuracy']}"
    assert metrics["macro_f1"] >= 0.90, f"Expected macro F1 >= 0.90, got {metrics['macro_f1']}"
    assert len(metrics["confusion_matrix"]) > 0
    assert len(metrics["feature_importances"]) > 0
    
    # Test inference on sample benign flow
    test_flow = {
        "destination_port": 443,
        "flow_duration": 450000,
        "total_fwd_packets": 5,
        "total_bwd_packets": 6,
        "total_fwd_len": 500,
        "total_bwd_len": 2400,
        "flow_bytes_per_sec": 6444.4,
        "flow_pkts_per_sec": 24.4,
        "syn_flag_cnt": 1,
        "ack_flag_cnt": 1,
        "fin_flag_cnt": 1,
        "init_win_bytes_fwd": 29200,
        "init_win_bytes_bwd": 28960
    }
    
    scaled_flow = loaded_scaler.transform(test_flow)
    pred_label = loaded_model.predict(scaled_flow)[0]
    probs = loaded_model.predict_proba(scaled_flow)[0]
    conf = float(max(probs))
    
    print(f"✓ Test sample predicted as: {pred_label} (Confidence: {conf * 100:.2f}%)")
    print(f"✓ Accuracy: {metrics['accuracy'] * 100:.2f}% | Macro F1: {metrics['macro_f1'] * 100:.2f}%")


if __name__ == "__main__":
    test_preprocessor_robustness()
    test_model_training_and_artifacts()
    print("\n--- Phase 2 Verification Passed Successfully! ---")
