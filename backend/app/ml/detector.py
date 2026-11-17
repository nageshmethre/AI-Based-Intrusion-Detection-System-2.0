"""AI Detection Engine.

Loads the trained Random Forest model and preprocessor, evaluates completed network flows,
and generates real-time threat predictions with confidence scores and explainable telemetry.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
import joblib
import numpy as np

from backend.app.config import settings
from backend.app.ml.schema import (
    FLOW_FEATURES,
    LABEL_BENIGN,
    CLASS_NAMES,
)
from backend.app.ml.preprocessor import FlowPreprocessor

logger = logging.getLogger("AIDetector")


class AIDetectionEngine:
    """Real-time ML intrusion detection inference engine."""

    def __init__(
        self,
        model_path: Optional[str] = None,
        scaler_path: Optional[str] = None,
        alert_confidence_threshold: Optional[float] = None,
        margin_threshold: Optional[float] = None
    ):
        self.model_path = Path(model_path or settings.MODEL_PATH)
        self.scaler_path = Path(scaler_path or settings.SCALER_PATH)
        self.alert_confidence_threshold = alert_confidence_threshold or settings.ML_ALERT_CONFIDENCE_THRESHOLD
        self.margin_threshold = margin_threshold or settings.ML_PROBABILITY_MARGIN_THRESHOLD
        self.candidate_threshold = settings.ML_CANDIDATE_THRESHOLD

        self.model = None
        self.preprocessor: Optional[FlowPreprocessor] = None
        self.is_loaded: bool = False
        self.classes_: List[str] = list(CLASS_NAMES)

        self._load_artifacts()

    def _load_artifacts(self) -> bool:
        """Load model and preprocessor from disk."""
        try:
            if not self.model_path.exists() or not self.scaler_path.exists():
                logger.warning("ML artifacts not found. Engine will run in standby mode.")
                return False

            self.model = joblib.load(self.model_path)
            self.preprocessor = FlowPreprocessor.load(self.scaler_path)
            
            if hasattr(self.model, "classes_"):
                self.classes_ = [str(c) for c in self.model.classes_]

            self.is_loaded = True
            logger.info("AI Detection Engine successfully loaded Random Forest model and preprocessor.")
            return True
        except Exception as e:
            logger.error(f"Failed to load AI model artifacts: {e}")
            self.is_loaded = False
            return False

    def predict_flow(self, flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate a single network flow against the AI model.
        Requires high confidence (>=0.80) and a substantial probability margin over BENIGN
        before escalating a flow into an active SOC threat alert.
        """
        if not self.is_loaded or self.model is None or self.preprocessor is None:
            return {
                "prediction": LABEL_BENIGN,
                "confidence": 0.5,
                "is_malicious": False,
                "is_threat_alert": False,
                "is_candidate": False,
                "probability_margin": 0.0,
                "severity": "INFO",
                "probabilities": {LABEL_BENIGN: 1.0},
                "status": "ENGINE_STANDBY"
            }

        try:
            # Transform flow features using preprocessor
            X_scaled = self.preprocessor.transform(flow_dict)
            
            # Predict probabilities across classes
            probs = self.model.predict_proba(X_scaled)[0]
            pred_idx = int(np.argmax(probs))
            predicted_class = str(self.classes_[pred_idx])
            confidence = float(probs[pred_idx])

            # Extract P(BENIGN) and probability margin
            benign_idx = self.classes_.index(LABEL_BENIGN) if LABEL_BENIGN in self.classes_ else -1
            p_benign = float(probs[benign_idx]) if benign_idx != -1 else 0.0
            malicious_prob = max(0.0, 1.0 - p_benign)

            # Margin between attack probability and benign probability
            if predicted_class != LABEL_BENIGN:
                probability_margin = max(0.0, confidence - p_benign)
            else:
                probability_margin = max(0.0, p_benign - (1.0 - p_benign))

            # 1. Confirmed Threat Alert Criteria:
            # - Must be predicted as an attack class (not BENIGN)
            # - Confidence must meet conservative threshold (>= 0.80)
            # - Must have meaningful probability margin over BENIGN (>= 0.25)
            is_confirmed_threat = (
                predicted_class != LABEL_BENIGN and
                confidence >= self.alert_confidence_threshold and
                probability_margin >= self.margin_threshold
            )

            # 2. Candidate / Suspicious Flow (Low-Confidence or Marginal Prediction):
            # Not an alert, but tracked for investigation
            is_candidate = (
                predicted_class != LABEL_BENIGN and
                not is_confirmed_threat and
                (confidence >= self.candidate_threshold or malicious_prob >= 0.50)
            )

            # Raw binary malicious classification
            is_malicious = (predicted_class != LABEL_BENIGN) and (confidence >= 0.50)

            # Dynamic Risk-Based Severity Calculation (no hardcoding by category)
            if not is_malicious:
                severity = "INFO"
                status_label = "NORMAL"
            elif is_confirmed_threat:
                if confidence >= 0.92 and probability_margin >= 0.50:
                    severity = "CRITICAL"
                elif confidence >= 0.85 and probability_margin >= 0.35:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
                status_label = "CONFIRMED_INCIDENT"
            elif is_candidate:
                severity = "LOW"
                status_label = "SUSPICIOUS_CANDIDATE"
            else:
                severity = "INFO"
                status_label = "LOW_CONFIDENCE"

            probabilities_dict = {
                cls_name: round(float(prob), 4)
                for cls_name, prob in zip(self.classes_, probs)
            }

            return {
                "prediction": predicted_class,
                "confidence": round(confidence, 4),
                "is_malicious": is_malicious,
                "is_threat_alert": is_confirmed_threat,
                "is_candidate": is_candidate,
                "probability_margin": round(probability_margin, 4),
                "malicious_probability": round(malicious_prob, 4),
                "severity": severity,
                "status": status_label,
                "probabilities": probabilities_dict,
                "detection_type": "MACHINE_LEARNING"
            }

        except Exception as e:
            logger.error(f"Error during flow inference: {e}")
            return {
                "prediction": "UNKNOWN",
                "confidence": 0.0,
                "is_malicious": False,
                "is_threat_alert": False,
                "is_candidate": False,
                "probability_margin": 0.0,
                "severity": "LOW",
                "probabilities": {},
                "error": str(e),
                "status": "INFERENCE_ERROR"
            }
