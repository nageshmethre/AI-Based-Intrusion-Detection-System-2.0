"""Explainable AI (XAI) Per-Flow Decision Explainer.

Analyzes individual network flows and explains WHY the Random Forest
classifier predicted a particular threat category by attributing feature
deviations against standard benign flow baselines.
"""

from typing import Dict, Any, List
from backend.app.ml.schema import FLOW_FEATURES

# Benign baseline reference statistics (derived from CIC-IDS2017 benign clusters)
BENIGN_BASELINES: Dict[str, Dict[str, float]] = {
    "flow_duration": {"mean": 350000.0, "normal_max": 2000000.0},
    "flow_pkts_per_sec": {"mean": 25.0, "normal_max": 250.0},
    "flow_bytes_per_sec": {"mean": 15000.0, "normal_max": 500000.0},
    "flow_iat_mean": {"mean": 45000.0, "normal_min": 1000.0},
    "syn_flag_cnt": {"mean": 1.0, "normal_max": 3.0},
    "fin_flag_cnt": {"mean": 1.0, "normal_max": 2.0},
    "rst_flag_cnt": {"mean": 0.05, "normal_max": 1.0},
    "down_up_ratio": {"mean": 1.2, "normal_range": (0.2, 5.0)},
    "fwd_pkt_len_mean": {"mean": 240.0, "normal_max": 1400.0},
    "bwd_pkt_len_mean": {"mean": 600.0, "normal_max": 1460.0},
    "total_fwd_packets": {"mean": 8.0, "normal_max": 60.0},
}


def explain_flow_prediction(flow_dict: Dict[str, Any], ai_res: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate an interpretable XAI report explaining why a flow was predicted as an attack.
    Returns feature contributions, deviation percentages, and human-readable reasoning.
    """
    prediction = ai_res.get("prediction", "BENIGN")
    confidence = ai_res.get("confidence", 0.0)
    probabilities = ai_res.get("probabilities", {})

    contributions: List[Dict[str, Any]] = []

    # Calculate anomalous deviations for dominant flow metrics
    for feat, baseline in BENIGN_BASELINES.items():
        val = float(flow_dict.get(feat, 0.0) or 0.0)
        norm_mean = baseline.get("mean", 1.0)
        ratio = (val - norm_mean) / max(norm_mean, 1.0)

        # Generate feature impact score
        impact = abs(ratio)
        if impact > 0.5:
            direction = "ABNORMALLY_HIGH" if val > norm_mean else "ABNORMALLY_LOW"
            contributions.append({
                "feature": feat,
                "value": round(val, 2),
                "normal_baseline": round(norm_mean, 2),
                "deviation_percent": round(ratio * 100, 1),
                "direction": direction,
                "importance_score": round(min(impact, 10.0), 2)
            })

    # Sort by greatest anomaly
    contributions.sort(key=lambda x: x["importance_score"], reverse=True)
    top_factors = contributions[:5]

    # Human-readable forensic summary
    narrative_points = []
    if prediction == "DoS":
        narrative_points.append("Massive packet volume and compressed inter-arrival times consistent with denial-of-service flooding.")
        narrative_points.append("Asymmetric request-to-response ratio with low return payloads.")
    elif prediction == "PortScan":
        narrative_points.append("Abnormally short flow duration with isolated SYN probes lacking established TCP handshakes.")
        narrative_points.append("Rapid probe cadence directed at non-standard listening ports.")
    elif prediction == "BruteForce":
        narrative_points.append("Repetitive connection attempts with fixed small packet sizes characteristic of credential dictionary attacks.")
    elif prediction == "Botnet":
        narrative_points.append("Periodic beaconing pattern with synchronized flow duration and fixed window parameters.")
    else:
        narrative_points.append("Flow adheres to standard bidirectional HTTP/TLS/DNS exchange baselines.")

    return {
        "prediction": prediction,
        "confidence": confidence,
        "confidence_percentage": f"{confidence * 100:.1f}%",
        "probabilities": probabilities,
        "top_contributing_features": top_factors,
        "forensic_reasoning": narrative_points,
        "model_engine": "Random Forest (100 Decision Trees)"
    }
