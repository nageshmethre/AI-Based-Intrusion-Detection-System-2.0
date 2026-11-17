"""Model training and evaluation pipeline using Random Forest on CIC-IDS2017 flow features.

Evaluates accuracy, precision, recall, F1-score, confusion matrix, per-class metrics,
False Positive Rate (FPR), and Gini feature importances.
Saves model, scaler, and metrics artifacts for the AI detection engine and SOC dashboard.
"""

import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_recall_fscore_support
)
import joblib

from backend.app.config import settings, MODELS_DIR, DATA_DIR
from backend.app.ml.schema import FLOW_FEATURES, CLASS_NAMES, LABEL_BENIGN
from backend.app.ml.preprocessor import FlowPreprocessor
from backend.app.ml.dataset_builder import prepare_training_data
from backend.app.ml.dataset_importer import (
    RAW_DIR,
    PROCESSED_DIR,
    MANIFEST_PATH,
    process_authentic_cicids2017
)

logger = logging.getLogger("cicids_train")


def calculate_false_positive_rates(cm: np.ndarray, classes: list) -> Dict[str, Any]:
    """Calculate per-class and macro False Positive Rate (FPR = FP / (FP + TN))."""
    fpr_dict = {}
    total_fp = 0
    total_tn = 0

    for i, cls in enumerate(classes):
        # TP = cm[i, i]
        fp = np.sum(cm[:, i]) - cm[i, i]
        fn = np.sum(cm[i, :]) - cm[i, i]
        tn = np.sum(cm) - (cm[i, i] + fp + fn)

        denominator = fp + tn
        fpr_val = float(fp / denominator) if denominator > 0 else 0.0
        fpr_dict[cls] = round(fpr_val, 5)
        total_fp += fp
        total_tn += tn

    macro_fpr = float(np.mean(list(fpr_dict.values()))) if fpr_dict else 0.0
    return {
        "per_class_fpr": fpr_dict,
        "macro_fpr": round(macro_fpr, 5)
    }


def train_model(
    data_path: Optional[Path] = None,
    use_authentic: bool = True,
    n_estimators: int = 100,
    max_depth: int = 22,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Train Random Forest classifier on authentic or standardized CIC-IDS2017 flow features.
    Guarantees strict train/test separation to prevent data leakage.
    """
    print("=== Phase 2: CIC-IDS2017 Model Training & Evaluation Pipeline ===")
    
    dataset_name = "CIC-IDS2017 Augmented Flow Standard"
    dataset_source = "Parametric distribution based on UNB CIC-IDS2017 schema"
    is_authentic = False

    # 1. Determine Dataset Source
    authentic_clean_path = PROCESSED_DIR / "cicids2017_authentic_clean.csv"

    if data_path and data_path.exists():
        print(f"Loading data from explicitly specified path: {data_path}")
        df = pd.read_csv(data_path)
        dataset_name = data_path.stem
    elif use_authentic and authentic_clean_path.exists():
        print(f"Loading authentic clean CIC-IDS2017 dataset from: {authentic_clean_path}")
        df = pd.read_csv(authentic_clean_path)
        if len(df) >= 100:
            dataset_name = "Authentic CIC-IDS2017 (UNB)"
            dataset_source = "Canadian Institute for Cybersecurity, University of New Brunswick (UNB)"
            is_authentic = True
        else:
            print(f"Authentic dataset has only {len(df)} samples (insufficient for 5-class stratified split). Using augmented standard dataset.")
            df = prepare_training_data()
    else:
        # Check if raw files exist that can be processed
        raw_csvs = list(RAW_DIR.glob("*.csv"))
        if use_authentic and len(raw_csvs) > 0 and any("ISCX" in f.name or "WorkingHours" in f.name for f in raw_csvs):
            print(f"Authentic raw files detected in {RAW_DIR}. Processing authentic chunks...")
            try:
                manifest = process_authentic_cicids2017(random_state=random_state)
                df = pd.read_csv(authentic_clean_path)
                dataset_name = "Authentic CIC-IDS2017 (UNB)"
                dataset_source = manifest.get("dataset_source", "Canadian Institute for Cybersecurity, UNB")
                is_authentic = True
            except Exception as e:
                print(f"Could not process authentic raw files: {e}. Falling back to augmented standard.")
                df = prepare_training_data()
        else:
            print("Using augmented standard CIC-IDS2017 flow training data...")
            df = prepare_training_data()

    # Drop any duplicate rows to prevent cross-split data leakage
    initial_len = len(df)
    df = df.drop_duplicates()
    if len(df) < initial_len:
        print(f"Removed {initial_len - len(df)} duplicate records to avoid data leakage.")

    print(f"Total dataset records: {len(df)}")
    print("Class distribution:\n", df["label"].value_counts().to_string())

    # 2. Extract Features and Labels
    y_raw = df["label"].astype(str)
    
    # Initialize Preprocessor
    preprocessor = FlowPreprocessor()
    X_clean_df = preprocessor.clean_dataframe(df)

    # 3. Stratified Train/Test Split
    X_train_df, X_test_df, y_train, y_test = train_test_split(
        X_clean_df, y_raw, test_size=0.20, random_state=random_state, stratify=y_raw
    )

    print(f"Training set: {len(X_train_df)} samples, Test set: {len(X_test_df)} samples")

    # Fit preprocessor strictly on training features only (prevents data leakage)
    X_train_scaled = preprocessor.fit_transform(X_train_df)
    X_test_scaled = preprocessor.transform(X_test_df)

    # 4. Train Random Forest Classifier
    print(f"Training Random Forest ({n_estimators} trees, max_depth={max_depth})...")
    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1
    )
    clf.fit(X_train_scaled, y_train)

    # 5. Evaluate Performance
    print("Evaluating Model Performance on Test Set...")
    y_pred = clf.predict(X_test_scaled)

    acc = float(accuracy_score(y_test, y_pred))
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(y_test, y_pred, average="macro", zero_division=0)
    p_weighted, r_weighted, f1_weighted, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted", zero_division=0)

    # Per-Class Classification Report
    class_report_dict = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    
    # Confusion Matrix
    unique_classes = sorted(list(set(y_test) | set(y_pred)))
    cm_arr = confusion_matrix(y_test, y_pred, labels=unique_classes)
    cm_list = cm_arr.tolist()

    # False Positive Rates
    fpr_info = calculate_false_positive_rates(cm_arr, unique_classes)

    # Feature Importances
    feature_importances = [
        {"feature": feat, "importance": float(imp)}
        for feat, imp in zip(FLOW_FEATURES, clf.feature_importances_)
    ]
    feature_importances.sort(key=lambda x: x["importance"], reverse=True)

    print(f"Accuracy: {acc:.4f} | Macro F1: {f1_macro:.4f} | Macro FPR: {fpr_info['macro_fpr']:.5f}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred, zero_division=0))

    # 6. Save Artifacts
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_save_path = Path(settings.MODEL_PATH)
    scaler_save_path = Path(settings.SCALER_PATH)
    metrics_save_path = Path(settings.METRICS_PATH)

    # Save model and preprocessor
    joblib.dump(clf, model_save_path)
    preprocessor.save(scaler_save_path)

    # Build metrics summary payload for Dashboard
    metrics_payload = {
        "model_type": "Random Forest Classifier",
        "dataset": dataset_name,
        "dataset_source": dataset_source,
        "is_authentic_unb": is_authentic,
        "total_samples": len(df),
        "train_samples": len(X_train_df),
        "test_samples": len(X_test_df),
        "accuracy": round(acc, 4),
        "macro_precision": round(float(p_macro), 4),
        "macro_recall": round(float(r_macro), 4),
        "macro_f1": round(float(f1_macro), 4),
        "weighted_f1": round(float(f1_weighted), 4),
        "false_positive_rate": fpr_info["macro_fpr"],
        "per_class_fpr": fpr_info["per_class_fpr"],
        "classes": unique_classes,
        "class_distribution": df["label"].value_counts().to_dict(),
        "confusion_matrix": cm_list,
        "classification_report": class_report_dict,
        "feature_importances": feature_importances[:15],
        "all_feature_importances": feature_importances,
        "training_date": pd.Timestamp.now().isoformat(),
        "timestamp": pd.Timestamp.now().isoformat()
    }

    with open(metrics_save_path, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)

    print(f"✓ Model saved to: {model_save_path}")
    print(f"✓ Scaler saved to: {scaler_save_path}")
    print(f"✓ Metrics saved to: {metrics_save_path}")

    return {
        "model": clf,
        "preprocessor": preprocessor,
        "metrics": metrics_payload
    }


if __name__ == "__main__":
    train_model()
