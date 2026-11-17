"""Feature preprocessing and validation pipeline for network flow intrusion detection."""

import numpy as np
import pandas as pd
from typing import Dict, Any, List, Union
from sklearn.preprocessing import RobustScaler
import joblib
from pathlib import Path
from backend.app.ml.schema import FLOW_FEATURES


class FlowPreprocessor:
    """Preprocesses raw network flow feature dictionaries or DataFrames into scaled ML arrays."""

    def __init__(self, scaler: RobustScaler = None):
        self.scaler = scaler or RobustScaler()
        self.feature_names: List[str] = list(FLOW_FEATURES)
        self.is_fitted: bool = scaler is not None

    def clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Sanitize dataframe: replace infinities, fill NaNs, enforce numeric dtype."""
        clean_df = df.copy()

        # Keep only required features
        for feat in self.feature_names:
            if feat not in clean_df.columns:
                clean_df[feat] = 0.0

        clean_df = clean_df[self.feature_names]

        # Convert to numeric
        for col in self.feature_names:
            clean_df[col] = pd.to_numeric(clean_df[col], errors="coerce")

        # Replace inf with upper percentile / NaN with 0
        clean_df = clean_df.replace([np.inf, -np.inf], np.nan)
        clean_df = clean_df.fillna(0.0)

        # Clip negative values where physical quantities cannot be negative (except init_win which can be -1)
        for col in self.feature_names:
            if col not in ["init_win_bytes_fwd", "init_win_bytes_bwd"]:
                clean_df[col] = clean_df[col].clip(lower=0.0)

        return clean_df

    def fit(self, X: Union[pd.DataFrame, np.ndarray]):
        """Fit the scaler on the cleaned feature matrix."""
        if isinstance(X, pd.DataFrame):
            X_clean = self.clean_dataframe(X).values
        else:
            X_clean = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)
        self.scaler.fit(X_clean)
        self.is_fitted = True
        return self

    def transform(self, X: Union[pd.DataFrame, np.ndarray, Dict[str, Any], List[Dict[str, Any]]]) -> np.ndarray:
        """Transform input features using the fitted scaler."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted or loaded before transform.")

        if isinstance(X, dict):
            # Single flow dict from real-time capture
            row = [float(X.get(k, 0.0) or 0.0) for k in self.feature_names]
            arr = np.array([row], dtype=np.float64)
            arr = np.nan_to_num(arr, nan=0.0, posinf=1e9, neginf=-1e9)
            return self.scaler.transform(arr)

        elif isinstance(X, list) and len(X) > 0 and isinstance(X[0], dict):
            # List of flow dicts
            rows = [[float(d.get(k, 0.0) or 0.0) for k in self.feature_names] for d in X]
            arr = np.array(rows, dtype=np.float64)
            arr = np.nan_to_num(arr, nan=0.0, posinf=1e9, neginf=-1e9)
            return self.scaler.transform(arr)

        elif isinstance(X, pd.DataFrame):
            clean_df = self.clean_dataframe(X)
            return self.scaler.transform(clean_df.values)

        else:
            arr = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)
            return self.scaler.transform(arr)

    def fit_transform(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Fit scaler and transform in one step."""
        return self.fit(X).transform(X)

    def save(self, file_path: Union[str, Path]):
        """Serialize preprocessor to disk using joblib."""
        data = {
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "is_fitted": self.is_fitted
        }
        joblib.dump(data, file_path)

    @classmethod
    def load(cls, file_path: Union[str, Path]) -> "FlowPreprocessor":
        """Load serialized preprocessor from disk."""
        data = joblib.load(file_path)
        preprocessor = cls(scaler=data.get("scaler"))
        preprocessor.feature_names = data.get("feature_names", list(FLOW_FEATURES))
        preprocessor.is_fitted = data.get("is_fitted", True)
        return preprocessor
