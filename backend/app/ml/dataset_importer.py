"""CIC-IDS2017 Authentic Dataset Importer & Chunk-Based Preprocessing Pipeline.

Provides automated scanning, chunkwise loading, data sanitization, deduplication,
label normalization, and class-balanced compilation for the official UNB CIC-IDS2017 dataset.

Official Source:
    Canadian Institute for Cybersecurity (CIC)
    University of New Brunswick (UNB), Fredericton, Canada
    URL: https://www.unb.ca/cic/datasets/ids-2017.html
    Mirror: https://www.kaggle.com/datasets/cicdataset/cicids2017
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import pandas as pd

from backend.app.config import DATA_DIR
from backend.app.ml.schema import (
    FLOW_FEATURES,
    CICIDS2017_COLUMN_MAPPING,
    ATTACK_CATEGORIES,
    LABEL_BENIGN,
    LABEL_PORTSCAN,
    LABEL_DOS,
    LABEL_BRUTEFORCE,
    LABEL_BOTNET,
)

logger = logging.getLogger("cicids_importer")

# Official UNB CSV Filenames
OFFICIAL_CICIDS2017_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
MANIFEST_PATH = DATA_DIR / "dataset_manifest.json"


def get_official_dataset_info() -> Dict[str, Any]:
    """Return official dataset metadata, download URLs, and description."""
    return {
        "dataset_name": "Intrusion Detection Evaluation Dataset (CIC-IDS2017)",
        "institution": "Canadian Institute for Cybersecurity (CIC), University of New Brunswick (UNB)",
        "authors": "Iman Sharafaldin, Arash Habibi Lashkari, Ali A. Ghorbani (ICISSP 2018)",
        "official_url": "https://www.unb.ca/cic/datasets/ids-2017.html",
        "archive_filename": "GeneratedLabelledFlows.zip",
        "kaggle_mirror": "https://www.kaggle.com/datasets/cicdataset/cicids2017",
        "official_csv_files": OFFICIAL_CICIDS2017_FILES,
        "raw_directory": str(RAW_DIR),
        "processed_directory": str(PROCESSED_DIR),
        "supported_attack_categories": [
            "BENIGN",
            "PortScan",
            "DoS Hulk",
            "DoS GoldenEye",
            "DoS slowloris",
            "DoS Slowhttptest",
            "DDoS",
            "FTP-Patator",
            "SSH-Patator",
            "Web Attack – Brute Force",
            "Web Attack – XSS",
            "Web Attack – Sql Injection",
            "Bot",
            "Infiltration",
            "Heartbleed"
        ]
    }


def scan_raw_dataset_files() -> Dict[str, Any]:
    """Scan raw directory for authentic CIC-IDS2017 CSV files."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    found_files = []
    total_raw_bytes = 0

    for file_path in RAW_DIR.glob("*.csv"):
        size_bytes = file_path.stat().st_size
        total_raw_bytes += size_bytes
        is_official = file_path.name in OFFICIAL_CICIDS2017_FILES
        found_files.append({
            "filename": file_path.name,
            "path": str(file_path),
            "size_mb": round(size_bytes / (1024 * 1024), 2),
            "is_official_file": is_official
        })

    # Check for existing processed dataset
    authentic_processed_path = PROCESSED_DIR / "cicids2017_authentic_clean.csv"
    has_processed_authentic = authentic_processed_path.exists()
    processed_size_mb = round(authentic_processed_path.stat().st_size / (1024 * 1024), 2) if has_processed_authentic else 0

    manifest = {}
    if MANIFEST_PATH.exists():
        try:
            with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception:
            manifest = {}

    return {
        "raw_files_count": len(found_files),
        "raw_files": found_files,
        "total_raw_size_mb": round(total_raw_bytes / (1024 * 1024), 2),
        "has_processed_authentic": has_processed_authentic,
        "processed_file": str(authentic_processed_path) if has_processed_authentic else None,
        "processed_size_mb": processed_size_mb,
        "manifest": manifest,
        "official_info": get_official_dataset_info()
    }


def clean_chunk(chunk: pd.DataFrame) -> pd.DataFrame:
    """Clean a single chunk: strip headers, map columns, clean NaNs/inf, standardize labels."""
    # Strip whitespace from columns
    chunk.columns = [c.strip() for c in chunk.columns]

    # Map column names to canonical schema
    rename_dict = {}
    for col in chunk.columns:
        if col in CICIDS2017_COLUMN_MAPPING:
            rename_dict[col] = CICIDS2017_COLUMN_MAPPING[col]
        elif col.strip() in CICIDS2017_COLUMN_MAPPING:
            rename_dict[col] = CICIDS2017_COLUMN_MAPPING[col.strip()]

    chunk = chunk.rename(columns=rename_dict)

    if "label" not in chunk.columns:
        return pd.DataFrame()

    # Standardize label
    chunk["label"] = chunk["label"].astype(str).str.strip()
    chunk["label"] = chunk["label"].map(lambda l: ATTACK_CATEGORIES.get(l, l))

    # Keep only canonical flow features + label
    required_cols = [f for f in FLOW_FEATURES if f in chunk.columns]
    chunk = chunk[required_cols + ["label"]]

    # Enforce numeric conversion
    for col in required_cols:
        chunk[col] = pd.to_numeric(chunk[col], errors="coerce")

    # Replace infinities and NaNs
    chunk = chunk.replace([np.inf, -np.inf], np.nan)
    chunk = chunk.dropna(subset=["label"])
    chunk = chunk.fillna(0.0)

    # Physical quantities non-negativity constraint
    for col in required_cols:
        if col not in ["init_win_bytes_fwd", "init_win_bytes_bwd"]:
            chunk[col] = chunk[col].clip(lower=0.0)

    return chunk


def process_authentic_cicids2017(
    chunk_size: int = 50000,
    max_samples_per_class: int = 15000,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Process raw authentic CIC-IDS2017 CSV files using chunking and stratified reservoir sampling.
    Prevents Out-Of-Memory (OOM) errors while preserving real attack distributions.
    """
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    csv_files = list(RAW_DIR.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {RAW_DIR}. Please place authentic CIC-IDS2017 CSV files in {RAW_DIR}."
        )

    logger.info(f"Starting chunked processing of {len(csv_files)} CSV files...")

    class_buffers: Dict[str, List[pd.DataFrame]] = {}
    class_counts: Dict[str, int] = {}
    total_raw_rows = 0
    total_clean_rows = 0
    files_processed = []

    for file_path in csv_files:
        logger.info(f"Processing raw file: {file_path.name}")
        file_rows = 0
        try:
            # Chunk-based ingestion
            for chunk in pd.read_csv(file_path, chunksize=chunk_size, low_memory=False, encoding="utf-8", on_bad_lines="skip"):
                total_raw_rows += len(chunk)
                file_rows += len(chunk)

                clean_df = clean_chunk(chunk)
                if clean_df.empty:
                    continue

                total_clean_rows += len(clean_df)

                # Group by label and buffer without blowing up RAM
                for label, group in clean_df.groupby("label"):
                    curr_count = class_counts.get(label, 0)
                    if curr_count < max_samples_per_class:
                        take_n = min(len(group), max_samples_per_class - curr_count)
                        sampled = group.sample(n=take_n, random_state=random_state) if take_n < len(group) else group
                        class_buffers.setdefault(label, []).append(sampled)
                        class_counts[label] = curr_count + len(sampled)

            files_processed.append({"filename": file_path.name, "rows": file_rows})
        except Exception as e:
            logger.error(f"Error reading {file_path.name}: {e}")

    # Concatenate per-class buffers
    final_dfs = []
    for label, buffer_list in class_buffers.items():
        if buffer_list:
            cls_df = pd.concat(buffer_list, ignore_index=True)
            # Deduplicate within class
            cls_df = cls_df.drop_duplicates()
            final_dfs.append(cls_df)

    if not final_dfs:
        raise ValueError("No valid flow records could be extracted from the provided CSV files.")

    merged_df = pd.concat(final_dfs, ignore_index=True)
    # Shuffle dataset
    merged_df = merged_df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)

    # Save authentic clean dataset
    out_path = PROCESSED_DIR / "cicids2017_authentic_clean.csv"
    merged_df.to_csv(out_path, index=False)

    final_distribution = merged_df["label"].value_counts().to_dict()

    manifest = {
        "dataset_type": "AUTHENTIC_CICIDS2017",
        "dataset_source": "Canadian Institute for Cybersecurity, University of New Brunswick (UNB)",
        "processed_file": str(out_path),
        "total_records": len(merged_df),
        "total_raw_rows_scanned": total_raw_rows,
        "files_processed": files_processed,
        "class_distribution": final_distribution,
        "features_count": len(FLOW_FEATURES),
        "processed_timestamp": pd.Timestamp.now().isoformat(),
        "is_synthetic": False
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    logger.info(f"Authentic dataset compiled successfully to {out_path} ({len(merged_df)} records).")
    return manifest
