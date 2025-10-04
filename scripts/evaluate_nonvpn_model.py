"""Evaluate the NonVPN services classifier on a CSV export."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate nonvpn_services_model.pkl against a CSV dataset")
    parser.add_argument("csv", type=Path, help="Path to the combined CSV file")
    parser.add_argument("model", type=Path, help="Path to nonvpn_services_model.pkl")
    parser.add_argument(
        "--label",
        type=str,
        default=None,
        help="Label to assign to every row if the CSV lacks a 'label' column (e.g. 'NonVPN-Chat')",
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=None,
        help="Optional path to write predictions alongside the original data",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Optional path to save the text classification report",
    )
    return parser.parse_args()


def _prepare_features(df: pd.DataFrame, model) -> pd.DataFrame:
    numeric_df = df.select_dtypes(include=[np.number])
    feature_names: Optional[np.ndarray] = getattr(model, "feature_names_in_", None)
    if feature_names is None:
        return numeric_df

    missing = [name for name in feature_names if name not in numeric_df.columns]
    if missing:
        raise ValueError(f"Input CSV is missing expected feature columns: {missing}")

    extra = [name for name in numeric_df.columns if name not in feature_names]
    if extra:
        numeric_df = numeric_df.drop(columns=extra)

    return numeric_df[feature_names]


def main() -> None:
    args = _parse_args()

    df = pd.read_csv(args.csv)
    if "label" not in df.columns:
        if args.label is None:
            raise ValueError("CSV lacks 'label' column; supply --label to evaluate accuracy")
        df["label"] = args.label

    model = joblib.load(args.model)
    X = _prepare_features(df, model)
    y_true = df["label"].astype(str)

    y_pred = model.predict(X)
    acc = accuracy_score(y_true, y_pred)
    report = classification_report(y_true, y_pred, zero_division=0)

    print(f"Samples: {len(df)}")
    print(f"Accuracy: {acc:.4f}")
    print(report)

    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(f"Accuracy: {acc:.4f}\n\n{report}\n")

    if args.output_csv is not None:
        out_df = df.copy()
        out_df["predicted_label"] = y_pred
        args.output_csv.parent.mkdir(parents=True, exist_ok=True)
        out_df.to_csv(args.output_csv, index=False)


if __name__ == "__main__":
    main()

