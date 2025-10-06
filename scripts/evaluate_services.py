#!/usr/bin/env python3
"""Batch evaluation across VPN and Non-VPN services with confusion matrices."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

SERVICES: List[str] = [
    "Chat",
    "Command&Control",
    "FileTransfer",
    "Streaming",
    "VoIP",
]


@dataclass
class GroupConfig:
    name: str
    csv_root: Path
    model_path: Path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate trained classifiers for each traffic service and plot"
            " confusion matrices for VPN and Non-VPN groups."
        )
    )
    parser.add_argument(
        "--nonvpn-root",
        type=Path,
        default=Path("dataset/Modified/CSV/NON-VPN"),
        help="Directory containing per-service Non-VPN CSV outputs",
    )
    parser.add_argument(
        "--vpn-root",
        type=Path,
        default=Path("dataset/Modified/CSV/VPN"),
        help="Directory containing per-service VPN CSV outputs",
    )
    parser.add_argument(
        "--nonvpn-model",
        type=Path,
        default=Path("src/models/nonvpn_services_model.pkl"),
        help="Path to trained Non-VPN services model",
    )
    parser.add_argument(
        "--vpn-model",
        type=Path,
        default=Path("src/models/vpn_services_model.pkl"),
        help="Path to trained VPN services model",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/evaluation"),
        help="Destination directory for reports and confusion matrices",
    )
    parser.add_argument(
        "--skip-missing",
        action="store_true",
        help="Skip services with missing CSVs instead of raising an error",
    )
    return parser.parse_args()


def _slugify(name: str) -> str:
    return (
        name.lower()
        .replace("&", "and")
        .replace("/", "_")
        .replace(" ", "_")
    )


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


def _find_combined_csv(root: Path) -> Optional[Path]:
    candidates = sorted(root.glob("*combined.csv"))
    if not candidates:
        return None
    return candidates[0]


def _plot_confusion_matrix(
    matrix: np.ndarray,
    labels: Iterable[str],
    output_path: Path,
    title: str,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(8, 6))
    im = ax.imshow(matrix, interpolation="nearest", cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    ax.set(
        xticks=np.arange(len(labels)),
        yticks=np.arange(len(labels)),
        xticklabels=labels,
        yticklabels=labels,
        ylabel="True label",
        xlabel="Predicted label",
        title=title,
    )

    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")

    thresh = matrix.max() / 2.0 if matrix.size else 0
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            ax.text(
                j,
                i,
                format(matrix[i, j], "d"),
                ha="center",
                va="center",
                color="white" if matrix[i, j] > thresh else "black",
            )

    fig.tight_layout()
    fig.savefig(output_path, dpi=200)
    plt.close(fig)


def _evaluate_group(
    config: GroupConfig,
    output_root: Path,
    skip_missing: bool,
) -> Dict[str, float]:
    print(f"\n=== Evaluating {config.name} services ===")
    model = joblib.load(config.model_path)
    classes = [str(label) for label in getattr(model, "classes_", SERVICES)]

    summary: Dict[str, float] = {}
    all_true: List[str] = []
    all_pred: List[str] = []

    group_output = output_root / _slugify(config.name)
    group_output.mkdir(parents=True, exist_ok=True)

    for service in SERVICES:
        csv_dir = config.csv_root / service
        csv_path = _find_combined_csv(csv_dir)
        if csv_path is None:
            message = f"Missing combined CSV for {config.name} service '{service}' in {csv_dir}"
            if skip_missing:
                print(f"  [skip] {message}")
                continue
            raise FileNotFoundError(message)

        print(f"  Processing {service}: {csv_path}")
        df = pd.read_csv(csv_path)
        if "label" not in df.columns:
            df["label"] = service

        X = _prepare_features(df, model)
        y_true = df["label"].astype(str)
        y_pred = model.predict(X)

        acc = accuracy_score(y_true, y_pred)
        summary[service] = acc

        report_text = classification_report(y_true, y_pred, zero_division=0)

        report_path = group_output / f"{_slugify(service)}_report.txt"
        report_path.write_text(f"Accuracy: {acc:.4f}\n\n{report_text}\n")

        predictions_path = group_output / f"{_slugify(service)}_predictions.csv"
        out_df = df.copy()
        out_df["predicted_label"] = y_pred
        out_df.to_csv(predictions_path, index=False)

        all_true.extend(y_true.tolist())
        all_pred.extend(y_pred.tolist())

    if all_true:
        matrix = confusion_matrix(all_true, all_pred, labels=classes)
        matrix_path = group_output / f"confusion_matrix_{_slugify(config.name)}.png"
        _plot_confusion_matrix(
            matrix,
            classes,
            matrix_path,
            title=f"{config.name} Services Confusion Matrix",
        )

        matrix_csv = group_output / f"confusion_matrix_{_slugify(config.name)}.csv"
        matrix_df = pd.DataFrame(matrix, index=classes, columns=classes)
        matrix_df.to_csv(matrix_csv)
    else:
        print(f"No samples evaluated for {config.name}; skipping confusion matrix.")

    summary_path = group_output / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))

    return summary


def main() -> None:
    args = _parse_args()
    output_root = args.output_dir
    output_root.mkdir(parents=True, exist_ok=True)

    groups = [
        GroupConfig("Non-VPN", args.nonvpn_root, args.nonvpn_model),
        GroupConfig("VPN", args.vpn_root, args.vpn_model),
    ]

    summaries: Dict[str, Dict[str, float]] = {}
    for group in groups:
        summaries[group.name] = _evaluate_group(group, output_root, args.skip_missing)

    combined_summary_path = output_root / "summaries.json"
    combined_summary_path.write_text(json.dumps(summaries, indent=2))
    print(f"\nEvaluation complete. Reports saved to {output_root}")


if __name__ == "__main__":
    main()
