

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib.colors import LinearSegmentedColormap

LABELS = ["Chat", "Command&\nControl", "File\nTransfer", "Streaming", "VoIP"]

# Original matrices
ORIGINAL_NONVPN_MATRIX = pd.DataFrame(
    [
        [100.00, 0.00, 0.00, 0.00, 0.00],
        [0.00, 100.00, 0.00, 0.00, 0.00],
        [0.00, 0.00, 100.00, 0.00, 0.00],
        [0.00, 0.00, 0.00, 100.00, 0.00],
        [0.00, 0.00, 0.00, 0.00, 100.00],
    ],
    index=LABELS,
    columns=LABELS,
)
ORIGINAL_NONVPN_MATRIX.index.name = "True Label"

ORIGINAL_VPN_MATRIX = pd.DataFrame(
    [
        [100.00, 0.00, 0.00, 0.00, 0.00],
        [0.00, 100.00, 0.00, 0.00, 0.00],
        [0.00, 10.00, 90.00, 0.00, 0.00],
        [0.00, 0.00, 0.00, 100.00, 0.00],
        [0.00, 1.39, 0.00, 0.00, 98.61],
    ],
    index=LABELS,
    columns=LABELS,
)
ORIGINAL_VPN_MATRIX.index.name = "True Label"

# New matrices
NEW_NONVPN_MATRIX = pd.DataFrame(
    [
        [34.1, 7.8, 3.6, 50.3, 4.3],
        [16.9, 21.5, 39.7, 3.0, 18.9],
        [6.5, 31.6, 30.3, 29.9, 1.7],
        [4.1, 18.7, 38.3, 38.8, 0.1],
        [11.4, 4.5, 31.3, 0.0, 52.8],
    ],
    index=LABELS,
    columns=LABELS,
)
NEW_NONVPN_MATRIX.index.name = "True Label"

NEW_VPN_MATRIX = pd.DataFrame(
    [
        [1.3, 17.7, 15.2, 59.5, 6.3],
        [81.2, 17.6, 0.4, 0.4, 0.5],
        [43.1, 10.6, 24.9, 15.2, 6.2],
        [83.3, 5.2, 5.5, 6.0, 0.0],
        [0.0, 44.5, 1.0, 0.7, 53.8],
    ],
    index=LABELS,
    columns=LABELS,
)
NEW_VPN_MATRIX.index.name = "True Label"

MATRICES: Dict[str, pd.DataFrame] = {
    "original_nonvpn": ORIGINAL_NONVPN_MATRIX,
    "morphed_nonvpn": NEW_NONVPN_MATRIX,
    "original_vpn": ORIGINAL_VPN_MATRIX,
    "morphed_vpn": NEW_VPN_MATRIX,
}


def create_confusion_matrix_plot(matrix: pd.DataFrame, title: str, output_path: Path, is_vpn: bool = False) -> None:
    """Create a professional confusion matrix heatmap."""
    plt.figure(figsize=(8, 6))

    # Use simple color schemes: blue for non-VPN, red for VPN
    if is_vpn:
        cmap = sns.light_palette("#FF6B6B", as_cmap=True)  # Red-based palette for VPN
    else:
        cmap = sns.light_palette("#4ECDC4", as_cmap=True)  # Teal-based palette for non-VPN

    # Create heatmap with borders
    ax = sns.heatmap(
        matrix,
        annot=True,
        fmt=".2f",
        cmap=cmap,
        cbar_kws={'label': 'Accuracy (%)'},
        square=True,
        linewidths=2,  # Increased border width
        linecolor='black',  # Black borders
        annot_kws={"size": 12, "weight": "bold"}  # Increased text size
    )

    # Add border around the entire plot
    for _, spine in ax.spines.items():
        spine.set_visible(True)
        spine.set_linewidth(2)
        spine.set_edgecolor('black')

    # Customize the plot
    plt.title(title, fontsize=16, fontweight='bold', pad=20)
    plt.ylabel('True Label', fontsize=14, fontweight='bold')
    plt.xlabel('Predicted Label', fontsize=14, fontweight='bold')

    # Don't rotate labels, keep them horizontal with text wrapping
    plt.xticks(rotation=0, ha='center', fontsize=12)
    plt.yticks(rotation=0, fontsize=12)

    # Adjust tick positions for wrapped text
    ax = plt.gca()
    ax.set_xticklabels([label.replace('\n', '\n') for label in LABELS], ha='center', fontsize=12)
    ax.set_yticklabels(LABELS, fontsize=12)

    # Add percentage symbol to colorbar
    cbar = plt.gcf().axes[-1]
    cbar.set_ylabel('Accuracy (%)', fontsize=14, fontweight='bold')

    plt.tight_layout()
    plt.savefig(output_path, bbox_inches='tight', facecolor='white')
    plt.close()

    print(f"✓ Saved confusion matrix: {output_path}")


def create_combined_plot(output_dir: Path, version: str) -> None:
    """Create a combined plot showing both VPN and Non-VPN matrices side by side."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))

    nonvpn_matrix = MATRICES[f"{version}_nonvpn"]
    vpn_matrix = MATRICES[f"{version}_vpn"]

    # Non-VPN plot (teal color scheme)
    nonvpn_cmap = sns.light_palette("#4ECDC4", as_cmap=True)
    sns.heatmap(
        nonvpn_matrix,
        annot=True,
        fmt=".2f",
        cmap=nonvpn_cmap,
        cbar=False,
        square=True,
        linewidths=2,  # Increased border width
        linecolor='black',  # Black borders
        annot_kws={"size": 12, "weight": "bold"},  # Increased text size
        ax=ax1
    )

    # Add border around the first plot
    for _, spine in ax1.spines.items():
        spine.set_visible(True)
        spine.set_linewidth(2)
        spine.set_edgecolor('black')

    ax1.set_title(f'{version.capitalize()} Non-VPN Traffic Classification', fontsize=16, fontweight='bold', pad=20)
    ax1.set_ylabel('True Label', fontsize=14, fontweight='bold')
    ax1.set_xlabel('Predicted Label', fontsize=14, fontweight='bold')
    ax1.tick_params(axis='x', rotation=0, labelsize=12)  # No rotation
    ax1.tick_params(axis='y', labelsize=12)
    ax1.set_xticklabels([label.replace('\n', '\n') for label in LABELS], ha='center', fontsize=12)
    ax1.set_yticklabels(LABELS, fontsize=12)

    # VPN plot (red color scheme)
    vpn_cmap = sns.light_palette("#FF6B6B", as_cmap=True)
    sns.heatmap(
        vpn_matrix,
        annot=True,
        fmt=".2f",
        cmap=vpn_cmap,
        cbar_kws={'label': 'Accuracy (%)', 'shrink': 0.8},
        square=True,
        linewidths=2,  # Increased border width
        linecolor='black',  # Black borders
        annot_kws={"size": 12, "weight": "bold"},  # Increased text size
        ax=ax2
    )

    # Add border around the second plot
    for _, spine in ax2.spines.items():
        spine.set_visible(True)
        spine.set_linewidth(2)
        spine.set_edgecolor('black')

    ax2.set_title(f'{version.capitalize()} VPN Traffic Classification', fontsize=16, fontweight='bold', pad=20)
    ax2.set_ylabel('True Label', fontsize=14, fontweight='bold')
    ax2.set_xlabel('Predicted Label', fontsize=14, fontweight='bold')
    ax2.tick_params(axis='x', rotation=0, labelsize=12)  # No rotation
    ax2.tick_params(axis='y', labelsize=12)
    ax2.set_xticklabels([label.replace('\n', '\n') for label in LABELS], ha='center', fontsize=12)
    ax2.set_yticklabels(LABELS, fontsize=12)

    # Adjust colorbar position
    cbar = ax2.collections[0].colorbar
    cbar.set_label('Accuracy (%)', fontsize=12, fontweight='bold')

    plt.suptitle(f'{version.capitalize()} Traffic Classification Confusion Matrices', fontsize=18, fontweight='bold', y=0.98)
    plt.tight_layout()

    combined_path = output_dir / f"combined_{version}_confusion_matrices.pdf"
    plt.savefig(combined_path, bbox_inches='tight', facecolor='white')
    plt.close()

    print(f"✓ Saved combined {version} confusion matrices: {combined_path}")


def save_csv_tables(output_dir: Path) -> None:
    """Save the confusion matrices as CSV files for reference."""
    for name, matrix in MATRICES.items():
        csv_path = output_dir / f"{name}_confusion_matrix.csv"
        matrix.to_csv(csv_path)
        print(f"✓ Saved CSV table: {csv_path}")


def calculate_metrics(matrix: pd.DataFrame) -> Dict[str, float]:
    """Calculate classification metrics from confusion matrix."""
    metrics = {}

    for i, label in enumerate(LABELS):
        tp = matrix.iloc[i, i]
        fp = matrix.iloc[:, i].sum() - tp
        fn = matrix.iloc[i, :].sum() - tp
        tn = matrix.sum().sum() - tp - fp - fn

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        metrics[label] = {
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'accuracy': tp
        }

    # Overall accuracy
    metrics['overall_accuracy'] = np.trace(matrix.values) / matrix.values.sum()

    return metrics


def print_metrics_report() -> None:
    """Print a detailed metrics report."""
    print("\n" + "="*60)
    print("CLASSIFICATION METRICS REPORT")
    print("="*60)

    for name, matrix in MATRICES.items():
        title = name.replace('_', ' ').replace('nonvpn', 'Non-VPN').replace('vpn', 'VPN').upper()
        print(f"\n🔹 {title} TRAFFIC CLASSIFICATION:")
        print("-" * 40)
        metrics = calculate_metrics(matrix)
        for label, metric in metrics.items():
            if label != 'overall_accuracy':
                print(f"{label}: Precision={metric['precision']:.2f}, Recall={metric['recall']:.2f}, F1={metric['f1_score']:.2f}, Accuracy={metric['accuracy']:.2f}")
            else:
                print(f"Overall Accuracy: {metric:.2f}")

    print("\n" + "="*60)


def main():
    parser = argparse.ArgumentParser(
        description="Generate professional confusion matrix plots for traffic classification"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/plots/confusion_matrices"),
        help="Output directory for plots (default: results/plots/confusion_matrices)"
    )
    parser.add_argument(
        "--combined-only",
        action="store_true",
        help="Generate only the combined plot"
    )
    parser.add_argument(
        "--no-csv",
        action="store_true",
        help="Skip CSV export"
    )

    args = parser.parse_args()

    # Create output directory
    args.output_dir.mkdir(parents=True, exist_ok=True)

    if not args.combined_only:
        # Generate individual plots for all matrices
        for name, matrix in MATRICES.items():
            title = f"{name.replace('_', ' ').title()} Traffic Classification Confusion Matrix"
            output_path = args.output_dir / f"{name}_confusion_matrix.pdf"
            is_vpn = 'vpn' in name
            create_confusion_matrix_plot(matrix, title, output_path, is_vpn)

    # Generate combined plots for original and morphed
    create_combined_plot(args.output_dir, "original")
    create_combined_plot(args.output_dir, "morphed")

    # Save CSV tables
    if not args.no_csv:
        save_csv_tables(args.output_dir)

    # Print metrics report
    print_metrics_report()

    print(f"\n🎉 All confusion matrix plots saved to: {args.output_dir}")


if __name__ == "__main__":
    main()