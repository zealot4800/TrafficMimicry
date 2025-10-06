import argparse
import json
from pathlib import Path
from typing import Dict

import numpy as np
import matplotlib.pyplot as plt


def _slugify(name: str) -> str:
    slug = name.lower().replace("&", "and").replace("/", "_")
    slug = slug.replace(" ", "_")
    return slug


def plot_fct_cdfs(data: dict, output_file: Path, title_prefix: str | None = None) -> None:
    """Plot the CDF of Flow Completion Times (FCTs) for baseline and transformed data."""

    baseline_fcts = np.array(data.get("baseline_fcts", []), dtype=float)
    transformed_fcts = np.array(data.get("transformed_fcts", []), dtype=float)
    baseline_count = int(data.get("baseline_count", baseline_fcts.size))
    transformed_count = int(data.get("transformed_count", transformed_fcts.size))
    label = data.get("label") or title_prefix
    if title_prefix and label is None:
        label = title_prefix

    if baseline_fcts.size == 0 and transformed_fcts.size == 0:
        print("No FCT data to plot.")
        return

    plt.figure(figsize=(10, 6))

    # Plot baseline CDF
    if baseline_fcts.size > 0:
        sorted_baseline = np.sort(baseline_fcts)
        yvals_baseline = np.arange(1, len(sorted_baseline) + 1) / len(sorted_baseline)
        baseline_label = f"Baseline (n={baseline_count})"
        plt.plot(sorted_baseline, yvals_baseline, label=baseline_label, color="blue")

    # Plot transformed CDF
    if transformed_fcts.size > 0:
        sorted_transformed = np.sort(transformed_fcts)
        yvals_transformed = np.arange(1, len(sorted_transformed) + 1) / len(sorted_transformed)
        transformed_label = f"Transformed (n={transformed_count})"
        plt.plot(
            sorted_transformed,
            yvals_transformed,
            label=transformed_label,
            color="red",
            linestyle="--",
        )

    plt.xlabel("Flow Completion Time (FCT) [seconds]")
    plt.ylabel("CDF")
    if label:
        plt.title(f"Flow Completion Time CDF — {label}")
    else:
        plt.title("Flow Completion Time (FCT) CDF")
    plt.legend()
    plt.grid(True)
    plt.xscale('log')
    
    # Ensure the output directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    plt.savefig(output_file)
    print(f"CDF plot saved to {output_file}")
    plt.close()

def main():
    parser = argparse.ArgumentParser(description="Plot FCT CDF from a JSON file.")
    parser.add_argument("input_file", type=Path, help="Input JSON file with FCT data.")
    parser.add_argument(
        "output_file",
        type=Path,
        help="Output PNG file for the aggregated plot.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional directory for service-level plots. Defaults to the output file's directory.",
    )
    args = parser.parse_args()

    if not args.input_file.exists():
        print(f"Error: Input file not found at {args.input_file}")
        return

    with open(args.input_file, "r") as f:
        data = json.load(f)

    output_dir = args.output_dir or args.output_file.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    aggregated = data.get("aggregated") or data
    aggregated_label = data.get("label")
    aggregated_entry: Dict = dict(aggregated)
    aggregated_entry.setdefault("label", aggregated_label)
    plot_fct_cdfs(aggregated_entry, args.output_file, title_prefix=aggregated_label)

    services: Dict[str, Dict] = data.get("services", {})
    if services:
        base_name = args.output_file.stem or "fct_cdf"
        suffix = args.output_file.suffix or ".png"
        for service_name, entry in services.items():
            slug = _slugify(service_name)
            service_label = (
                f"{aggregated_label} — {service_name}"
                if aggregated_label
                else service_name
            )
            output_path = output_dir / f"{base_name}_{slug}{suffix}"
            entry = dict(entry)
            entry.setdefault("label", service_label)
            plot_fct_cdfs(entry, output_path, title_prefix=service_label)

if __name__ == "__main__":
    main()
