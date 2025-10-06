import argparse
import json
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt

def plot_fct_cdfs(data: dict, output_file: Path):
    """
    Plots the CDF of Flow Completion Times (FCTs) for baseline and transformed data.
    """
    baseline_fcts = np.array(data.get("baseline_fcts", []))
    transformed_fcts = np.array(data.get("transformed_fcts", []))

    if baseline_fcts.size == 0 and transformed_fcts.size == 0:
        print("No FCT data to plot.")
        return

    plt.figure(figsize=(10, 6))

    # Plot baseline CDF
    if baseline_fcts.size > 0:
        sorted_baseline = np.sort(baseline_fcts)
        yvals_baseline = np.arange(1, len(sorted_baseline) + 1) / len(sorted_baseline)
        plt.plot(sorted_baseline, yvals_baseline, label="Baseline", color="blue")

    # Plot transformed CDF
    if transformed_fcts.size > 0:
        sorted_transformed = np.sort(transformed_fcts)
        yvals_transformed = np.arange(1, len(sorted_transformed) + 1) / len(sorted_transformed)
        plt.plot(sorted_transformed, yvals_transformed, label="Transformed", color="red", linestyle="--")

    plt.xlabel("Flow Completion Time (FCT) [seconds]")
    plt.ylabel("CDF")
    plt.title("CDF of Flow Completion Time (FCT)")
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
    parser.add_argument("output_file", type=Path, help="Output PNG file for the plot.")
    args = parser.parse_args()

    if not args.input_file.exists():
        print(f"Error: Input file not found at {args.input_file}")
        return

    with open(args.input_file, "r") as f:
        data = json.load(f)

    plot_fct_cdfs(data, args.output_file)

if __name__ == "__main__":
    main()
