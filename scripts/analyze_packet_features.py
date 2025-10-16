from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import json
from collections import defaultdict
from math import isfinite

import numpy as np
from tqdm import tqdm

try:
    from scripts.utils.stats import safe_slug
except ModuleNotFoundError:
    import sys
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(PROJECT_ROOT))
    from scripts.utils.stats import safe_slug

try:
    from scapy.all import PcapReader, Raw, IP, TCP, UDP
except ImportError:
    raise SystemExit("Scapy is required. Install with: pip install scapy")

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    raise SystemExit("matplotlib is required for plotting. Install with: pip install matplotlib")

def _iter_pcaps(root: Path) -> List[Path]:
    if not root.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {root}")
    pcaps = sorted(root.rglob("*.pcap")) + sorted(root.rglob("*.pcapng"))
    pcaps = [p for p in pcaps if "_sample.pcap" not in p.name and ".sample.pcap" not in p.name]
    if not pcaps:
        print(f"Warning: no PCAP files found in {root}")
    return pcaps

def _pkt_len(packet) -> int:
    if hasattr(packet, "wirelen"):
        try:
            return int(packet.wirelen)
        except Exception:
            pass
    try:
        return len(bytes(packet))
    except Exception:
        if Raw in packet:
            try:
                return int(len(packet[Raw].load))
            except Exception:
                pass
        return int(getattr(packet, "len", 0))


@dataclass
class PacketFeatureCollection:
    iats: List[float]
    lengths: List[float]
    total_bytes: float
    total_wall_time: float
    total_active_time: float
    flow_stats: Optional[Dict[tuple, Dict[str, float]]] = None

def collect_features_all_packets(
    pcap_dir: Path,
    collect_flows: bool = False,
) -> PacketFeatureCollection:
    iats: List[float] = []
    lengths: List[float] = []

    total_bytes = 0
    total_wall_time = 0.0
    total_active_time = 0.0

    pcaps = _iter_pcaps(pcap_dir)
    flows: Optional[Dict[tuple, Dict[str, float]]] = {} if collect_flows else None
    with tqdm(pcaps, desc=f"Scanning {pcap_dir.name}") as pbar:
        for pcap in pbar:
            pbar.set_description(f"Reading {pcap.name}")
            try:
                with PcapReader(str(pcap)) as reader:
                    prev_time: float | None = None
                    file_first: float | None = None
                    file_last: float | None = None

                    for pkt in reader:
                        ts = float(getattr(pkt, "time", 0.0))
                        pkt_length = float(_pkt_len(pkt))
                        total_bytes += pkt_length
                        lengths.append(pkt_length)
                        if flows is not None:
                            key = get_flow_key(pkt)
                            if key is not None:
                                blen = float(getattr(pkt, "wirelen", pkt_length))
                                ent = flows.get(key)
                                if ent is None:
                                    flows[key] = {'start': ts, 'end': ts, 'bytes': blen}
                                else:
                                    if ts < ent['start']:
                                        ent['start'] = ts
                                    if ts > ent['end']:
                                        ent['end'] = ts
                                    ent['bytes'] += blen

                        if file_first is None:
                            file_first = ts
                        file_last = ts

                        if prev_time is not None:
                            delta = ts - prev_time
                            if delta > 0.0:
                                iats.append(delta)
                                total_active_time += delta
                        prev_time = ts

                    if file_first is not None and file_last is not None and file_last >= file_first:
                        total_wall_time += (file_last - file_first)

            except Exception as exc:
                print(f"Warning: failed to parse {pcap}: {exc}")
                continue

    return PacketFeatureCollection(
        iats=iats,
        lengths=lengths,
        total_bytes=total_bytes,
        total_wall_time=total_wall_time,
        total_active_time=total_active_time,
        flow_stats=flows if flows is not None else None,
    )

def _ecdf(data: List[float]) -> Tuple[np.ndarray, np.ndarray]:
    samples = np.asarray(data, dtype=float)
    samples = samples[np.isfinite(samples)]
    if samples.size == 0:
        return np.array([]), np.array([])
    samples.sort()
    y = np.arange(1, samples.size + 1) / samples.size
    return samples, y


_SUMMARY_PERCENTILES = (0, 1, 5, 10, 25, 50, 75, 90, 95, 99, 100)


def _distribution_summary(
    samples: List[float],
    percentiles: Tuple[int, ...] = _SUMMARY_PERCENTILES,
) -> Dict[str, object]:
    summary: Dict[str, object] = {
        "count": len(samples),
        "finite_count": 0,
        "min": None,
        "max": None,
        "mean": None,
        "std": None,
        "percentiles": {f"p{q}": None for q in percentiles},
    }
    if not samples:
        return summary

    arr = np.asarray(samples, dtype=float)
    arr = arr[np.isfinite(arr)]
    if arr.size == 0:
        return summary

    summary["finite_count"] = int(arr.size)
    summary["min"] = float(arr.min())
    summary["max"] = float(arr.max())
    summary["mean"] = float(arr.mean())
    summary["std"] = float(arr.std(ddof=0))
    pct = {f"p{q}": float(np.percentile(arr, q)) for q in percentiles}
    summary["percentiles"] = pct
    return summary

def plot_ecdf_overlay(
    baseline: List[float],
    transformed: List[float],
    ax,
    title: str,
    xlabel: str,
    use_log_x: bool = False,
) -> None:
    x_base, y_base = _ecdf(baseline)
    x_trans, y_trans = _ecdf(transformed)

    if x_base.size:
        ax.step(x_base, y_base, where="post", label="Baseline", color="#1f77b4")
    if x_trans.size:
        ax.step(x_trans, y_trans, where="post", label="Transformed", color="#ff7f0e")

    if use_log_x:
        ax.set_xscale("log")

    ax.set_xlabel(xlabel)
    ax.set_ylabel("ECDF")
    ax.set_title(title)
    ax.grid(True, alpha=0.3)
    ax.legend()


def create_combined_figures(
    vpn_baseline_dir: Path,
    vpn_transformed_dir: Path,
    nonvpn_baseline_dir: Path,
    nonvpn_transformed_dir: Path,
    output_dir: Path,
    label: str = "VPN-vs-NonVPN",
) -> str:
    print(f"Collecting combined features for {label} (ALL packets) ...")
    vpn_baseline = collect_features_all_packets(vpn_baseline_dir)
    vpn_transformed = collect_features_all_packets(vpn_transformed_dir)
    nonvpn_baseline = collect_features_all_packets(nonvpn_baseline_dir)
    nonvpn_transformed = collect_features_all_packets(nonvpn_transformed_dir)

    output_dir.mkdir(parents=True, exist_ok=True)
    fig_path = output_dir / f"{safe_slug(label)}_combined_feature_ecdf.png"

    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))

    # IAT ECDF (log-x)
    for x, y, name in [
        (_ecdf(vpn_baseline.iats),  "VPN Baseline"),
        (_ecdf(vpn_transformed.iats),  "VPN Transformed"),
        (_ecdf(nonvpn_baseline.iats),   "NonVPN Baseline"),
        (_ecdf(nonvpn_transformed.iats),   "NonVPN Transformed"),
    ]:
        X, Y = x
        if X.size:
            axes[0].step(X, Y, where="post", label=name)
    axes[0].set_xscale("log")
    axes[0].set_xlabel("IAT (seconds)")
    axes[0].set_ylabel("ECDF")
    axes[0].set_title("Inter-arrival Time ECDF")
    axes[0].grid(True, alpha=0.3)
    axes[0].legend()

    for x, y, name in [
        (_ecdf(vpn_baseline.lengths), "VPN Baseline"),
        (_ecdf(vpn_transformed.lengths), "VPN Transformed"),
        (_ecdf(nonvpn_baseline.lengths),  "NonVPN Baseline"),
        (_ecdf(nonvpn_transformed.lengths),  "NonVPN Transformed"),
    ]:
        X, Y = x
        if X.size:
            axes[1].step(X, Y, where="post", label=name)
    axes[1].set_xlabel("Packet size (bytes)")
    axes[1].set_ylabel("ECDF")
    axes[1].set_title("Packet Length ECDF")
    axes[1].grid(True, alpha=0.3)
    axes[1].legend()

    fig.suptitle(f"{label} – Combined Packet Feature ECDFs", fontsize=14)
    fig.tight_layout(rect=[0, 0, 1, 0.98])
    fig.savefig(fig_path)
    plt.close(fig)

    print(f"Combined figure saved to {fig_path}")
    return str(fig_path)

def get_flow_key(packet):
    if IP not in packet:
        return None

    proto = packet[IP].proto
    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif UDP in packet:
        sport = packet[UDP].sport
        dport = packet[UDP].dport
    else:
        return None

    return (packet[IP].src, sport, packet[IP].dst, dport, proto)


def calculate_fcts_for_directory(pcap_dir: Path) -> List[float]:
    if not pcap_dir.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {pcap_dir}")

    all_fcts: List[float] = []
    pcap_files = sorted(
        [
            p
            for p in list(pcap_dir.rglob("*.pcap")) + list(pcap_dir.rglob("*.pcapng"))
            if "_sample.pcap" not in p.name and ".sample.pcap" not in p.name
        ]
    )
    if not pcap_files:
        print(f"Warning: No .pcap or .pcapng files found in {pcap_dir}")
        return []

    with tqdm(pcap_files) as pbar:
        for pcap_file in pbar:
            pbar.set_description(f"Processing {pcap_file.name}")
            flows: Dict[tuple, Dict[str, float]] = {}
            try:
                with PcapReader(str(pcap_file)) as reader:
                    for packet in reader:
                        flow_key = get_flow_key(packet)
                        if flow_key:
                            packet_time = float(packet.time)
                            if flow_key not in flows:
                                flows[flow_key] = {'start': packet_time, 'end': packet_time}
                            else:
                                flows[flow_key]['end'] = packet_time
            except Exception as e:
                print(f"Warning: Could not process {pcap_file}: {e}")
                continue

            for _, times in flows.items():
                if times['end'] > times['start']:
                    fct = times['end'] - times['start']
                    all_fcts.append(fct)

    return all_fcts

def collect_flow_stats(pcap_dir: Path) -> Dict[tuple, Dict[str, float]]:
    flows: Dict[tuple, Dict[str, float]] = {}
    pcaps = _iter_pcaps(pcap_dir)
    with tqdm(pcaps, desc=f"Flow scan {pcap_dir.name}") as pbar:
        for pcap in pbar:
            pbar.set_description(f"Reading {pcap.name}")
            try:
                with PcapReader(str(pcap)) as reader:
                    for pkt in reader:
                        key = get_flow_key(pkt)
                        if not key:
                            continue
                        ts = float(getattr(pkt, "time", 0.0))
                        blen = float(getattr(pkt, "wirelen", _pkt_len(pkt)))
                        ent = flows.get(key)
                        if ent is None:
                            flows[key] = {'start': ts, 'end': ts, 'bytes': blen}
                        else:
                            if ts < ent['start']:
                                ent['start'] = ts
                            if ts > ent['end']:
                                ent['end'] = ts
                            ent['bytes'] += blen
            except Exception as exc:
                print(f"Warning: failed to parse {pcap}: {exc}")
                continue
    return flows


def per_flow_throughputs(flow_stats: Dict[tuple, Dict[str, float]]) -> List[float]:
    tputs: List[float] = []
    for ent in flow_stats.values():
        dur = ent['end'] - ent['start']
        if dur > 0:
            tputs.append(ent['bytes'] / dur)
    return tputs


def weighted_mean(values: List[float], weights: List[float]) -> float:
    wsum = sum(weights)
    return (sum(v*w for v, w in zip(values, weights)) / wsum) if wsum > 0 else 0.0


def percentiles(arr: List[float], qs=(50, 90, 99)) -> Dict[str, float]:
    if not arr:
        return {f"p{q}": 0.0 for q in qs}
    a = np.asarray(arr, dtype=float)
    a = a[np.isfinite(a)]
    if a.size == 0:
        return {f"p{q}": 0.0 for q in qs}
    out = {}
    for q in qs:
        out[f"p{q}"] = float(np.percentile(a, q))
    return out


def normalize_throughput_by_flow(
    baseline_dir: Path,
    transformed_dir: Path,
    baseline_flow_stats: Optional[Dict[tuple, Dict[str, float]]] = None,
    transformed_flow_stats: Optional[Dict[tuple, Dict[str, float]]] = None,
) -> Dict[str, object]:
    print("Computing flow-normalized throughputs ...")
    base_flows = baseline_flow_stats if baseline_flow_stats is not None else collect_flow_stats(baseline_dir)
    trans_flows = transformed_flow_stats if transformed_flow_stats is not None else collect_flow_stats(transformed_dir)

    base_tputs = per_flow_throughputs(base_flows)
    trans_tputs = per_flow_throughputs(trans_flows)
    base_weights = [ent['bytes'] for ent in base_flows.values() if (ent['end'] - ent['start']) > 0]
    trans_weights = [ent['bytes'] for ent in trans_flows.values() if (ent['end'] - ent['start']) > 0]
    base_wmean = weighted_mean(base_tputs, base_weights) if base_tputs else 0.0
    trans_wmean = weighted_mean(trans_tputs, trans_weights) if trans_tputs else 0.0

    base_pct = percentiles(base_tputs)
    trans_pct = percentiles(trans_tputs)
    med_over_abs = trans_pct["p50"] - base_pct["p50"]
    med_over_pct = (med_over_abs / base_pct["p50"] * 100.0) if base_pct["p50"] > 0 else 0.0
    wmean_over_abs = trans_wmean - base_wmean
    wmean_over_pct = (wmean_over_abs / base_wmean * 100.0) if base_wmean > 0 else 0.0
    matched_keys = set(base_flows.keys()) & set(trans_flows.keys())
    matched_ratios: List[float] = []
    for k in matched_keys:
        b = base_flows[k]; t = trans_flows[k]
        bdur = b['end'] - b['start']
        tdur = t['end'] - t['start']
        if bdur > 0 and tdur > 0:
            btput = b['bytes'] / bdur
            ttput = t['bytes'] / tdur
            if btput > 0:
                matched_ratios.append(ttput / btput)
    matched_pct = percentiles(matched_ratios) if matched_ratios else {"p50": 0.0, "p90": 0.0, "p99": 0.0}

    return {
        "flow_normalized": {
            "baseline": {
                "num_flows": len(base_tputs),
                "throughput_percentiles": base_pct,
                "throughput_weighted_mean": base_wmean,
            },
            "transformed": {
                "num_flows": len(trans_tputs),
                "throughput_percentiles": trans_pct,
                "throughput_weighted_mean": trans_wmean,
            },
            "overhead_via_median": {
                "absolute": med_over_abs,
                "percent": med_over_pct
            },
            "overhead_via_weighted_mean": {
                "absolute": wmean_over_abs,
                "percent": wmean_over_pct
            },
            "matched_flows": {
                "count": len(matched_ratios),
                "ratio_percentiles": matched_pct  
            }
        }
    }

def _list_service_dirs(root: Path) -> Dict[str, Path]:
    services: Dict[str, Path] = {}
    if not root.exists():
        return services
    for child in sorted(root.iterdir()):
        if child.is_dir():
            services[child.name] = child
    has_pcap_files = any(
        child.is_file() and child.suffix.lower() in {".pcap", ".pcapng"}
        for child in root.iterdir()
    )
    if has_pcap_files:
        services[root.name] = root
    return services


def _plot_fct_distributions(
    baseline: List[float],
    transformed: List[float],
    title: str,
    plot_dir: Path,
    filename: str,
    plt_module,
) -> Tuple[Optional[str], Optional[Dict[str, List[float]]]]:
    if plt_module is None:
        return None, None
    if not baseline and not transformed:
        return None, None

    data = np.array(baseline + transformed, dtype=float)
    if data.size == 0:
        return None, None

    low, high = data.min(), data.max()
    if low == high:
        high = low + 1e-9

    bins = max(10, min(200, int(np.sqrt(data.size))))

    plt = plt_module
    fig, ax = plt.subplots(figsize=(8, 4.5))

    bin_edges = np.linspace(low, high, bins + 1)
    centers = (bin_edges[:-1] + bin_edges[1:]) / 2.0

    distribution_data = {
        "bin_edges": bin_edges.tolist(),
        "bin_centers": centers.tolist(),
        "baseline_density": [],
        "transformed_density": [],
    }

    if baseline:
        baseline_hist, _ = np.histogram(baseline, bins=bin_edges, density=True)
        distribution_data["baseline_density"] = baseline_hist.tolist()
        ax.plot(centers, baseline_hist, label="Baseline", linewidth=1.8)

    if transformed:
        transformed_hist, _ = np.histogram(transformed, bins=bin_edges, density=True)
        distribution_data["transformed_density"] = transformed_hist.tolist()
        ax.plot(centers, transformed_hist, label="Transformed", linewidth=1.8)

    ax.set_xlabel("Flow Completion Time (s)")
    ax.set_ylabel("Density")
    ax.set_title(title)
    ax.legend()
    ax.grid(True, alpha=0.3)
    plot_dir.mkdir(parents=True, exist_ok=True)
    plot_path = plot_dir / filename
    fig.tight_layout()
    fig.savefig(plot_path)
    plt.close(fig)
    return str(plot_path), distribution_data


def analyze_fcts(
    baseline_dir: Path,
    transformed_dir: Path,
    output_file: Path,
    label: str,
    plot_dir: Optional[Path] = None,
) -> None:
    print(f"Processing dataset: {label}")

    plt_module = None
    if plot_dir is not None:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            plt_module = plt
        except ImportError:
            print("Matplotlib not installed; skipping plot generation.")
            plot_dir = None

    services_results: Dict[str, Dict[str, List[float] | int | str | dict | None | float]] = {}
    aggregated_baseline_fcts: List[float] = []
    aggregated_transformed_fcts: List[float] = []

    baseline_services = _list_service_dirs(baseline_dir)
    transformed_services = _list_service_dirs(transformed_dir)
    all_service_names = sorted(set(baseline_services) | set(transformed_services))

    for service_name in all_service_names:
        print(f"\nProcessing service: {service_name}")
        baseline_dir_svc = baseline_services.get(service_name)
        transformed_dir_svc = transformed_services.get(service_name)

        if baseline_dir_svc is None:
            print(f"  Warning: No baseline directory found for service '{service_name}'")
            baseline_service_fcts: List[float] = []
        else:
            print(f"  Calculating baseline FCTs for: {baseline_dir_svc}")
            baseline_service_fcts = calculate_fcts_for_directory(baseline_dir_svc)

        if transformed_dir_svc is None:
            print(f"  Warning: No transformed directory found for service '{service_name}'")
            transformed_service_fcts: List[float] = []
        else:
            print(f"  Calculating transformed FCTs for: {transformed_dir_svc}")
            transformed_service_fcts = calculate_fcts_for_directory(transformed_dir_svc)

        plot_path = None
        distribution_data = None
        if plot_dir is not None and plt_module is not None:
            services_plot_dir = plot_dir / "services"
            plot_filename = f"{safe_slug(service_name or 'service')}_fct_distribution.png"
            plot_path, distribution_data = _plot_fct_distributions(
                baseline_service_fcts,
                transformed_service_fcts,
                f"{service_name} FCT Distribution",
                services_plot_dir,
                plot_filename,
                plt_module,
            )

        service_entry: Dict[str, List[float] | int | str | float | None] = {
            "label": service_name,
            "baseline_fcts": baseline_service_fcts,
            "baseline_count": len(baseline_service_fcts),
            "transformed_fcts": transformed_service_fcts,
            "transformed_count": len(transformed_service_fcts),
        }
        if plot_path:
            service_entry["plot_path"] = plot_path
        if distribution_data:
            service_entry["distribution_data"] = distribution_data

        services_results[service_name] = service_entry

        aggregated_baseline_fcts.extend(baseline_service_fcts)
        aggregated_transformed_fcts.extend(transformed_service_fcts)

    aggregated_plot_path = None
    aggregated_distribution_data = None
    if plot_dir is not None and plt_module is not None:
        plot_filename = f"{safe_slug(label or 'aggregated')}_aggregated_fct_distribution.png"
        aggregated_plot_path, aggregated_distribution_data = _plot_fct_distributions(
            aggregated_baseline_fcts,
            aggregated_transformed_fcts,
            f"{label} Aggregated FCT Distribution",
            plot_dir,
            plot_filename,
            plt_module,
        )

    results = {
        "label": label,
        "aggregated": {
            "label": label,
            "baseline_fcts": aggregated_baseline_fcts,
            "baseline_count": len(aggregated_baseline_fcts),
            "transformed_fcts": aggregated_transformed_fcts,
            "transformed_count": len(aggregated_transformed_fcts),
        },
        "services": services_results,
    }
    if aggregated_plot_path:
        results["aggregated"]["plot_path"] = aggregated_plot_path
    if aggregated_distribution_data:
        results["aggregated"]["distribution_data"] = aggregated_distribution_data

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nFCT results saved to {output_file}")
    print(f"Total baseline flows found: {len(aggregated_baseline_fcts)}")
    print(f"Total transformed flows found: {len(aggregated_transformed_fcts)}")

def create_figures(
    baseline_dir: Path,
    transformed_dir: Path,
    output_dir: Path,
    label: str,
    flow_normalize: bool = False,
) -> Dict[str, str | float | int | dict]:
    print(f"Collecting features for {label} (ALL packets) ...")

    baseline_stats = collect_features_all_packets(baseline_dir, collect_flows=flow_normalize)
    transformed_stats = collect_features_all_packets(transformed_dir, collect_flows=flow_normalize)

    baseline_tput_wall = (baseline_stats.total_bytes / baseline_stats.total_wall_time) if baseline_stats.total_wall_time > 0 else 0.0
    transformed_tput_wall = (transformed_stats.total_bytes / transformed_stats.total_wall_time) if transformed_stats.total_wall_time > 0 else 0.0
    wall_overhead = transformed_tput_wall - baseline_tput_wall
    wall_overhead_pct = (wall_overhead / baseline_tput_wall * 100.0) if baseline_tput_wall > 0 else 0.0
    baseline_tput_active = (baseline_stats.total_bytes / baseline_stats.total_active_time) if baseline_stats.total_active_time > 0 else 0.0
    transformed_tput_active = (transformed_stats.total_bytes / transformed_stats.total_active_time) if transformed_stats.total_active_time > 0 else 0.0
    active_overhead = transformed_tput_active - baseline_tput_active
    active_overhead_pct = (active_overhead / baseline_tput_active * 100.0) if baseline_tput_active > 0 else 0.0
    print("Generating Figure 1 (ECDF overlays)...")
    output_dir.mkdir(parents=True, exist_ok=True)
    fig1_path = output_dir / f"{safe_slug(label)}_feature_ecdf.png"

    base_iat_ecdf_x, base_iat_ecdf_y = _ecdf(baseline_stats.iats)
    trans_iat_ecdf_x, trans_iat_ecdf_y = _ecdf(transformed_stats.iats)
    base_len_ecdf_x, base_len_ecdf_y = _ecdf(baseline_stats.lengths)
    trans_len_ecdf_x, trans_len_ecdf_y = _ecdf(transformed_stats.lengths)

    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    plot_ecdf_overlay(
        baseline_stats.iats,
        transformed_stats.iats,
        axes[0],
        "Inter-arrival Time ECDF",
        "IAT (seconds)",
        use_log_x=True,
    )
    plot_ecdf_overlay(
        baseline_stats.lengths,
        transformed_stats.lengths,
        axes[1],
        "Packet Length ECDF",
        "Packet size (bytes)",
        use_log_x=False,
    )
    fig.suptitle(f"{label} – Packet Feature ECDFs (All Packets)", fontsize=14)
    fig.tight_layout(rect=[0, 0, 1, 0.98])
    fig.savefig(fig1_path)
    plt.close(fig)

    result: Dict[str, str | float | int | dict] = {
        "ecdf_figure": str(fig1_path),
        "baseline_total_bytes": baseline_stats.total_bytes,
        "baseline_wall_time": baseline_stats.total_wall_time,
        "baseline_active_time": baseline_stats.total_active_time,
        "transformed_total_bytes": transformed_stats.total_bytes,
        "transformed_wall_time": transformed_stats.total_wall_time,
        "transformed_active_time": transformed_stats.total_active_time,
        "baseline_throughput_wall": baseline_tput_wall,
        "transformed_throughput_wall": transformed_tput_wall,
        "throughput_overhead_wall": wall_overhead,
        "throughput_overhead_wall_percent": wall_overhead_pct,
        "baseline_throughput_active": baseline_tput_active,
        "transformed_throughput_active": transformed_tput_active,
        "throughput_overhead_active": active_overhead,
        "throughput_overhead_active_percent": active_overhead_pct,
        "baseline_iat_sample_count": len(baseline_stats.iats),
        "baseline_packet_sample_count": len(baseline_stats.lengths),
        "transformed_iat_sample_count": len(transformed_stats.iats),
        "transformed_packet_sample_count": len(transformed_stats.lengths),
        "distribution_summaries": {
            "iat": {
                "baseline": _distribution_summary(baseline_stats.iats),
                "transformed": _distribution_summary(transformed_stats.iats),
            },
            "packet_length": {
                "baseline": _distribution_summary(baseline_stats.lengths),
                "transformed": _distribution_summary(transformed_stats.lengths),
            },
        },
    }

    if flow_normalize:
        try:
            extras = normalize_throughput_by_flow(
                baseline_dir,
                transformed_dir,
                baseline_flow_stats=baseline_stats.flow_stats,
                transformed_flow_stats=transformed_stats.flow_stats,
            )
            result.update(extras)
        except Exception as exc:
            print(f"Warning: flow-normalized stats failed: {exc}")

    return result

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze packet features or Flow Completion Times (FCTs) from PCAP directories."
    )
    parser.add_argument(
        "--mode",
        choices=["packet-features", "fct"],
        default="packet-features",
        help="Analysis mode: 'packet-features' for IAT/length analysis, 'fct' for flow completion times.",
    )
    parser.add_argument(
        "--baseline-dir",
        type=Path,
        help="Directory with baseline (original) PCAP files.",
    )
    parser.add_argument(
        "--transformed-dir",
        type=Path,
        help="Directory with transformed PCAP files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory to store generated figures (for packet-features mode).",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        help="JSON file to save FCT results (for fct mode).",
    )
    parser.add_argument(
        "--label",
        type=str,
        default=None,
        help="Optional label describing this dataset.",
    )
    parser.add_argument(
        "--plot-dir",
        type=Path,
        default=None,
        help="Optional directory to save FCT distribution plots (for fct mode).",
    )
    parser.add_argument(
        "--flow-normalize",
        action="store_true",
        help="Also compute per-flow throughput stats and normalized overheads."
    )
    parser.add_argument(
        "--combined", 
        action="store_true",
        help="Generate a combined VPN vs NonVPN ECDF figure (requires the four *_dir args below).")
    parser.add_argument(
        "--vpn-baseline-dir", 
        type=Path, 
        help="VPN baseline dir (for --combined).")
    parser.add_argument(
        "--vpn-transformed-dir", 
        type=Path, 
        help="VPN transformed dir (for --combined).")
    parser.add_argument(
        "--nonvpn-baseline-dir", 
        type=Path, 
        help="NonVPN baseline dir (for --combined).")
    parser.add_argument(
        "--nonvpn-transformed-dir", 
        type=Path, 
        help="NonVPN transformed dir (for --combined).")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.combined:
        if not all([args.vpn_baseline_dir, args.vpn_transformed_dir,
                    args.nonvpn_baseline_dir, args.nonvpn_transformed_dir, args.output_dir]):
            raise ValueError("--combined requires --vpn-baseline-dir, --vpn-transformed-dir, "
                             "--nonvpn-baseline-dir, --nonvpn-transformed-dir, and --output-dir")
        create_combined_figures(
            args.vpn_baseline_dir,
            args.vpn_transformed_dir,
            args.nonvpn_baseline_dir,
            args.nonvpn_transformed_dir,
            args.output_dir,
            label=args.label or "VPN-vs-NonVPN"
        )
        return
    if not args.baseline_dir or not args.transformed_dir:
        raise ValueError("Regular mode requires --baseline-dir and --transformed-dir")

    label = args.label or args.baseline_dir.name

    if args.mode == "packet-features":
        if args.output_dir is None:
            raise ValueError("--output-dir is required for packet-features mode")
        summary = create_figures(
            args.baseline_dir,
            args.transformed_dir,
            args.output_dir,
            label,
            flow_normalize=args.flow_normalize,
        )
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / f"{safe_slug(label)}_summary.json"
        with open(json_path, "w") as f:
            json.dump(summary, f, indent=2)

        print(f"Summary saved to {json_path}")
        print("\nSummary:")
        for key, value in summary.items():
            if isinstance(value, float):
                printable = f"{value:.6f}"
            else:
                printable = value
            print(f"  {key}: {printable}")

    elif args.mode == "fct":
        if args.output_file is None:
            raise ValueError("--output-file is required for fct mode")
        analyze_fcts(
            args.baseline_dir,
            args.transformed_dir,
            args.output_file,
            label,
            args.plot_dir,
        )

if __name__ == "__main__":
    main()
