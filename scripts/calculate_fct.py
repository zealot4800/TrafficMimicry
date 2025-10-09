import argparse
import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from tqdm import tqdm

try:
    from scapy.all import PcapReader, IP, TCP, UDP
except ImportError:
    print("Scapy is not installed. Please run: pip install scapy")
    exit(1)

def get_flow_key(packet):
    """Extracts a 5-tuple flow key from a packet."""
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
    """
    Calculates Flow Completion Times (FCTs) for all PCAP files in a directory.
    """
    if not pcap_dir.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {pcap_dir}")

    all_fcts: List[float] = []
    pcap_files = sorted(list(pcap_dir.rglob("*.pcap")) + list(pcap_dir.rglob("*.pcapng")))
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

            for flow_key, times in flows.items():
                if times['end'] > times['start']:
                    fct = times['end'] - times['start']
                    all_fcts.append(fct)

    return all_fcts


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


def _summarize_fcts(fcts: List[float]) -> Tuple[List[float], int]:
    return fcts, len(fcts)

def main():
    parser = argparse.ArgumentParser(
        description="Calculate Flow Completion Times (FCTs) from PCAP directories."
    )
    parser.add_argument(
        "--baseline-dir",
        type=Path,
        required=True,
        help="Directory with baseline (original) PCAP files.",
    )
    parser.add_argument(
        "--transformed-dir",
        type=Path,
        required=True,
        help="Directory with transformed PCAP files.",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        required=True,
        help="JSON file to save the FCT results.",
    )
    parser.add_argument(
        "--label",
        type=str,
        default=None,
        help=(
            "Optional label describing this dataset (e.g., 'Non-VPN' or 'VPN')."
        ),
    )
    args = parser.parse_args()

    label = args.label or args.baseline_dir.name
    print(f"Processing dataset: {label}")

    services_results: Dict[str, Dict[str, List[float] | int | str]] = {}
    aggregated_baseline_fcts: List[float] = []
    aggregated_transformed_fcts: List[float] = []

    baseline_services = _list_service_dirs(args.baseline_dir)
    transformed_services = _list_service_dirs(args.transformed_dir)
    all_service_names = sorted(set(baseline_services) | set(transformed_services))

    # Service-specific FCTs
    for service_name in all_service_names:
        print(f"\nProcessing service: {service_name}")
        baseline_dir = baseline_services.get(service_name)
        transformed_dir = transformed_services.get(service_name)

        if baseline_dir is None:
            print(f"  Warning: No baseline directory found for service '{service_name}'")
            baseline_service_fcts: List[float] = []
        else:
            print(f"  Calculating baseline FCTs for: {baseline_dir}")
            baseline_service_fcts = calculate_fcts_for_directory(baseline_dir)

        if transformed_dir is None:
            print(f"  Warning: No transformed directory found for service '{service_name}'")
            transformed_service_fcts: List[float] = []
        else:
            print(f"  Calculating transformed FCTs for: {transformed_dir}")
            transformed_service_fcts = calculate_fcts_for_directory(transformed_dir)

        services_results[service_name] = {
            "label": service_name,
            "baseline_fcts": baseline_service_fcts,
            "baseline_count": len(baseline_service_fcts),
            "transformed_fcts": transformed_service_fcts,
            "transformed_count": len(transformed_service_fcts),
        }
        
        aggregated_baseline_fcts.extend(baseline_service_fcts)
        aggregated_transformed_fcts.extend(transformed_service_fcts)

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

    args.output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nFCT results saved to {args.output_file}")
    print(f"Total baseline flows found: {len(aggregated_baseline_fcts)}")
    print(f"Total transformed flows found: {len(aggregated_transformed_fcts)}")

if __name__ == "__main__":
    main()
