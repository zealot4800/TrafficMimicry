import argparse
import json
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional

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
    pcap_files = sorted(list(pcap_dir.rglob("*.pcap")))
    if not pcap_files:
        print(f"Warning: No .pcap files found in {pcap_dir}")
        return []

    for pcap_file in pcap_files:
        flows = defaultdict(list)
        try:
            with PcapReader(str(pcap_file)) as reader:
                for packet in reader:
                    flow_key = get_flow_key(packet)
                    if flow_key:
                        flows[flow_key].append(float(packet.time))
        except Exception as e:
            print(f"Warning: Could not process {pcap_file}: {e}")
            continue

        for flow_key, timestamps in flows.items():
            if len(timestamps) > 1:
                fct = max(timestamps) - min(timestamps)
                all_fcts.append(fct)
                
    return all_fcts

def main():
    parser = argparse.ArgumentParser(description="Calculate Flow Completion Times (FCTs) from PCAP directories.")
    parser.add_argument("--baseline-dir", type=Path, required=True, help="Directory with baseline (original) PCAP files.")
    parser.add_argument("--transformed-dir", type=Path, required=True, help="Directory with transformed PCAP files.")
    parser.add_argument("--output-file", type=Path, required=True, help="JSON file to save the FCT results.")
    args = parser.parse_args()

    print(f"Processing baseline directory: {args.baseline_dir}")
    baseline_fcts = calculate_fcts_for_directory(args.baseline_dir)
    
    print(f"Processing transformed directory: {args.transformed_dir}")
    transformed_fcts = calculate_fcts_for_directory(args.transformed_dir)

    results = {
        "baseline_fcts": baseline_fcts,
        "transformed_fcts": transformed_fcts,
    }

    args.output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"FCT results saved to {args.output_file}")
    print(f"Baseline flows found: {len(baseline_fcts)}")
    print(f"Transformed flows found: {len(transformed_fcts)}")

if __name__ == "__main__":
    main()
