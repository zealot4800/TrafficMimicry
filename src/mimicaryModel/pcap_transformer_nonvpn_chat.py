from __future__ import annotations
import argparse
import json
import math
import os
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple
try:
    from scapy.all import IP, TCP, UDP, Raw, PcapReader, PcapWriter, fragment, conf
except ImportError as exc:
    raise ImportError("Scapy is required. Install with: pip install scapy") from exc
PACKET_LEN_IMP = 0.55765215
TCP_FLAGS_IMP = 0.2464132
SLA_THRESHOLDS = {
    "pps_band_pct": (0.20, 0.30),
    "mean_iat_band_pct": (0.20, 0.30),
    "stdev_iat_max_pct_of_mean": 2.0,
    "stdev_iat_abs_max_ms": 2000.0,
    "per_gap_margin_pct": (0.10, 0.20),
    "max_total_stretch_pct": 0.10,
}
FRAGMENT_SIZE = 500
PADDING_MIN, PADDING_MAX = 50, 600
MILLISECONDS = 1000.0
MIN_TIME_INC = 1e-6
def get_baseline_metrics(packets: Iterable) -> Dict[str, float]:
    metrics = MetricsAccumulator()
    for pkt in packets:
        metrics.update(float(getattr(pkt, "time", 0.0)))
    return metrics.as_dict()
def calculate_sla_from_baseline(baseline_metrics: Dict[str, float], thresholds: Dict) -> Dict[str, float]:
    base_pps = baseline_metrics.get("pps", 0)
    base_iat_ms = baseline_metrics.get("mean_iat_ms", 0)
    _, pps_margin_max = thresholds["pps_band_pct"]
    pps_min = base_pps * (1 - pps_margin_max)
    pps_max = base_pps * (1 + pps_margin_max)
    iat_margin_min, iat_margin_max = thresholds["mean_iat_band_pct"]
    iat_min_ms = base_iat_ms * (1 + iat_margin_min)
    iat_max_ms = base_iat_ms * (1 + iat_margin_max)
    stdev_cap_from_mean = base_iat_ms * thresholds["stdev_iat_max_pct_of_mean"]
    stdev_iat_max_ms = min(stdev_cap_from_mean, thresholds["stdev_iat_abs_max_ms"])
    return {
        "SLA_PPS_MIN": pps_min,
        "SLA_PPS_MAX": pps_max,
        "SLA_IAT_MIN_MS": iat_min_ms,
        "SLA_IAT_MAX_MS": iat_max_ms,
        "SLA_IAT_STDEV_MAX_MS": stdev_iat_max_ms,
    }
@dataclass
class MetricsAccumulator:
    count: int = 0
    first_time: Optional[float] = None
    last_time: Optional[float] = None
    _iat_count: int = 0
    _iat_mean: float = 0.0
    _iat_m2: float = 0.0
    def update(self, timestamp: float) -> None:
        timestamp = float(timestamp)
        if self.count == 0:
            self.first_time = timestamp
        else:
            if self.last_time is not None:
                delta = timestamp - self.last_time
                if delta >= 0.0:
                    self._update_iat(delta)
        self.last_time = timestamp
        self.count += 1
    def _update_iat(self, delta: float) -> None:
        self._iat_count += 1
        diff = delta - self._iat_mean
        self._iat_mean += diff / self._iat_count
        self._iat_m2 += diff * (delta - self._iat_mean)
    def as_dict(self) -> Dict[str, float]:
        duration = 0.0
        if self.first_time is not None and self.last_time is not None:
            duration = self.last_time - self.first_time
        mean_iat_sec = self._iat_mean if self._iat_count > 0 else 0.0
        stdev_iat_sec = math.sqrt(self._iat_m2 / self._iat_count) if self._iat_count > 0 else 0.0
        pps = self.count / duration if duration > 0.0 else 0.0
        return {
            "duration_sec": duration,
            "mean_iat_ms": mean_iat_sec * MILLISECONDS,
            "stdev_iat_ms": stdev_iat_sec * MILLISECONDS,
            "pps": pps,
            "packet_count": self.count,
        }
def _recalc_checksums(pkt) -> None:
    if IP in pkt:
        pkt[IP].len = None
        pkt[IP].chksum = None
    for layer in (TCP, UDP):
        if layer in pkt:
            pkt[layer].chksum = None
def _copy_stream(packets: Iterable) -> Iterator:
    for pkt in packets:
        yield pkt.copy()
def apply_packet_fragmentation(packets: Iterable, importance: float) -> Iterator:
    if importance <= 0:
        yield from _copy_stream(packets)
        return
    threshold = int(FRAGMENT_SIZE * (1 - importance * 0.5))
    for pkt in packets:
        if IP in pkt and len(pkt) > threshold:
            yield from fragment(pkt, fragsize=threshold)
        else:
            yield pkt.copy()
def apply_traffic_padding(packets: Iterable, importance: float) -> Iterator:
    if importance <= 0:
        yield from _copy_stream(packets)
        return
    max_pad = int(PADDING_MAX * importance)
    min_pad = int(PADDING_MIN * importance)
    for pkt in packets:
        if IP in pkt and max_pad > 0:
            padded = pkt.copy()
            pad_size = random.randint(min_pad, max_pad)
            pad_bytes = os.urandom(pad_size)
            if Raw in padded:
                padded[Raw].load += pad_bytes
            else:
                padded /= Raw(pad_bytes)
            _recalc_checksums(padded)
            yield padded
        else:
            yield pkt.copy()
def apply_size_randomization(packets: Iterable, importance: float) -> Iterator:
    for pkt in packets:
        if IP in pkt and Raw in pkt:
            modified = pkt.copy()
            current_size = len(modified[Raw].load)
            size_delta = int(current_size * importance * random.uniform(-0.3, 0.5))
            if size_delta > 0:
                modified[Raw].load = bytes(modified[Raw].load) + os.urandom(size_delta)
            elif size_delta < 0 and current_size + size_delta > 0:
                modified[Raw].load = bytes(modified[Raw].load)[:current_size + size_delta]
            _recalc_checksums(modified)
            yield modified
        else:
            yield pkt.copy()
def apply_tcp_flag_manipulation(packets: Iterable, importance: float) -> Iterator:
    if importance <= 0:
        yield from _copy_stream(packets)
        return
    for pkt in packets:
        modified_pkt = pkt.copy()
        if TCP in modified_pkt and random.random() < importance:
            current_flags = int(modified_pkt[TCP].flags)
            if current_flags & 0b100:
                modified_pkt[TCP].flags ^= 0b010
            else:
                modified_pkt[TCP].flags ^= 0b100
            _recalc_checksums(modified_pkt)
        yield modified_pkt
def apply_recommended_transformations_with_sla(
    packets: Iterable,
) -> Tuple[Iterator, Dict[str, float]]:
    original_packets = list(packets)
    if not original_packets:
        raise ValueError("No packets to transform")
    original_metrics = get_baseline_metrics(original_packets)
    sla_constraints = calculate_sla_from_baseline(original_metrics, SLA_THRESHOLDS)
    return apply_progressive_transformations_with_sla_check(original_packets, original_metrics, sla_constraints)
def apply_progressive_transformations_with_sla_check(
    original_packets: List,
    original_result: Dict[str, float],
    sla_constraints: Dict[str, float]
) -> Tuple[Iterator, Dict[str, float]]:
    transformations = [
        ("fragmentation", apply_packet_fragmentation, PACKET_LEN_IMP),
        ("padding", apply_traffic_padding, PACKET_LEN_IMP),
        ("size_randomization", apply_size_randomization, PACKET_LEN_IMP),
        ("tcp_flags", apply_tcp_flag_manipulation, TCP_FLAGS_IMP),
    ]
    current_packets = list(_copy_stream(original_packets))
    applied_transformations = []
    last_sla_compliant_packets = list(_copy_stream(original_packets))
    last_sla_compliant_transformations = []
    for transform_name, transform_func, base_importance in transformations:
        transformation_applied_successfully = False
        for intensity_scale in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]:
            test_importance = base_importance * intensity_scale
            test_stream = transform_func(iter(current_packets), test_importance)
            test_packets = list(test_stream)
            if not test_packets:
                continue
            test_metrics = get_baseline_metrics(test_packets)
            sla_results = validate_sla(test_metrics, sla_constraints)
            if all(sla_results.values()):
                current_packets = test_packets
                current_applied_transformations = applied_transformations + [{
                    "name": transform_name,
                    "importance": test_importance,
                    "intensity_scale": intensity_scale
                }]
                last_sla_compliant_packets = current_packets
                last_sla_compliant_transformations = current_applied_transformations
                transformation_applied_successfully = True
                break
        if transformation_applied_successfully:
            applied_transformations = last_sla_compliant_transformations
        else:
            current_packets = last_sla_compliant_packets
    if not applied_transformations:
        result = original_result.copy()
        result["sla_validation"] = validate_sla(original_result, sla_constraints)
        result["sla_passed"] = True
        result["applied_transformations"] = []
        result["reason"] = "No transformations could be applied while maintaining SLA"
        return iter(_copy_stream(original_packets)), result
    final_packets = last_sla_compliant_packets
    final_metrics = get_baseline_metrics(final_packets)
    final_result = final_metrics
    final_result["sla_validation"] = validate_sla(final_metrics, sla_constraints)
    final_result["sla_passed"] = all(final_result["sla_validation"].values())
    final_result["applied_transformations"] = last_sla_compliant_transformations
    final_result["transformation_count"] = len(last_sla_compliant_transformations)
    return iter(final_packets), final_result
def find_pcap_files(directory: Path) -> List[Path]:
    pcap_files = []
    for ext in ['*.pcap', '*.pcapng', '*.cap']:
        pcap_files.extend(directory.rglob(ext))
    return sorted(pcap_files)
def process_directory(
    input_dir: Path,
    output_dir: Path,
    seed: int = 1337,
) -> Dict[str, Dict[str, float]]:
    results = {}
    pcap_files = find_pcap_files(input_dir)
    if not pcap_files:
        raise ValueError(f"No PCAP files found in {input_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    for pcap_file in pcap_files:
        relative_path = pcap_file.relative_to(input_dir)
        output_file = output_dir / relative_path
        output_file.parent.mkdir(parents=True, exist_ok=True)
        print(f"Processing: {relative_path}")
        try:
            random.seed(seed)
            reader = PcapReader(str(pcap_file))
            all_packets = list(reader)
            linktype = reader.linktype
            reader.close()
            if not all_packets:
                print(f"  Warning: No packets in {relative_path}")
                continue
            packets = [pkt for pkt in all_packets if IP in pkt]
            if not packets:
                print(f"  Warning: No IP packets in {relative_path}")
                continue
            if len(packets) != len(all_packets):
                print(f"  Info: Filtered {len(all_packets)} -> {len(packets)} IP packets")
            transformed, result = apply_recommended_transformations_with_sla(packets)
            writer = PcapWriter(str(output_file), append=False, sync=True, linktype=linktype)
            for pkt in transformed:
                writer.write(pkt)
            writer.close()
            results[str(relative_path)] = result
            if result.get("no_transformation", False):
                reason = result.get("reason", "")
                print(f"  Unchanged: {result['packet_count']} packets, {reason}")
            elif result.get("sla_passed", False):
                transform_count = result.get("transformation_count", 0)
                if transform_count > 0:
                    applied = [t["name"] for t in result.get("applied_transformations", [])]
                    print(f"  Success: {result['packet_count']} packets, {transform_count} transformations applied: {', '.join(applied)}")
                else:
                    print(f"  Success: {result['packet_count']} packets, no transformations needed")
            else:
                fallback_msg = " (fallback used)" if result.get("fallback_used", False) else ""
                print(f"  Partial: {result['packet_count']} packets, SLA not met{fallback_msg}")
        except Exception as e:
            print(f"  Error: {e}")
            results[str(relative_path)] = {"error": str(e)}
    return results
def validate_sla(
    metrics: Dict[str, float], sla: Dict[str, float]
) -> Dict[str, bool]:
    return {
        "pps_ok": sla["SLA_PPS_MIN"] <= metrics["pps"] <= sla["SLA_PPS_MAX"],
        "iat_ok": sla["SLA_IAT_MIN_MS"] <= metrics["mean_iat_ms"] <= sla["SLA_IAT_MAX_MS"],
        "stdev_iat_ok": metrics["stdev_iat_ms"] <= sla["SLA_IAT_STDEV_MAX_MS"],
    }
def main():
    parser = argparse.ArgumentParser(description="Non-VPN Chat PCAP Transformer")
    parser.add_argument("input", type=Path, help="Input PCAP file or directory")
    parser.add_argument("output", type=Path, help="Output PCAP file or directory")
    parser.add_argument("--recommended", action="store_true", help="Use recommended transformations", required=True)
    parser.add_argument("--seed", type=int, default=1337, help="Random seed")
    args = parser.parse_args()
    if not args.input.exists():
        print(f"Error: Input path {args.input} does not exist")
        return 1
    try:
        if args.input.is_dir():
            if args.output.is_file():
                print("Error: Cannot output directory to file")
                return 1
            results = process_directory(args.input, args.output, args.seed)
            summary = {
                "total_files": len(results),
                "transformed_files": sum(1 for r in results.values() if not r.get("no_transformation")),
                "untransformed_files": sum(1 for r in results.values() if r.get("no_transformation")),
            }
            print("\n--- Transformation Summary ---")
            print(json.dumps(summary, indent=2))
            print("--------------------------\n")
        else:
            reader = PcapReader(str(args.input))
            all_packets = list(reader)
            linktype = reader.linktype
            reader.close()
            if not all_packets:
                print("Error: Input PCAP is empty")
                return 1
            packets = [pkt for pkt in all_packets if IP in pkt]
            if not packets:
                print("Error: No IP packets found in input PCAP")
                return 1
            transformed_packets, result = apply_recommended_transformations_with_sla(packets)
            writer = PcapWriter(str(args.output), append=False, sync=True, linktype=linktype)
            for pkt in transformed_packets:
                writer.write(pkt)
            writer.close()
            print(json.dumps(result, indent=4))
    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()
        return 1
    return 0
if __name__ == "__main__":
    exit(main())
