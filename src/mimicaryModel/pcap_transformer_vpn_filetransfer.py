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
    from scapy.all import IP, TCP, UDP, Raw, PcapReader, PcapWriter, fragment
except ImportError as exc:
    raise ImportError("Scapy is required. Install with: pip install scapy") from exc

# VPN-FileTransfer Configuration
PACKET_LEN_IMP = 0.30755022
BYTE_COUNTER_IMP = 0.34572279
IAT_IMP = 0.19724878
TCP_FLAG_IMP = 0.04901062
BLOCK_RATE_IMP = 0.10046761

# SLA Constraints
SLA_PPS_MIN = 80.0
SLA_PPS_MAX = 8000.0
SLA_IAT_MIN_MS = 0.125
SLA_IAT_MAX_MS = 12.5
SLA_IAT_STDEV_MAX_MS = 100.0

# Transformation parameters
FRAGMENT_SIZE = 500
PADDING_MIN, PADDING_MAX = 50, 600
DUMMY_RATE, DUMMY_SIZE = 0.15, 120
DUMMY_SPORT, DUMMY_DPORT = 65000, 65001
MILLISECONDS = 1000.0
MIN_TIME_INC = 1e-6

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

@dataclass(frozen=True)
class FlowKey:
    src: str
    sport: int
    dst: str
    dport: int
    proto: str

    @classmethod
    def from_packet(cls, pkt) -> Optional["FlowKey"]:
        if IP not in pkt:
            return None
        if TCP in pkt:
            layer = pkt[TCP]
            proto = "tcp"
        elif UDP in pkt:
            layer = pkt[UDP]
            proto = "udp"
        else:
            return None
        return cls(
            pkt[IP].src,
            int(layer.sport),
            pkt[IP].dst,
            int(layer.dport),
            proto,
        )


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

def inject_dummy_packets(packets: Iterable, importance: float) -> Iterator:
    if importance <= 0:
        yield from _copy_stream(packets)
        return
    
    rate = DUMMY_RATE * importance
    for pkt in packets:
        yield pkt.copy()
        
        if IP in pkt and random.random() < rate:
            dummy = IP(src=pkt[IP].src, dst=pkt[IP].dst)
            dummy /= UDP(sport=DUMMY_SPORT, dport=DUMMY_DPORT)
            dummy /= Raw(os.urandom(DUMMY_SIZE))
            dummy.time = getattr(pkt, "time", 0.0) + random.uniform(0.0001, 0.001)
            _recalc_checksums(dummy)
            yield dummy

def apply_packet_duplication(packets: Iterable, importance: float) -> Iterator:
    if importance <= 0:
        yield from _copy_stream(packets)
        return
    
    dup_rate = importance * 0.1
    for pkt in packets:
        yield pkt.copy()
        if random.random() < dup_rate:
            dup = pkt.copy()
            dup.time = getattr(pkt, "time", 0.0) + MIN_TIME_INC
            yield dup

def apply_packet_coalescing(packets: Iterable, importance: float) -> Iterator:
    max_coalesce_size = int(1200 * importance)
    buffer: Optional[Tuple[FlowKey, object, bytes]] = None
    
    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            flow = FlowKey.from_packet(pkt)
            payload = bytes(pkt[Raw].load)
            
            if flow is None or len(payload) > max_coalesce_size:
                if buffer is not None:
                    yield buffer[1]
                    buffer = None
                yield pkt.copy()
                continue
            
            if buffer is None:
                buffer = (flow, pkt.copy(), payload)
            elif buffer[0] == flow and len(buffer[2]) + len(payload) <= max_coalesce_size:
                _, buffered_pkt, buffered_payload = buffer
                merged_payload = buffered_payload + payload
                buffered_pkt[Raw].load = merged_payload
                buffered_pkt.time = max(getattr(buffered_pkt, "time", 0.0), getattr(pkt, "time", 0.0))
                _recalc_checksums(buffered_pkt)
                buffer = (flow, buffered_pkt, merged_payload)
            else:
                yield buffer[1]
                buffer = (flow, pkt.copy(), payload)
        else:
            if buffer is not None:
                yield buffer[1]
                buffer = None
            yield pkt.copy()
    
    if buffer is not None:
        yield buffer[1]

def apply_iat_manipulation(packets: Iterable, importance: float) -> Iterator:
    if importance <= 0:
        yield from _copy_stream(packets)
        return

    last_time = None
    for pkt in packets:
        pkt_copy = pkt.copy()
        if last_time is not None:
            delay = random.uniform(0, 0.001 * importance)
            pkt_copy.time += delay
        
        yield pkt_copy
        last_time = pkt_copy.time

def apply_tcp_flag_manipulation(packets: Iterable, importance: float) -> Iterator:
    if importance <= 0:
        yield from _copy_stream(packets)
        return
    
    flag_options = ["S", "A", "F", "R", "P", "U"]
    
    for pkt in packets:
        if TCP in pkt:
            modified = pkt.copy()
            
            if random.random() < importance * 0.2:
                num_flags_to_flip = random.randint(1, int(importance * 3) + 1)
                flags_to_flip = random.sample(flag_options, k=min(num_flags_to_flip, len(flag_options)))
                
                current_flags = modified[TCP].flags
                for flag in flags_to_flip:
                    current_flags ^= flag
                modified[TCP].flags = current_flags
                
                _recalc_checksums(modified)
                yield modified
            else:
                yield pkt.copy()
        else:
            yield pkt.copy()

def apply_recommended_transformations_with_sla(
    packets: Iterable,
) -> Tuple[Iterator, Dict[str, float]]:
    original_packets = list(packets)
    
    if not original_packets:
        raise ValueError("No packets to transform")
    
    original_metrics = MetricsAccumulator()
    for pkt in original_packets:
        original_metrics.update(float(getattr(pkt, "time", 0.0)))
    original_result = original_metrics.as_dict()

    # We will now attempt to transform even if the original is not compliant.
    # The progressive application will check SLA at each step.
    return apply_progressive_transformations_with_sla_check(original_packets, original_result)


def apply_progressive_transformations_with_sla_check(
    original_packets: List,
    original_result: Dict[str, float]
) -> Tuple[Iterator, Dict[str, float]]:
    
    transformations = [
        ("fragmentation", apply_packet_fragmentation, PACKET_LEN_IMP),
        ("padding", apply_traffic_padding, PACKET_LEN_IMP),
        ("size_randomization", apply_size_randomization, PACKET_LEN_IMP),
        ("dummy_injection", inject_dummy_packets, BYTE_COUNTER_IMP),
        ("duplication", apply_packet_duplication, BYTE_COUNTER_IMP),
        ("coalescing", apply_packet_coalescing, BYTE_COUNTER_IMP),
        ("iat_manipulation", apply_iat_manipulation, IAT_IMP),
        ("tcp_flag_manipulation", apply_tcp_flag_manipulation, TCP_FLAG_IMP),
    ]
    
    current_packets = list(_copy_stream(original_packets))
    applied_transformations = []
    
    for transform_name, transform_func, base_importance in transformations:
        transformation_applied = False
        for intensity_scale in [0.3, 0.5, 0.7, 1.0]:
            test_importance = base_importance * intensity_scale
            test_stream = transform_func(iter(current_packets), test_importance)
            test_packets = list(test_stream)
            
            if not test_packets:
                continue
            test_metrics = MetricsAccumulator()
            for pkt in test_packets:
                test_metrics.update(float(getattr(pkt, "time", 0.0)))
            
            test_result = test_metrics.as_dict()
            sla_results = validate_sla(test_result)
            
            if all(sla_results.values()):
                current_packets = test_packets
                applied_transformations.append({
                    "name": transform_name,
                    "importance": test_importance,
                    "intensity_scale": intensity_scale
                })
                transformation_applied = True
                break
        if not transformation_applied:
            continue

    if not current_packets:
        result = original_result.copy()
        result["sla_validation"] = validate_sla(original_result)
        result["sla_passed"] = True
        result["applied_transformations"] = []
        result["reason"] = "No transformations could be applied while maintaining SLA"
        return iter(_copy_stream(original_packets)), result
    final_metrics = MetricsAccumulator()
    for pkt in current_packets:
        final_metrics.update(float(getattr(pkt, "time", 0.0)))
    
    final_result = final_metrics.as_dict()
    final_result["sla_validation"] = validate_sla(final_result)
    final_result["sla_passed"] = all(final_result["sla_validation"].values())
    final_result["applied_transformations"] = applied_transformations
    final_result["transformation_count"] = len(applied_transformations)
    
    return iter(current_packets), final_result


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


def validate_sla(metrics: Dict[str, float]) -> Dict[str, bool]:
    return {
        "pps_min": metrics.get("pps", 0.0) >= SLA_PPS_MIN,
        "pps_max": metrics.get("pps", 0.0) <= SLA_PPS_MAX,
        "mean_iat_ms_min": metrics.get("mean_iat_ms", 0.0) >= SLA_IAT_MIN_MS,
        "mean_iat_ms_max": metrics.get("mean_iat_ms", 0.0) <= SLA_IAT_MAX_MS,
        "stdev_iat_ms_max": metrics.get("stdev_iat_ms", 0.0) <= SLA_IAT_STDEV_MAX_MS,
    }


def main():
    parser = argparse.ArgumentParser(description="VPN-FileTransfer PCAP Transformer")
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
