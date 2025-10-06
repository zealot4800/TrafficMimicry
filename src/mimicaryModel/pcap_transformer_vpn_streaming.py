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

TRANSFORMATION_PARAMS = {
    "FRAGMENT_SIZE": 860,  
    "PADDING_MIN": 16, 
    "PADDING_MAX": 96,
    "DUMMY_RATE": 0.19804912,
    "DUMMY_SIZE": 120,
    "TCP_FLAGS_IMPORTANCE": 0.0,
    "COALESCE_MAX_SIZE": 1500
}

MILLISECONDS = 1000.0

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

def apply_packet_fragmentation(packets: Iterable, fragment_size: int) -> Iterator:
    if fragment_size <= 0:
        yield from _copy_stream(packets)
        return
    for pkt in packets:
        if IP in pkt and len(pkt) > fragment_size:
            conf.checkIPsrc = False
            frags = fragment(pkt, fragsize=fragment_size)
            conf.checkIPsrc = True
            yield from frags
        else:
            yield pkt.copy()

def apply_traffic_padding(packets: Iterable, padding_min: int, padding_max: int) -> Iterator:
    if padding_max <= 0:
        yield from _copy_stream(packets)
        return
    if padding_min > padding_max:
        padding_min = padding_max
    for pkt in packets:
        if IP in pkt:
            padded = pkt.copy()
            pad_size = random.randint(padding_min, padding_max)
            pad_bytes = os.urandom(pad_size)
            if Raw in padded:
                padded[Raw].load += pad_bytes
            else:
                padded /= Raw(pad_bytes)
            _recalc_checksums(padded)
            yield padded
        else:
            yield pkt.copy()

def apply_dummy_packets(packets: List, rate: float, size: int) -> List:
    if rate <= 0 or size <= 0 or not packets:
        return packets
    new_packets = []
    src_ip, dst_ip = ("127.0.0.1", "127.0.0.2")
    if IP in packets[0]:
        src_ip, dst_ip = packets[0][IP].src, packets[0][IP].dst

    for pkt in packets:
        new_packets.append(pkt)
        if random.random() < rate:
            dummy_pkt_time = float(pkt.time) + random.uniform(1e-4, 1e-3)
            dummy_payload = os.urandom(size)
            dummy_pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(49152, 65535), dport=random.randint(49152, 65535)) / Raw(dummy_payload)
            dummy_pkt.time = dummy_pkt_time
            _recalc_checksums(dummy_pkt)
            new_packets.append(dummy_pkt)
    new_packets.sort(key=lambda p: p.time)
    return new_packets

def apply_packet_duplication(packets: List, rate: float) -> List:
    if rate <= 0 or not packets:
        return packets
    new_packets = []
    for pkt in packets:
        new_packets.append(pkt)
        if random.random() < rate:
            dup = pkt.copy()
            dup.time = float(pkt.time) + 1e-6
            new_packets.append(dup)
    new_packets.sort(key=lambda p: p.time)
    return new_packets

def apply_packet_coalescing(packets: Iterable, max_coalesce_size: int) -> Iterator:
    if max_coalesce_size <= 0:
        yield from _copy_stream(packets)
        return
        
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
                buffered_pkt.time = max(float(buffered_pkt.time), float(pkt.time))
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

def apply_iat_manipulation(packets: List, rate: float) -> List:
    if rate <= 0 or not packets:
        return packets
    
    new_packets = []
    last_time = None
    for pkt in packets:
        pkt_copy = pkt.copy()
        if last_time is not None and random.random() < rate:
            delay = random.uniform(0, 0.001)
            pkt_copy.time += delay
        
        new_packets.append(pkt_copy)
        last_time = pkt_copy.time
    new_packets.sort(key=lambda p: p.time)
    return new_packets

def apply_tcp_flag_manipulation(packets: List, rate: float) -> List:
    if rate <= 0 or not packets:
        return packets
    
    flag_options = ["S", "A", "F", "R", "P", "U"]
    new_packets = []
    for pkt in packets:
        if TCP in pkt and random.random() < rate:
            modified = pkt.copy()
            num_flags_to_flip = random.randint(1, 3)
            flags_to_flip = random.sample(flag_options, k=min(num_flags_to_flip, len(flag_options)))
            
            current_flags = modified[TCP].flags
            for flag in flags_to_flip:
                current_flags ^= flag
            modified[TCP].flags = current_flags
            
            _recalc_checksums(modified)
            new_packets.append(modified)
        else:
            new_packets.append(pkt.copy())
    return new_packets

def apply_transformations(
    packets: Iterable,
) -> Iterator:
    
    original_packets = list(packets)
    if not original_packets:
        raise ValueError("No packets to transform")

    params = TRANSFORMATION_PARAMS
    
    packets_for_padding = []
    packets_for_coalescing = []
    for i, pkt in enumerate(original_packets):
        if i % 2 == 0:
            packets_for_padding.append(pkt)
        else:
            packets_for_coalescing.append(pkt)
    padded_packets = list(apply_traffic_padding(
        packets_for_padding,
        params.get("PADDING_MIN", 0),
        params.get("PADDING_MAX", 0)
    ))
    coalesced_packets = list(apply_packet_coalescing(
        packets_for_coalescing,
        params.get("COALESCE_MAX_SIZE", 0)
    ))
    transformed_packets = padded_packets + coalesced_packets
    transformed_packets.sort(key=lambda p: p.time)
    transformed_packets = list(apply_packet_fragmentation(
        transformed_packets,
        params.get("FRAGMENT_SIZE", 0)
    ))
    transformed_packets = apply_dummy_packets(
        transformed_packets,
        params.get("DUMMY_RATE", 0.0),
        params.get("DUMMY_SIZE", 0)
    )
    transformed_packets = list(apply_tcp_flag_manipulation(
        transformed_packets,
        params.get("TCP_FLAGS_IMPORTANCE", 0.0)
    ))

    return iter(transformed_packets)

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
            
            transformed = apply_transformations(packets)
            
            writer = PcapWriter(str(output_file), append=False, sync=True, linktype=linktype)
            for pkt in transformed:
                writer.write(pkt)
            writer.close()
            results[str(relative_path)] = {"status": "success"}
            
            print(f"  Success: Transformations applied.")

        except Exception as e:
            print(f"  Error: {e}")
            results[str(relative_path)] = {"error": str(e)}
    return results

def main():
    parser = argparse.ArgumentParser(description="VPN Streaming PCAP Transformer")
    parser.add_argument("input", type=Path, help="Input PCAP file or directory")
    parser.add_argument("output", type=Path, help="Output PCAP file or directory")
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
                "transformed_files": len(results),
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
            transformed_packets, _ = apply_transformations(packets)
            
            writer = PcapWriter(str(args.output), append=False, sync=True, linktype=linktype)
            for pkt in transformed_packets:
                writer.write(pkt)
            writer.close()
            print("Transformation complete.")
    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()
        return 1
    return 0

if __name__ == "__main__":
    exit(main())
