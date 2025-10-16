from __future__ import annotations

import argparse
import random
from collections import deque
from pathlib import Path

import yaml
from scapy.all import IP, PcapReader, PcapWriter, Raw, UDP
from scapy.layers.inet import fragment
from tqdm import tqdm

# 3. Inter-Arrival Time (IAT) & Flow Timing
def rebase_packet_times(packets: list, start_time: float = 0.0) -> tuple[list, float]:
    if not packets:
        return packets, start_time

    base_time = float(getattr(packets[0], "time", 0.0))
    delta = start_time - base_time
    for packet in packets:
        packet.time = float(getattr(packet, "time", 0.0)) + delta
    packets.sort(key=lambda pkt: float(getattr(pkt, "time", 0.0)))
    return packets, float(getattr(packets[-1], "time", start_time))

# 2. Byte/Packet Counters & Ratios
def get_packet_size_distribution(input_pcap: str) -> list[int]:
    with PcapReader(input_pcap) as pcap_reader:
        return [len(packet) for packet in pcap_reader if IP in packet]

# 4. TCP/Control Flags & Header Features
def clone_packet(packet):
    try:
        cloned = packet.copy()
    except Exception:
        try:
            cloned = packet.__class__(bytes(packet))
        except Exception:
            cloned = IP(bytes(packet))
    if hasattr(packet, "time"):
        cloned.time = packet.time
    return cloned


# 1. Packet Length & Size Features
def build_dummy_packet(desired_size: int) -> IP:
    if desired_size <= 0:
        desired_size = 20

    base_ip = IP(src="198.18.0.1", dst="198.18.0.2")
    minimal_size = len(base_ip)

    if desired_size <= minimal_size:
        dummy = clone_packet(base_ip)
    else:
        udp_stub = UDP(sport=12345, dport=54321)
        packet = base_ip / udp_stub
        payload_size = desired_size - len(packet)
        if payload_size < 0:
            payload_size = 0
        packet = packet / Raw(load=b"\x00" * payload_size)
        dummy = packet

    dummy.time = 0.0
    return dummy


def resize_packet(packet, desired_size: int, mtu: int | None = None):
    """
    Adjusts a packet's size by padding or trimming payloads to reach the desired size.
    """
    if desired_size <= 0:
        return packet, []

    current_size = len(packet)
    if mtu is not None:
        desired_size = min(desired_size, mtu)

    if desired_size == current_size:
        return packet, []

    if desired_size > current_size:
        pad_len = desired_size - current_size
        padding = b"\x00" * pad_len
        if packet.haslayer(Raw):
            packet[Raw].load += padding
        else:
            packet = packet / Raw(load=padding)
        return packet

    # Shrinking path
    shrink_len = current_size - desired_size
    if packet.haslayer(Raw):
        raw_payload = bytes(packet[Raw].load)
        if shrink_len < len(raw_payload):
            packet[Raw].load = raw_payload[:-shrink_len]
            return packet
        elif shrink_len == len(raw_payload):
            packet[Raw].load = b""
            return packet

    dummy = build_dummy_packet(desired_size)
    if hasattr(packet, "time"):
        dummy.time = packet.time
    return dummy


def align_packets_to_size_profile(packets: list, size_profile: list[int], mtu: int | None = None) -> list:
    if not size_profile:
        return packets

    target_count = len(size_profile)
    mutable_packets = [clone_packet(pkt) for pkt in packets]

    if not mutable_packets:
        mutable_packets = [build_dummy_packet(size) for size in size_profile]
    else:
        if len(mutable_packets) < target_count:
            while len(mutable_packets) < target_count:
                template = random.choice(mutable_packets)
                mutable_packets.append(clone_packet(template))

    desired_sizes = sorted(size_profile)

    for idx, desired_size in zip(packet_indices, desired_sizes):
        mutable_packets[idx] = resize_packet(mutable_packets[idx], desired_size, mtu=mtu)

    # Shuffle to avoid ordered artifacts.
    random.shuffle(mutable_packets)
    return mutable_packets


# Transformation Functions (File-based)
def add_constant_padding(input_pcap: str, output_pcap: str, fixed_size: int):
    """
    Reads packets from an input PCAP file, adds padding to a fixed size,
    and writes the modified packets to an output PCAP file.
    """
    with PcapReader(input_pcap) as pcap_reader:
        with PcapWriter(output_pcap, append=True) as pcap_writer:
            for packet in pcap_reader:
                if IP in packet:
                    current_size = len(packet)
                    if current_size < fixed_size:
                        padding_size = fixed_size - current_size
                        padding = b'\x00' * padding_size
                        
                        if packet.haslayer(Raw):
                            packet[Raw].load += padding
                        else:
                            packet = packet / Raw(load=padding)

                pcap_writer.write(packet)

def add_randomized_padding(input_pcap: str, output_pcap: str, min_size: int, max_size: int):
    """
    Reads packets from an input PCAP file, adds random padding to each packet,
    and writes the modified packets to an output PCAP file.
    """
    with PcapReader(input_pcap) as pcap_reader:
        with PcapWriter(output_pcap, append=True) as pcap_writer:
            for packet in pcap_reader:
                if IP in packet:
                    target_size = random.randint(min_size, max_size)
                    current_size = len(packet)
                    if current_size < target_size:
                        padding_size = target_size - current_size
                        padding = b'\x00' * padding_size
                        
                        if packet.haslayer(Raw):
                            packet[Raw].load += padding
                        else:
                            packet = packet / Raw(load=padding)

                pcap_writer.write(packet)

def get_packet_size_distribution(input_pcap: str) -> list[int]:
    """
    Calculates the packet size distribution of a PCAP file.
    """
    with PcapReader(input_pcap) as pcap_reader:
        return [len(packet) for packet in pcap_reader if IP in packet]

def morph_packet_size_distribution(source_pcap: str, output_pcap: str, target_pcap: str):
    """
    Morphs the packet size distribution of a source PCAP to match the target PCAP.
    """
    target_distribution = get_packet_size_distribution(target_pcap)
    if not target_distribution:
        print("Warning: Target PCAP has no packets to create a distribution from.")
        return

    with PcapReader(source_pcap) as pcap_reader:
        with PcapWriter(output_pcap, append=True) as pcap_writer:
            for packet in pcap_reader:
                if IP in packet:
                    target_size = random.choice(target_distribution)
                    current_size = len(packet)
                    if current_size < target_size:
                        padding_size = target_size - current_size
                        padding = b'\x00' * padding_size
                        
                        if packet.haslayer(Raw):
                            packet[Raw].load += padding
                        else:
                            packet = packet / Raw(load=padding)
                
                pcap_writer.write(packet)

def apply_fragmentation(input_pcap: str, output_pcap: str, mtu: int = 1500):
    """
    Reads a PCAP file, fragments packets larger than the MTU,
    and writes the resulting packets to a new PCAP file.
    """
    with PcapReader(input_pcap) as pcap_reader:
        with PcapWriter(output_pcap, append=True) as pcap_writer:
            for packet in pcap_reader:
                if IP in packet and len(packet) > mtu:
                    fragments = fragment(packet, fragsize=mtu - len(packet[IP].options) - 20)
                    for frag in fragments:
                        pcap_writer.write(frag)
                else:
                    pcap_writer.write(packet)

def inject_dummy_packets(input_pcap: str, output_pcap: str, injection_rate: int = 10):
    """
    Injects dummy TCP packets into a PCAP stream at a specified rate.
    """
    with PcapReader(input_pcap) as pcap_reader:
        with PcapWriter(output_pcap, append=True) as pcap_writer:
            packet_count = 0
            for packet in pcap_reader:
                pcap_writer.write(packet)
                packet_count += 1
                if packet_count % injection_rate == 0:
                    dummy_packet = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=12345, dport=80)
                    dummy_packet.time = packet.time
                    pcap_writer.write(dummy_packet)

def throttle_rate(input_pcap: str, output_pcap: str, scaling_factor: float):
    """
    Throttles the rate of packets in a PCAP file by scaling the inter-arrival times.
    """
    with PcapReader(input_pcap) as pcap_reader:
        with PcapWriter(output_pcap, append=True) as pcap_writer:
            last_timestamp = None
            for packet in pcap_reader:
                if last_timestamp is not None:
                    iat = packet.time - last_timestamp
                    new_iat = iat * scaling_factor
                    packet.time = last_timestamp + new_iat
                
                pcap_writer.write(packet)
                last_timestamp = packet.time

def inject_jitter(input_pcap: str, output_pcap: str, jitter_amount: float):
    """
    Legacy passthrough that simply copies packets without altering timing.
    """
    with PcapReader(input_pcap) as pcap_reader:
        with PcapWriter(output_pcap, append=True) as pcap_writer:
            for packet in pcap_reader:
                pcap_writer.write(packet)

def get_iat_distribution(input_pcap: str) -> list[float]:
    with PcapReader(input_pcap) as pcap_reader:
        iats = []
        last_timestamp = None
        for packet in pcap_reader:
            if last_timestamp is not None:
                iat = packet.time - last_timestamp
                iats.append(iat)
            last_timestamp = packet.time
        return iats


# 3. Inter-Arrival Time (IAT) & Flow Timing
def morph_iat_distribution_on_list_with_dist(packets: list, target_iat_distribution: list[float]) -> list:
    if not target_iat_distribution:
        return packets

    morphed_packets = []
    last_timestamp = None
    for packet in packets:
        if last_timestamp is not None:
            new_iat = random.choice(target_iat_distribution)
            if new_iat < 0:
                new_iat = 0
            packet.time = last_timestamp + new_iat

        morphed_packets.append(packet)
        last_timestamp = packet.time

    return morphed_packets


# 3. Inter-Arrival Time (IAT) & Flow Timing
def stream_pcap_in_chunks(pcap_path: str, chunk_size: int):
    try:
        with PcapReader(pcap_path) as pcap_reader:
            chunk = []
            i = 0
            for packet in pcap_reader:
                chunk.append(packet)
                i += 1
                if i == chunk_size:
                    yield chunk
                    chunk = []
                    i = 0
            if chunk:
                yield chunk
    except Exception as e:
        print(f"Error reading {pcap_path}: {e}")


# 2. Byte/Packet Counters & Ratios
def main():
    parser = argparse.ArgumentParser(description="PCAP Transformer")
    parser.add_argument("scenario", help="Name of the scenario to run from the YAML file.")
    parser.add_argument("--config", default="src/mimicaryModel/scenarios.yaml", help="Path to the YAML configuration file.")
    args = parser.parse_args()

    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)

    if args.scenario not in config:
        raise ValueError(f"Scenario '{args.scenario}' not found in the configuration file.")

    scenario_config = config[args.scenario]

    if "multi_mimic" in scenario_config:
        input_dir = Path(scenario_config["input_dir"])
        output_dir_base = Path(scenario_config["output_dir_base"])
        multi_mimic_targets = scenario_config["multi_mimic"]
        chunk_size = scenario_config.get("chunk_size", 100000) # Packets per chunk

        output_dir_base.mkdir(parents=True, exist_ok=True)
        
        all_files = list(input_dir.rglob("*.pcap")) + list(input_dir.rglob("*.pcapng"))
        input_files = [f for f in all_files if not f.name.endswith("_sample.pcap")]
        mimic_targets_with_dist = []
        for idx, target in enumerate(multi_mimic_targets):
            target_pcap = target["target_pcap"]
            size_dist = get_packet_size_distribution(target_pcap)
            if max_packet_size is not None:
                size_dist = [min(packet_size, max_packet_size) for packet_size in size_dist]
            mimic_targets_with_dist.append({
                "target_pcap": target_pcap,
                "size_dist": size_dist,
                "iat_dist": get_iat_distribution(target_pcap),
                "max_size": (
                    min(max(size_dist), max_packet_size)
                    if size_dist and max_packet_size is not None
                    else (max(size_dist) if size_dist else max_packet_size)
                ),
                "packet_count": len(size_dist),
                "total_bytes": sum(size_dist),
                "target_service": target.get("target_service", f"target_{idx}")
            })
        num_targets = len(mimic_targets_with_dist)

        for input_file in tqdm(input_files, desc=f"Processing multi-mimic scenario: {args.scenario}"):
            output_file = output_dir_base / input_file.name
            target_packets_map = {idx: [] for idx in range(num_targets)}

            if num_targets == 0:
                output_file.write_bytes(input_file.read_bytes())
                continue

            for packet_chunk in stream_pcap_in_chunks(str(input_file), chunk_size):
                if not packet_chunk:
                    continue
                random.shuffle(packet_chunk)
                for idx, packet in enumerate(packet_chunk):
                    target_idx = idx % num_targets
                    target_info = mimic_targets_with_dist[target_idx]
                    cloned_packet = clone_packet(packet)
                    extras = []
                    if IP in cloned_packet and target_info["size_dist"]:
                        desired_size = random.choice(target_info["size_dist"])
                        cloned_packet, extras = resize_packet(
                            cloned_packet,
                            desired_size,
                            mtu=target_info["max_size"],
                        )
                    target_packets_map[target_idx].append(cloned_packet)
                    for extra_packet in extras:
                        target_packets_map[target_idx].append(extra_packet)

            consolidated_packets = []
            current_offset = 0.0
            for idx, target_info in enumerate(mimic_targets_with_dist):
                packets_for_target = target_packets_map.get(idx, [])
                size_profile = target_info["size_dist"]
                mtu = target_info["max_size"]
                packets_for_target = align_packets_to_size_profile(packets_for_target, size_profile, mtu=mtu)
                if target_info["iat_dist"]:
                    packets_for_target = morph_iat_distribution_on_list_with_dist(packets_for_target, target_info["iat_dist"])
                packets_for_target.sort(key=lambda pkt: float(getattr(pkt, "time", 0.0)))
                packets_for_target, current_offset = rebase_packet_times(packets_for_target, start_time=current_offset)
                if packets_for_target:
                    current_offset = float(getattr(packets_for_target[-1], "time", current_offset))
                    current_offset += 1e-12
                consolidated_packets.extend(packets_for_target)

            consolidated_packets.sort(key=lambda pkt: float(getattr(pkt, "time", 0.0)))

            with PcapWriter(str(output_file)) as final_pcap_writer:
                for pkt in consolidated_packets:
                    final_pcap_writer.write(pkt)

if __name__ == "__main__":
    main()
