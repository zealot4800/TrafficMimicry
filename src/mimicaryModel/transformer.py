from __future__ import annotations

import argparse
import datetime
import random
from collections import deque
from pathlib import Path

import yaml
from scapy.all import IP, PcapReader, PcapWriter, Raw, UDP, TCP
try:
    from scapy.error import Scapy_Exception, ScapyWarning
except ImportError:
    from scapy.error import Scapy_Exception

    class ScapyWarning(Warning):
        """Fallback warning when scapy.error.ScapyWarning is unavailable."""
        pass
from scapy.layers.inet import fragment
from tqdm import tqdm

def rebase_packet_times(packets: list, start_time: float = 0.0) -> tuple[list, float]:
    """
    Shifts packet timestamps so that the first packet starts at start_time.
    """
    if not packets:
        return packets, start_time

    base_time = float(getattr(packets[0], "time", 0.0))
    delta = start_time - base_time
    for packet in packets:
        packet.time = float(getattr(packet, "time", 0.0)) + delta
    packets.sort(key=lambda pkt: float(getattr(pkt, "time", 0.0)))
    return packets, float(getattr(packets[-1], "time", start_time))


def clone_packet(packet):
    """
    Creates a lightweight copy of a scapy packet while preserving metadata like timestamps.
    """
    try:
        cloned = packet.copy()
    except Exception:
        # Fallback: rebuild from raw bytes if direct copy is unsupported.
        try:
            cloned = packet.__class__(bytes(packet))
        except Exception:
            cloned = IP(bytes(packet))
    if hasattr(packet, "time"):
        cloned.time = packet.time
    return cloned


def build_dummy_packet(desired_size: int) -> IP:
    """
    Builds a synthetic IP/UDP/Raw packet that closely matches the desired size.
    """
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


def _clone_with_payload(base_packet, payload: bytes):
    """
    Clone a packet while replacing the Raw payload bytes.
    """
    cloned = clone_packet(base_packet)
    if payload:
        if cloned.haslayer(Raw):
            cloned[Raw].load = payload
        else:
            cloned = cloned / Raw(load=payload)
    else:
        if cloned.haslayer(Raw):
            cloned[Raw].load = b""
    return cloned


def resize_packet(packet, desired_size: int, mtu: int | None = None) -> tuple:
    """
    Adjusts a packet's size by padding or trimming payloads while preserving data.
    Returns a tuple of (resized_packet, leftover_packets).
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
        return packet, []

    # Shrinking path with payload preservation.
    payload_bytes = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
    header_size = current_size - len(payload_bytes)
    primary_payload_len = max(min(desired_size - header_size, len(payload_bytes)), 0)
    primary_payload = payload_bytes[:primary_payload_len]
    leftover_payload = payload_bytes[primary_payload_len:]

    if desired_size < header_size and not payload_bytes:
        # Cannot shrink below header size without payload; fall back to fragmenting if possible.
        if IP in packet:
            fragsize = max(desired_size - len(packet[IP].options) - 20, 8)
            fragments = fragment(packet, fragsize=fragsize)
            if fragments:
                primary = fragments[0]
                leftovers = fragments[1:]
                return primary, leftovers
        dummy = build_dummy_packet(desired_size)
        if hasattr(packet, "time"):
            dummy.time = packet.time
        return dummy, []

    primary_packet = _clone_with_payload(packet, primary_payload)
    leftovers = []

    if leftover_payload:
        max_payload = None
        if mtu is not None:
            max_payload = max(mtu - header_size, 0)

        # Ensure leftover payload is distributed into additional packets.
        offset_time = getattr(packet, "time", 0.0)
        chunk_index = 1
        while leftover_payload:
            if max_payload and max_payload > 0:
                chunk = leftover_payload[:max_payload]
                leftover_payload = leftover_payload[max_payload:]
            else:
                chunk = leftover_payload
                leftover_payload = b""

            new_packet = _clone_with_payload(packet, chunk)
            if hasattr(new_packet, "time"):
                new_packet.time = offset_time + chunk_index * 1e-9
            leftovers.append(new_packet)
            chunk_index += 1

    return primary_packet, leftovers


def align_packets_to_size_profile(packets: list, size_profile: list[int], mtu: int | None = None) -> list:
    """
    Ensures packets match the size distribution from a target profile.
    """
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
    available_packets = deque(mutable_packets)
    aligned_packets = []

    for desired_size in desired_sizes:
        if not available_packets:
            available_packets.append(build_dummy_packet(desired_size))
        packet = available_packets.popleft()
        resized_packet, leftovers = resize_packet(packet, desired_size, mtu=mtu)
        aligned_packets.append(resized_packet)
        for leftover in leftovers:
            available_packets.append(leftover)

    # Append any remaining leftover packets so payload bytes are preserved.
    aligned_packets.extend(list(available_packets))
    random.shuffle(aligned_packets)
    return aligned_packets


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
    """
    Calculates the inter-arrival time (IAT) distribution of a PCAP file.
    """
    with PcapReader(input_pcap) as pcap_reader:
        iats = []
        last_timestamp = None
        for packet in pcap_reader:
            if last_timestamp is not None:
                iat = packet.time - last_timestamp
                iats.append(iat)
            last_timestamp = packet.time
        return iats

def morph_iat_distribution(source_pcap: str, output_pcap: str, target_pcap: str):
    """
    Morphs the inter-arrival time (IAT) distribution of a source PCAP to match the target PCAP.
    """
    target_iat_distribution = get_iat_distribution(target_pcap)
    if not target_iat_distribution:
        print("Warning: Target PCAP has no packets to create an IAT distribution from.")
        return

    with PcapReader(source_pcap) as pcap_reader:
        with PcapWriter(output_pcap, append=True) as pcap_writer:
            last_timestamp = None
            for packet in pcap_reader:
                if last_timestamp is not None:
                    new_iat = random.choice(target_iat_distribution)
                    if new_iat < 0:
                        new_iat = 0
                    packet.time = last_timestamp + new_iat
                
                pcap_writer.write(packet)
                last_timestamp = packet.time

def mimic_time_of_day(input_pcap: str, output_pcap: str, target_time: str):
    """
    Shifts the timestamps of all packets in a PCAP file to a new time of day.
    """
    try:
        target_t = datetime.strptime(target_time, "%H:%M:%S").time()
    except ValueError:
        print(f"Error: Invalid time format for target_time. Please use HH:MM:SS.")
        return

    with PcapReader(input_pcap) as pcap_reader:
        with PcapWriter(output_pcap, append=True) as pcap_writer:
            first_packet = True
            time_shift = 0.0

            first_pkt = next(iter(pcap_reader), None)
            if first_pkt is None:
                return

            original_dt = datetime.fromtimestamp(float(first_pkt.time))
            new_start_dt = datetime.combine(original_dt.date(), target_t)
            time_shift = (new_start_dt - original_dt).total_seconds()
            
            pcap_reader = PcapReader(input_pcap)
            for packet in pcap_reader:
                packet.time += time_shift
                pcap_writer.write(packet)

def get_pcap_stats(pcap_path: str) -> tuple[int, float]:
    packet_count = 0
    first_packet_time = None
    last_packet_time = None
    try:
        with PcapReader(pcap_path) as pcap_reader:
            for packet in pcap_reader:
                if first_packet_time is None:
                    first_packet_time = float(packet.time)
                last_packet_time = float(packet.time)
                packet_count += 1
    except Scapy_Exception:
        # This can happen for empty or corrupt pcap files
        return 0, 0.0

    if packet_count < 2:
        return packet_count, 0.0
    
    duration = last_packet_time - first_packet_time
    
    return packet_count, duration

def morph_packet_size_distribution_on_list(packets: list, target_pcap: str) -> list:
    target_distribution = get_packet_size_distribution(target_pcap)
    if not target_distribution:
        print("Warning: Target PCAP has no packets to create a distribution from.")
        return packets

    morphed_packets = []
    for packet in packets:
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
        morphed_packets.append(packet)
    return morphed_packets

def morph_iat_distribution_on_list_with_dist(packets: list, target_iat_distribution: list[float]) -> list:
    """
    Morphs IAT on a list of packets using a pre-calculated distribution.
    """
    if not target_iat_distribution:
        return packets

    morphed_packets = []
    last_timestamp = None
    for packet in packets:
        if last_timestamp is not None:
            new_iat = random.choice(target_iat_distribution)
            if new_iat < 0:
                new_iat = 0
            # scapy packets are mutable, so this modifies the packet in the list
            packet.time = last_timestamp + new_iat
        
        morphed_packets.append(packet)
        last_timestamp = packet.time
            
    return morphed_packets

def morph_iat_distribution_on_list(packets: list, target_pcap: str) -> list:
    target_iat_distribution = get_iat_distribution(target_pcap)
    if not target_iat_distribution:
        print("Warning: Target PCAP has no packets to create an IAT distribution from.")
        return packets
    return morph_iat_distribution_on_list_with_dist(packets, target_iat_distribution)

def morph_packet_rate_on_list(packets: list, target_pcap: str) -> list:
    if not packets:
        return []

    target_packet_count, target_duration = get_pcap_stats(target_pcap)
    if target_duration == 0.0:
        print("Warning: Target PCAP has zero duration, cannot calculate packet rate.")
        return packets

    target_packet_rate = target_packet_count / target_duration

    source_duration = float(packets[-1].time - packets[0].time)
    if source_duration == 0.0:
        return packets

    expected_packet_count = int(source_duration * target_packet_rate)
    current_packet_count = len(packets)

    if current_packet_count == expected_packet_count:
        return packets
    elif current_packet_count > expected_packet_count:
        # Drop packets by shuffling and truncating - more memory efficient than random.sample
        random.shuffle(packets)
        del packets[expected_packet_count:]
        return packets
    else:
        # Duplicate packets
        morphed_packets = list(packets)
        packets_to_add = expected_packet_count - current_packet_count
        for _ in range(packets_to_add):
            morphed_packets.append(random.choice(packets))
        random.shuffle(morphed_packets)
        return morphed_packets

def stream_pcap_in_chunks(pcap_path: str, chunk_size: int):
    """
    Generator that reads a PCAP file and yields chunks of packets.
    """
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
    except Scapy_Exception as e:
        print(f"Error reading {pcap_path}: {e}")

def inject_jitter_on_list(packets: list, jitter_amount: float) -> list:
    """
    Legacy passthrough helper that leaves packets unchanged.
    """
    return packets

def apply_fragmentation_on_list(packets: list, mtu: int = 1500) -> list:
    """
    Applies IP fragmentation to packets in a list that exceed the MTU.
    """
    fragmented_packets = []
    for packet in packets:
        if IP in packet and len(packet) > mtu:
            ip_header_len = packet[IP].ihl * 4
            frag_payload_size = (mtu - ip_header_len) // 8 * 8
            
            fragments = fragment(packet, fragsize=frag_payload_size)
            fragmented_packets.extend(fragments)
        else:
            fragmented_packets.append(packet)
    return fragmented_packets

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
        # Handle multi-mimic scenario with chunking to manage memory
        input_dir = Path(scenario_config["input_dir"])
        output_dir_base = Path(scenario_config["output_dir_base"])
        multi_mimic_targets = scenario_config["multi_mimic"]
        max_packet_size = scenario_config.get("max_packet_size")
        chunk_size = scenario_config.get("chunk_size", 100000) # Packets per chunk

        output_dir_base.mkdir(parents=True, exist_ok=True)
        
        all_files = list(input_dir.rglob("*.pcap")) + list(input_dir.rglob("*.pcapng"))
        input_files = [f for f in all_files if not f.name.endswith("_sample.pcap")]

        # Pre-calculate target distributions/statistics to avoid re-reading files in the loop
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
                    # Add a small offset so the next target's packets do not overlap in timestamps.
                    current_offset += 1e-6
                consolidated_packets.extend(packets_for_target)

            consolidated_packets.sort(key=lambda pkt: float(getattr(pkt, "time", 0.0)))

            with PcapWriter(str(output_file)) as final_pcap_writer:
                for pkt in consolidated_packets:
                    final_pcap_writer.write(pkt)

    else:
        # Handle single transformation pipeline
        input_dir = Path(scenario_config["input_dir"])
        output_dir = Path(scenario_config["output_dir"])
        transformations = scenario_config.get("transformations", [])

        output_dir.mkdir(parents=True, exist_ok=True)

        all_files = list(input_dir.rglob("*.pcap")) + list(input_dir.rglob("*.pcapng"))
        input_files = [f for f in all_files if not f.name.endswith("_sample.pcap")]

        for input_file in tqdm(input_files, desc=f"Processing scenario: {args.scenario}"):
            output_file = output_dir / input_file.name
            
            if not transformations:
                # If no transformations, just copy the file
                output_file.write_bytes(input_file.read_bytes())
                continue

            current_input = str(input_file)
            temp_files = []

            for i, transform in enumerate(transformations):
                # Make a copy of the params to avoid modifying the original config dict
                params = dict(transform)
                transform_type = params.pop("type")
                
                is_last_transform = (i == len(transformations) - 1)
                
                if is_last_transform:
                    current_output = str(output_file)
                else:
                    temp_file_path = output_dir / f"{input_file.stem}_{i}.tmp"
                    current_output = str(temp_file_path)
                    temp_files.append(temp_file_path)

                try:
                    transform_func = globals()[transform_type]
                    transform_func(current_input, current_output, **params)
                    current_input = current_output
                except Exception as e:
                    print(f"Error during transformation {transform_type} on {input_file}: {e}")
                    # Stop processing this file on error
                    break
            
            # Clean up temporary files
            for temp_file in temp_files:
                try:
                    temp_file.unlink()
                except OSError as e:
                    print(f"Error removing temp file {temp_file}: {e}")


if __name__ == "__main__":
    main()
