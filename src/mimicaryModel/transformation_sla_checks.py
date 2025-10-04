"""Quick sanity checks for pcap_transformer primitives.

Run with:

    python src/mimicaryModel/transformation_sla_checks.py

The script fabricates synthetic Scapy packets so you can validate how padding,
splitting, and combining alter packet counts and timing while still respecting
the SLA guardrails that were added to ``pcap_transformer``.
"""

from __future__ import annotations

import argparse
import statistics
from pathlib import Path
from typing import Iterable, List, Sequence

try:
    from scapy.all import IP, TCP, Raw, rdpcap  # type: ignore
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "Scapy is required to run transformation_sla_checks. Install it with 'pip install scapy'."
    ) from exc

from .pcap_transformer import (
    apply_traffic_padding,
    combine_small_messages,
    compute_metrics,
    enforce_sla_constraints,
    split_logical_messages,
)


def _make_flow(
    *,
    packets: int,
    payload_size: int,
    gap_ms: float,
    seq_stride: int = 100,
) -> List:
    base_gap = gap_ms / 1000.0
    result: List = []
    for idx in range(packets):
        payload = bytes([idx % 251]) * payload_size
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=idx * seq_stride)
        pkt /= Raw(payload)
        pkt.time = idx * base_gap
        result.append(pkt)
    return result


def _print_metrics(label: str, packets: Sequence) -> None:
    metrics = compute_metrics(packets)
    pretty = ", ".join(
        f"{key}={value:.6f}" for key, value in metrics.items()
    )
    print(f"[{label}] {pretty}")


def _sum_payload_bytes(packets: Sequence) -> int:
    total = 0
    for pkt in packets:
        if Raw in pkt:
            total += len(pkt[Raw].load)
    return total


def _check_padding() -> None:
    original = _make_flow(packets=4, payload_size=60, gap_ms=10)
    padded = apply_traffic_padding(original, target_length=120)
    print("Padding check: payload sizes")
    for before, after in zip(original, padded):
        raw_before = len(before[Raw].load)
        raw_after = len(after[Raw].load)
        print(f"  seq={before[TCP].seq:5d}: {raw_before} -> {raw_after}")
        assert raw_after >= raw_before <= 120
    _print_metrics("padding:original", original)
    _print_metrics("padding:transformed", padded)


def _check_split_and_combine() -> None:
    original = _make_flow(packets=2, payload_size=500, gap_ms=12)
    split_packets = split_logical_messages(original, chunk_size=180)
    combined_packets = combine_small_messages(split_packets, max_payload=240, window=3)
    print(f"Split produced {len(split_packets)} packets")
    print(f"Combine collapsed to {len(combined_packets)} packets")
    _print_metrics("split:original", original)
    _print_metrics("split:after_split", split_packets)
    _print_metrics("split:after_combine", combined_packets)
    assert len(split_packets) > len(original)
    assert len(combined_packets) <= len(split_packets)
    assert _sum_payload_bytes(original) == _sum_payload_bytes(split_packets)
    assert _sum_payload_bytes(split_packets) == _sum_payload_bytes(combined_packets)


def _check_sla(category: str) -> None:
    synthetic = _make_flow(packets=50, payload_size=90, gap_ms=15)
    constrained = enforce_sla_constraints(synthetic, category)
    _print_metrics("sla:original", synthetic)
    _print_metrics("sla:enforced", constrained)
    inter_arrivals = [
        constrained[idx + 1].time - constrained[idx].time
        for idx in range(len(constrained) - 1)
    ]
    print(
        f"  inter-arrival mean={statistics.mean(inter_arrivals):.6f}, stdev={statistics.pstdev(inter_arrivals):.6f}"
    )


def _inspect_real_capture(
    pcap_path: Path,
    *,
    padding_target: int,
    split_chunk_size: int,
    combine_max_payload: int,
    combine_window: int,
    category: str,
) -> None:
    print(f"Loading capture: {pcap_path}")
    packets = rdpcap(str(pcap_path))
    print(f"  total packets: {len(packets)}")
    _print_metrics("real:original", packets)

    # Traffic padding validation
    if padding_target > 0:
        padded = apply_traffic_padding(packets, padding_target)
        padded_lengths = [len(pkt[Raw].load) for pkt in padded if Raw in pkt]
        if padded_lengths:
            print(
                f"  padding: min={min(padded_lengths)}, max={max(padded_lengths)}, count={len(padded_lengths)}"
            )
        _print_metrics("real:padding", padded)
    else:
        padded = [pkt.copy() for pkt in packets]

    # Split validation
    split_packets = split_logical_messages(padded, split_chunk_size)
    _print_metrics("real:split", split_packets)
    original_payload = _sum_payload_bytes(padded)
    split_payload = _sum_payload_bytes(split_packets)
    print(f"  split payload bytes preserved: {original_payload == split_payload}")
    if any(Raw in pkt and len(pkt[Raw].load) > split_chunk_size for pkt in padded):
        print(
            f"  packet count grew from {len(padded)} to {len(split_packets)}"
        )

    # Combine validation
    combined_packets = combine_small_messages(split_packets, combine_max_payload, combine_window)
    _print_metrics("real:combine", combined_packets)
    combined_payload = _sum_payload_bytes(combined_packets)
    print(f"  combine payload bytes preserved: {split_payload == combined_payload}")
    print(f"  combine reduced packet count: {len(combined_packets) <= len(split_packets)}")

    # Optional SLA enforcement
    if category:
        final_packets = enforce_sla_constraints(combined_packets, category)
        _print_metrics("real:sla_enforced", final_packets)
    else:
        final_packets = combined_packets

    print("  final packet count:", len(final_packets))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run quick SLA sanity checks against transformer primitives.")
    parser.add_argument(
        "--category",
        type=str,
        default="VPN-VoIP",
        help="SLA category to enforce during the timing check",
    )
    parser.add_argument(
        "--pcap",
        type=Path,
        default=None,
        help="Optional PCAP file for real-data validation",
    )
    parser.add_argument("--padding", type=int, default=600, help="Target length for padding test")
    parser.add_argument("--split-chunk", type=int, default=500, help="Chunk size for split validation")
    parser.add_argument(
        "--combine-max",
        type=int,
        default=300,
        help="Maximum payload size for combine validation",
    )
    parser.add_argument(
        "--combine-window",
        type=int,
        default=3,
        help="Window parameter forwarded to combine_small_messages",
    )
    args = parser.parse_args()

    print("== Padding Scenario ==")
    _check_padding()
    print("\n== Split/Combine Scenario ==")
    _check_split_and_combine()
    print("\n== SLA Timing Scenario ==")
    _check_sla(args.category)

    if args.pcap is not None:
        print("\n== Real Capture Validation ==")
        _inspect_real_capture(
            args.pcap,
            padding_target=args.padding,
            split_chunk_size=args.split_chunk,
            combine_max_payload=args.combine_max,
            combine_window=args.combine_window,
            category=args.category,
        )


if __name__ == "__main__":
    main()
