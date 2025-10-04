import argparse
import copy
import json
import math
import os
import random
import statistics
import tempfile
from collections import deque
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

try:
    from scapy.all import IP, TCP, UDP, Raw, PcapReader, PcapWriter  # type: ignore
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "Scapy is required to run pcap_transformer. Install it with 'pip install scapy'."
    ) from exc


# Global defaults (kept together for quick audit/tuning)
DEFAULT_TRAFFIC_PADDING = 0
DEFAULT_SPLIT_CHUNK_SIZE = 0
DEFAULT_SPLIT_SPACING_US = 100.0
DEFAULT_COMBINE_MAX_PAYLOAD = 0
DEFAULT_COMBINE_WINDOW = 3
DEFAULT_DUMMY_RATE = 0.0
DEFAULT_DUMMY_SIZE = 0
DEFAULT_DUMMY_UDP_SPORT = 65000
DEFAULT_DUMMY_UDP_DPORT = 65001
DEFAULT_RATE_LIMIT = 0.0
DEFAULT_JITTER_MS = 0.0
DEFAULT_TUNNEL_PROTO = ""
DEFAULT_TUNNEL_SPORT = 55000
DEFAULT_TUNNEL_DPORT = 55001
DEFAULT_PORT_HOP_LIST = ""
DEFAULT_RANDOM_SEED = 1337
MIN_TIME_INCREMENT = 1e-6
MICROSECONDS_PER_SECOND = 1_000_000.0
MILLISECONDS_PER_SECOND = 1_000.0
MIN_SPLIT_SPACING_US = 1.0
DUMMY_PACKET_TIME_JITTER = 0.001
TCP_SEQ_MODULO = 1 << 32
MIN_COMBINE_WINDOW = 1
AUTO_TRAFFIC_PADDING_BYTES = 600
AUTO_SPLIT_CHUNK_SIZE = 800
AUTO_COMBINE_MAX_PAYLOAD = 200
AUTO_COMBINE_WINDOW = 3
AUTO_DUMMY_RATE = 0.05
AUTO_DUMMY_SIZE = 120
AUTO_RATE_LIMIT_PPS = 800.0
AUTO_JITTER_MS = 4.0
AUTO_PORT_HOP_LIST = [443, 8443, 9443]
AUTO_TUNNEL_PROTO = "udp"
AUTO_TUNNEL_SPORT = 55000
AUTO_TUNNEL_DPORT = 55001
DEFAULT_CATEGORY_CONFIG = Path(__file__).resolve().parents[1] / "utils" / "categorized_feature_patterns.json"


CATEGORY_SYNONYMS = {
    "VPN-Streaming (Live)": "VPN-Streaming",
    "VPN-Streaming (VOD)": "VPN-Streaming",
    "VPN-Command & Control (SSH/remote ops)": "VPN-Command&Control",
    "VPN-FileTransfer (bulk)": "VPN-FileTransfer",
    "VPN-Chat (text/IM)": "VPN-Chat",
}


SLA_VALIDATION_EPSILON = 1e-6


@dataclass
class MetricsAccumulator:
    count: int = 0
    first_time: Optional[float] = None
    last_time: Optional[float] = None
    _iat_count: int = 0
    _iat_mean: float = 0.0
    _iat_m2: float = 0.0

    def update(self, timestamp: float) -> None:
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

    def merge_packet(self, pkt) -> None:
        self.update(getattr(pkt, "time", 0.0))

    def as_dict(self) -> Dict[str, float]:
        duration = 0.0
        if self.first_time is not None and self.last_time is not None:
            duration = self.last_time - self.first_time
        mean_iat = self._iat_mean if self._iat_count > 0 else 0.0
        stdev_iat = math.sqrt(self._iat_m2 / self._iat_count) if self._iat_count > 0 else 0.0
        pps = self.count / duration if duration > 0.0 else 0.0
        return {
            "duration": duration,
            "mean_iat": mean_iat,
            "stdev_iat": stdev_iat,
            "pps": pps,
        }


class ChatBurstValidator:
    def __init__(self, burst_mode: Dict[str, float]) -> None:
        self.burst_mode = burst_mode
        self.window_limit = burst_mode["duration_sec_max"]
        self.timestamps: Deque[float] = deque()
        self.inter_arrivals: Deque[float] = deque()
        self.window_valid = False

    def observe(self, timestamp: float) -> None:
        if self.timestamps:
            delta = timestamp - self.timestamps[-1]
            self.inter_arrivals.append(delta)
        self.timestamps.append(timestamp)
        self._trim(timestamp)
        self._evaluate()

    def _trim(self, current: float) -> None:
        limit = self.window_limit + SLA_VALIDATION_EPSILON
        while self.timestamps and current - self.timestamps[0] > limit:
            self.timestamps.popleft()
            if self.inter_arrivals:
                self.inter_arrivals.popleft()

    def _evaluate(self) -> None:
        if len(self.timestamps) < 2:
            return
        duration = self.timestamps[-1] - self.timestamps[0]
        if duration <= 0.0 or duration > self.window_limit + SLA_VALIDATION_EPSILON:
            return
        gap_count = len(self.timestamps) - 1
        if gap_count <= 0:
            return

        local_pps = len(self.timestamps) / duration if duration > 0.0 else float("inf")
        if local_pps < self.burst_mode["pps_min"] - SLA_VALIDATION_EPSILON:
            return
        if local_pps > self.burst_mode["pps_max"] + SLA_VALIDATION_EPSILON:
            return

        mean_ms = statistics.mean(self.inter_arrivals) * MILLISECONDS_PER_SECOND if self.inter_arrivals else 0.0
        if mean_ms < self.burst_mode["mean_iat_ms_min"] - SLA_VALIDATION_EPSILON:
            return
        if mean_ms > self.burst_mode["mean_iat_ms_max"] + SLA_VALIDATION_EPSILON:
            return

        if len(self.inter_arrivals) > 1:
            stdev_ms = statistics.pstdev(self.inter_arrivals) * MILLISECONDS_PER_SECOND
        else:
            stdev_ms = 0.0
        if stdev_ms > self.burst_mode["stdev_iat_ms_max"] + SLA_VALIDATION_EPSILON:
            return

        self.window_valid = True

    def assert_valid(self) -> None:
        if not self.window_valid:
            raise ValueError(
                "SLA violation for VPN-Chat (text/IM): no burst window satisfies burst constraints"
            )


def _copy_packet(pkt):
    return pkt.copy()


def _copy_stream(packets: Iterable) -> Iterator:
    for pkt in packets:
        yield pkt.copy()


def _track_metrics(packets: Iterable, accumulator: MetricsAccumulator) -> Iterator:
    for pkt in packets:
        accumulator.merge_packet(pkt)
        yield pkt


def _iter_pcap(path: Path) -> Iterator:
    reader = PcapReader(str(path))
    try:
        for pkt in reader:
            yield pkt
    finally:
        reader.close()


def _write_packets(
    packets: Iterable,
    writer: PcapWriter,
    metrics: MetricsAccumulator,
) -> None:
    for pkt in packets:
        metrics.merge_packet(pkt)
        writer.write(pkt)


def _materialize_to_temp(packets: Iterable) -> Tuple[Path, MetricsAccumulator]:
    temp_handle = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    temp_path = Path(temp_handle.name)
    temp_handle.close()
    metrics = MetricsAccumulator()
    writer = PcapWriter(str(temp_path), append=False, sync=True)
    try:
        _write_packets(packets, writer, metrics)
    finally:
        writer.close()
    return temp_path, metrics


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


def ensure_checksum_recalc(pkt) -> None:
    if IP in pkt:
        pkt[IP].len = None
        pkt[IP].chksum = None
    if TCP in pkt:
        pkt[TCP].chksum = None
    if UDP in pkt:
        pkt[UDP].chksum = None


FEATURE_ID_TO_DESC = {
    1: "Packet Length & Size Features",
    2: "Byte/Packet Counters & Ratios",
    3: "Inter-Arrival Time (IAT) & Flow Timing",
    4: "TCP/Control Flags & Header Features",
    5: "Block Rate & Throughput Features",
    6: "Port & Protocol Features",
}


@lru_cache(maxsize=None)
def _load_category_data(config_path: str) -> Dict[str, Any]:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Category configuration not found: {config_path}")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _resolve_category_key(classes: Dict[str, Any], category: str) -> str:
    if category in classes:
        return category
    synonym = CATEGORY_SYNONYMS.get(category)
    if synonym and synonym in classes:
        return synonym
    for alias, canonical in CATEGORY_SYNONYMS.items():
        if canonical == category and alias in classes:
            return alias
    available = ", ".join(sorted(classes.keys()))
    raise KeyError(f"Category '{category}' not present in config. Available: {available}")


def _load_category_entry(config_path: Path, category: str) -> Dict[str, Any]:
    data = _load_category_data(str(config_path))
    classes = data.get("classes", {})
    category_key = _resolve_category_key(classes, category)
    return classes[category_key]


def load_recommended_features(config_path: Path, category: str) -> List[int]:
    entry = _load_category_entry(config_path, category)
    recommended = entry.get("Recommanded") or entry.get("Recommended") or []
    if not isinstance(recommended, list):
        raise ValueError(f"Recommended field for category '{category}' must be a list")
    return [int(item) for item in recommended]


def load_sla_constraints(config_path: Path, category: str) -> Optional[Dict[str, Any]]:
    entry = _load_category_entry(config_path, category)
    constraints = entry.get("sla_constraints")
    if constraints is None:
        return None
    return copy.deepcopy(constraints)


def apply_feature_bundle(packets: List, feature_id: int) -> List:
    return list(apply_feature_bundle_iter(packets, feature_id))


def apply_feature_bundle_iter(packets: Iterable, feature_id: int) -> Iterator:
    if feature_id == 1:
        stream = apply_traffic_padding_iter(packets, AUTO_TRAFFIC_PADDING_BYTES)
        stream = split_logical_messages_iter(stream, AUTO_SPLIT_CHUNK_SIZE)
        return combine_small_messages_iter(stream, AUTO_COMBINE_MAX_PAYLOAD, AUTO_COMBINE_WINDOW)
    if feature_id == 2:
        return add_dummy_packets_iter(packets, AUTO_DUMMY_RATE, AUTO_DUMMY_SIZE)
    if feature_id == 3:
        return inject_jitter_iter(packets, AUTO_JITTER_MS)
    if feature_id == 4:
        return apply_protocol_tunneling_iter(packets, AUTO_TUNNEL_PROTO, AUTO_TUNNEL_SPORT, AUTO_TUNNEL_DPORT)
    if feature_id == 5:
        return apply_rate_limit_iter(packets, AUTO_RATE_LIMIT_PPS)
    if feature_id == 6:
        return apply_port_hopping_iter(packets, AUTO_PORT_HOP_LIST)
    return _copy_stream(packets)


def apply_recommended_features(packets: List, feature_ids: Sequence[int]) -> List:
    return list(apply_recommended_features_iter(packets, feature_ids))


def apply_recommended_features_iter(packets: Iterable, feature_ids: Sequence[int]) -> Iterator:
    stream: Iterable = _copy_stream(packets)
    for feature_id in feature_ids:
        stream = apply_feature_bundle_iter(stream, feature_id)
    return stream


def apply_traffic_padding_iter(packets: Iterable, target_length: int) -> Iterator:
    if target_length <= 0:
        for pkt in packets:
            yield pkt.copy()
        return
    for pkt in packets:
        if Raw in pkt and len(pkt[Raw].load) < target_length:
            pad_len = target_length - len(pkt[Raw].load)
            padded = pkt.copy()
            if pad_len > 0:
                padded_payload = bytes(padded[Raw].load) + b"\x00" * pad_len
                padded[Raw].load = padded_payload
                ensure_checksum_recalc(padded)
            yield padded
        else:
            yield pkt.copy()


def apply_traffic_padding(packets: List, target_length: int) -> List:
    return list(apply_traffic_padding_iter(packets, target_length))


def split_logical_messages_iter(
    packets: Iterable,
    chunk_size: int,
    spacing_us: float = DEFAULT_SPLIT_SPACING_US,
) -> Iterator:
    if chunk_size <= 0:
        for pkt in packets:
            yield pkt.copy()
        return
    spacing = max(spacing_us, MIN_SPLIT_SPACING_US) / MICROSECONDS_PER_SECOND
    for pkt in packets:
        if TCP in pkt and Raw in pkt and len(pkt[Raw].load) > chunk_size:
            payload = bytes(pkt[Raw].load)
            base_time = getattr(pkt, "time", 0.0)
            seq = int(pkt[TCP].seq)
            offset = 0
            part_index = 0
            while offset < len(payload):
                chunk = payload[offset : offset + chunk_size]
                new_pkt = pkt.copy()
                new_pkt[TCP].seq = (seq + offset) % TCP_SEQ_MODULO
                new_pkt.time = base_time + part_index * spacing
                new_pkt[Raw].load = chunk
                ensure_checksum_recalc(new_pkt)
                yield new_pkt
                offset += len(chunk)
                part_index += 1
        else:
            yield pkt.copy()


def split_logical_messages(
    packets: List,
    chunk_size: int,
    spacing_us: float = DEFAULT_SPLIT_SPACING_US,
) -> List:
    return list(split_logical_messages_iter(packets, chunk_size, spacing_us))


def combine_small_messages_iter(
    packets: Iterable,
    max_payload: int,
    window: int = DEFAULT_COMBINE_WINDOW,
) -> Iterator:
    if max_payload <= 0 or window <= MIN_COMBINE_WINDOW:
        for pkt in packets:
            yield pkt.copy()
        return
    buffer: Optional[Tuple[Tuple[Any, str, str], Any]] = None
    count_in_buffer = 0
    for pkt in packets:
        if TCP in pkt and Raw in pkt and len(pkt[Raw].load) <= max_payload:
            flow = FlowKey.from_packet(pkt)
            direction = (flow, pkt[IP].src, pkt[IP].dst) if flow is not None else None
            payload = bytes(pkt[Raw].load)
            if direction is None:
                if buffer is not None:
                    yield buffer[1]
                    buffer = None
                yield pkt.copy()
                count_in_buffer = 0
                continue

            if buffer is None:
                tpl = pkt.copy()
                tpl[Raw].load = payload
                buffer = (direction, tpl)
                count_in_buffer = 1
                continue

            prev_direction, prev_pkt = buffer
            if direction == prev_direction and count_in_buffer < window:
                merged = prev_pkt
                merged_payload = bytes(merged[Raw].load) + payload
                merged[Raw].load = merged_payload
                merged.time = max(getattr(merged, "time", 0.0), getattr(pkt, "time", 0.0))
                ensure_checksum_recalc(merged)
                buffer = (direction, merged)
                count_in_buffer += 1
                continue

            yield prev_pkt
            tpl = pkt.copy()
            tpl[Raw].load = payload
            buffer = (direction, tpl)
            count_in_buffer = 1
        else:
            if buffer is not None:
                yield buffer[1]
                buffer = None
                count_in_buffer = 0
            yield pkt.copy()
    if buffer is not None:
        yield buffer[1]


def combine_small_messages(
    packets: List,
    max_payload: int,
    window: int = DEFAULT_COMBINE_WINDOW,
) -> List:
    return list(combine_small_messages_iter(packets, max_payload, window))


def add_dummy_packets_iter(
    packets: Iterable,
    rate: float,
    payload_size: int,
    udp_sport: int = DEFAULT_DUMMY_UDP_SPORT,
    udp_dport: int = DEFAULT_DUMMY_UDP_DPORT,
) -> Iterator:
    if rate <= 0.0 or payload_size <= 0:
        for pkt in packets:
            yield pkt.copy()
        return
    for pkt in packets:
        base_pkt = pkt.copy()
        yield base_pkt
        if IP in pkt and random.random() < rate:
            dummy = IP(src=pkt[IP].src, dst=pkt[IP].dst) / UDP(sport=udp_sport, dport=udp_dport)
            dummy /= Raw(os.urandom(payload_size))
            dummy.time = getattr(pkt, "time", 0.0) + random.random() * DUMMY_PACKET_TIME_JITTER
            ensure_checksum_recalc(dummy)
            yield dummy


def add_dummy_packets(
    packets: List,
    rate: float,
    payload_size: int,
    udp_sport: int = DEFAULT_DUMMY_UDP_SPORT,
    udp_dport: int = DEFAULT_DUMMY_UDP_DPORT,
) -> List:
    return list(add_dummy_packets_iter(packets, rate, payload_size, udp_sport, udp_dport))


def apply_rate_limit_iter(packets: Iterable, max_pps: float) -> Iterator:
    if max_pps <= 0:
        for pkt in packets:
            yield pkt.copy()
        return
    min_gap = 1.0 / max_pps
    last_time: Optional[float] = None
    for pkt in packets:
        new_pkt = pkt.copy()
        pkt_time = getattr(new_pkt, "time", 0.0)
        if last_time is None:
            last_time = pkt_time
        else:
            if pkt_time < last_time + min_gap:
                pkt_time = last_time + min_gap
                new_pkt.time = pkt_time
            last_time = pkt_time
        yield new_pkt


def apply_rate_limit(packets: List, max_pps: float) -> List:
    return list(apply_rate_limit_iter(packets, max_pps))


def inject_jitter_iter(packets: Iterable, jitter_ms: float) -> Iterator:
    if jitter_ms <= 0:
        for pkt in packets:
            yield pkt.copy()
        return
    jitter_seconds = jitter_ms / 1000.0
    last_time: Optional[float] = None
    for pkt in packets:
        new_pkt = pkt.copy()
        base_time = getattr(new_pkt, "time", 0.0)
        jitter = random.uniform(-jitter_seconds, jitter_seconds)
        new_time = base_time + jitter
        if last_time is not None and new_time <= last_time:
            new_time = last_time + MIN_TIME_INCREMENT
        new_pkt.time = new_time
        last_time = new_time
        yield new_pkt


def inject_jitter(packets: List, jitter_ms: float) -> List:
    return list(inject_jitter_iter(packets, jitter_ms))


def apply_protocol_tunneling_iter(packets: Iterable, outer_proto: str, outer_sport: int, outer_dport: int) -> Iterator:
    if outer_proto.lower() != "udp":
        for pkt in packets:
            yield pkt.copy()
        return
    for pkt in packets:
        if IP in pkt:
            payload_bytes = bytes(pkt[IP])
            tunneled = IP(src=pkt[IP].src, dst=pkt[IP].dst) / UDP(sport=outer_sport, dport=outer_dport)
            tunneled /= Raw(payload_bytes)
            tunneled.time = getattr(pkt, "time", 0.0)
            ensure_checksum_recalc(tunneled)
            yield tunneled
        else:
            yield pkt.copy()


def apply_protocol_tunneling(packets: List, outer_proto: str, outer_sport: int, outer_dport: int) -> List:
    return list(apply_protocol_tunneling_iter(packets, outer_proto, outer_sport, outer_dport))


def apply_port_hopping_iter(packets: Iterable, ports: Sequence[int]) -> Iterator:
    if not ports:
        for pkt in packets:
            yield pkt.copy()
        return
    port_cycle: Dict[FlowKey, Deque[int]] = {}
    for pkt in packets:
        if TCP in pkt or UDP in pkt:
            flow = FlowKey.from_packet(pkt)
            if flow is None:
                yield pkt.copy()
                continue
            if flow not in port_cycle:
                port_cycle[flow] = deque(ports)
            dq = port_cycle[flow]
            dq.rotate(-1)
            next_port = dq[0]
            modified = pkt.copy()
            if TCP in modified:
                modified[TCP].dport = next_port
            if UDP in modified:
                modified[UDP].dport = next_port
            ensure_checksum_recalc(modified)
            yield modified
        else:
            yield pkt.copy()


def apply_port_hopping(packets: List, ports: Sequence[int]) -> List:
    return list(apply_port_hopping_iter(packets, ports))


def compute_metrics(packets: Iterable) -> Dict[str, float]:
    timestamps = [getattr(pkt, "time", 0.0) for pkt in packets]
    timestamps.sort()
    if len(timestamps) < 2:
        return {"duration": 0.0, "mean_iat": 0.0, "stdev_iat": 0.0, "pps": 0.0}
    inter_arrivals = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:]) if t2 >= t1]
    duration = timestamps[-1] - timestamps[0]
    mean_iat = statistics.mean(inter_arrivals) if inter_arrivals else 0.0
    stdev_iat = statistics.pstdev(inter_arrivals) if len(inter_arrivals) > 1 else 0.0
    pps = len(timestamps) / duration if duration > 0 else 0.0
    return {
        "duration": duration,
        "mean_iat": mean_iat,
        "stdev_iat": stdev_iat,
        "pps": pps,
    }


def clamp(value: float, *, min_value: Optional[float] = None, max_value: Optional[float] = None) -> float:
    if min_value is not None:
        value = max(value, min_value)
    if max_value is not None:
        value = min(value, max_value)
    return value


def _sorted_packet_copies(packets: Sequence) -> List:
    indexed = [(idx, pkt.copy()) for idx, pkt in enumerate(packets)]
    indexed.sort(key=lambda item: getattr(item[1], "time", 0.0))
    return [pkt for _, pkt in indexed]


def _validate_metric_range(
    value: float,
    *,
    min_value: Optional[float] = None,
    max_value: Optional[float] = None,
    epsilon: float = SLA_VALIDATION_EPSILON,
    metric_name: str,
    category: str,
) -> None:
    if min_value is not None and value < min_value - epsilon:
        raise ValueError(
            f"SLA violation for {category}: {metric_name}={value:.6f} below minimum {min_value:.6f}"
        )
    if max_value is not None and value > max_value + epsilon:
        raise ValueError(
            f"SLA violation for {category}: {metric_name}={value:.6f} above maximum {max_value:.6f}"
        )


def _validate_standard_sla(metrics: Dict[str, float], category: str, constraints: Dict[str, float]) -> None:
    duration = metrics["duration"]
    duration_expected = constraints.get("duration_sec")
    if duration_expected is not None:
        tolerance = max(0.001, duration_expected * 0.02)
        if abs(duration - duration_expected) > tolerance:
            raise ValueError(
                f"SLA violation for {category}: duration {duration:.6f}s differs from target {duration_expected:.6f}s"
            )

    pps = metrics["pps"]
    _validate_metric_range(
        pps,
        min_value=constraints.get("pps_min"),
        max_value=constraints.get("pps_max"),
        metric_name="pps",
        category=category,
    )

    mean_iat_ms = metrics["mean_iat"] * MILLISECONDS_PER_SECOND
    _validate_metric_range(
        mean_iat_ms,
        min_value=constraints.get("mean_iat_ms_min"),
        max_value=constraints.get("mean_iat_ms_max"),
        metric_name="mean_iat_ms",
        category=category,
    )

    stdev_iat_ms = metrics["stdev_iat"] * MILLISECONDS_PER_SECOND
    _validate_metric_range(
        stdev_iat_ms,
        min_value=None,
        max_value=constraints.get("stdev_iat_ms_max"),
        metric_name="stdev_iat_ms",
        category=category,
    )


def _compute_duration_window(
    total_packets: int,
    constraints: Dict[str, float],
) -> Tuple[float, float]:
    intervals = total_packets - 1
    if intervals <= 0:
        return (0.0, math.inf)

    lower = 0.0
    upper = math.inf

    duration_target = constraints.get("duration_sec")
    if duration_target is not None:
        tolerance = max(0.001, duration_target * 0.02)
        lower = max(lower, duration_target - tolerance)
        upper = min(upper, duration_target + tolerance)

    pps_min = constraints.get("pps_min")
    pps_max = constraints.get("pps_max")
    if pps_max is not None and pps_max > 0:
        lower = max(lower, total_packets / pps_max)
    if pps_min is not None and pps_min > 0:
        upper = min(upper, total_packets / pps_min)

    mean_iat_min = constraints.get("mean_iat_ms_min")
    mean_iat_max = constraints.get("mean_iat_ms_max")
    if mean_iat_min is not None:
        lower = max(lower, intervals * mean_iat_min / MILLISECONDS_PER_SECOND)
    if mean_iat_max is not None:
        upper = min(upper, intervals * mean_iat_max / MILLISECONDS_PER_SECOND)

    if lower > upper:
        raise ValueError(
            "SLA constraints are unsatisfiable given the packet count: "
            f"required duration window [{lower:.6f}, {upper:.6f}] is empty."
        )
    return lower, upper


def _enforce_standard_sla_stream(
    source_path: Path,
    destination_path: Path,
    constraints: Dict[str, float],
    *,
    resolved_label: str,
    source_metrics: Dict[str, float],
    packet_count: int,
    base_time: float,
) -> Dict[str, float]:
    if packet_count <= 0:
        writer = PcapWriter(str(destination_path), append=False, sync=True)
        writer.close()
        return {"duration": 0.0, "mean_iat": 0.0, "stdev_iat": 0.0, "pps": 0.0}

    duration_lower, duration_upper = _compute_duration_window(packet_count, constraints)
    target_duration = constraints.get("duration_sec")

    if target_duration is None or target_duration <= 0.0:
        target_duration = clamp(
            source_metrics.get("duration", 0.0),
            min_value=duration_lower,
            max_value=duration_upper if not math.isinf(duration_upper) else None,
        )
    else:
        target_duration = clamp(
            target_duration,
            min_value=duration_lower,
            max_value=duration_upper if not math.isinf(duration_upper) else None,
        )

    if math.isinf(target_duration) or target_duration <= 0.0:
        target_duration = max(duration_lower, 0.0)

    intervals = packet_count - 1
    interval = target_duration / intervals if intervals > 0 else 0.0

    metrics = MetricsAccumulator()
    reader = PcapReader(str(source_path))
    writer = PcapWriter(str(destination_path), append=False, sync=True)
    try:
        current_time = base_time
        for index, pkt in enumerate(reader):
            new_pkt = pkt.copy()
            if index == 0:
                new_pkt.time = base_time
            else:
                current_time += interval
                new_pkt.time = current_time
            metrics.merge_packet(new_pkt)
            writer.write(new_pkt)
    finally:
        reader.close()
        writer.close()

    metrics_dict = metrics.as_dict()
    _validate_standard_sla(metrics_dict, resolved_label, constraints)
    return metrics_dict


def _enforce_standard_sla(packets: Sequence, constraints: Dict[str, float]) -> List:
    sorted_packets = _sorted_packet_copies(packets)
    if len(sorted_packets) <= 1:
        return sorted_packets

    duration_lower, duration_upper = _compute_duration_window(len(sorted_packets), constraints)
    target_duration = constraints.get("duration_sec")
    if target_duration is None:
        target_duration = clamp(
            duration_upper,
            min_value=duration_lower,
            max_value=duration_upper,
        )
    else:
        target_duration = clamp(target_duration, min_value=duration_lower, max_value=duration_upper)

    intervals = len(sorted_packets) - 1
    interval = target_duration / intervals

    base_time = getattr(sorted_packets[0], "time", 0.0)
    sorted_packets[0].time = base_time
    current_time = base_time
    for pkt in sorted_packets[1:]:
        current_time += interval
        pkt.time = current_time
    return sorted_packets


def _build_chat_intervals(
    total_intervals: int,
    target_duration: float,
    avg_mode: Dict[str, float],
    burst_mode: Dict[str, float],
) -> Optional[List[float]]:
    if total_intervals <= 0:
        return []

    burst_interval_min = max(
        1.0 / burst_mode["pps_max"],
        burst_mode["mean_iat_ms_min"] / MILLISECONDS_PER_SECOND,
    )
    burst_interval_max = min(
        1.0 / burst_mode["pps_min"],
        burst_mode["mean_iat_ms_max"] / MILLISECONDS_PER_SECOND,
    )
    if burst_interval_min > burst_interval_max:
        return None
    burst_interval = (burst_interval_min + burst_interval_max) / 2.0

    burst_packets_per_segment = 5
    burst_intervals_per_segment = burst_packets_per_segment - 1
    if burst_intervals_per_segment <= 0:
        return None

    max_bursts = min(3, total_intervals // burst_intervals_per_segment)
    if max_bursts == 0:
        return None

    idle_interval_min = max(
        1.0 / max(avg_mode["pps_max"], 1.0),
        avg_mode["mean_iat_ms_min"] / MILLISECONDS_PER_SECOND,
    )

    for bursts in range(max_bursts, 0, -1):
        burst_intervals = bursts * burst_intervals_per_segment
        if burst_intervals >= total_intervals:
            continue
        idle_intervals = total_intervals - burst_intervals
        idle_duration = target_duration - burst_intervals * burst_interval
        if idle_duration <= 0:
            continue
        idle_interval = idle_duration / idle_intervals
        if idle_interval < idle_interval_min:
            continue

        distribution_slots = bursts + 1
        slot_counts = [0] * distribution_slots
        for idx in range(idle_intervals):
            slot_counts[idx % distribution_slots] += 1

        intervals: List[float] = []
        slot_index = 0
        for burst_index in range(bursts):
            idle_count = slot_counts[slot_index]
            intervals.extend([idle_interval] * idle_count)
            slot_index += 1
            intervals.extend([burst_interval] * burst_intervals_per_segment)
        intervals.extend([idle_interval] * slot_counts[slot_index])

        if len(intervals) == total_intervals:
            return intervals
    return None


def _enforce_chat_sla(packets: Sequence, constraints: Dict[str, float]) -> List:
    sorted_packets = _sorted_packet_copies(packets)
    if len(sorted_packets) <= 1:
        return sorted_packets

    target_duration = constraints["duration_sec"]
    total_intervals = len(sorted_packets) - 1

    avg_mode = constraints["avg_mode"]
    burst_mode = constraints["burst_mode"]

    overall_pps_cap = avg_mode["pps_max"]
    if overall_pps_cap > 0:
        min_duration_needed = len(sorted_packets) / overall_pps_cap
        if min_duration_needed > target_duration + SLA_VALIDATION_EPSILON:
            raise ValueError(
                "SLA violation: insufficient total duration to keep overall PPS under cap for VPN-Chat"
            )

    intervals = _build_chat_intervals(total_intervals, target_duration, avg_mode, burst_mode)
    if intervals is None:
        raise ValueError("Unable to construct burst/idle schedule that satisfies VPN-Chat SLA constraints")

    base_time = getattr(sorted_packets[0], "time", 0.0)
    sorted_packets[0].time = base_time
    current_time = base_time
    for pkt, gap in zip(sorted_packets[1:], intervals):
        current_time += gap
        pkt.time = current_time
    return sorted_packets


def _enforce_chat_sla_stream(
    source_path: Path,
    destination_path: Path,
    constraints: Dict[str, Any],
    *,
    packet_count: int,
    base_time: float,
) -> Dict[str, float]:
    if packet_count <= 0:
        writer = PcapWriter(str(destination_path), append=False, sync=True)
        writer.close()
        return {"duration": 0.0, "mean_iat": 0.0, "stdev_iat": 0.0, "pps": 0.0}

    target_duration = constraints["duration_sec"]
    total_intervals = packet_count - 1
    if total_intervals <= 0:
        reader = PcapReader(str(source_path))
        writer = PcapWriter(str(destination_path), append=False, sync=True)
        metrics = MetricsAccumulator()
        try:
            for pkt in reader:
                new_pkt = pkt.copy()
                new_pkt.time = base_time
                metrics.merge_packet(new_pkt)
                writer.write(new_pkt)
        finally:
            reader.close()
            writer.close()
        return metrics.as_dict()

    avg_mode = constraints["avg_mode"]
    burst_mode = constraints["burst_mode"]

    overall_pps_cap = avg_mode["pps_max"]
    if overall_pps_cap > 0:
        min_duration_needed = packet_count / overall_pps_cap
        if min_duration_needed > target_duration + SLA_VALIDATION_EPSILON:
            raise ValueError(
                "SLA violation: insufficient total duration to keep overall PPS under cap for VPN-Chat"
            )

    intervals = _build_chat_intervals(total_intervals, target_duration, avg_mode, burst_mode)
    if intervals is None:
        raise ValueError(
            "Unable to construct burst/idle schedule that satisfies VPN-Chat SLA constraints"
        )

    interval_iter = iter(intervals)
    intervals_consumed = 0
    metrics = MetricsAccumulator()
    validator = ChatBurstValidator(burst_mode)

    reader = PcapReader(str(source_path))
    writer = PcapWriter(str(destination_path), append=False, sync=True)
    try:
        current_time = base_time
        for index, pkt in enumerate(reader):
            new_pkt = pkt.copy()
            if index == 0:
                new_pkt.time = base_time
            else:
                try:
                    gap = next(interval_iter)
                except StopIteration as exc:
                    raise ValueError(
                        "Constructed VPN-Chat schedule shorter than packet sequence"
                    ) from exc
                intervals_consumed += 1
                current_time += gap
                new_pkt.time = current_time
            metrics.merge_packet(new_pkt)
            validator.observe(getattr(new_pkt, "time", 0.0))
            writer.write(new_pkt)
    finally:
        reader.close()
        writer.close()

    try:
        next(interval_iter)
        raise ValueError("Constructed VPN-Chat schedule longer than packet sequence")
    except StopIteration:
        pass

    if intervals_consumed != total_intervals:
        raise ValueError("Constructed VPN-Chat schedule did not match packet count")

    metrics_dict = metrics.as_dict()

    duration_expected = target_duration
    tolerance = max(0.001, duration_expected * 0.02)
    if abs(metrics_dict["duration"] - duration_expected) > tolerance:
        raise ValueError(
            f"SLA violation for VPN-Chat (text/IM): duration {metrics_dict['duration']:.6f}s does not match target {duration_expected:.6f}s"
        )

    if avg_mode.get("pps_max") is not None:
        _validate_metric_range(
            metrics_dict["pps"],
            min_value=None,
            max_value=avg_mode["pps_max"],
            metric_name="pps",
            category="VPN-Chat (text/IM)",
        )

    mean_iat_ms = metrics_dict["mean_iat"] * MILLISECONDS_PER_SECOND
    _validate_metric_range(
        mean_iat_ms,
        min_value=avg_mode.get("mean_iat_ms_min"),
        max_value=None,
        metric_name="mean_iat_ms",
        category="VPN-Chat (text/IM)",
    )

    validator.assert_valid()

    return metrics_dict


def _validate_chat_sla(packets: Sequence, constraints: Dict[str, float]) -> None:
    metrics = compute_metrics(packets)
    duration_expected = constraints["duration_sec"]
    if abs(metrics["duration"] - duration_expected) > max(0.001, duration_expected * 0.02):
        raise ValueError(
            f"SLA violation for VPN-Chat (text/IM): duration {metrics['duration']:.6f}s does not match target {duration_expected:.6f}s"
        )

    avg_mode = constraints["avg_mode"]
    _validate_metric_range(
        metrics["pps"],
        min_value=None,
        max_value=avg_mode.get("pps_max"),
        metric_name="pps",
        category="VPN-Chat (text/IM)",
    )

    mean_iat_ms = metrics["mean_iat"] * MILLISECONDS_PER_SECOND
    _validate_metric_range(
        mean_iat_ms,
        min_value=avg_mode.get("mean_iat_ms_min"),
        max_value=None,
        metric_name="mean_iat_ms",
        category="VPN-Chat (text/IM)",
    )

    timestamps = [getattr(pkt, "time", 0.0) for pkt in packets]
    timestamps.sort()

    burst_mode = constraints["burst_mode"]
    window_limit = burst_mode["duration_sec_max"]
    found_valid_burst = False
    for start_idx in range(len(timestamps)):
        for end_idx in range(start_idx + 1, len(timestamps)):
            window_duration = timestamps[end_idx] - timestamps[start_idx]
            if window_duration > window_limit:
                break
            gap_count = end_idx - start_idx
            if gap_count <= 0:
                continue
            inter_arrivals = [
                timestamps[i + 1] - timestamps[i]
                for i in range(start_idx, end_idx)
            ]
            if not inter_arrivals:
                continue
            local_mean = statistics.mean(inter_arrivals)
            local_stdev = (
                statistics.pstdev(inter_arrivals)
                if len(inter_arrivals) > 1
                else 0.0
            )
            local_pps = (gap_count + 1) / window_duration if window_duration > 0 else float("inf")

            if local_pps < burst_mode["pps_min"] - SLA_VALIDATION_EPSILON:
                continue
            if local_pps > burst_mode["pps_max"] + SLA_VALIDATION_EPSILON:
                continue
            mean_ms = local_mean * MILLISECONDS_PER_SECOND
            if mean_ms < burst_mode["mean_iat_ms_min"] - SLA_VALIDATION_EPSILON:
                continue
            if mean_ms > burst_mode["mean_iat_ms_max"] + SLA_VALIDATION_EPSILON:
                continue
            stdev_ms = local_stdev * MILLISECONDS_PER_SECOND
            if stdev_ms > burst_mode["stdev_iat_ms_max"] + SLA_VALIDATION_EPSILON:
                continue
            found_valid_burst = True
            break
        if found_valid_burst:
            break

    if not found_valid_burst:
        raise ValueError("SLA violation for VPN-Chat (text/IM): no burst window satisfies burst constraints")


def enforce_sla_constraints(
    packets: Sequence,
    category: str,
    *,
    config_path: Optional[Path] = None,
) -> List:
    if not category:
        return [pkt.copy() for pkt in packets]

    effective_config = config_path or DEFAULT_CATEGORY_CONFIG
    try:
        constraints = load_sla_constraints(effective_config, category)
    except KeyError:
        return [pkt.copy() for pkt in packets]

    if constraints is None:
        return [pkt.copy() for pkt in packets]

    resolved_label = CATEGORY_SYNONYMS.get(category, category)
    if resolved_label == "VPN-Chat":
        adjusted = _enforce_chat_sla(packets, constraints)
        _validate_chat_sla(adjusted, constraints)
    else:
        adjusted = _enforce_standard_sla(packets, constraints)
        metrics = compute_metrics(adjusted)
        _validate_standard_sla(metrics, resolved_label, constraints)
    return adjusted


def parse_port_list(port_arg: Optional[str]) -> List[int]:
    if not port_arg:
        return []
    ports: List[int] = []
    for part in port_arg.split(","):
        part = part.strip()
        if not part:
            continue
        ports.append(int(part))
    return ports


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply mimicry transformations to a PCAP file.")
    parser.add_argument("input", type=Path, help="Source PCAP file")
    parser.add_argument("output", type=Path, help="Destination PCAP file")
    parser.add_argument(
        "--category",
        type=str,
        default="",
        help="Traffic category label used to look up recommended transformations",
    )
    parser.add_argument(
        "--category-config",
        type=Path,
        default=None,
        help="Path to categorized feature pattern JSON (defaults to repo config)",
    )
    parser.add_argument(
        "--traffic-padding",
        type=int,
        default=DEFAULT_TRAFFIC_PADDING,
        help="Pad TCP payloads up to the given byte length",
    )
    parser.add_argument(
        "--split-chunk-size",
        type=int,
        default=DEFAULT_SPLIT_CHUNK_SIZE,
        help="Split large TCP payloads into chunks of this size",
    )
    parser.add_argument(
        "--combine-max-payload",
        type=int,
        default=DEFAULT_COMBINE_MAX_PAYLOAD,
        help="Combine consecutive TCP payloads up to this size",
    )
    parser.add_argument(
        "--combine-window",
        type=int,
        default=DEFAULT_COMBINE_WINDOW,
        help="Maximum packets to merge when combining",
    )
    parser.add_argument(
        "--dummy-rate",
        type=float,
        default=DEFAULT_DUMMY_RATE,
        help="Probability of injecting a dummy UDP packet after each packet",
    )
    parser.add_argument(
        "--dummy-size",
        type=int,
        default=DEFAULT_DUMMY_SIZE,
        help="Payload size for dummy packets",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=DEFAULT_RATE_LIMIT,
        help="Cap packets-per-second to this value",
    )
    parser.add_argument(
        "--jitter-ms",
        type=float,
        default=DEFAULT_JITTER_MS,
        help="Inject ± jitter (milliseconds) into timestamps",
    )
    parser.add_argument(
        "--tunnel",
        type=str,
        default=DEFAULT_TUNNEL_PROTO,
        help="Outer protocol for tunneling (currently supports 'udp')",
    )
    parser.add_argument(
        "--tunnel-sport",
        type=int,
        default=DEFAULT_TUNNEL_SPORT,
        help="Source port for outer tunnel",
    )
    parser.add_argument(
        "--tunnel-dport",
        type=int,
        default=DEFAULT_TUNNEL_DPORT,
        help="Destination port for outer tunnel",
    )
    parser.add_argument(
        "--port-hop",
        type=str,
        default=DEFAULT_PORT_HOP_LIST,
        help="Comma-separated list of ports for hopping",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_RANDOM_SEED,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--apply-recommended",
        action="store_true",
        help="Apply the recommended obfuscation bundles for the given category",
    )
    parser.add_argument("--metrics", action="store_true", help="Print SLA-oriented timing metrics before/after")

    args = parser.parse_args()

    random.seed(args.seed)

    config_path = args.category_config or DEFAULT_CATEGORY_CONFIG

    original_metrics_acc = MetricsAccumulator()

    stream: Iterable = _iter_pcap(args.input)
    stream = _track_metrics(stream, original_metrics_acc)

    if args.apply_recommended:
        if not args.category:
            parser.error("--apply-recommended requires --category")
        recommended_ids = load_recommended_features(config_path, args.category)
        if recommended_ids:
            stream = apply_recommended_features_iter(stream, recommended_ids)
        else:
            print(f"No recommended features found for category '{args.category}'.")

    if args.traffic_padding:
        stream = apply_traffic_padding_iter(stream, args.traffic_padding)
    if args.split_chunk_size:
        stream = split_logical_messages_iter(stream, args.split_chunk_size)
    if args.combine_max_payload:
        stream = combine_small_messages_iter(stream, args.combine_max_payload, args.combine_window)
    if args.dummy_rate and args.dummy_size:
        stream = add_dummy_packets_iter(stream, args.dummy_rate, args.dummy_size)
    if args.rate_limit:
        stream = apply_rate_limit_iter(stream, args.rate_limit)
    if args.jitter_ms:
        stream = inject_jitter_iter(stream, args.jitter_ms)
    if args.port_hop:
        ports = parse_port_list(args.port_hop)
        stream = apply_port_hopping_iter(stream, ports)
    if args.tunnel:
        stream = apply_protocol_tunneling_iter(stream, args.tunnel, args.tunnel_sport, args.tunnel_dport)

    args.output.parent.mkdir(parents=True, exist_ok=True)

    sla_constraints: Optional[Dict[str, Any]] = None
    resolved_label = CATEGORY_SYNONYMS.get(args.category, args.category)
    if args.category:
        try:
            sla_constraints = load_sla_constraints(config_path, args.category)
        except KeyError:
            sla_constraints = None

    enforce_sla = sla_constraints is not None

    if enforce_sla:
        temp_path, transform_metrics = _materialize_to_temp(stream)
        try:
            packet_count = transform_metrics.count
            base_time = transform_metrics.first_time or 0.0
            source_metrics = transform_metrics.as_dict()
            if resolved_label == "VPN-Chat":
                final_metrics = _enforce_chat_sla_stream(
                    temp_path,
                    args.output,
                    sla_constraints,
                    packet_count=packet_count,
                    base_time=base_time,
                )
            else:
                final_metrics = _enforce_standard_sla_stream(
                    temp_path,
                    args.output,
                    sla_constraints,
                    resolved_label=resolved_label,
                    source_metrics=source_metrics,
                    packet_count=packet_count,
                    base_time=base_time,
                )
        finally:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
    else:
        writer = PcapWriter(str(args.output), append=False, sync=True)
        transformed_metrics = MetricsAccumulator()
        try:
            _write_packets(stream, writer, transformed_metrics)
        finally:
            writer.close()
        final_metrics = transformed_metrics.as_dict()

    if args.metrics:
        original_metrics = original_metrics_acc.as_dict()
        print("Baseline metrics:")
        for key, value in original_metrics.items():
            print(f"  {key}: {value:.6f}")
        print("\nTransformed metrics:")
        for key, value in final_metrics.items():
            print(f"  {key}: {value:.6f}")


if __name__ == "__main__":
    main()
