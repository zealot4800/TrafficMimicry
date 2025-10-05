from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, List

import sys


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CICFlowMeter offline helper")

    input_mode = parser.add_mutually_exclusive_group(required=True)
    input_mode.add_argument("--pcap", type=Path, help="Input PCAP file")
    input_mode.add_argument(
        "--pcap-dir",
        type=Path,
        help="Directory containing PCAP/PCAPNG files",
    )

    parser.add_argument(
        "--csv",
        type=Path,
        help="Output CSV path (single file mode)",
    )
    parser.add_argument(
        "--csv-dir",
        type=Path,
        help="Output directory (mirrors structure when using --pcap-dir)",
    )
    parser.add_argument(
        "--combined-csv",
        type=Path,
        help="Final CSV path to consolidate results when using --pcap-dir",
    )
    parser.add_argument(
        "--patterns",
        nargs="*",
        default=["*.pcap", "*.pcapng"],
        help="Glob patterns to search in directory mode",
    )
    parser.add_argument(
        "--cic-root",
        default=Path("/home/zealot/cicflowmeter/src"),
        type=Path,
        help="Path to cicflowmeter source tree",
    )
    args = parser.parse_args()

    if args.pcap and not args.csv:
        parser.error("--csv is required when using --pcap")
    if args.pcap_dir:
        if not args.csv_dir:
            parser.error("--csv-dir is required when using --pcap-dir")
        if not args.combined_csv:
            parser.error("--combined-csv is required when using --pcap-dir")

    return args


def _collect_pcaps(root: Path, patterns: Iterable[str]) -> List[Path]:
    files: List[Path] = []
    for pattern in patterns:
        files.extend(root.rglob(pattern))
    return sorted(set(files))


def _convert_file(session_factory, sniffer_cls, pcap: Path, csv_path: Path) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    session = session_factory(str(csv_path))

    sniffer = sniffer_cls(
        offline=str(pcap),
        prn=session.process,
        store=False,
    )
    sniffer.start()
    sniffer.join()
    session.flush_flows()


def _combine_csvs(csv_files: List[Path], combined_path: Path) -> None:
    if not csv_files:
        print("No CSV files to combine; skipping consolidation")
        return

    combined_path.parent.mkdir(parents=True, exist_ok=True)

    header_line: str | None = None
    with combined_path.open("w", newline="") as combined_handle:
        for csv_file in csv_files:
            with csv_file.open("r", newline="") as source_handle:
                for line_number, line in enumerate(source_handle):
                    if line_number == 0:
                        stripped = line.strip()
                        if not stripped:
                            continue
                        if header_line is None:
                            header_line = stripped
                            combined_handle.write(line)
                        elif stripped != header_line:
                            raise ValueError(
                                f"Header mismatch while combining CSVs: {csv_file}"
                            )
                        continue
                    combined_handle.write(line)

    if header_line is None:
        raise ValueError("Combined CSV is empty; no header detected")


def main() -> None:
    args = _parse_args()
    sys.path.insert(0, str(args.cic_root))

    from cicflowmeter.flow_session import FlowSession
    from cicflowmeter.features.flow_bytes import FlowBytes
    from cicflowmeter.features.context import PacketDirection
    from scapy.sendrecv import AsyncSniffer

    def _safe_min_forward_header_bytes(self) -> int:
        values = [
            self._header_size(packet)
            for packet, direction in self.flow.packets
            if direction == PacketDirection.FORWARD
        ]
        return min(values) if values else 0

    FlowBytes.get_min_forward_header_bytes = _safe_min_forward_header_bytes  # type: ignore[assignment]

    def session_factory(destination: str) -> FlowSession:
        return FlowSession(
            output_mode="csv",
            output=destination,
            fields=None,
            verbose=False,
        )

    if args.pcap:
        pcap_path = args.pcap.resolve()
        csv_path = args.csv.resolve()
        print(f"Processing {pcap_path} -> {csv_path}")
        _convert_file(session_factory, AsyncSniffer, pcap_path, csv_path)
        return

    pcap_root = args.pcap_dir.resolve()
    csv_root = args.csv_dir.resolve()
    combined_target = args.combined_csv.resolve()
    pcaps = _collect_pcaps(pcap_root, args.patterns)
    if not pcaps:
        print(f"No PCAP files found under {pcap_root}")
        return

    total = len(pcaps)
    csv_outputs: List[Path] = []
    for index, pcap in enumerate(pcaps, start=1):
        relative = pcap.relative_to(pcap_root)
        destination = (csv_root / relative).with_suffix(".csv")
        print(f"[{index}/{total}] {pcap} -> {destination}")
        _convert_file(session_factory, AsyncSniffer, pcap, destination)
        csv_outputs.append(destination)

    resolved_outputs = [path.resolve() for path in csv_outputs]
    if combined_target in resolved_outputs:
        raise ValueError("--combined-csv must differ from per-file CSV destinations")

    print(f"Combining {len(csv_outputs)} CSV files into {combined_target}")
    _combine_csvs(csv_outputs, combined_target)

    removed = 0
    for csv_file, resolved in zip(csv_outputs, resolved_outputs):
        if resolved == combined_target:
            continue
        csv_file.unlink(missing_ok=True)
        removed += 1
    print(f"Removed {removed} intermediate CSV files")


if __name__ == "__main__":
    main()
