"""Batch apply recommended obfuscation bundles to a tree of PCAP files.

This script walks an input dataset (e.g., dataset/VPN&NonVPN) and, for every
PCAP/PCAPNG file, invokes ``pcap_transformer.py`` with the category-derived
recommended feature set. The transformed captures are written to an output
root while preserving the original directory structure.

Usage example:

    python3 src/mimicaryModel/batch_apply_recommended.py \
        --input-root dataset/VPN\&NonVPN \
        --output-root dataset/Modified/VPN\&NonVPN \
        --metrics

The script relies on the category names present in ``dataset/VPN&NonVPN``.
If you add new sub-folders, extend ``CATEGORY_MAP`` accordingly.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, Optional, Sequence, Tuple


# Maps (top-level, sub-category) directories to feature category labels used in
# categorized_feature_patterns.json. Update if you introduce new traffic types.
CATEGORY_MAP: Dict[Tuple[str, str], str] = {
    ("VPN", "Chat"): "VPN-Chat",
    ("VPN", "Command&Control"): "VPN-Command&Control",
    ("VPN", "FileTransfer"): "VPN-FileTransfer",
    ("VPN", "Streaming"): "VPN-Streaming",
    ("VPN", "VoIP"): "VPN-VoIP",
    ("NonVPN", "Chat"): "NonVPN-Chat",
    ("NonVPN", "Command&Control"): "NonVPN-Command&Control",
    ("NonVPN", "FileTransfer"): "NonVPN-FileTransfer",
    ("NonVPN", "Streaming"): "NonVPN-Streaming",
    ("NonVPN", "VoIP"): "NonVPN-VoIP",
}


def iter_pcaps(root: Path, patterns: Sequence[str]) -> Iterable[Path]:
    for pattern in patterns:
        yield from root.rglob(pattern)


def resolve_category(rel_path: Path) -> Optional[str]:
    parts = rel_path.parts
    if len(parts) >= 2:
        key = (parts[0], parts[1])
        return CATEGORY_MAP.get(key)
    return None


def build_command(
    transformer: Path,
    input_file: Path,
    output_file: Path,
    category: str,
    *,
    category_config: Optional[Path],
    seed: int,
    include_metrics: bool,
) -> Sequence[str]:
    cmd = [
        sys.executable,
        str(transformer),
        str(input_file),
        str(output_file),
        "--category",
        category,
        "--apply-recommended",
        "--seed",
        str(seed),
    ]
    if category_config is not None:
        cmd.extend(["--category-config", str(category_config)])
    if include_metrics:
        cmd.append("--metrics")
    return cmd


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Batch-apply recommended mimicry transformations to PCAP datasets.",
    )
    parser.add_argument(
        "--input-root",
        type=Path,
        default=Path("dataset") / "VPN&NonVPN",
        help="Root directory that contains source PCAP files",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("dataset") / "Modified" / "VPN&NonVPN",
        help="Destination root for transformed PCAPs (structure is preserved)",
    )
    parser.add_argument(
        "--category-config",
        type=Path,
        default=None,
        help="Optional override for categorized_feature_patterns.json",
    )
    parser.add_argument(
        "--patterns",
        nargs="*",
        default=["*.pcap", "*.pcapng"],
        help="Glob patterns to match PCAP files",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process at most this many PCAPs (useful for sampling large captures)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1337,
        help="Random seed forwarded to the transformer",
    )
    parser.add_argument(
        "--metrics",
        action="store_true",
        help="Pass --metrics to the transformer for before/after telemetry",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the commands that would run without executing them",
    )

    args = parser.parse_args()

    input_root: Path = args.input_root.resolve()
    output_root: Path = args.output_root.resolve()
    transformer = Path(__file__).resolve().parent / "pcap_transformer.py"

    if not input_root.exists():
        parser.error(f"Input root does not exist: {input_root}")

    output_root.mkdir(parents=True, exist_ok=True)

    category_config_path: Optional[Path] = None
    if args.category_config is not None:
        category_config_path = args.category_config.expanduser().resolve()
        if not category_config_path.exists():
            parser.error(f"Category config not found: {category_config_path}")

    pcaps = sorted(iter_pcaps(input_root, args.patterns))
    if args.limit is not None:
        if args.limit < 0:
            parser.error("--limit must be non-negative")
        if args.limit == 0:
            print("--limit set to 0; nothing to do")
            return
        pcaps = pcaps[: args.limit]
    if not pcaps:
        print(f"No PCAPs found under {input_root}")
        return

    for pcap in pcaps:
        rel = pcap.relative_to(input_root)
        category = resolve_category(rel)
        if category is None:
            print(f"Skipping {pcap}: no category mapping for {rel.parts[:2]}")
            continue

        destination = output_root / rel
        destination.parent.mkdir(parents=True, exist_ok=True)

        cmd = build_command(
            transformer,
            pcap,
            destination,
            category,
            category_config=category_config_path,
            seed=args.seed,
            include_metrics=args.metrics,
        )

        if args.dry_run:
            print("DRY-RUN:", " ".join(cmd))
            continue

        print(f"Processing {pcap} -> {destination} (category: {category})")
        result = subprocess.run(cmd, capture_output=False)
        if result.returncode != 0:
            print(f"  Transformer failed with exit code {result.returncode}")


if __name__ == "__main__":
    main()
