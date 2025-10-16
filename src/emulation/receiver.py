"""
Simple receiver that records the streamed file verbatim and reports progress.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import struct
import sys
import time
from pathlib import Path
from typing import Optional


LENGTH_STRUCT = struct.Struct("!I")
PROGRESS_INTERVAL = 1.0


def _validate_mininet_ip(address: str, role: str) -> None:
    if not address.startswith("10.0.0."):
        raise ValueError(f"{role} must be within the Mininet 10.0.0.0/24 subnet (got {address!r})")


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Receive the chunked stream inside Mininet.")
    parser.add_argument("--host", default="10.0.0.1", help="Sender IP (default 10.0.0.1)")
    parser.add_argument("--port", type=int, default=9000, help="Sender port (default 9000)")
    parser.add_argument("--local-ip", default="10.0.0.2", help="Receiver IP (default 10.0.0.2)")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/emulation/received_payload.bin"),
        help="Destination file (default results/emulation/received_payload.bin)",
    )
    parser.add_argument("--verbose", action="store_true", help="Print progress while receiving")
    return parser.parse_args(argv)


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


async def receive(args: argparse.Namespace) -> None:
    reader, writer = await asyncio.open_connection(args.host, args.port, local_addr=(args.local_ip, 0))
    metadata_line = await reader.readline()
    if not metadata_line:
        raise RuntimeError("Sender closed before metadata arrived")
    metadata = json.loads(metadata_line.decode("utf-8"))
    if metadata.get("payload_mode") != "binary":
        raise RuntimeError(f"Unexpected payload mode {metadata.get('payload_mode')} from sender")

    file_size = metadata.get("file_size", 0)
    source_name = metadata.get("source_name")
    if args.output == Path("results/emulation/received_payload.bin") and source_name:
        output_path = Path("results/emulation") / source_name
    else:
        output_path = args.output

    ensure_parent(output_path)
    out_handle = output_path.open("wb")

    total_bytes = 0
    total_chunks = 0
    start_ts = time.perf_counter()
    last_report = start_ts

    try:
        while True:
            header_len_bytes = await reader.readexactly(LENGTH_STRUCT.size)
            header_len = LENGTH_STRUCT.unpack(header_len_bytes)[0]
            if header_len == 0:
                break
            await reader.readexactly(header_len)  # header not used currently

            payload_len = LENGTH_STRUCT.unpack(await reader.readexactly(LENGTH_STRUCT.size))[0]
            payload = await reader.readexactly(payload_len)

            out_handle.write(payload)
            total_chunks += 1
            total_bytes += payload_len

            now = time.perf_counter()
            if args.verbose and (now - last_report) >= PROGRESS_INTERVAL:
                elapsed = max(now - start_ts, 1e-9)
                percent = min((total_bytes / file_size) * 100, 100.0) if file_size else None
                remaining = max(file_size - total_bytes, 0) if file_size else None
                rate_mbps = (total_bytes * 8) / (elapsed * 1_000_000)
                msg = (
                    f"[progress] receiver: {total_chunks} chunks, {total_bytes} bytes received "
                    f"(avg {rate_mbps:.2f} Mbps)"
                )
                if percent is not None and remaining is not None:
                    msg += f", {percent:.1f}% complete, {remaining} bytes remaining"
                print(msg, file=sys.stderr)
                last_report = now
    finally:
        out_handle.close()
        writer.close()
        await writer.wait_closed()

    elapsed = max(time.perf_counter() - start_ts, 1e-9)
    rate_mbps = (total_bytes * 8) / (elapsed * 1_000_000)
    percent = min((total_bytes / file_size) * 100, 100.0) if file_size else None
    summary = (
        f"Receiver complete: {total_chunks} chunks, {total_bytes} bytes in {elapsed:.2f}s "
        f"(avg {rate_mbps:.2f} Mbps) -> {output_path}"
    )
    if percent is not None:
        summary += f", {percent:.1f}% of expected"
    print(summary)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    _validate_mininet_ip(args.host, "Sender host")
    _validate_mininet_ip(args.local_ip, "Local host")
    try:
        asyncio.run(receive(args))
    except KeyboardInterrupt:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
