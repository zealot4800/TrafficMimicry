"""
Simple chunked sender for the Mininet emulation setup.
Streams the source file verbatim with periodic progress reporting.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
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
    parser = argparse.ArgumentParser(description="Stream a file to the receiver host inside Mininet.")
    parser.add_argument("--host", default="10.0.0.1", help="Sender host IP (default 10.0.0.1)")
    parser.add_argument("--port", type=int, default=9000, help="Sender listening port (default 9000)")
    parser.add_argument(
        "--allowed-client",
        default="10.0.0.2",
        help="Receiver IP permitted to connect (default 10.0.0.2)",
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("src/emulation/Song_720.mp4"),
        help="File to stream (default src/emulation/Song_720.mp4)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=1450,
        help="Chunk size in bytes (default 1450, accounting for TCP/IP headers)",
    )
    parser.add_argument("--verbose", action="store_true", help="Print verbose information")
    return parser.parse_args(argv)


async def stream_file(writer: asyncio.StreamWriter, source: Path, chunk_size: int, verbose: bool) -> None:
    file_size = source.stat().st_size
    sent_bytes = 0
    sent_chunks = 0
    start_ts = time.perf_counter()
    last_report = start_ts

    metadata = {
        "payload_mode": "binary",
        "source_name": source.name,
        "file_size": file_size,
        "chunk_size": chunk_size,
    }
    writer.write(json.dumps(metadata).encode("utf-8") + b"\n")
    await writer.drain()

    with source.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break

            header = {"kind": "binary_chunk", "seq": sent_chunks}
            header_bytes = json.dumps(header).encode("utf-8")

            writer.write(LENGTH_STRUCT.pack(len(header_bytes)))
            writer.write(header_bytes)
            writer.write(LENGTH_STRUCT.pack(len(chunk)))
            writer.write(chunk)
            await writer.drain()

            sent_chunks += 1
            sent_bytes += len(chunk)

            now = time.perf_counter()
            if verbose and (now - last_report) >= PROGRESS_INTERVAL:
                elapsed = max(now - start_ts, 1e-9)
                percent = min((sent_bytes / file_size) * 100, 100.0) if file_size else None
                remaining = max(file_size - sent_bytes, 0) if file_size else None
                rate_mbps = (sent_bytes * 8) / (elapsed * 1_000_000)
                msg = (
                    f"[progress] sender: {sent_chunks} chunks, {sent_bytes} bytes sent "
                    f"(avg {rate_mbps:.2f} Mbps)"
                )
                if percent is not None and remaining is not None:
                    msg += f", {percent:.1f}% complete, {remaining} bytes remaining"
                print(msg, file=sys.stderr)
                last_report = now

    writer.write(LENGTH_STRUCT.pack(0))
    try:
        await writer.drain()
    except ConnectionResetError:
        pass
    writer.close()
    await writer.wait_closed()

    elapsed = max(time.perf_counter() - start_ts, 1e-9)
    rate_mbps = (sent_bytes * 8) / (elapsed * 1_000_000)
    percent = min((sent_bytes / file_size) * 100, 100.0) if file_size else None
    summary = (
        f"Sender complete: {sent_chunks} chunks, {sent_bytes} bytes in {elapsed:.2f}s "
        f"(avg {rate_mbps:.2f} Mbps)"
    )
    if percent is not None:
        summary += f", {percent:.1f}% of source"
    print(summary)


async def client_session(args: argparse.Namespace, writer: asyncio.StreamWriter) -> None:
    await stream_file(writer, args.source, args.chunk_size, verbose=args.verbose)


async def run(args: argparse.Namespace) -> None:
    _validate_mininet_ip(args.host, "Sender bind address")
    _validate_mininet_ip(args.allowed_client, "Allowed client")

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    for signame in ("SIGINT", "SIGTERM"):
        if hasattr(signal, signame):
            loop.add_signal_handler(getattr(signal, signame), stop_event.set)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        if not peer:
            writer.close()
            await writer.wait_closed()
            return
        client_ip = peer[0]
        if client_ip != args.allowed_client:
            if args.verbose:
                print(f"Rejecting {client_ip}: not authorised", file=sys.stderr)
            writer.close()
            await writer.wait_closed()
            return
        await client_session(args, writer)
        stop_event.set()

    server = await asyncio.start_server(handle, args.host, args.port)
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"Sender listening on {sockets} | streaming {args.source}")

    async with server:
        await stop_event.wait()
        server.close()
        await server.wait_closed()


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    if not args.source.exists():
        print(f"Source file {args.source} not found", file=sys.stderr)
        return 2
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
