"""
Minimal streaming sender for the Mininet emulation setup.
It serves an MP4 file packet-by-packet to a single authorised receiver.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import signal
import struct
import sys
import time
from fractions import Fraction
from pathlib import Path
from typing import Callable, Iterable, Optional, Tuple

LENGTH_HEADER_STRUCT = struct.Struct("!I")
PROGRESS_INTERVAL = 1.0


def _validate_mininet_address(address: str, role: str) -> None:
    if not address.startswith("10.0.0."):
        raise ValueError(f"{role} must be within the Mininet 10.0.0.0/24 subnet, got {address!r}")


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stream a single MP4 file to the Mininet receiver.")
    parser.add_argument("--host", default="10.0.0.1", help="Sender IP inside Mininet (default: 10.0.0.1).")
    parser.add_argument("--port", type=int, default=9000, help="TCP port to bind (default: 9000).")
    parser.add_argument(
        "--allowed-client",
        default="10.0.0.2",
        help="Receiver IP inside Mininet allowed to connect (default: 10.0.0.2).",
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("src/emulation/Song_720.mp4"),
        help="MP4 file to stream (default: src/emulation/Song_720.mp4).",
    )
    parser.add_argument("--verbose", action="store_true", help="Print debug information.")
    return parser.parse_args(argv)


class VideoPacketIterator:
    """Provides encoded video packets from the source file."""

    def __init__(self, source: Path):
        try:
            import av  # type: ignore
        except ImportError as exc:  # pragma: no cover - runtime import guard
            raise RuntimeError("Install 'av' (PyAV) to stream video files.") from exc

        self._av = av
        self._container = av.open(str(source))
        video_streams = [stream for stream in self._container.streams if stream.type == "video"]
        if not video_streams:
            raise RuntimeError(f"No video stream found in {source}")
        self._stream = video_streams[0]
        self._stream.thread_type = "AUTO"
        self._first_pts = None
        self._source = source

    def stream_info(self) -> dict:
        codec = self._stream.codec_context
        avg_rate = self._stream.average_rate
        time_base = self._stream.time_base
        extradata = codec.extradata or b""
        return {
            "codec_name": codec.name,
            "width": codec.width,
            "height": codec.height,
            "bit_rate": codec.bit_rate,
            "time_base": [time_base.numerator, time_base.denominator] if time_base else None,
            "avg_rate": [avg_rate.numerator, avg_rate.denominator] if avg_rate else None,
            "extradata": base64.b64encode(extradata).decode("ascii") if extradata else None,
            "path": str(self._source),
        }

    def packets(self) -> Iterable[Tuple[dict, bytes]]:
        for packet in self._container.demux(self._stream):
            if packet.size <= 0:
                continue
            if self._first_pts is None and packet.pts is not None:
                self._first_pts = packet.pts
            payload = bytes(packet)
            packet_time_base = packet.time_base or self._stream.time_base or Fraction(1, 30)
            header = {
                "kind": "video_packet",
                "pts": packet.pts,
                "dts": packet.dts,
                "duration": packet.duration,
                "time_base": [packet_time_base.numerator, packet_time_base.denominator],
                "is_keyframe": bool(packet.is_keyframe),
            }
            yield header, payload

    def relative_delay(self, header: dict) -> Optional[float]:
        pts = header.get("pts")
        time_base_values = header.get("time_base")
        if pts is None or self._first_pts is None or not time_base_values:
            return None
        time_base = Fraction(time_base_values[0], time_base_values[1])
        return float((pts - self._first_pts) * time_base)

    def close(self) -> None:
        self._container.close()


async def stream_binary(
    writer: asyncio.StreamWriter,
    source: Path,
    chunk_size: int,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Tuple[int, int]:
    total_chunks = 0
    total_bytes = 0
    with source.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            header = {"kind": "binary_chunk", "seq": total_chunks}
            header_bytes = json.dumps(header).encode("utf-8")
            writer.write(LENGTH_HEADER_STRUCT.pack(len(header_bytes)))
            writer.write(header_bytes)
            writer.write(LENGTH_HEADER_STRUCT.pack(len(chunk)))
            writer.write(chunk)
            await writer.drain()
            total_chunks += 1
            total_bytes += len(chunk)
            if progress_cb:
                progress_cb(total_bytes, total_chunks)
    return total_chunks, total_bytes


async def stream_session(writer: asyncio.StreamWriter, args: argparse.Namespace) -> None:
    mode = "video"
    iterator: Optional[VideoPacketIterator] = None
    metadata = {"source_path": str(args.source)}
    source_size = args.source.stat().st_size if args.source.exists() else 0
    try:
        iterator = VideoPacketIterator(args.source)
        metadata["payload_mode"] = "video"
        metadata["video_stream"] = iterator.stream_info()
    except RuntimeError as exc:
        mode = "binary"
        metadata["payload_mode"] = "binary"
        metadata["note"] = str(exc)

    writer.write(json.dumps(metadata).encode("utf-8") + b"\n")
    await writer.drain()

    if mode == "video" and iterator:
        start_wall = time.perf_counter()
        last_progress = start_wall
        packets_sent = 0
        total_bytes = 0

        def log_progress(total_bytes_sent: int, units: int, *, force: bool = False) -> None:
            nonlocal last_progress
            now = time.perf_counter()
            if not force and (now - last_progress) < PROGRESS_INTERVAL:
                return
            elapsed = max(now - start_wall, 1e-9)
            percent = None
            remaining = None
            if source_size > 0:
                percent = min((total_bytes_sent / source_size) * 100, 100.0)
                remaining = max(source_size - total_bytes_sent, 0)
            rate_mbps = (total_bytes_sent * 8) / (elapsed * 1_000_000)
            message = (
                f"[progress] video mode: {units} packets, {total_bytes_sent} bytes sent "
                f"(avg {rate_mbps:.2f} Mbps)"
            )
            if percent is not None and remaining is not None:
                message += f", {percent:.1f}% complete, {remaining} bytes remaining"
            print(message, file=sys.stderr)
            last_progress = now

        try:
            for header, payload in iterator.packets():
                header_bytes = json.dumps(header).encode("utf-8")
                writer.write(LENGTH_HEADER_STRUCT.pack(len(header_bytes)))
                writer.write(header_bytes)
                writer.write(LENGTH_HEADER_STRUCT.pack(len(payload)))
                writer.write(payload)
                await writer.drain()

                packets_sent += 1
                total_bytes += len(payload)
                log_progress(total_bytes, packets_sent)
                delay_target = iterator.relative_delay(header)
                if delay_target is not None:
                    elapsed = time.perf_counter() - start_wall
                    remaining = delay_target - elapsed
                    if remaining > 0:
                        await asyncio.sleep(remaining)
        finally:
            iterator.close()

        log_progress(total_bytes, packets_sent, force=True)
        elapsed = max(time.perf_counter() - start_wall, 1e-9)
        rate_mbps = (total_bytes * 8) / (elapsed * 1_000_000)
        percent = min((total_bytes / source_size) * 100, 100.0) if source_size > 0 else None
        summary = (
            f"Sender complete: {packets_sent} packets, {total_bytes} bytes in {elapsed:.2f}s "
            f"(avg {rate_mbps:.2f} Mbps)"
        )
        if percent is not None:
            summary += f", {percent:.1f}% of source"
        print(summary, flush=True)
        if args.verbose:
            print(f"Completed streaming {packets_sent} packets from {args.source}", file=sys.stderr)
    else:
        start_wall = time.perf_counter()
        last_progress = start_wall

        def log_progress(total_bytes_sent: int, units: int, *, force: bool = False) -> None:
            nonlocal last_progress
            now = time.perf_counter()
            if not force and (now - last_progress) < PROGRESS_INTERVAL:
                return
            elapsed = max(now - start_wall, 1e-9)
            percent = None
            remaining = None
            if source_size > 0:
                percent = min((total_bytes_sent / source_size) * 100, 100.0)
                remaining = max(source_size - total_bytes_sent, 0)
            rate_mbps = (total_bytes_sent * 8) / (elapsed * 1_000_000)
            message = (
                f"[progress] binary mode: {units} chunks, {total_bytes_sent} bytes sent "
                f"(avg {rate_mbps:.2f} Mbps)"
            )
            if percent is not None and remaining is not None:
                message += f", {percent:.1f}% complete, {remaining} bytes remaining"
            print(message, file=sys.stderr)
            last_progress = now

        chunks, total_bytes = await stream_binary(
            writer,
            args.source,
            chunk_size=65536,
            progress_cb=lambda total_bytes_sent, units: log_progress(total_bytes_sent, units),
        )
        log_progress(total_bytes, chunks, force=True)
        elapsed = max(time.perf_counter() - start_wall, 1e-9)
        rate_mbps = (total_bytes * 8) / (elapsed * 1_000_000)
        percent = min((total_bytes / source_size) * 100, 100.0) if source_size > 0 else None
        summary = (
            f"Sender complete: {chunks} chunks, {total_bytes} bytes in {elapsed:.2f}s "
            f"(avg {rate_mbps:.2f} Mbps)"
        )
        if percent is not None:
            summary += f", {percent:.1f}% of source"
        print(summary, flush=True)
        if args.verbose:
            print(f"Completed fallback streaming ({chunks} chunks) from {args.source}", file=sys.stderr)

    writer.write(LENGTH_HEADER_STRUCT.pack(0))
    try:
        await writer.drain()
    except ConnectionResetError:
        pass
    writer.close()
    await writer.wait_closed()


async def run_server(args: argparse.Namespace) -> None:
    _validate_mininet_address(args.host, "Sender bind address")
    _validate_mininet_address(args.allowed_client, "Allowed client")

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    for signame in ("SIGINT", "SIGTERM"):
        if hasattr(signal, signame):
            loop.add_signal_handler(getattr(signal, signame), stop_event.set)

    async def client_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        if not peer:
            writer.close()
            await writer.wait_closed()
            return
        client_ip = peer[0]
        if client_ip != args.allowed_client:
            if args.verbose:
                print(f"Connection attempt from {client_ip} rejected.", file=sys.stderr)
            writer.close()
            await writer.wait_closed()
            return
        await stream_session(writer, args)
        stop_event.set()

    server = await asyncio.start_server(client_handler, args.host, args.port)
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"Sender listening on {sockets}, serving {args.source}")

    async with server:
        await stop_event.wait()
        server.close()
        await server.wait_closed()


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    if not args.source.exists():
        print(f"Source {args.source} not found.", file=sys.stderr)
        return 2
    try:
        asyncio.run(run_server(args))
    except KeyboardInterrupt:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
