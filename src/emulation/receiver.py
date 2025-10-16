"""
Minimal receiver that connects through the Mininet switch and rebuilds the streamed MP4 file.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import struct
import sys
import time
from fractions import Fraction
from pathlib import Path
from typing import Optional

LENGTH_HEADER_STRUCT = struct.Struct("!I")
PROGRESS_INTERVAL = 1.0


def _validate_mininet_address(address: str, role: str) -> None:
    if not address.startswith("10.0.0."):
        raise ValueError(f"{role} must be within the Mininet 10.0.0.0/24 subnet, got {address!r}")


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Receive an MP4 stream inside the Mininet topology.")
    parser.add_argument("--host", default="10.0.0.1", help="Sender IP inside Mininet (default: 10.0.0.1).")
    parser.add_argument("--port", type=int, default=9000, help="Sender port (default: 9000).")
    parser.add_argument("--local-ip", default="10.0.0.2", help="Local Mininet IP (default: 10.0.0.2).")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/emulation/received_video.mp4"),
        help="Where to store the reconstructed MP4 (default: results/emulation/received_video.mp4).",
    )
    return parser.parse_args(argv)


class VideoAssembler:
    """Decode received packets and write them into an MP4 container."""

    def __init__(self, metadata: dict, output_path: Path):
        try:
            import av  # type: ignore
        except ImportError as exc:  # pragma: no cover - runtime import guard
            raise RuntimeError("Install 'av' (PyAV) to receive video streams.") from exc

        self._av = av
        video_info = metadata["video_stream"]
        ensure_parent(output_path)
        self._container = av.open(str(output_path), mode="w")

        codec_name = video_info["codec_name"]
        avg_rate = video_info.get("avg_rate")
        rate = Fraction(avg_rate[0], avg_rate[1]) if avg_rate else Fraction(30, 1)

        self._decoder = av.CodecContext.create(codec_name, "r")
        extradata_b64 = video_info.get("extradata")
        if extradata_b64:
            self._decoder.extradata = base64.b64decode(extradata_b64)

        self._stream = self._container.add_stream("libx264", rate=rate)
        self._stream.width = video_info.get("width") or 1280
        self._stream.height = video_info.get("height") or 720
        self._stream.pix_fmt = "yuv420p"

    def consume(self, header: dict, payload: bytes) -> None:
        packet = self._av.packet.Packet(payload)
        tb = header.get("time_base")
        if tb:
            packet.time_base = Fraction(tb[0], tb[1])
        packet.pts = header.get("pts")
        packet.dts = header.get("dts")
        packet_duration = header.get("duration")

        for frame in self._decoder.decode(packet):
            frame = frame.reformat(format="yuv420p")
            for encoded in self._stream.encode(frame):
                self._container.mux(encoded)

    def finalize(self) -> None:
        for encoded in self._stream.encode(None):
            self._container.mux(encoded)
        self._container.close()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


async def receive(args: argparse.Namespace) -> None:
    reader, writer = await asyncio.open_connection(args.host, args.port, local_addr=(args.local_ip, 0))
    metadata_line = await reader.readline()
    if not metadata_line:
        raise RuntimeError("Sender closed before metadata was sent.")
    metadata = json.loads(metadata_line.decode("utf-8"))
    mode = metadata.get("payload_mode", "binary")
    assembler: Optional[VideoAssembler] = None
    output_handle: Optional[object] = None

    source_path = metadata.get("source_path")
    source_size = Path(source_path).stat().st_size if source_path and Path(source_path).exists() else 0
    total_bytes = 0
    total_units = 0
    start_ts = time.perf_counter()
    last_report = start_ts

    if mode == "video":
        assembler = VideoAssembler(metadata, args.output)
    else:
        ensure_parent(args.output)
        output_handle = args.output.open("wb")
        if metadata.get("note"):
            print(f"Receiver note: {metadata['note']}", file=sys.stderr)

    def report_progress(force: bool = False) -> None:
        nonlocal last_report
        now = time.perf_counter()
        if not force and (now - last_report) < PROGRESS_INTERVAL:
            return
        elapsed = max(now - start_ts, 1e-9)
        percent = None
        remaining = None
        if source_size > 0:
            percent = min((total_bytes / source_size) * 100, 100.0)
            remaining = max(source_size - total_bytes, 0)
        rate_mbps = (total_bytes * 8) / (elapsed * 1_000_000)
        label = "packets" if mode == "video" else "chunks"
        message = (
            f"[progress] receiver: {total_units} {label}, {total_bytes} bytes received "
            f"(avg {rate_mbps:.2f} Mbps)"
        )
        if percent is not None and remaining is not None:
            message += f", {percent:.1f}% complete, {remaining} bytes remaining"
        print(message, file=sys.stderr)
        last_report = now

    try:
        while True:
            header_len_bytes = await reader.readexactly(LENGTH_HEADER_STRUCT.size)
            header_len = LENGTH_HEADER_STRUCT.unpack(header_len_bytes)[0]
            if header_len == 0:
                break

            header = json.loads((await reader.readexactly(header_len)).decode("utf-8"))
            payload_len = LENGTH_HEADER_STRUCT.unpack(await reader.readexactly(LENGTH_HEADER_STRUCT.size))[0]
            payload = await reader.readexactly(payload_len)
            total_units += 1
            total_bytes += payload_len

            if assembler:
                assembler.consume(header, payload)
            elif output_handle:
                output_handle.write(payload)
            report_progress()
    finally:
        if assembler:
            assembler.finalize()
        if output_handle:
            output_handle.close()
        writer.close()
        await writer.wait_closed()

    report_progress(force=True)
    elapsed = max(time.perf_counter() - start_ts, 1e-9)
    rate_mbps = (total_bytes * 8) / (elapsed * 1_000_000)
    label = "packets" if mode == "video" else "chunks"
    print(
        f"Receiver complete: {total_units} {label}, {total_bytes} bytes in {elapsed:.2f}s "
        f"(avg {rate_mbps:.2f} Mbps). Output -> {args.output}"
    )


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    _validate_mininet_address(args.host, "Sender host")
    _validate_mininet_address(args.local_ip, "Local host")
    try:
        asyncio.run(receive(args))
    except KeyboardInterrupt:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
