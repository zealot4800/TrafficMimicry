"""
Minimal Mininet harness that connects the sender and receiver through a single switch
and captures the exchanged traffic into a PCAP file.
"""

from __future__ import annotations

import argparse
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, List, Optional


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Launch the emulation switch with sender and receiver hosts.")
    parser.add_argument(
        "--media",
        type=Path,
        default=Path("src/emulation/Song_720.mp4"),
        help="Media file streamed by the sender (default: src/emulation/Song_720.mp4).",
    )
    parser.add_argument(
        "--pcap",
        type=Path,
        default=Path("results/emulation/stream_capture.pcap"),
        help="PCAP output file (default: results/emulation/stream_capture.pcap).",
    )
    parser.add_argument(
        "--python-bin",
        default=sys.executable,
        help="Python interpreter used inside Mininet hosts (default: current interpreter).",
    )
    parser.add_argument("--verbose", action="store_true", help="Show sender/receiver stdout.")
    return parser.parse_args(argv)


def _import_mininet() -> None:
    try:
        import mininet 
    except ImportError as exc:  
        raise SystemExit("Mininet must be installed to run this script.") from exc


def _build_command(parts: List[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _terminate(proc: Optional[subprocess.Popen], sig: int = signal.SIGTERM) -> None:
    if proc is None:
        return
    if proc.poll() is None:
        try:
            proc.send_signal(sig)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        except (ProcessLookupError, PermissionError):
            pass


def launch(args: argparse.Namespace) -> None:
    _import_mininet()

    from mininet.clean import cleanup
    from mininet.link import TCLink
    from mininet.log import setLogLevel
    from mininet.net import Mininet
    from mininet.node import Controller, OVSSwitch

    setLogLevel("info" if args.verbose else "warning")
    cleanup()

    net = Mininet(controller=Controller, switch=OVSSwitch, link=TCLink, autoSetMacs=True, autoStaticArp=True)
    controller = net.addController("c0")
    switch = net.addSwitch("s1")
    sender = net.addHost("sender", ip="10.0.0.1/24")
    receiver = net.addHost("receiver", ip="10.0.0.2/24")
    net.addLink(sender, switch)
    net.addLink(receiver, switch)

    net.build()
    net.start()

    sender_ip = sender.IP()
    receiver_ip = receiver.IP()

    sniff_intf = "receiver-eth0"

    sender_script = Path(__file__).with_name("sender.py").resolve()
    receiver_script = Path(__file__).with_name("receiver.py").resolve()
    if not sender_script.exists() or not receiver_script.exists():
        raise FileNotFoundError("sender.py or receiver.py not found in the emulation directory.")

    _ensure_parent(args.pcap.resolve())

    sender_cmd = [
        args.python_bin,
        str(sender_script),
        "--source",
        str(args.media.resolve()),
        "--verbose",
    ]
    receiver_cmd = [
        args.python_bin,
        str(receiver_script),
        "--output",
        str(Path("results/emulation/received_video.mp4").resolve()),
    ]

    sender_log = Path("results/emulation/sender.log").resolve()
    receiver_log = Path("results/emulation/receiver.log").resolve()
    tcpdump_log_path = Path("results/emulation/tcpdump.log").resolve()

    for path in (sender_log, receiver_log, tcpdump_log_path):
        _ensure_parent(path)

    tcpdump_handle: Optional[object] = None

    capture = sender_process = receiver_process = None

    try:
        if not args.verbose:
            tcpdump_handle = tcpdump_log_path.open("w")
        capture_cmd = _build_command(
            [
                "tcpdump",
                "-U",
                "-n",
                "-i",
                sniff_intf,
                "-w",
                str(args.pcap.resolve()),
                "tcp",
                "port",
                "9000",
            ]
        )
        capture = receiver.popen(
            capture_cmd,
            stdout=None if args.verbose else tcpdump_handle,
            stderr=subprocess.STDOUT if not args.verbose else None,
        )

        sender_exec = _build_command(sender_cmd)
        if args.verbose:
            sender_process = sender.popen(sender_exec)
        else:
            sender_process = sender.popen(f"{sender_exec} 2>&1 | tee {shlex.quote(str(sender_log))}")

        time.sleep(1.0)

        receiver_exec = _build_command(receiver_cmd)
        if args.verbose:
            receiver_process = receiver.popen(receiver_exec)
        else:
            receiver_process = receiver.popen(f"{receiver_exec} 2>&1 | tee {shlex.quote(str(receiver_log))}")

        receiver_process.wait()
        _terminate(sender_process)
        _terminate(capture, sig=signal.SIGINT)
    finally:
        if tcpdump_handle:
            tcpdump_handle.close()
        net.stop()

    pcap_path = args.pcap.resolve()
    if not pcap_path.exists():
        hint = (
            f"tcpdump did not create {pcap_path}. Check {tcpdump_log_path} for errors "
            "and ensure the capture interface is correct."
        )
        print(hint, file=sys.stderr)
    else:
        print(f"PCAP stored at {pcap_path}")


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    launch(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
