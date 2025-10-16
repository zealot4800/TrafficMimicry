"""
Minimal Mininet harness that connects the sender and receiver through a single switch
and captures the exchanged traffic into a PCAP file.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, Optional


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

    results_dir = Path("results/emulation").resolve()
    results_dir.mkdir(parents=True, exist_ok=True)

    sender_cmd = [
        args.python_bin,
        str(sender_script),
        "--source",
        str(args.media.resolve()),
        "--chunk-size",
        "1450",
    ]
    receiver_output = (results_dir / args.media.name) if args.media else (results_dir / "received_payload.bin")
    receiver_cmd = [
        args.python_bin,
        str(receiver_script),
        "--output",
        str(receiver_output.resolve()),
    ]
    if args.verbose:
        sender_cmd.append("--verbose")
        receiver_cmd.append("--verbose")

    sender_log = results_dir / "sender.log"
    receiver_log = results_dir / "receiver.log"
    tcpdump_log_path = results_dir / "tcpdump.log"

    for path in (sender_log, receiver_log, tcpdump_log_path):
        _ensure_parent(path)

    tcpdump_handle: Optional[object] = None
    sender_handle: Optional[object] = None
    receiver_handle: Optional[object] = None

    capture = sender_process = receiver_process = None

    try:
        if not args.verbose:
            tcpdump_handle = tcpdump_log_path.open("w")
        
        capture_cmd = [
            "sh",
            "-c",
            " ".join([
                "tcpdump",
                "-l",
                "-q",
                "-U",
                "-n",
                "-i",
                sniff_intf,
                "-w",
                str(args.pcap.resolve()),
                "-s",
                "1500",
                "tcp",
                "port",
                "9000",
            ]) + " 2>/dev/null"
        ]
        
        capture = receiver.popen(
            capture_cmd,
            stdout=tcpdump_handle if tcpdump_handle else subprocess.DEVNULL,
            stderr=tcpdump_handle if tcpdump_handle else subprocess.DEVNULL,
        )

        if args.verbose:
            sender_process = sender.popen(sender_cmd)
        else:
            sender_handle = sender_log.open("w")
            sender_process = sender.popen(
                sender_cmd,
                stdout=sender_handle,
                stderr=subprocess.STDOUT,
            )

        time.sleep(1.0)

        if args.verbose:
            receiver_process = receiver.popen(receiver_cmd)
        else:
            receiver_handle = receiver_log.open("w")
            receiver_process = receiver.popen(
                receiver_cmd,
                stdout=receiver_handle,
                stderr=subprocess.STDOUT,
            )

        receiver_process.wait()

        _terminate(sender_process)
        _terminate(capture, sig=signal.SIGINT)

        if sender_process:
            try:
                sender_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _terminate(sender_process, sig=signal.SIGKILL)

        if capture:
            try:
                capture.wait(timeout=10)
            except subprocess.TimeoutExpired:
                _terminate(capture, sig=signal.SIGKILL)

        time.sleep(0.5)
    finally:
        for handle in (tcpdump_handle, sender_handle, receiver_handle):
            if handle:
                handle.close()
        net.stop()

    pcap_path = args.pcap.resolve()
    if pcap_path.exists():
        target_uid = int(os.environ.get("SUDO_UID", os.getuid()))
        target_gid = int(os.environ.get("SUDO_GID", os.getgid()))
        for path in (pcap_path, sender_log, receiver_log, tcpdump_log_path, receiver_output):
            try:
                if Path(path).exists():
                    os.chown(path, target_uid, target_gid)
            except PermissionError:
                pass
        print(f"PCAP stored at {pcap_path}")
    else:
        hint = (
            f"tcpdump did not create {pcap_path}. Check {tcpdump_log_path} for errors "
            "and ensure the capture interface is correct."
        )
        print(hint, file=sys.stderr)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    launch(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
