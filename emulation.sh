#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
MEDIA_PATH="${MEDIA_PATH:-${ROOT_DIR}/src/emulation/Second_720p.mp4}"
PCAP_PATH="${PCAP_PATH:-${ROOT_DIR}/results/emulation/stream_capture.pcap}"
VERBOSE_FLAG="${VERBOSE_EMULATION:-0}"

mkdir -p "${ROOT_DIR}/results/emulation"

cmd=(sudo "${PYTHON_BIN}" "${ROOT_DIR}/src/emulation/switch.py"
  --media "${MEDIA_PATH}"
  --pcap "${PCAP_PATH}"
  --python-bin "${PYTHON_BIN}")

if [[ "${VERBOSE_FLAG}" != "0" ]]; then
  cmd+=("--verbose")
fi

if [[ "$#" -gt 0 ]]; then
  cmd+=("$@")
fi

echo "Executing emulation pipeline:"
printf '  %q' "${cmd[@]}"
printf '\n'

"${cmd[@]}"
