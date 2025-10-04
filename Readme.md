Traffic mimicry toolkit for PCAP experimentation.

Transformations available
- Packet Length & Size: traffic padding, split large payloads, merge small payloads
- Packet counters & ratios: inject dummy packets, rate limiting
- Timing: jitter injection
- Control/header: protocol tunneling (UDP wrapper)
- Port & protocol: port hopping

Workflow guidance
- Work on copies of sensitive captures; original files stay untouched.
- Capture baseline metrics with `pcap_transformer.py --metrics` to lock in SLA guardrails.
- Apply one transformation at a time, validate metrics, then stack additional steps.

Category-driven automation
- Feature weights and recommended bundles live in `src/utils/categorized_feature_patterns.json`.
- Run `pcap_transformer.py` with `--category <label> --apply-recommended` to apply the suggested obfuscation set for that traffic type.
- Override the lookup file with `--category-config <path>` if you maintain custom weights.

Usage example
```
python3 src/mimicaryModel/pcap_transformer.py \
    src/mimicaryModel/nonvpn_skype-chat_capture1.pcap \
    src/mimicaryModel/nonvpn_skype-chat_capture1_mimic.pcap \
    --traffic-padding 600 \
    --split-chunk-size 800 \
    --combine-max-payload 200 --combine-window 3 \
    --dummy-rate 0.05 --dummy-size 120 \
    --rate-limit 800 \
    --jitter-ms 4 \
    --port-hop 443,8443,9443 \
    --tunnel udp --metrics

# Auto apply recommended feature mix for VPN chat traffic
python3 src/mimicaryModel/pcap_transformer.py \
    dataset/VPN\&NonVPN/VPN/Chat/vpn_skype-chat_capture1.pcap \
    /tmp/vpn_chat_recommended.pcap \
    --category "VPN-Chat" --apply-recommended --metrics

# Batch run across the dataset while preserving folder structure
python3 src/mimicaryModel/batch_apply_recommended.py \
    --input-root dataset/VPN\&NonVPN \
    --output-root dataset/Modified/VPN\&NonVPN \
    --metrics

# Sample only the first few files (useful after splitting a huge capture)
python3 src/mimicaryModel/batch_apply_recommended.py \
    --input-root dataset/VPN\&NonVPN \
    --output-root dataset/Modified/VPN\&NonVPN \
    --patterns "NonVPN/FileTransfer/nonvpn_scp_long_capture1_chunks/*.pcap" \
    --limit 1 --metrics

# Sample to convert the pcap folder into the corresponding csv files
PYTHONPATH=/home/zealot/cicflowmeter/src \
/home/zealot/cicflowmeter/.venv/bin/python scripts/run_cicflowmeter.py \
    --pcap-dir /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified/VPN&NonVPN/NonVPN/Chat \
    --csv-dir /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified/CSV/NON-VPN/Chat \
    --combined-csv /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified/CSV/NON-VPN/Chat_combined.csv \
    --patterns "*.pcap" "*.pcapng"

# Evaluate NonVPN service classifier against a combined CSV
python3 scripts/evaluate_nonvpn_model.py \
    "dataset/Modified/CSV/NON-VPN/Chat/Chat_combined.csv" \
    "src/models/nonvpn_services_model.pkl" \
    --label NonVPN-Chat \
    --output-csv "dataset/Modified/CSV/NON-VPN/Chat/Chat_with_predictions.csv"

```


Validation checklist
- Compare `duration`, `mean_iat`, `stdev_iat`, and `pps` between baseline and transformed outputs.
- Inspect port distribution (`tshark -z endpoints,tcp`, `-z conv,udp`) after port hopping or tunneling.
- Replay transformed PCAP (e.g., `tcpreplay --pps=...`) under monitoring to ensure SLA thresholds remain satisfied.

Implementation notes
- Code lives in `src/mimicaryModel/pcap_transformer.py` and is Scapy-based.
- All checksum-sensitive edits reset IP/TCP/UDP checksums before writing.
- Randomized actions accept `--seed` for reproducibility.
