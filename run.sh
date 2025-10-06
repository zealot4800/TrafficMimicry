#!/bin/bash

# This script runs all the transformer commands listed in the Readme.md.

echo "Running Non-VPN Transformers..."

python src/mimicaryModel/pcap_transformer_nonvpn_chat.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/Chat/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/chat/ 
python src/mimicaryModel/pcap_transformer_nonvpn_command_control.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/Command\&Control/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/command\&control/ 
python src/mimicaryModel/pcap_transformer_nonvpn_streaming.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/Streaming/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/streaming/ 
python src/mimicaryModel/pcap_transformer_nonvpn_voip.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/VoIP/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/voip/ 

echo "Running VPN Transformers..."

python src/mimicaryModel/pcap_transformer_vpn_chat.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/Chat/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/chat/ 
python src/mimicaryModel/pcap_transformer_vpn_command_control.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/Command\&Control/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/Command\&Control/ 
python src/mimicaryModel/pcap_transformer_vpn_streaming.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/Streaming/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/streaming/
python src/mimicaryModel/pcap_transformer_vpn_voip.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/VoIP/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/voip/ 

python src/mimicaryModel/pcap_transformer_vpn_filetransfer.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/FileTransfer/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/FileTransfer/ 
python src/mimicaryModel/pcap_transformer_nonvpn_filetransfer.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/FileTransfer/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/FileTransfer/ 

echo "All transformer commands have been executed."

echo "Running CICFlowMeter for each service..."

# Base directories
PCAP_BASE="/home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M"
CSV_BASE="/home/zealot/ICC/TrafficMimicrySystem/dataset/Modified/CSV"

# Non-VPN services
echo "Processing Non-VPN services..."
python scripts/run_cicflowmeter.py --pcap-dir "$PCAP_BASE/NonVPN/chat/" --csv-dir "$CSV_BASE/NON-VPN/Chat/"
python scripts/run_cicflowmeter.py --pcap-dir "$PCAP_BASE/NonVPN/command&control/" --csv-dir "$CSV_BASE/NON-VPN/Command&Control/"
python scripts/run_cicflowmeter.py --pcap-dir "$PCAP_BASE/NonVPN/FileTransfer/" --csv-dir "$CSV_BASE/NON-VPN/FileTransfer/"
python scripts/run_cicflowmeter.py --pcap-dir "$PCAP_BASE/NonVPN/streaming/" --csv-dir "$CSV_BASE/NON-VPN/Streaming/"
python scripts/run_cicflowmeter.py --pcap-dir "$PCAP_BASE/NonVPN/voip/" --csv-dir "$CSV_BASE/NON-VPN/VoIP/"

# VPN services
echo "Processing VPN services..."
python scripts/run_cicflowmeter.py --pcap-dir "$PCAP_BASE/VPN/chat/" --csv-dir "$CSV_BASE/VPN/Chat/"
python scripts/run_cicflowmeter.py --pcap-dir "$PCAP_BASE/VPN/Command&Control/" --csv-dir "$CSV_BASE/VPN/Command&Control/"
python scripts/run_cicflowmeter.py --pcap-dir "$PCAP_BASE/VPN/FileTransfer/" --csv-dir "$CSV_BASE/VPN/FileTransfer/"
python scripts/run_cicflowmeter.py --pcap-dir "$PCAP_BASE/VPN/streaming/" --csv-dir "$CSV_BASE/VPN/Streaming/"
python scripts/run_cicflowmeter.py --pcap-dir "$PCAP_BASE/VPN/voip/" --csv-dir "$CSV_BASE/VPN/VoIP/"

echo "CICFlowMeter has finished for all services."
echo "Calculating and plotting FCT CDFs for all services..."

# Base directories
BASELINE_PCAP_BASE="/home/zealot/ICC/TrafficMimicrySystem/dataset/VPN&NonVPN"
TRANSFORMED_PCAP_BASE="/home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M"
RESULTS_BASE="/home/zealot/ICC/TrafficMimicrySystem/results"
FCT_RESULTS_BASE="$RESULTS_BASE/fct"

# Ensure the results directory exists
mkdir -p "$RESULTS_BASE"
mkdir -p "$FCT_RESULTS_BASE"

# --- Non-VPN Services ---
echo "Processing Non-VPN aggregate FCT..."
NONVPN_FCT_DIR="$FCT_RESULTS_BASE/nonvpn"
mkdir -p "$NONVPN_FCT_DIR"
python scripts/calculate_fct.py \
  --baseline-dir "$BASELINE_PCAP_BASE/NonVPN/" \
  --transformed-dir "$TRANSFORMED_PCAP_BASE/NonVPN/" \
  --output-file "$NONVPN_FCT_DIR/fct_data.json" \
  --label "Non-VPN"
python scripts/plot_fct_cdf.py \
  "$NONVPN_FCT_DIR/fct_data.json" \
  "$NONVPN_FCT_DIR/fct_cdf.png" \
  --output-dir "$NONVPN_FCT_DIR"

# --- VPN Services ---
echo "Processing VPN aggregate FCT..."
VPN_FCT_DIR="$FCT_RESULTS_BASE/vpn"
mkdir -p "$VPN_FCT_DIR"
python scripts/calculate_fct.py \
  --baseline-dir "$BASELINE_PCAP_BASE/VPN/" \
  --transformed-dir "$TRANSFORMED_PCAP_BASE/VPN/" \
  --output-file "$VPN_FCT_DIR/fct_data.json" \
  --label "VPN"
python scripts/plot_fct_cdf.py \
  "$VPN_FCT_DIR/fct_data.json" \
  "$VPN_FCT_DIR/fct_cdf.png" \
  --output-dir "$VPN_FCT_DIR"

echo "FCT CDF generation complete. Plots are in the results/ directory."

echo "Running service-level evaluations and confusion matrices..."
python scripts/evaluate_services.py --skip-missing --output-dir "${RESULTS_BASE}/evaluation"

echo "Evaluation artifacts placed under ${RESULTS_BASE}/evaluation." 
