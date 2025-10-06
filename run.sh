#!/bin/bash

# This script runs all the transformer commands listed in the Readme.md.

echo "Running Non-VPN Transformers..."

python src/mimicaryModel/pcap_transformer_nonvpn_chat.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/Chat/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/chat/ 
python src/mimicaryModel/pcap_transformer_nonvpn_command_control.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/Command\&Control/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/command\&control/ 
python src/mimicaryModel/pcap_transformer_nonvpn_filetransfer.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/FileTransfer/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/FileTransfer/ 
python src/mimicaryModel/pcap_transformer_nonvpn_streaming.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/Streaming/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/streaming/ 
python src/mimicaryModel/pcap_transformer_nonvpn_voip.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/VoIP/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/voip/ 

echo "Running VPN Transformers..."

python src/mimicaryModel/pcap_transformer_vpn_chat.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/Chat/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/chat/ 
python src/mimicaryModel/pcap_transformer_vpn_command_control.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/Command\&Control/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/Command\&Control/ 
python src/mimicaryModel/pcap_transformer_vpn_filetransfer.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/FileTransfer/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/FileTransfer/ 
python src/mimicaryModel/pcap_transformer_vpn_streaming.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/Streaming/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/streaming/
python src/mimicaryModel/pcap_transformer_vpn_voip.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/VoIP/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/voip/ 

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

# Ensure the results directory exists
mkdir -p "$RESULTS_BASE"

# --- Non-VPN Services ---
echo "Processing Non-VPN - Chat..."
python scripts/calculate_fct.py --baseline-dir "$BASELINE_PCAP_BASE/NonVPN/Chat/" --transformed-dir "$TRANSFORMED_PCAP_BASE/NonVPN/chat/" --output-file "$RESULTS_BASE/fct_data_nonvpn_chat.json"
python scripts/plot_fct_cdf.py "$RESULTS_BASE/fct_data_nonvpn_chat.json" "$RESULTS_BASE/fct_cdf_nonvpn_chat.png"

echo "Processing Non-VPN - Command&Control..."
python scripts/calculate_fct.py --baseline-dir "$BASELINE_PCAP_BASE/NonVPN/Command&Control/" --transformed-dir "$TRANSFORMED_PCAP_BASE/NonVPN/command&control/" --output-file "$RESULTS_BASE/fct_data_nonvpn_command&control.json"
python scripts/plot_fct_cdf.py "$RESULTS_BASE/fct_data_nonvpn_command&control.json" "$RESULTS_BASE/fct_cdf_nonvpn_command&control.png"

echo "Processing Non-VPN - FileTransfer..."
python scripts/calculate_fct.py --baseline-dir "$BASELINE_PCAP_BASE/NonVPN/FileTransfer/" --transformed-dir "$TRANSFORMED_PCAP_BASE/NonVPN/FileTransfer/" --output-file "$RESULTS_BASE/fct_data_nonvpn_filetransfer.json"
python scripts/plot_fct_cdf.py "$RESULTS_BASE/fct_data_nonvpn_filetransfer.json" "$RESULTS_BASE/fct_cdf_nonvpn_filetransfer.png"

echo "Processing Non-VPN - Streaming..."
python scripts/calculate_fct.py --baseline-dir "$BASELINE_PCAP_BASE/NonVPN/Streaming/" --transformed-dir "$TRANSFORMED_PCAP_BASE/NonVPN/streaming/" --output-file "$RESULTS_BASE/fct_data_nonvpn_streaming.json"
python scripts/plot_fct_cdf.py "$RESULTS_BASE/fct_data_nonvpn_streaming.json" "$RESULTS_BASE/fct_cdf_nonvpn_streaming.png"

echo "Processing Non-VPN - VoIP..."
python scripts/calculate_fct.py --baseline-dir "$BASELINE_PCAP_BASE/NonVPN/VoIP/" --transformed-dir "$TRANSFORMED_PCAP_BASE/NonVPN/voip/" --output-file "$RESULTS_BASE/fct_data_nonvpn_voip.json"
python scripts/plot_fct_cdf.py "$RESULTS_BASE/fct_data_nonvpn_voip.json" "$RESULTS_BASE/fct_cdf_nonvpn_voip.png"

# --- VPN Services ---
echo "Processing VPN - Chat..."
python scripts/calculate_fct.py --baseline-dir "$BASELINE_PCAP_BASE/VPN/Chat/" --transformed-dir "$TRANSFORMED_PCAP_BASE/VPN/chat/" --output-file "$RESULTS_BASE/fct_data_vpn_chat.json"
python scripts/plot_fct_cdf.py "$RESULTS_BASE/fct_data_vpn_chat.json" "$RESULTS_BASE/fct_cdf_vpn_chat.png"

echo "Processing VPN - Command&Control..."
python scripts/calculate_fct.py --baseline-dir "$BASELINE_PCAP_BASE/VPN/Command&Control/" --transformed-dir "$TRANSFORMED_PCAP_BASE/VPN/Command&Control/" --output-file "$RESULTS_BASE/fct_data_vpn_command&control.json"
python scripts/plot_fct_cdf.py "$RESULTS_BASE/fct_data_vpn_command&control.json" "$RESULTS_BASE/fct_cdf_vpn_command&control.png"

echo "Processing VPN - FileTransfer..."
python scripts/calculate_fct.py --baseline-dir "$BASELINE_PCAP_BASE/VPN/FileTransfer/" --transformed-dir "$TRANSFORMED_PCAP_BASE/VPN/FileTransfer/" --output-file "$RESULTS_BASE/fct_data_vpn_filetransfer.json"
python scripts/plot_fct_cdf.py "$RESULTS_BASE/fct_data_vpn_filetransfer.json" "$RESULTS_BASE/fct_cdf_vpn_filetransfer.png"

echo "Processing VPN - Streaming..."
python scripts/calculate_fct.py --baseline-dir "$BASELINE_PCAP_BASE/VPN/Streaming/" --transformed-dir "$TRANSFORMED_PCAP_BASE/VPN/streaming/" --output-file "$RESULTS_BASE/fct_data_vpn_streaming.json"
python scripts/plot_fct_cdf.py "$RESULTS_BASE/fct_data_vpn_streaming.json" "$RESULTS_BASE/fct_cdf_vpn_streaming.png"

echo "Processing VPN - VoIP..."
python scripts/calculate_fct.py --baseline-dir "$BASELINE_PCAP_BASE/VPN/VoIP/" --transformed-dir "$TRANSFORMED_PCAP_BASE/VPN/voip/" --output-file "$RESULTS_BASE/fct_data_vpn_voip.json"
python scripts/plot_fct_cdf.py "$RESULTS_BASE/fct_data_vpn_voip.json" "$RESULTS_BASE/fct_cdf_vpn_voip.png"

echo "FCT CDF generation complete. Plots are in the results/ directory."

echo "Running service-level evaluations and confusion matrices..."
python scripts/evaluate_services.py --skip-missing --output-dir "${RESULTS_BASE}/evaluation"

echo "Evaluation artifacts placed under ${RESULTS_BASE}/evaluation." 
