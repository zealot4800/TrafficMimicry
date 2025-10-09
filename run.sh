#!/bin/bash
echo "Running traffic transformations..."

python src/mimicaryModel/transformer.py "nonvpn_chat"
python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/NonVPN/Chat/" --csv-dir "dataset/Modified_M/CSV/NON-VPN/Chat/" --combined-csv "dataset/Modified_M/CSV/NON-VPN/Chat/Chat_Combined.csv"

python src/mimicaryModel/transformer.py "nonvpn_command_control"
python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/NonVPN/Command&Control/" --csv-dir "dataset/Modified_M/CSV/NON-VPN/Command&Control/" --combined-csv "dataset/Modified_M/CSV/NON-VPN/Command&Control/Command&Control_Combined.csv"

python src/mimicaryModel/transformer.py "nonvpn_voip"
python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/NonVPN/VoIP/" --csv-dir "dataset/Modified_M/CSV/NON-VPN/VoIP/" --combined-csv "dataset/Modified_M/CSV/NON-VPN/VoIP/VoIP_Combined.csv"

python src/mimicaryModel/transformer.py "nonvpn_streaming"
python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/NonVPN/Streaming/" --csv-dir "dataset/Modified_M/CSV/NON-VPN/Streaming/" --combined-csv "dataset/Modified_M/CSV/NON-VPN/Streaming/Streaming_Combined.csv"

python src/mimicaryModel/transformer.py "nonvpn_filetransfer"
python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/NonVPN/FileTransfer/" --csv-dir "dataset/Modified_M/CSV/NON-VPN/FileTransfer/" --combined-csv "dataset/Modified_M/CSV/NON-VPN/FileTransfer/FileTransfer_Combined.csv"

python src/mimicaryModel/transformer.py "vpn_chat"
python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/VPN/Chat/" --csv-dir "dataset/Modified_M/CSV/VPN/Chat/" --combined-csv "dataset/Modified_M/CSV/VPN/Chat/Chat_Combined.csv"

python src/mimicaryModel/transformer.py "vpn_command_control"
python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/VPN/Command&Control/" --csv-dir "dataset/Modified_M/CSV/VPN/Command&Control/" --combined-csv "dataset/Modified_M/CSV/VPN/Command&Control/Command&Control_Combined.csv"

python src/mimicaryModel/transformer.py "vpn_voip"
python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/VPN/VoIP/" --csv-dir "dataset/Modified_M/CSV/VPN/VoIP/" --combined-csv "dataset/Modified_M/CSV/VPN/VoIP/VoIP_Combined.csv"

python src/mimicaryModel/transformer.py "vpn_streaming"
python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/VPN/Streaming/" --csv-dir "dataset/Modified_M/CSV/VPN/Streaming/" --combined-csv "dataset/Modified_M/CSV/VPN/Streaming/Streaming_Combined.csv"

python src/mimicaryModel/transformer.py "vpn_filetransfer"
python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/VPN/FileTransfer/" --csv-dir "dataset/Modified_M/CSV/VPN/FileTransfer/" --combined-csv "dataset/Modified_M/CSV/VPN/FileTransfer/FileTransfer_Combined.csv"


# --- Aggregated Non-VPN ---
echo "Processing Aggregated Non-VPN FCT..."
python scripts/calculate_fct.py \
  --baseline-dir "dataset/VPN&NonVPN/NonVPN/" \
  --transformed-dir "dataset/Modified_M/NonVPN/" \
  --output-file "results/fct/nonvpn/aggregated_fct_data.json" \
  --label "Non-VPN"
  
python scripts/plot_fct_cdf.py \
  "results/fct/nonvpn/aggregated_fct_data.json" \
  "results/fct/nonvpn/aggregated_fct_cdf.png" \
  --output-dir "results/fct/nonvpn"

# --- Aggregated VPN ---
echo "Processing Aggregated VPN FCT..."
mkdir -p "results/fct/vpn"
python scripts/calculate_fct.py \
  --baseline-dir "dataset/VPN&NonVPN/VPN/" \
  --transformed-dir "dataset/Modified_M/VPN/" \
  --output-file "results/fct/vpn/aggregated_fct_data.json" \
  --label "VPN"

python scripts/plot_fct_cdf.py \
  "results/fct/vpn/aggregated_fct_data.json" \
  "results/fct/vpn/aggregated_fct_cdf.png" \
  --output-dir "results/fct/vpn"

echo "FCT CDF generation complete. Plots are in the results/ directory."

echo "Running service-level evaluations and confusion matrices..."
python scripts/evaluate_services.py --skip-missing --output-dir "results/evaluation"