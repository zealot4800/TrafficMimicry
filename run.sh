#!/bin/bash
set -euo pipefail

# Ensure project root is on PYTHONPATH for package-style imports
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="${PYTHONPATH:-}:${PROJECT_ROOT}"

# echo "Running traffic transformations..."

# python src/mimicaryModel/transformer.py "nonvpn_chat"
# python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/NonVPN/Chat/" --csv-dir "dataset/Modified_M/CSV/NON-VPN/Chat/" --combined-csv "dataset/Modified_M/CSV/NON-VPN/Chat/Chat_Combined.csv" 

# python src/mimicaryModel/transformer.py "nonvpn_command_control"
# python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/NonVPN/Command&Control/" --csv-dir "dataset/Modified_M/CSV/NON-VPN/Command&Control/" --combined-csv "dataset/Modified_M/CSV/NON-VPN/Command&Control/Command&Control_Combined.csv" 

# python src/mimicaryModel/transformer.py "nonvpn_voip"
# python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/NonVPN/VoIP/" --csv-dir "dataset/Modified_M/CSV/NON-VPN/VoIP/" --combined-csv "dataset/Modified_M/CSV/NON-VPN/VoIP/VoIP_Combined.csv" 

# python src/mimicaryModel/transformer.py "nonvpn_streaming"
# python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/NonVPN/Streaming/" --csv-dir "dataset/Modified_M/CSV/NON-VPN/Streaming/" --combined-csv "dataset/Modified_M/CSV/NON-VPN/Streaming/Streaming_Combined.csv" 

# python src/mimicaryModel/transformer.py "nonvpn_filetransfer"
# python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/NonVPN/FileTransfer/" --csv-dir "dataset/Modified_M/CSV/NON-VPN/FileTransfer/" --combined-csv "dataset/Modified_M/CSV/NON-VPN/FileTransfer/FileTransfer_Combined.csv" 

# python src/mimicaryModel/transformer.py "vpn_chat"
# python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/VPN/Chat/" --csv-dir "dataset/Modified_M/CSV/VPN/Chat/" --combined-csv "dataset/Modified_M/CSV/VPN/Chat/Chat_Combined.csv" 

# python src/mimicaryModel/transformer.py "vpn_command_control"
# python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/VPN/Command&Control/" --csv-dir "dataset/Modified_M/CSV/VPN/Command&Control/" --combined-csv "dataset/Modified_M/CSV/VPN/Command&Control/Command&Control_Combined.csv" 

# python src/mimicaryModel/transformer.py "vpn_voip"
# python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/VPN/VoIP/" --csv-dir "dataset/Modified_M/CSV/VPN/VoIP/" --combined-csv "dataset/Modified_M/CSV/VPN/VoIP/VoIP_Combined.csv" 

# python src/mimicaryModel/transformer.py "vpn_streaming"
# python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/VPN/Streaming/" --csv-dir "dataset/Modified_M/CSV/VPN/Streaming/" --combined-csv "dataset/Modified_M/CSV/VPN/Streaming/Streaming_Combined.csv" 

# python src/mimicaryModel/transformer.py "vpn_filetransfer"
# python scripts/run_cicflowmeter.py --pcap-dir "dataset/Modified_M/VPN/FileTransfer/" --csv-dir "dataset/Modified_M/CSV/VPN/FileTransfer/" --combined-csv "dataset/Modified_M/CSV/VPN/FileTransfer/FileTransfer_Combined.csv"  

############################################
#           PER-SERVICE — NON-VPN          #
############################################

# echo "Generating Non-VPN Chat feature analysis..."
# python scripts/analyze_packet_features.py \
#   --mode packet-features \
#   --baseline-dir "dataset/VPN&NonVPN/NonVPN/Chat/" \
#   --transformed-dir "dataset/Modified_M/NonVPN/Chat/" \
#   --output-dir "results/features/nonvpn/Chat" \
#   --label "Non-VPN-Chat" \
#   --flow-normalize
# echo

# echo "Generating Non-VPN Command&Control feature analysis..."
# python scripts/analyze_packet_features.py \
#   --mode packet-features \
#   --baseline-dir "dataset/VPN&NonVPN/NonVPN/Command&Control/" \
#   --transformed-dir "dataset/Modified_M/NonVPN/Command&Control/" \
#   --output-dir "results/features/nonvpn/Command&Control" \
#   --label "Non-VPN-Command&Control" \
#   --flow-normalize
# echo

# echo "Generating Non-VPN Streaming feature analysis..."
# python scripts/analyze_packet_features.py \
#   --mode packet-features \
#   --baseline-dir "dataset/VPN&NonVPN/NonVPN/Streaming/" \
#   --transformed-dir "dataset/Modified_M/NonVPN/Streaming/" \
#   --output-dir "results/features/nonvpn/Streaming" \
#   --label "Non-VPN-Streaming" \
#   --flow-normalize
# echo

# echo "Generating Non-VPN VoIP feature analysis..."
# python scripts/analyze_packet_features.py \
#   --mode packet-features \
#   --baseline-dir "dataset/VPN&NonVPN/NonVPN/VoIP/" \
#   --transformed-dir "dataset/Modified_M/NonVPN/VoIP/" \
#   --output-dir "results/features/nonvpn/VoIP" \
#   --label "Non-VPN-VoIP" \
#   --flow-normalize
# echo

# echo "Generating Non-VPN FileTransfer feature analysis..."
# python scripts/analyze_packet_features.py \
#   --mode packet-features \
#   --baseline-dir "dataset/VPN&NonVPN/NonVPN/FileTransfer/" \
#   --transformed-dir "dataset/Modified_M/NonVPN/FileTransfer/" \
#   --output-dir "results/features/nonvpn/FileTransfer" \
#   --label "Non-VPN-FileTransfer" \
#   --flow-normalize
# echo

############################################
#             PER-SERVICE — VPN            #
############################################

# echo "Generating VPN Chat feature analysis..."
# python scripts/analyze_packet_features.py \
#   --mode packet-features \
#   --baseline-dir "dataset/VPN&NonVPN/VPN/Chat/" \
#   --transformed-dir "dataset/Modified_M/VPN/Chat/" \
#   --output-dir "results/features/vpn/Chat" \
#   --label "VPN-Chat" \
#   --flow-normalize
# echo

# echo "Generating VPN Command&Control feature analysis..."
# python scripts/analyze_packet_features.py \
#   --mode packet-features \
#   --baseline-dir "dataset/VPN&NonVPN/VPN/Command&Control/" \
#   --transformed-dir "dataset/Modified_M/VPN/Command&Control/" \
#   --output-dir "results/features/vpn/Command&Control" \
#   --label "VPN-Command&Control" \
#   --flow-normalize
# echo

# echo "Generating VPN Streaming feature analysis..."
# python scripts/analyze_packet_features.py \
#   --mode packet-features \
#   --baseline-dir "dataset/VPN&NonVPN/VPN/Streaming/" \
#   --transformed-dir "dataset/Modified_M/VPN/Streaming/" \
#   --output-dir "results/features/vpn/Streaming" \
#   --label "VPN-Streaming" \
#   --flow-normalize
# echo

# echo "Generating VPN VoIP feature analysis..."
# python scripts/analyze_packet_features.py \
#   --mode packet-features \
#   --baseline-dir "dataset/VPN&NonVPN/VPN/VoIP/" \
#   --transformed-dir "dataset/Modified_M/VPN/VoIP/" \
#   --output-dir "results/features/vpn/VoIP" \
#   --label "VPN-VoIP" \
#   --flow-normalize
# echo

# echo "Generating VPN FileTransfer feature analysis..."
# python scripts/analyze_packet_features.py \
#   --mode packet-features \
#   --baseline-dir "dataset/VPN&NonVPN/VPN/FileTransfer/" \
#   --transformed-dir "dataset/Modified_M/VPN/FileTransfer/" \
#   --output-dir "results/features/vpn/FileTransfer" \
#   --label "VPN-FileTransfer" \
#   --flow-normalize
# echo

########################################################
#      AGGREGATED (COMBINED ACROSS ALL SERVICES)       #
########################################################

# # Features — combine all services under the VPN root
# echo "Generating VPN (ALL services) aggregated feature analysis..."
# python scripts/analyze_packet_features.py \
#   --mode packet-features \
#   --baseline-dir "dataset/VPN&NonVPN/VPN" \
#   --transformed-dir "dataset/Modified_M/VPN" \
#   --output-dir "results/features/vpn/_all" \
#   --label "VPN-AllServices" \
#   --flow-normalize
# echo

# # Features — combine all services under the Non-VPN root
# echo "Generating Non-VPN (ALL services) aggregated feature analysis..."
# python scripts/analyze_packet_features.py \
#   --mode packet-features \
#   --baseline-dir "dataset/VPN&NonVPN/NonVPN" \
#   --transformed-dir "dataset/Modified_M/NonVPN" \
#   --output-dir "results/features/nonvpn/_all" \
#   --label "NonVPN-AllServices" \
#   --flow-normalize
# echo

# # FCT — VPN (ALL services)
# echo "Generating VPN (ALL services) aggregated FCT..."
# python scripts/analyze_packet_features.py \
#   --mode fct \
#   --baseline-dir "dataset/VPN&NonVPN/VPN" \
#   --transformed-dir "dataset/Modified_M/VPN" \
#   --output-file "results/fct/vpn/aggregated_fct_data.json" \
#   --label "VPN" \
#   --plot-dir "results/fct/vpn"
# echo

# # FCT — Non-VPN (ALL services)
# echo "Generating Non-VPN (ALL services) aggregated FCT..."
# python scripts/analyze_packet_features.py \
#   --mode fct \
#   --baseline-dir "dataset/VPN&NonVPN/NonVPN" \
#   --transformed-dir "dataset/Modified_M/NonVPN" \
#   --output-file "results/fct/nonvpn/aggregated_fct_data.json" \
#   --label "Non-VPN" \
#   --plot-dir "results/fct/nonvpn"
# echo


echo "FCT and feature analysis complete. Results are in the results/ directory."

echo "Running service-level evaluations and confusion matrices..."
# python scripts/evaluate_services.py --skip-missing --output-dir "results/evaluation"
