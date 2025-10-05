#!/bin/bash

# This script runs all the transformer commands listed in the Readme.md.

echo "Running Non-VPN Transformers..."

python src/mimicaryModel/pcap_transformer_nonvpn_chat.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/Chat/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/chat/ --recommended
python src/mimicaryModel/pcap_transformer_nonvpn_command_control.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/Command\&Control/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/command\&control/ --recommended
python src/mimicaryModel/pcap_transformer_nonvpn_filetransfer.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/FileTransfer/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/FileTransfer/ --recommended
python src/mimicaryModel/pcap_transformer_nonvpn_streaming.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/Streaming/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/streaming/ --recommended
python src/mimicaryModel/pcap_transformer_nonvpn_voip.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/VoIP/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/voip/ --recommended

echo "Running VPN Transformers..."

python src/mimicaryModel/pcap_transformer_vpn_chat.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/Chat/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/chat/ --recommended
python src/mimicaryModel/pcap_transformer_vpn_command_control.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/Command\&Control/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/Command\&Control/ --recommended
python src/mimicaryModel/pcap_transformer_vpn_filetransfer.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/FileTransfer/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/FileTransfer/ --recommended
python src/mimicaryModel/pcap_transformer_vpn_streaming.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/Streaming/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/streaming/ --recommended
python src/mimicaryModel/pcap_transformer_vpn_voip.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/VoIP/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/voip/ --recommended

echo "All transformer commands have been executed."
