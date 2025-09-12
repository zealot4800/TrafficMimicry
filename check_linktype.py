from scapy.utils import PcapReader

with PcapReader('nonvpn_skype-chat_capture1.pcap') as reader:
    print('Linktype:', reader.linktype)
