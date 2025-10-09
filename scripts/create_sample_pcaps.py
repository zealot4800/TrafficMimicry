import argparse
from pathlib import Path
from scapy.all import PcapReader, PcapWriter

def create_sample_pcap(input_dir: str, num_packets: int = 100):
    input_path = Path(input_dir)
    
    # Extract service and type from the path
    service_name = input_path.name
    vpn_type = input_path.parent.name
    
    output_filename = f"{vpn_type.lower()}_{service_name.lower()}_sample.pcap"
    output_path = input_path / output_filename

    pcap_files = list(input_path.rglob("*.pcap")) + list(input_path.rglob("*.pcapng"))
    if not pcap_files:
        print(f"Warning: No pcap files found in {input_dir}")
        return

    source_pcap = pcap_files[0]

    with PcapReader(str(source_pcap)) as pcap_reader:
        with PcapWriter(str(output_path), append=False) as pcap_writer:
            for i, packet in enumerate(pcap_reader):
                if i >= num_packets:
                    break
                pcap_writer.write(packet)
    print(f"Created sample pcap at {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a small sample PCAP from a directory of PCAPs.")
    parser.add_argument("input_dir", help="Directory containing the source PCAP files.")
    parser.add_argument("--num_packets", type=int, default=100, help="Number of packets to include in the sample.")
    args = parser.parse_args()
    create_sample_pcap(args.input_dir, args.num_packets)