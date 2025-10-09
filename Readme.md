# Traffic Mimicry System

This project is designed to apply adversarial transformations to network traffic captures (PCAP files). The goal is to modify the statistical features of the traffic to mimic a different type of traffic, effectively obfuscating its original signature. This is useful for testing the robustness of traffic classifiers and for research into network privacy and security.

## Getting Started

The traffic transformation process is controlled by a central script, `src/mimicaryModel/transformer.py`, which is configured using a YAML file, `src/mimicaryModel/scenarios.yaml`.

### 1. Create Sample PCAP Files

The transformation process uses small sample PCAP files to define the statistical profile of the target traffic type. You can generate these sample files using the `scripts/create_sample_pcaps.py` script.

This script will take a small number of packets from the first PCAP file in a given directory and save them to a new file named `{vpn/non-vpn}_{service_name}_sample.pcap`.

To generate sample files for all your non-VPN and VPN services, you can run the following commands:

```bash
# Generate non-VPN samples
python scripts/create_sample_pcaps.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/Chat/
python scripts/create_sample_pcaps.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/VoIP/
python scripts/create_sample_pcaps.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/Streaming/
python scripts/create_sample_pcaps.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/FileTransfer/
python scripts/create_sample_pcaps.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/Command\&Control/

# Generate VPN samples
python scripts/create_sample_pcaps.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/Chat/
python scripts/create_sample_pcaps.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/VoIP/
python scripts/create_sample_pcaps.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/Streaming/
python scripts/create_sample_pcaps.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/FileTransfer/
python scripts/create_sample_pcaps.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/Command\&Control/
```

### 2. Configure Scenarios

The `src/mimicaryModel/scenarios.yaml` file defines the transformation scenarios. The primary way to use this system is through the "multi-mimic" scenarios, which are designed to make one type of traffic look like a mix of other traffic types.

Here is an example of a multi-mimic scenario:

```yaml
nonvpn_chat_multi_mimic:
  input_dir: "/home/zealot/ICC/TrafficMimicrySystem/dataset/VPN&NonVPN/NonVPN/Chat/"
  output_dir_base: "/home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/Chat_multi_mimic/"
  multi_mimic:
    - target_service: "voip"
      target_pcap: "/home/zealot/ICC/TrafficMimicrySystem/dataset/VPN&NonVPN/NonVPN/VoIP/nonvpn_voip_sample.pcap"
    - target_service: "streaming"
      target_pcap: "/home/zealot/ICC/TrafficMimicrySystem/dataset/VPN&NonVPN/NonVPN/Streaming/nonvpn_streaming_sample.pcap"
    # ... and so on
```

You can customize these scenarios to change the input directories, output directories, and the target traffic profiles.

### 3. Run Transformations

To run a scenario, execute the `src/mimicaryModel/transformer.py` script with the name of the scenario you want to run:

```bash
python src/mimicaryModel/transformer.py nonvpn_chat_multi_mimic
```

## Automated Workflow with `run.sh`

The `run.sh` script provides an automated way to run all the multi-mimic transformations and the subsequent evaluation steps.

To run the entire workflow, simply execute the script:

```bash
./run.sh
```

This will:
1.  Run all the multi-mimic scenarios defined in `scenarios.yaml`.
2.  Run the CICFlowMeter tool to generate CSV files from the transformed PCAPs.
3.  Calculate and plot the Flow Completion Time (FCT) CDFs.
4.  Run the service-level evaluations.

## Utility and Evaluation Scripts

The `scripts/` directory contains several utility and evaluation scripts:

-   `create_sample_pcaps.py`: Creates small sample PCAP files.
-   `run_cicflowmeter.py`: Converts PCAPs to CSVs using CICFlowMeter.
-   `evaluate_services.py`: Evaluates a trained model against a CSV dataset.
-   `calculate_fct.py`: Calculates Flow Completion Times (FCTs).
-   `plot_fct_cdf.py`: Plots FCT CDFs.