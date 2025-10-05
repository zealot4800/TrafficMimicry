# Traffic Mimicry System

This project is designed to apply adversarial transformations to network traffic captures (PCAP files). The goal is to modify the statistical features of the traffic to mimic a different type of traffic, effectively obfuscating its original signature. This is useful for testing the robustness of traffic classifiers and for research into network privacy and security.

## Core Transformation Scripts

The main components of this system are the `pcap_transformer_*.py` scripts located in `src/mimicaryModel/`. Each script is specialized to transform input PCAP files to match the statistical profile of a specific traffic category.

### Transformation Strategy

The core strategy for each script is as follows:

1.  **Feature-Driven Transformations**: Each script contains a `FEATURE_IMPORTANCE` dictionary that assigns a weight to various traffic features (e.g., packet length, inter-arrival time). These weights determine which transformations are prioritized.
2.  **Progressive Application**: The script iteratively applies transformations (like padding, splitting, and introducing delays) to the PCAP data.
3.  **SLA Compliance**: After each transformation, the script checks if the modified traffic complies with a set of Service Level Agreement (SLA) constraints defined for the target traffic type.

### How to Run

All transformation scripts follow the same command-line structure.

---

### Available Transformer Scripts

**Non-VPN Transformers:**

-   `pcap_transformer_nonvpn_chat.py`
    -   **Strategy**: Mimics non-VPN chat traffic by focusing on altering packet sizes and manipulating TCP control flags. The primary methods are:
        -   **Packet Length & Size**: Applies Fragmentation, Padding, and Size Randomization.
        -   **TCP/Control Flags**: Applies TCP Flag Manipulation.
    -   **Command**:
        ```bash
        python src/mimicaryModel/pcap_transformer_nonvpn_chat.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/Chat/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/chat/ --recommended
        ```

-   `pcap_transformer_nonvpn_command_control.py`
    -   **Strategy**: Mimics non-VPN Command & Control traffic by focusing on packet sizes and packet/byte counters. The primary methods are:
        -   **Packet Length & Size**: Applies traffic padding, payload splitting, and merging.
        -   **Byte/Packet Counters**: Uses dummy packet injection to alter flow density.
    -   **Command**:
        ```bash
        python src/mimicaryModel/pcap_transformer_nonvpn_command_control.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/Command\&Control/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/command\&control/ --recommended
        ```

-   `pcap_transformer_nonvpn_filetransfer.py`
    -   **Strategy**: Mimics non-VPN file transfer traffic by heavily modifying packet sizes and altering packet counts. The primary methods are:
        -   **Packet Length & Size**: Applies traffic padding, payload splitting, and merging.
        -   **Byte/Packet Counters**: Uses dummy packet injection to alter flow density.
    -   **Command**:
        ```bash
        python src/mimicaryModel/pcap_transformer_nonvpn_filetransfer.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/FileTransfer/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/FileTransfer/ --recommended
        ```

-   `pcap_transformer_nonvpn_streaming.py`
    -   **Strategy**: Mimics non-VPN streaming traffic by focusing on packet sizes and TCP control flags. The primary methods are:
        -   **Packet Length & Size**: Applies traffic padding, payload splitting, and merging.
        -   **TCP/Control Flags**: Modifies TCP header flags to change flow patterns.
    -   **Command**:
        ```bash
        python src/mimicaryModel/pcap_transformer_nonvpn_streaming.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/Streaming/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/streaming/ --recommended
        ```

-   `pcap_transformer_nonvpn_voip.py`
    -   **Strategy**: Mimics non-VPN VoIP traffic by focusing on packet sizes and packet counts. The primary methods are:
        -   **Packet Length & Size**: Applies traffic padding, payload splitting, and merging.
        -   **Byte/Packet Counters**: Uses dummy packet injection to alter flow density.
    -   **Command**:
        ```bash
        python src/mimicaryModel/pcap_transformer_nonvpn_voip.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/NonVPN/VoIP/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/NonVPN/voip/ --recommended
        ```

**VPN Transformers:**

-   `pcap_transformer_vpn_chat.py`
    -   **Strategy**: Mimics VPN chat traffic by focusing on packet sizes and altering packet counts. The primary methods are:
        -   **Packet Length & Size**: Applies traffic padding, payload splitting, and merging.
        -   **Byte/Packet Counters**: Uses dummy packet injection to alter flow density.
    -   **Command**:
        ```bash
        python src/mimicaryModel/pcap_transformer_vpn_chat.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/Chat/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/chat/ --recommended
        ```

-   `pcap_transformer_vpn_command_control.py`
    -   **Strategy**: Mimics VPN Command & Control traffic by focusing on packet sizes and timing. The primary methods are:
        -   **Packet Length & Size**: Applies traffic padding, payload splitting, and merging.
        -   **Flow Timing**: Injects random delays (jitter) to alter inter-arrival times.
    -   **Command**:
        ```bash
        python src/mimicaryModel/pcap_transformer_vpn_command_control.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/Command\&Control/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/Command\&Control/ --recommended
        ```

-   `pcap_transformer_vpn_filetransfer.py`
    -   **Strategy**: Mimics VPN file transfer traffic by balancing changes across packet size, packet counts, and timing. The primary methods are:
        -   **Packet Length & Size**: Applies traffic padding, payload splitting, and merging.
        -   **Byte/Packet Counters**: Uses dummy packet injection to alter flow density.
        -   **Flow Timing**: Injects random delays (jitter) to alter inter-arrival times.
    -   **Command**:
        ```bash
        python src/mimicaryModel/pcap_transformer_vpn_filetransfer.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/FileTransfer/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/FileTransfer/ --recommended
        ```

-   `pcap_transformer_vpn_streaming.py`
    -   **Strategy**: Mimics VPN streaming traffic by modifying packet sizes, altering packet counts, and adjusting flow timing. The primary methods are:
        -   **Packet Length & Size**: Applies traffic padding, payload splitting, and merging.
        -   **Byte/Packet Counters**: Uses dummy packet injection to alter flow density.
        -   **Flow Timing**: Injects random delays (jitter) to alter inter-arrival times.
    -   **Command**:
        ```bash
        python src/mimicaryModel/pcap_transformer_vpn_streaming.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/Streaming/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/streaming/ --recommended
        ```

-   `pcap_transformer_vpn_voip.py`
    -   **Strategy**: Mimics VPN VoIP traffic by focusing on packet sizes and packet counts. The primary methods are:
        -   **Packet Length & Size**: Applies traffic padding, payload splitting, and merging.
        -   **Byte/Packet Counters**: Uses dummy packet injection to alter flow density.
    -   **Command**:
        ```bash
        python src/mimicaryModel/pcap_transformer_vpn_voip.py /home/zealot/ICC/TrafficMimicrySystem/dataset/VPN\&NonVPN/VPN/VoIP/ /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/VPN/voip/ --recommended
        ```

---

## Utility and Evaluation Scripts

These scripts handle workflow tasks like data conversion, model evaluation, and dataset preparation.

### `scripts/run_cicflowmeter.py`

-   **Purpose**: Converts a directory of PCAP files into CSV files containing network flow features using the CICFlowMeter tool.
-   **Command**:
    ```bash
    python scripts/run_cicflowmeter.py --pcap-dir /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified_M/ --csv-dir /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified/CSV/
    ```

### `scripts/evaluate_model.py`

-   **Purpose**: Evaluates a trained model against a CSV dataset to classify traffic services (for Non-VPN traffic).
-   **Command**:
    ```bash
    python scripts/evaluate_model.py /home/zealot/ICC/TrafficMimicrySystem/dataset/Modified/CSV/NON-VPN/Chat_combined.csv src/models/nonvpn_services_model.pkl --label "NonVPN-Chat"
    ```
    ```
