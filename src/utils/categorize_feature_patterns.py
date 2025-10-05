import json
from datetime import datetime
from pathlib import Path

# Define the 6 different Feature Categories
FEATURE_CATEGORIES = {
    "1. Packet Length & Size Features": [
        'pkt_len_min', 'pkt_len_max', 'pkt_len_mean', 'pkt_len_std', 'pkt_len_var',
        'pkt_size_avg',
        'fwd_pkt_len_min', 'fwd_pkt_len_max', 'fwd_pkt_len_mean', 'fwd_pkt_len_std',
        'bwd_pkt_len_min', 'bwd_pkt_len_max', 'bwd_pkt_len_mean', 'bwd_pkt_len_std',
        'fwd_seg_size_avg', 'bwd_seg_size_avg', 'fwd_seg_size_min'
    ],
    "2. Byte/Packet Counters & Ratios": [
        'totlen_fwd_pkts', 'totlen_bwd_pkts', 'tot_fwd_pkts', 'tot_bwd_pkts',
        'subflow_fwd_byts', 'subflow_bwd_byts', 'subflow_fwd_pkts', 'subflow_bwd_pkts',
        'fwd_act_data_pkts', 'flow_byts_s', 'flow_pkts_s',
        'down_up_ratio',
        'fwd_pkts_b_avg', 'bwd_pkts_b_avg', 'fwd_byts_b_avg', 'bwd_byts_b_avg',
        'fwd_pkts_s', 'bwd_pkts_s'
    ],
    "3. Inter-Arrival Time (IAT) & Flow Timing": [
        'fwd_iat_tot', 'bwd_iat_tot',
        'fwd_iat_mean', 'fwd_iat_max', 'fwd_iat_min', 'fwd_iat_std',
        'bwd_iat_mean', 'bwd_iat_max', 'bwd_iat_min', 'bwd_iat_std',
        'flow_iat_mean', 'flow_iat_max', 'flow_iat_min', 'flow_iat_std',
        'flow_duration',
        'idle_mean', 'idle_std', 'idle_min', 'idle_max',
        'active_mean', 'active_std', 'active_min', 'active_max'
    ],
    "4. TCP/Control Flags & Header Features": [
        'ack_flag_cnt', 'psh_flag_cnt', 'fwd_psh_flags', 'bwd_psh_flags',
        'fin_flag_cnt', 'syn_flag_cnt', 'urg_flag_cnt', 'cwr_flag_count', 'ece_flag_cnt', 'rst_flag_cnt',
        'fwd_header_len', 'bwd_header_len',
        'init_fwd_win_byts', 'init_bwd_win_byts',
        'protocol'
    ],
    "5. Block Rate & Throughput Features": [
        'fwd_blk_rate_avg', 'bwd_blk_rate_avg'
    ],
    "6. Port & Protocol Features": [
        'src_port', 'dst_port'
    ]
}

# Keep original VPN / NonVPN names
RECOMMENDED_FEATURE_BUNDLES = {
    "VPN-Chat": [1, 2],
    "VPN-Command&Control": [1, 3],
    "VPN-FileTransfer": [1, 2, 3],
    "VPN-Streaming": [1, 2, 3],
    "VPN-VoIP": [1, 2],
    "NonVPN-Chat": [1, 4],
    "NonVPN-Command&Control": [1, 2],
    "NonVPN-FileTransfer": [1, 2],
    "NonVPN-Streaming": [1, 4],
    "NonVPN-VoIP": [1, 2],
}

# If your feature file uses short names for SLA lookup, keep these aliases:
SLA_LOOKUP_MAP = {
    'VPN-Streaming': 'VPN-Streaming (Live)',
    'VPN-Command&Control': 'VPN-Command & Control (SSH/remote ops)',
    'VPN-FileTransfer': 'VPN-FileTransfer (bulk)',
    # IMPORTANT: leave VPN-Chat mapped to itself now (standard SLA)
    'VPN-Chat': 'VPN-Chat'
}

# Meta-classes to ignore entirely
DROP_CLASS_NAMES = {'VPN-NONVPN-VPN', 'VPN-NONVPN-NonVPN'}


def parse_feature_patterns(file_path: Path):
    classes_data = {}
    current_class = None
    features = {}

    with open(file_path, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith('Class:'):
                if current_class and features and current_class not in DROP_CLASS_NAMES:
                    classes_data[current_class] = features
                current_class = line.split('Class: ', 1)[1]
                features = {}
            elif ':' in line and current_class:
                key, val = line.split(':', 1)
                key = key.strip()
                try:
                    score = float(val.strip())
                except ValueError:
                    continue
                features[key] = score

    if current_class and features and current_class not in DROP_CLASS_NAMES:
        classes_data[current_class] = features

    return classes_data


def categorize_features_for_class(features, feature_categories):
    category_scores = {}
    for category_name, category_features in feature_categories.items():
        s = 0.0
        for feat in category_features:
            if feat in features:
                s += features[feat]
        category_scores[category_name] = s
    return category_scores


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    input_file = base_dir / 'feature_patterns.txt'
    classes_data = parse_feature_patterns(input_file)
    categorized_results = {}

    for class_name, features in classes_data.items():
        # compute 6-category sums
        category_scores = categorize_features_for_class(features, FEATURE_CATEGORIES)

        # recommended bundles (if known)
        if class_name in RECOMMENDED_FEATURE_BUNDLES:
            category_scores['Recommanded'] = RECOMMENDED_FEATURE_BUNDLES[class_name]

        categorized_results[class_name] = category_scores

    output_data = {
        'metadata': {
            'generated_on': datetime.now().strftime('%d %B %Y'),
            'description': 'Feature importance patterns categorized into 6 groups for each traffic class',
            'categories': list(FEATURE_CATEGORIES.keys())
        },
        'classes': categorized_results
    }

    output_file = base_dir / 'categorized_feature_patterns.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)


if __name__ == "__main__":
    main()
