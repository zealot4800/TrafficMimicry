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


SLA_CONSTRAINTS = {
    "VPN-VoIP": {
        "duration_sec": 10.0,
        "pps_min": 40.0,
        "pps_max": 60.0,
        "mean_iat_ms_min": 20.0,
        "mean_iat_ms_max": 25.0,
        "stdev_iat_ms_max": 5.0,
    },
    "VPN-Streaming (Live)": {
        "duration_sec": 5.0,
        "pps_min": 400.0,
        "pps_max": 1000.0,
        "mean_iat_ms_min": 1.0,
        "mean_iat_ms_max": 2.5,
        "stdev_iat_ms_max": 3.0,
    },
    "VPN-Streaming (VOD)": {
        "duration_sec": 30.0,
        "pps_min": 250.0,
        "pps_max": 800.0,
        "mean_iat_ms_min": 1.25,
        "mean_iat_ms_max": 4.0,
        "stdev_iat_ms_max": 10.0,
    },
    "VPN-Chat (text/IM)": {
        "duration_sec": 60.0,
        "avg_mode": {
            "pps_max": 2.0,
            "mean_iat_ms_min": 500.0,
        },
        "burst_mode": {
            "duration_sec_max": 3.0,
            "pps_min": 5.0,
            "pps_max": 20.0,
            "mean_iat_ms_min": 50.0,
            "mean_iat_ms_max": 200.0,
            "stdev_iat_ms_max": 20.0,
        },
        "stdev_breach_ms_max": 20.0,
    },
    "VPN-Command & Control (SSH/remote ops)": {
        "duration_sec": 2.0,
        "pps_min": 10.0,
        "pps_max": 50.0,
        "mean_iat_ms_min": 20.0,
        "mean_iat_ms_max": 100.0,
        "stdev_iat_ms_max": 10.0,
    },
    "VPN-FileTransfer (bulk)": {
        "duration_sec": 10.0,
        "pps_min": 200.0,
        "pps_max": 2000.0,
        "mean_iat_ms_min": 0.5,
        "mean_iat_ms_max": 5.0,
        "stdev_iat_ms_max": 10.0,
    },
}


def parse_feature_patterns(file_path):
    classes_data = {}
    current_class = None
    features = {}
    
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('Class:'):
                if current_class and features:
                    classes_data[current_class] = features
                current_class = line.split('Class: ')[1]
                features = {}
            elif ':' in line and current_class:
                parts = line.split(': ')
                if len(parts) == 2:
                    feature_name = parts[0]
                    try:
                        score = float(parts[1])
                        features[feature_name] = score
                    except ValueError:
                        continue
    
    if current_class and features:
        classes_data[current_class] = features
    
    return classes_data

def categorize_features_for_class(features, feature_categories):
    category_scores = {}
    for category_name, category_features in feature_categories.items():
        category_feature_scores = []
        
        for feature in category_features:
            if feature in features:
                category_feature_scores.append(features[feature])
        
        if category_feature_scores:
            category_scores[category_name] = sum(category_feature_scores) 
        else:
            category_scores[category_name] = 0.0
    
    return category_scores

def main() -> None:
    base_dir = Path(__file__).resolve().parent
    input_file = base_dir / 'feature_patterns.txt'
    classes_data = parse_feature_patterns(input_file)
    categorized_results = {}

    for class_name, features in classes_data.items():
        category_scores = categorize_features_for_class(features, FEATURE_CATEGORIES)
        if class_name in RECOMMENDED_FEATURE_BUNDLES:
            category_scores['Recommanded'] = RECOMMENDED_FEATURE_BUNDLES[class_name]
        sla_key = class_name
        if sla_key not in SLA_CONSTRAINTS and class_name in (
            'VPN-Streaming',
            'VPN-Command&Control',
            'VPN-FileTransfer',
            'VPN-Chat',
        ):
            sla_lookup = {
                'VPN-Streaming': 'VPN-Streaming (Live)',
                'VPN-Command&Control': 'VPN-Command & Control (SSH/remote ops)',
                'VPN-FileTransfer': 'VPN-FileTransfer (bulk)',
                'VPN-Chat': 'VPN-Chat (text/IM)',
            }
            sla_key = sla_lookup.get(class_name, class_name)
        if sla_key in SLA_CONSTRAINTS:
            category_scores['sla_constraints'] = SLA_CONSTRAINTS[sla_key]
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
