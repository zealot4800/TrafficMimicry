import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import math

# Paths
dataset_dir = '/home/zealot/ICC/Traffic Mimicry System/dataset/VPN&NonVPN'
model_dir = '/home/zealot/ICC/Traffic Mimicry System/src/classificationModel/VPN&NonVPNClassification/models'

# Load datasets
df_vpn = pd.read_csv(os.path.join(dataset_dir, 'all_traffic_vpn.csv'))
df_nonvpn = pd.read_csv(os.path.join(dataset_dir, 'all_traffic_non-vpn.csv'))
df = pd.concat([df_vpn, df_nonvpn], ignore_index=True)

# Create category column
df['category'] = df['label'].apply(lambda x: 'VPN' if x.startswith('VPN-') else 'NonVPN')

# Features
features = df.select_dtypes(include=[float, int]).drop(['label'], axis=1, errors='ignore')
features = features.drop(['category'], axis=1, errors='ignore')
feature_names = features.columns.tolist()

# Load models
level1_model = joblib.load(os.path.join(model_dir, 'level1_model.pkl'))
vpn_model = joblib.load(os.path.join(model_dir, 'vpn_services_model.pkl'))
nonvpn_model = joblib.load(os.path.join(model_dir, 'nonvpn_services_model.pkl'))

def get_class_patterns(X, y, classes, model_name, output_file):
    output_file.write(f"\n=== {model_name} Class Patterns ===\n")
    for cls in classes:
        output_file.write(f"\nClass: {cls}\n")
        # Create binary labels
        y_binary = (y == cls).astype(int)

        # Train one-vs-rest classifier
        ovr_model = RandomForestClassifier(n_estimators=100, random_state=42)
        ovr_model.fit(X, y_binary)

        # Get feature importances
        importances = ovr_model.feature_importances_
        indices = np.argsort(importances)[::-1]

        # Top 10 features
        top_features = [feature_names[i] for i in indices[:20]]
        top_importances = importances[indices[:20]]

        output_file.write("Top 20 important features (softmax normalized 0-1):\n")
        # Apply softmax to the top importances
        exp_importances = [math.exp(imp) for imp in top_importances]
        sum_exp = sum(exp_importances)
        softmax_scores = [exp_imp / sum_exp for exp_imp in exp_importances]

        for feat, score in zip(top_features, softmax_scores):
            output_file.write(f"{feat}: {score:.3f}\n")

        avg_score = sum(softmax_scores) / len(softmax_scores) if softmax_scores else 0
        output_file.write(f"Average score: {avg_score:.3f}\n")
        output_file.write(f"Total sum: {sum(softmax_scores):.3f}\n")

# Open output file
with open('/home/zealot/ICC/Traffic Mimicry System/src/classificationModel/VPN&NonVPNClassification/utils/feature_patterns.txt', 'w') as f:
    f.write("TRAFFIC MIMICRY SYSTEM - FEATURE IMPORTANCE PATTERNS\n")
    f.write("=" * 60 + "\n")
    f.write("Generated on: 14 September 2025\n")
    f.write("This file contains the softmax-normalized feature importance patterns for each traffic class.\n")
    f.write("Each score represents the relative importance as a probability (0-1 scale).\n")
    f.write("The top 10 features for each class sum to 1.000.\n\n")

    # Level 1: VPN vs NonVPN
    X_level1 = features
    y_level1 = df['category']
    classes_level1 = ['VPN', 'NonVPN']
    get_class_patterns(X_level1, y_level1, classes_level1, "Level 1: VPN vs NonVPN", f)

    # VPN Services
    df_vpn_only = df[df['category'] == 'VPN'].copy()
    df_vpn_only['service'] = df_vpn_only['label'].apply(lambda x: x.split('-')[1])
    X_vpn = df_vpn_only.select_dtypes(include=[float, int]).drop(['label'], axis=1, errors='ignore')
    X_vpn = X_vpn.drop(['category', 'service'], axis=1, errors='ignore')
    y_vpn = df_vpn_only['service']
    classes_vpn = ['Chat', 'Command&Control', 'FileTransfer', 'Streaming', 'VoIP']
    get_class_patterns(X_vpn, y_vpn, classes_vpn, "VPN Services", f)

    # NonVPN Services
    df_nonvpn_only = df[df['category'] == 'NonVPN'].copy()
    df_nonvpn_only['service'] = df_nonvpn_only['label'].apply(lambda x: x.split('-')[1] if '-' in x else x)
    X_nonvpn = df_nonvpn_only.select_dtypes(include=[float, int]).drop(['label'], axis=1, errors='ignore')
    X_nonvpn = X_nonvpn.drop(['category', 'service'], axis=1, errors='ignore')
    y_nonvpn = df_nonvpn_only['service']
    classes_nonvpn = ['Chat', 'Command&Control', 'FileTransfer', 'Streaming', 'VoIP']
    get_class_patterns(X_nonvpn, y_nonvpn, classes_nonvpn, "NonVPN Services", f)

    f.write("\n" + "=" * 60 + "\n")
    f.write("END OF FEATURE PATTERNS REPORT\n")

print("Feature patterns have been saved to: /home/zealot/ICC/Traffic Mimicry System/src/classificationModel/VPN&NonVPNClassification/utils/feature_patterns.txt")
