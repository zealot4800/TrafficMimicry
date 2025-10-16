import os
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

# Paths
dataset_dir = '/home/zealot/ICC/TrafficMimicrySystem/dataset/CSV-Dataset/Vpn&NonVpn'
model_dir = Path(__file__).resolve().parent / "models"
model_dir.mkdir(parents=True, exist_ok=True)

# Load the combined dataset
df_vpn = pd.read_csv(os.path.join(dataset_dir, 'all_traffic_vpn.csv'))
df_nonvpn = pd.read_csv(os.path.join(dataset_dir, 'all_traffic_non-vpn.csv'))
df = pd.concat([df_vpn, df_nonvpn], ignore_index=True)

# Create category column: VPN or NonVPN
df['label'] = df['label'].astype(str)
df['category'] = df['label'].apply(lambda x: 'VPN' if x.startswith('VPN-') else 'NonVPN')

def _select_numeric_features(frame: pd.DataFrame, drop_columns: list[str]) -> pd.DataFrame:
    """Select clean numeric feature columns from the provided frame."""
    working = frame.drop(columns=drop_columns, errors='ignore').copy()
    numeric = working.select_dtypes(include=[float, int])
    numeric.columns = [col.strip() for col in numeric.columns]
    numeric = numeric.loc[:, ~numeric.columns.duplicated()]
    numeric = numeric.replace([np.inf, -np.inf], np.nan)
    numeric = numeric.dropna(axis=1, how='all')
    return numeric


# Features: all columns except label and category, and only numeric
features = _select_numeric_features(df, ['label', 'category'])


def impute_train_test(X_train, X_test):
    """Impute missing values using the median of the training split."""
    valid_columns = X_train.columns[~X_train.isna().all()]
    X_train = X_train[valid_columns]
    X_test = X_test.reindex(columns=valid_columns)

    imputer = SimpleImputer(strategy='median')
    X_train_imputed = pd.DataFrame(
        imputer.fit_transform(X_train),
        columns=X_train.columns,
        index=X_train.index,
    )
    X_test_imputed = pd.DataFrame(
        imputer.transform(X_test),
        columns=X_test.columns,
        index=X_test.index,
    )
    return X_train_imputed, X_test_imputed

# Level 1: VPN vs NonVPN classification
X_level1 = features
y_level1 = df['category']

X_train1, X_test1, y_train1, y_test1 = train_test_split(X_level1, y_level1, test_size=0.2, random_state=42, stratify=y_level1)
X_train1, X_test1 = impute_train_test(X_train1, X_test1)

model_level1 = RandomForestClassifier(n_estimators=500, random_state=42)
model_level1.fit(X_train1, y_train1)

y_pred1 = model_level1.predict(X_test1)
print("Level 1 Classification Report:")
print(classification_report(y_test1, y_pred1))

# Confusion Matrix for Level 1
cm1 = confusion_matrix(y_test1, y_pred1, normalize='true')
plt.figure(figsize=(6, 4))
sns.heatmap(cm1, annot=True, fmt='.2%', cmap='Blues', xticklabels=['NonVPN', 'VPN'], yticklabels=['NonVPN', 'VPN'])
plt.title('Level 1: VPN vs Non-VPN Confusion Matrix (Normalized)')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.savefig(model_dir / 'level1_confusion_matrix.png')
plt.show()

# Save Level 1 model
joblib.dump(model_level1, model_dir / 'level1_model.pkl')

# Level 2a: VPN services
df_vpn = df[df['category'] == 'VPN'].copy()
df_vpn['service'] = df_vpn['label'].apply(lambda x: x.split('-')[1])

X_vpn = _select_numeric_features(df_vpn, ['label', 'category', 'service'])
y_vpn = df_vpn['service']

X_train_vpn, X_test_vpn, y_train_vpn, y_test_vpn = train_test_split(X_vpn, y_vpn, test_size=0.2, random_state=42, stratify=y_vpn)
X_train_vpn, X_test_vpn = impute_train_test(X_train_vpn, X_test_vpn)

smote = SMOTE(random_state=42)
X_train_vpn_sm, y_train_vpn_sm = smote.fit_resample(X_train_vpn, y_train_vpn)

model_vpn = RandomForestClassifier(n_estimators=500, random_state=42)
model_vpn.fit(X_train_vpn_sm, y_train_vpn_sm)

y_pred_vpn = model_vpn.predict(X_test_vpn)
print("VPN Services Classification Report:")
print(classification_report(y_test_vpn, y_pred_vpn))

# Confusion Matrix for VPN Services
cm_vpn = confusion_matrix(y_test_vpn, y_pred_vpn, normalize='true')
plt.figure(figsize=(8, 6))
sns.heatmap(cm_vpn, annot=True, fmt='.2%', cmap='Greens', xticklabels=sorted(y_vpn.unique()), yticklabels=sorted(y_vpn.unique()))
plt.title('VPN Services Confusion Matrix (Normalized)')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.savefig(model_dir / 'vpn_services_confusion_matrix.png')
plt.show()

# Save VPN model
joblib.dump(model_vpn, model_dir / 'vpn_services_model.pkl')

# Level 2b: NonVPN services
df_nonvpn = df[df['category'] == 'NonVPN'].copy()
df_nonvpn['service'] = df_nonvpn['label'].apply(lambda x: x.split('-')[1] if '-' in x else x)

X_nonvpn = _select_numeric_features(df_nonvpn, ['label', 'category', 'service'])
y_nonvpn = df_nonvpn['service']

X_train_nonvpn, X_test_nonvpn, y_train_nonvpn, y_test_nonvpn = train_test_split(X_nonvpn, y_nonvpn, test_size=0.2, random_state=42, stratify=y_nonvpn)
X_train_nonvpn, X_test_nonvpn = impute_train_test(X_train_nonvpn, X_test_nonvpn)

smote = SMOTE(random_state=42)
X_train_nonvpn_sm, y_train_nonvpn_sm = smote.fit_resample(X_train_nonvpn, y_train_nonvpn)

model_nonvpn = RandomForestClassifier(n_estimators=500, random_state=42)
model_nonvpn.fit(X_train_nonvpn_sm, y_train_nonvpn_sm)

y_pred_nonvpn = model_nonvpn.predict(X_test_nonvpn)
print("NonVPN Services Classification Report:")
print(classification_report(y_test_nonvpn, y_pred_nonvpn))

# Confusion Matrix for Non-VPN Services
cm_nonvpn = confusion_matrix(y_test_nonvpn, y_pred_nonvpn, normalize='true')
plt.figure(figsize=(6, 4))
sns.heatmap(cm_nonvpn, annot=True, fmt='.2%', cmap='Oranges', xticklabels=sorted(y_nonvpn.unique()), yticklabels=sorted(y_nonvpn.unique()))
plt.title('Non-VPN Services Confusion Matrix (Normalized)')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.savefig(model_dir / 'nonvpn_services_confusion_matrix.png')
plt.show()

# Save NonVPN model
joblib.dump(model_nonvpn, model_dir / 'nonvpn_services_model.pkl')

print("Models trained and saved successfully.")
