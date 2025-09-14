import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os
from imblearn.over_sampling import SMOTE
import matplotlib.pyplot as plt
import seaborn as sns

# Paths
dataset_dir = '../../../dataset/TOR&NonTOR'
model_dir = 'models'
os.makedirs(model_dir, exist_ok=True)

# Load the combined dataset
df_tor = pd.read_csv(os.path.join(dataset_dir, 'all_tor_traffic.csv'))
df_nontor = pd.read_csv(os.path.join(dataset_dir, 'all_non-tor_traffic.csv'))
df = pd.concat([df_tor, df_nontor], ignore_index=True)

# Remove Chat, Mail, P2P samples
df = df[~df['label'].str.contains('Chat|Mail|P2P')]

# Create category column: TOR or NonTOR
df['category'] = df['label'].apply(lambda x: 'TOR' if x.startswith('Tor-') else 'NonTOR')

# Features: all columns except label and category, and only numeric
features = df.select_dtypes(include=[float, int]).drop(['label'], axis=1, errors='ignore')
features = features.drop(['category'], axis=1, errors='ignore')

# Level 1: TOR vs NonTOR classification
X_level1 = features
y_level1 = df['category']

X_train1, X_test1, y_train1, y_test1 = train_test_split(X_level1, y_level1, test_size=0.2, random_state=42, stratify=y_level1)

model_level1 = RandomForestClassifier(n_estimators=500, random_state=42)
model_level1.fit(X_train1, y_train1)

y_pred1 = model_level1.predict(X_test1)
print("Level 1 Classification Report:")
print(classification_report(y_test1, y_pred1))

# Confusion Matrix for Level 1
cm1 = confusion_matrix(y_test1, y_pred1, normalize='true')
plt.figure(figsize=(6, 4))
sns.heatmap(cm1, annot=True, fmt='.2%', cmap='Blues', xticklabels=['NonTOR', 'TOR'], yticklabels=['NonTOR', 'TOR'])
plt.title('Level 1: TOR vs Non-TOR Confusion Matrix (Normalized)')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.savefig(os.path.join(model_dir, 'level1_confusion_matrix.png'))
plt.show()

# Save Level 1 model
joblib.dump(model_level1, os.path.join(model_dir, 'level1_model.pkl'))

# Level 2a: TOR services
df_tor = df[df['category'] == 'TOR'].copy()
df_tor['service'] = df_tor['label'].apply(lambda x: x.split('-')[1])

X_tor = df_tor.select_dtypes(include=[float, int]).drop(['label'], axis=1, errors='ignore')
X_tor = X_tor.drop(['category', 'service'], axis=1, errors='ignore')
y_tor = df_tor['service']

X_train_tor, X_test_tor, y_train_tor, y_test_tor = train_test_split(X_tor, y_tor, test_size=0.2, random_state=42, stratify=y_tor)

smote = SMOTE(random_state=42)
X_train_tor_sm, y_train_tor_sm = smote.fit_resample(X_train_tor, y_train_tor)

model_tor = RandomForestClassifier(n_estimators=500, random_state=42)
model_tor.fit(X_train_tor_sm, y_train_tor_sm)

y_pred_tor = model_tor.predict(X_test_tor)
print("TOR Services Classification Report:")
print(classification_report(y_test_tor, y_pred_tor))

# Confusion Matrix for TOR Services
cm_tor = confusion_matrix(y_test_tor, y_pred_tor, normalize='true')
plt.figure(figsize=(8, 6))
sns.heatmap(cm_tor, annot=True, fmt='.2%', cmap='Greens', xticklabels=sorted(y_tor.unique()), yticklabels=sorted(y_tor.unique()))
plt.title('TOR Services Confusion Matrix (Normalized)')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.savefig(os.path.join(model_dir, 'tor_services_confusion_matrix.png'))
plt.show()

# Save TOR model
joblib.dump(model_tor, os.path.join(model_dir, 'tor_services_model.pkl'))

# Level 2b: NonTOR services
df_nontor = df[df['category'] == 'NonTOR'].copy()
df_nontor['service'] = df_nontor['label'].apply(lambda x: x.split('-')[1])

X_nontor = df_nontor.select_dtypes(include=[float, int]).drop(['label'], axis=1, errors='ignore')
X_nontor = X_nontor.drop(['category', 'service'], axis=1, errors='ignore')
y_nontor = df_nontor['service']

X_train_nontor, X_test_nontor, y_train_nontor, y_test_nontor = train_test_split(X_nontor, y_nontor, test_size=0.2, random_state=42, stratify=y_nontor)

smote = SMOTE(random_state=42)
X_train_nontor_sm, y_train_nontor_sm = smote.fit_resample(X_train_nontor, y_train_nontor)

model_nontor = RandomForestClassifier(n_estimators=500, random_state=42)
model_nontor.fit(X_train_nontor_sm, y_train_nontor_sm)

y_pred_nontor = model_nontor.predict(X_test_nontor)
print("NonTOR Services Classification Report:")
print(classification_report(y_test_nontor, y_pred_nontor))

# Confusion Matrix for Non-TOR Services
cm_nontor = confusion_matrix(y_test_nontor, y_pred_nontor, normalize='true')
plt.figure(figsize=(6, 4))
sns.heatmap(cm_nontor, annot=True, fmt='.2%', cmap='Oranges', xticklabels=sorted(y_nontor.unique()), yticklabels=sorted(y_nontor.unique()))
plt.title('Non-TOR Services Confusion Matrix (Normalized)')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.savefig(os.path.join(model_dir, 'nontor_services_confusion_matrix.png'))
plt.show()

# Save NonTOR model
joblib.dump(model_nontor, os.path.join(model_dir, 'nontor_services_model.pkl'))

print("Models trained and saved successfully.")
