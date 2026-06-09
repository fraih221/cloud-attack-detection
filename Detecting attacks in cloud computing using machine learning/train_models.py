import os
import sys
import numpy as np
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

# Get the base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, 'Dataset')
MODELS_DIR = os.path.join(BASE_DIR, 'models')

# Create models directory if it doesn't exist
os.makedirs(MODELS_DIR, exist_ok=True)

# Import ML libraries
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier
import joblib

print("\n" + "="*80)
print("CLOUD ATTACK DETECTION SYSTEM - MODEL TRAINING")
print("="*80 + "\n")

# Load dataset
print("[1/7] Loading dataset...")
dataset_path = os.path.join(DATASET_DIR, 'UNSW_NB15_set.csv')

if not os.path.exists(dataset_path):
    print(f"ERROR: Dataset not found at {dataset_path}")
    print("Please ensure UNSW_NB15_set.csv is in the Dataset folder")
    sys.exit(1)

data = pd.read_csv(dataset_path)
print(f"✓ Dataset loaded successfully!")
print(f"  Shape: {data.shape}")
print(f"  Records: {len(data):,}")

# Data preprocessing
print("\n[2/7] Preprocessing data...")

# Drop unnecessary columns
if 'id' in data.columns:
    data = data.drop(['id'], axis=1)
if 'label' in data.columns:
    data = data.drop(['label'], axis=1)

# Convert attack categories to binary
if 'attack_cat' in data.columns:
    data['attack_cat'] = np.where(data['attack_cat'] != 'Normal', 1, 0)

# Encode categorical features
le = LabelEncoder()
categorical_columns = ['proto', 'service', 'state']

for col in categorical_columns:
    if col in data.columns:
        data[col] = le.fit_transform(data[col].astype(str))
        print(f"  ✓ Encoded: {col}")

print("✓ Data preprocessing complete!")

# Split features and target
print("\n[3/7] Splitting data...")
X = data.drop(['attack_cat'], axis=1).values
y = data['attack_cat'].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"✓ Data split complete!")
print(f"  Training set: {X_train.shape[0]:,} samples")
print(f"  Testing set: {X_test.shape[0]:,} samples")

# Feature scaling
print("\n[4/7] Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
print("✓ Features scaled successfully!")

# Train XGBoost
print("\n[5/7] Training XGBoost model...")
xgb_params = {
    'objective': 'binary:logistic',
    'max_depth': 6,
    'learning_rate': 0.1,
    'n_estimators': 200,
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'random_state': 42,
    'eval_metric': 'logloss'
}

xgb_model = XGBClassifier(**xgb_params)
xgb_model.fit(X_train_scaled, y_train)

# Evaluate XGBoost
xgb_pred = xgb_model.predict(X_test_scaled)
xgb_accuracy = accuracy_score(y_test, xgb_pred)
xgb_precision = precision_score(y_test, xgb_pred, average='weighted')
xgb_recall = recall_score(y_test, xgb_pred, average='weighted')
xgb_f1 = f1_score(y_test, xgb_pred, average='weighted')

print("✓ XGBoost training complete!")
print(f"  Accuracy:  {xgb_accuracy:.4f} ({xgb_accuracy*100:.2f}%)")
print(f"  Precision: {xgb_precision:.4f}")
print(f"  Recall:    {xgb_recall:.4f}")
print(f"  F1-Score:  {xgb_f1:.4f}")

# Train Isolation Forest
print("\n[6/7] Training Isolation Forest model...")
iso_forest = IsolationForest(
    n_estimators=100,
    contamination=0.1,
    random_state=42,
    n_jobs=-1
)

iso_forest.fit(X_train_scaled)

# Evaluate Isolation Forest
iso_pred = iso_forest.predict(X_test_scaled)
iso_pred_binary = np.where(iso_pred == -1, 1, 0)
iso_accuracy = accuracy_score(y_test, iso_pred_binary)
iso_precision = precision_score(y_test, iso_pred_binary, average='weighted')
iso_recall = recall_score(y_test, iso_pred_binary, average='weighted')
iso_f1 = f1_score(y_test, iso_pred_binary, average='weighted')

print("✓ Isolation Forest training complete!")
print(f"  Accuracy:  {iso_accuracy:.4f} ({iso_accuracy*100:.2f}%)")
print(f"  Precision: {iso_precision:.4f}")
print(f"  Recall:    {iso_recall:.4f}")
print(f"  F1-Score:  {iso_f1:.4f}")

# Save models
print("\n[7/7] Saving models...")

# Save XGBoost
xgb_path = os.path.join(MODELS_DIR, 'xgboost_model.pkl')
joblib.dump(xgb_model, xgb_path)
print(f"  ✓ XGBoost saved: {xgb_path}")

# Save Isolation Forest
iso_path = os.path.join(MODELS_DIR, 'isolation_forest_model.pkl')
joblib.dump(iso_forest, iso_path)
print(f"  ✓ Isolation Forest saved: {iso_path}")

# Save scaler
scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')
joblib.dump(scaler, scaler_path)
print(f"  ✓ Scaler saved: {scaler_path}")

# Save label encoder
le_path = os.path.join(MODELS_DIR, 'label_encoder.pkl')
joblib.dump(le, le_path)
print(f"  ✓ Label Encoder saved: {le_path}")

# Save results
results_path = os.path.join(MODELS_DIR, 'model_results.csv')
results_df = pd.DataFrame({
    'Model': ['XGBoost', 'Isolation Forest'],
    'Accuracy': [xgb_accuracy, iso_accuracy],
    'Precision': [xgb_precision, iso_precision],
    'Recall': [xgb_recall, iso_recall],
    'F1-Score': [xgb_f1, iso_f1]
})
results_df.to_csv(results_path, index=False)
print(f"  ✓ Results saved: {results_path}")

print("\n" + "="*80)
print("✓ MODEL TRAINING COMPLETED SUCCESSFULLY!")
print("="*80)
print("\nSummary:")
print(f"  • XGBoost Accuracy: {xgb_accuracy*100:.2f}%")
print(f"  • Isolation Forest Accuracy: {iso_accuracy*100:.2f}%")
print(f"  • Models saved in: {MODELS_DIR}")
print("\nYou can now run the Flask application using: python app.py")
print("="*80 + "\n")
