import pandas as pd
import numpy as np
import xgboost as xgb
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
import joblib
import os

def train():
    # 1. Load Dataset
    dataset_path = 'Detecting attacks in cloud computing using machine learning/Dataset/UNSW_NB15_set.csv'
    if not os.path.exists(dataset_path):
        print(f"Dataset not found at {dataset_path}")
        return
    
    data = pd.read_csv(dataset_path)
    
    # 2. Preprocessing (Based on Notebook)
    # Drop irrelevant columns if they exist
    cols_to_drop = ['id', 'label']
    for col in cols_to_drop:
        if col in data.columns:
            data = data.drop(col, axis=1)
            
    # Simplify attack categories
    if 'attack_cat' in data.columns:
        data["attack_cat"] = np.where(data["attack_cat"] != "Normal", 'Attacks&malicious', 'Normal')
    
    # Encoding
    le_dict = {}
    categorical_cols = ['proto', 'service', 'state', 'attack_cat']
    for col in categorical_cols:
        if col in data.columns:
            le = LabelEncoder()
            data[col] = le.fit_transform(data[col])
            le_dict[col] = le
            
    # 3. Splitting
    X = data.drop(['attack_cat'], axis=1)
    y = data['attack_cat']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 4. Train XGBoost (From Notebook)
    params = {
        'objective': 'binary:logistic',
        'max_depth': 4,
        'alpha': 10,
        'learning_rate': 1.0,
        'n_estimators': 600
    }
    xgb_model = XGBClassifier(**params)
    xgb_model.fit(X_train, y_train)
    
    # Verify
    preds = xgb_model.predict(X_test)
    print(f"XGBoost Accuracy: {accuracy_score(y_test, preds):.4f}")
    
    # 5. Isolation Forest (Requested in prompt, though not explicitly in notebook snippet, but added for Hybrid approach)
    from sklearn.ensemble import IsolationForest
    iso_forest = IsolationForest(contamination=0.1, random_state=42)
    iso_forest.fit(X_train)
    
    # 6. Save Models
    os.makedirs('models', exist_ok=True)
    joblib.dump(xgb_model, 'models/xgboost_model.pkl')
    joblib.dump(iso_forest, 'models/isolation_forest_model.pkl')
    joblib.dump(le_dict, 'models/label_encoders.pkl')
    joblib.dump(X.columns.tolist(), 'models/feature_names.pkl')
    
    print("Models saved successfully in models/ directory.")

if __name__ == "__main__":
    train()
