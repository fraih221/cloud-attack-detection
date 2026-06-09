# ============================================================================
# CLOUD ATTACK DETECTION SYSTEM - CONFIGURATION FILE
# ============================================================================

import os

# Base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Directories
DATASET_DIR = os.path.join(BASE_DIR, 'Dataset')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
STATIC_DIR = os.path.join(BASE_DIR, 'static')
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',  # Change this if you have a password
    'database': 'cloud_attack_detection'
}

# Flask configuration
FLASK_CONFIG = {
    'SECRET_KEY': 'cloud_attack_detection_secret_key_2026',
    'DEBUG': True,
    'HOST': '0.0.0.0',
    'PORT': 5000
}

# Model configuration
MODEL_CONFIG = {
    'xgboost': {
        'objective': 'binary:logistic',
        'max_depth': 6,
        'learning_rate': 0.1,
        'n_estimators': 200,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'random_state': 42,
        'eval_metric': 'logloss'
    },
    'isolation_forest': {
        'n_estimators': 100,
        'contamination': 0.1,
        'random_state': 42,
        'n_jobs': -1
    }
}

# Dataset configuration
DATASET_CONFIG = {
    'test_size': 0.2,
    'random_state': 42,
    'stratify': True
}

# File paths
DATASET_PATH = os.path.join(DATASET_DIR, 'UNSW_NB15_set.csv')
XGBOOST_MODEL_PATH = os.path.join(MODELS_DIR, 'xgboost_model.pkl')
ISOLATION_FOREST_MODEL_PATH = os.path.join(MODELS_DIR, 'isolation_forest_model.pkl')
SCALER_PATH = os.path.join(MODELS_DIR, 'scaler.pkl')
LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, 'label_encoder.pkl')
RESULTS_PATH = os.path.join(MODELS_DIR, 'model_results.csv')

# Create directories if they don't exist
for directory in [DATASET_DIR, MODELS_DIR, STATIC_DIR, TEMPLATES_DIR]:
    os.makedirs(directory, exist_ok=True)

# Logging configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'default': {
            'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'default'
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'app.log'),
            'formatter': 'default'
        }
    },
    'root': {
        'level': 'INFO',
        'handlers': ['console', 'file']
    }
}

# Feature names (will be loaded from dataset)
FEATURE_NAMES = []

# API configuration
API_CONFIG = {
    'rate_limit': '100 per hour',
    'cors_origins': '*'
}

# Security configuration
SECURITY_CONFIG = {
    'session_lifetime': 3600,  # 1 hour in seconds
    'password_min_length': 6,
    'max_login_attempts': 5
}

print("Configuration loaded successfully!")
