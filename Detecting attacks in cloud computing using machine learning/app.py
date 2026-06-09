import os
import sys
import json
import pymysql
import pymysql.cursors
import random
import hashlib
import functools
import numpy as np
import pandas as pd
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import joblib
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
DATASET_DIR = os.path.join(BASE_DIR, 'Dataset')

MYSQL_HOST = os.environ.get('MYSQL_HOST', '127.0.0.1')
MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'root')
MYSQL_DATABASE = os.environ.get('MYSQL_DATABASE', 'cloud_attack_db')
MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))
MYSQL_SOCKET = os.environ.get('MYSQL_SOCKET', '/tmp/mysql.sock')

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'cloud_attack_detection_secret_key_2026')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
CORS(app)


def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def verify_password(password, hashed):
    if len(hashed) == 64:
        return hash_password(password) == hashed
    return password == hashed


def login_required_api(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

xgboost_model = None
isolation_forest_model = None
scaler = None
label_encoder = None
feature_names = None
label_encoders_dict = None
model_feature_importance = None

ATTACK_TYPES = ['Generic', 'Exploits', 'Fuzzers', 'DoS', 'Reconnaissance', 'Analysis', 'Backdoor', 'Shellcode', 'Worms']
SEVERITY_MAP = {
    'Generic': 'Medium', 'Exploits': 'Critical', 'Fuzzers': 'Low',
    'DoS': 'High', 'Reconnaissance': 'Low', 'Analysis': 'Low',
    'Backdoor': 'Critical', 'Shellcode': 'Critical', 'Worms': 'High'
}

ATTACK_DESCRIPTIONS = {
    'Generic': 'General attack pattern that does not fit specific categories. Often involves port scanning or protocol abuse.',
    'Exploits': 'Exploitation of known vulnerabilities in software or systems to gain unauthorized access or execute code.',
    'Fuzzers': 'Automated testing with random/malformed data to find crashes, memory leaks, or assertion failures.',
    'DoS': 'Denial of Service attack aimed at overwhelming network resources and disrupting service availability.',
    'Reconnaissance': 'Network scanning and information gathering to identify targets and vulnerabilities.',
    'Analysis': 'Port scan, spam, and HTML attacks used for probing and intelligence gathering.',
    'Backdoor': 'Covert channel providing unauthorized remote access, bypassing authentication mechanisms.',
    'Shellcode': 'Injection of executable code into running processes, often exploiting buffer overflows.',
    'Worms': 'Self-replicating malware that spreads across networks without user interaction.'
}

MITIGATION_STRATEGIES = {
    'Generic': ['Implement network segmentation', 'Deploy intrusion prevention systems', 'Enable deep packet inspection', 'Update firewall rules'],
    'Exploits': ['Apply security patches immediately', 'Use WAF (Web Application Firewall)', 'Enable virtual patching', 'Conduct vulnerability scanning'],
    'Fuzzers': ['Implement input validation', 'Deploy rate limiting', 'Enable request size limits', 'Use anomaly-based IDS'],
    'DoS': ['Enable DDoS protection', 'Configure rate limiting', 'Use CDN with DDoS mitigation', 'Implement traffic shaping'],
    'Reconnaissance': ['Disable ICMP responses', 'Implement port knocking', 'Use honeypots for detection', 'Enable stealth mode on firewalls'],
    'Analysis': ['Block suspicious scanning IPs', 'Implement CAPTCHA for web services', 'Enable threat intelligence feeds', 'Deploy behavioral analytics'],
    'Backdoor': ['Conduct full system audit', 'Monitor outbound connections', 'Implement application whitelisting', 'Deploy endpoint detection and response'],
    'Shellcode': ['Enable DEP and ASLR', 'Use code integrity checks', 'Deploy memory protection', 'Implement execution prevention policies'],
    'Worms': ['Isolate affected network segments', 'Update antivirus signatures', 'Disable unnecessary services', 'Implement network quarantine']
}

ATTACK_SIMULATION_PROFILES = {
    'DoS': [0.000001, 113.0, 0.0, 3.0, 500.0, 2.0, 50000.0, 100.0, 999999.0, 254.0, 0.0, 500000.0, 50.0, 0.0, 0.0, 0.000001, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 200.0, 0.0, 0.0, 0.0, 4.0, 2.0, 1.0, 1.0, 1.0, 4.0, 0.0, 0.0, 0.0, 2.0, 4.0, 0.0],
    'Reconnaissance': [0.000005, 20.0, 0.0, 3.0, 80.0, 0.0, 40.0, 0.0, 16000000.0, 254.0, 0.0, 8000000.0, 0.0, 0.0, 0.0, 0.000005, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 4.0, 2.0, 1.0, 1.0, 1.0, 80.0, 0.0, 0.0, 0.0, 2.0, 4.0, 0.0],
    'Exploits': [15.5, 113.0, 0.0, 2.0, 10.0, 8.0, 500.0, 8000.0, 1.29, 31.0, 252.0, 32.26, 516.13, 0.0, 0.0, 15.5, 50.0, 800.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 50.0, 1000.0, 0.0, 0.0, 43.0, 1.0, 1.0, 1.0, 1.0, 2.0, 0.0, 0.0, 0.0, 1.0, 6.0, 0.0],
    'Backdoor': [120.0, 113.0, 0.0, 2.0, 3.0, 3.0, 80.0, 60.0, 0.05, 252.0, 252.0, 26.67, 20.0, 0.0, 0.0, 120.0, 26.67, 20.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 27.0, 20.0, 0.0, 0.0, 43.0, 1.0, 1.0, 1.0, 1.0, 2.0, 0.0, 0.0, 0.0, 1.0, 6.0, 0.0],
    'Generic': [0.5, 113.0, 0.0, 2.0, 20.0, 15.0, 3000.0, 2000.0, 70.0, 252.0, 252.0, 150.0, 133.33, 0.0, 17.0, 0.5, 150.0, 133.33, 1500.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 150.0, 133.33, 0.0, 0.0, 43.0, 1.0, 1.0, 1.0, 1.0, 2.0, 0.0, 0.0, 0.0, 1.0, 6.0, 0.0],
    'Shellcode': [0.2, 113.0, 0.0, 2.0, 5.0, 3.0, 800.0, 200.0, 40.0, 252.0, 252.0, 160.0, 66.67, 0.0, 0.0, 0.2, 160.0, 66.67, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 160.0, 66.67, 0.0, 0.0, 43.0, 1.0, 1.0, 1.0, 1.0, 2.0, 0.0, 0.0, 0.0, 1.0, 6.0, 0.0],
    'Fuzzers': [1.0, 113.0, 0.0, 2.0, 30.0, 10.0, 3500.0, 500.0, 40.0, 252.0, 252.0, 116.67, 50.0, 0.0, 0.0, 1.0, 116.67, 50.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 116.67, 50.0, 0.0, 0.0, 43.0, 1.0, 1.0, 1.0, 1.0, 2.0, 0.0, 0.0, 0.0, 1.0, 6.0, 0.0],
    'Worms': [0.8, 113.0, 0.0, 2.0, 50.0, 30.0, 4000.0, 3000.0, 100.0, 252.0, 0.0, 80.0, 100.0, 0.0, 0.0, 0.8, 80.0, 100.0, 2000.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 80.0, 100.0, 0.0, 0.0, 43.0, 1.0, 1.0, 1.0, 1.0, 2.0, 0.0, 0.0, 0.0, 1.0, 6.0, 0.0],
    'Analysis': [2.0, 20.0, 0.0, 3.0, 3.0, 2.0, 150.0, 100.0, 2.5, 252.0, 252.0, 50.0, 50.0, 0.0, 0.0, 2.0, 50.0, 50.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 50.0, 50.0, 0.0, 0.0, 43.0, 1.0, 1.0, 1.0, 1.0, 2.0, 0.0, 0.0, 0.0, 1.0, 6.0, 0.0],
}

def get_db_connection():
    conn = pymysql.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE,
        port=MYSQL_PORT,
        unix_socket=MYSQL_SOCKET if os.path.exists(MYSQL_SOCKET) else None,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
        charset='utf8mb4'
    )
    return conn

def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            full_name VARCHAR(255) DEFAULT '',
            role VARCHAR(50) DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN full_name VARCHAR(255) DEFAULT '' AFTER password")
    except Exception:
        pass

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS predictions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            prediction_result VARCHAR(50),
            attack_type VARCHAR(100) DEFAULT 'N/A',
            severity VARCHAR(50) DEFAULT 'N/A',
            confidence DOUBLE,
            xgboost_result VARCHAR(50),
            isolation_forest_result VARCHAR(50),
            anomaly_score DOUBLE DEFAULT 0.0,
            risk_score DOUBLE DEFAULT 0.0,
            model_used VARCHAR(100),
            features_data TEXT,
            shap_values TEXT,
            prediction_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            attack_type VARCHAR(100),
            severity VARCHAR(50),
            source_ip VARCHAR(45),
            destination_ip VARCHAR(45),
            protocol VARCHAR(20),
            confidence DOUBLE DEFAULT 0.0,
            risk_score DOUBLE DEFAULT 0.0,
            anomaly_score DOUBLE DEFAULT 0.0,
            features_summary TEXT,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(50) DEFAULT 'detected'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_stats (
            id INT AUTO_INCREMENT PRIMARY KEY,
            total_predictions INT DEFAULT 0,
            total_attacks_detected INT DEFAULT 0,
            total_normal_traffic INT DEFAULT 0,
            accuracy_rate DOUBLE DEFAULT 0.0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS model_performance (
            id INT AUTO_INCREMENT PRIMARY KEY,
            model_name VARCHAR(255),
            accuracy DOUBLE,
            precision_score DOUBLE,
            recall_score DOUBLE,
            f1_score DOUBLE,
            evaluation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_settings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            setting_key VARCHAR(255) UNIQUE NOT NULL,
            setting_value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("SELECT COUNT(*) AS cnt FROM system_stats")
    if cursor.fetchone()['cnt'] == 0:
        cursor.execute("""
            INSERT INTO system_stats (total_predictions, total_attacks_detected, total_normal_traffic, accuracy_rate)
            VALUES (0, 0, 0, 0.0)
        """)

    cursor.execute("SELECT COUNT(*) AS cnt FROM users WHERE username = 'admin' OR email = 'admin@cloudattack.com'")
    if cursor.fetchone()['cnt'] == 0:
        try:
            cursor.execute("""
                INSERT INTO users (username, email, password, full_name, role)
                VALUES ('admin', 'admin@cloudattack.com', %s, 'Security Admin', 'admin')
            """, (hash_password('admin123'),))
            print("Default admin user created (username: admin, password: admin123)")
        except Exception:
            pass
    else:
        cursor.execute("SELECT password FROM users WHERE username = 'admin'")
        row = cursor.fetchone()
        if row and len(row['password']) < 64:
            cursor.execute("UPDATE users SET password = %s WHERE username = 'admin'", (hash_password(row['password']),))

    defaults = [
        ('detection_threshold', '75'),
        ('auto_block', 'true'),
        ('alert_level', 'all'),
        ('active_model', 'hybrid'),
    ]
    for key, val in defaults:
        cursor.execute("INSERT IGNORE INTO system_settings (setting_key, setting_value) VALUES (%s, %s)", (key, val))

    load_model_performance(cursor)

    conn.commit()
    cursor.close()
    conn.close()
    print("All tables created successfully!")
    return True

def load_model_performance(cursor):
    cursor.execute("SELECT COUNT(*) AS cnt FROM model_performance")
    if cursor.fetchone()['cnt'] == 0:
        results_path = os.path.join(MODELS_DIR, 'model_results.csv')
        if os.path.exists(results_path):
            df = pd.read_csv(results_path)
            for _, row in df.iterrows():
                cursor.execute("""
                    INSERT INTO model_performance (model_name, accuracy, precision_score, recall_score, f1_score)
                    VALUES (%s, %s, %s, %s, %s)
                """, (row.get('Model', 'Unknown'),
                      row.get('Accuracy', 0),
                      row.get('Precision', 0),
                      row.get('Recall', 0),
                      row.get('F1-Score', 0)))

def load_models():
    global xgboost_model, isolation_forest_model, scaler, label_encoder, feature_names, label_encoders_dict, model_feature_importance

    try:
        xgb_path = os.path.join(MODELS_DIR, 'xgboost_model.pkl')
        if os.path.exists(xgb_path):
            xgboost_model = joblib.load(xgb_path)
            print("XGBoost model loaded successfully!")

        iso_path = os.path.join(MODELS_DIR, 'isolation_forest_model.pkl')
        if os.path.exists(iso_path):
            isolation_forest_model = joblib.load(iso_path)
            print("Isolation Forest model loaded successfully!")

        scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')
        if os.path.exists(scaler_path):
            scaler = joblib.load(scaler_path)
            print("Scaler loaded successfully!")

        le_path = os.path.join(MODELS_DIR, 'label_encoder.pkl')
        if os.path.exists(le_path):
            label_encoder = joblib.load(le_path)
            print("Label Encoder loaded successfully!")

        le_dict_path = os.path.join(MODELS_DIR, 'label_encoders.pkl')
        if os.path.exists(le_dict_path):
            label_encoders_dict = joblib.load(le_dict_path)
            print("Label Encoders dict loaded successfully!")

        dataset_path = os.path.join(DATASET_DIR, 'UNSW_NB15_set.csv')
        if os.path.exists(dataset_path):
            df = pd.read_csv(dataset_path, nrows=1)
            feature_names = [col for col in df.columns if col not in ['id', 'label', 'attack_cat']]
            print(f"Feature names loaded: {len(feature_names)} features")
        else:
            feature_names = []

        if xgboost_model is not None:
            try:
                importances = xgboost_model.feature_importances_
                if feature_names and len(importances) == len(feature_names):
                    fi = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
                    model_feature_importance = fi
                    print(f"Feature importance extracted: top feature = {fi[0][0]}")
            except Exception as e:
                print(f"Could not extract feature importance: {e}")

        return True
    except Exception as e:
        print(f"Error loading models: {e}")
        return False

def compute_risk_score(confidence, anomaly_score, is_attack):
    if not is_attack:
        return round(max(0, (1 - confidence) * 30 + abs(anomaly_score) * 10), 2)
    base = confidence * 70
    anomaly_factor = max(0, -anomaly_score) * 15 if anomaly_score < 0 else 0
    return round(min(100, base + anomaly_factor + 10), 2)

def classify_attack_type(features_array, confidence):
    if features_array is None or len(features_array) == 0:
        return random.choice(ATTACK_TYPES)
    feat = features_array.flatten()
    dur = feat[0] if len(feat) > 0 else 0
    sbytes = feat[6] if len(feat) > 6 else 0
    dbytes = feat[7] if len(feat) > 7 else 0
    spkts = feat[4] if len(feat) > 4 else 0
    dpkts = feat[5] if len(feat) > 5 else 0
    rate = feat[12] if len(feat) > 12 else 0

    if sbytes > 10000 and spkts > 100:
        return 'DoS'
    elif dur < 0.01 and spkts > 50:
        return 'Reconnaissance'
    elif dbytes > 5000 and dur > 10:
        return 'Exploits'
    elif sbytes < 100 and dbytes < 100 and dur > 5:
        return 'Backdoor'
    elif rate > 1000:
        return 'Generic'
    elif sbytes > 500 and dur < 0.5:
        return 'Shellcode'
    elif spkts < 5 and dpkts < 5:
        return 'Analysis'
    elif sbytes > 2000:
        return 'Fuzzers'
    else:
        return 'Generic'

def generate_ip():
    return f"{random.randint(10,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def compute_threat_level(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as c FROM attack_logs WHERE detected_at >= NOW() - INTERVAL 1 HOUR")
    last_hour = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM attack_logs WHERE severity IN ('High','Critical') AND detected_at >= NOW() - INTERVAL 1 HOUR")
    critical_hour = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM attack_logs WHERE status = 'detected'")
    active = cursor.fetchone()['c']
    cursor.execute("SELECT AVG(risk_score) as avg_risk FROM attack_logs WHERE detected_at >= NOW() - INTERVAL 24 HOUR")
    row = cursor.fetchone()
    avg_risk = row['avg_risk'] if row['avg_risk'] else 0

    score = min(100, (last_hour * 8) + (critical_hour * 15) + (active * 3) + avg_risk * 0.5)

    if score >= 80:
        level = 'Critical'
        color = '#ef4444'
    elif score >= 60:
        level = 'High'
        color = '#f97316'
    elif score >= 35:
        level = 'Medium'
        color = '#f59e0b'
    elif score >= 10:
        level = 'Low'
        color = '#10b981'
    else:
        level = 'Minimal'
        color = '#06b6d4'

    return {
        'score': round(score, 1),
        'level': level,
        'color': color,
        'attacks_last_hour': last_hour,
        'critical_last_hour': critical_hour,
        'active_threats': active,
        'avg_risk_24h': round(avg_risk, 1)
    }

def generate_security_recommendations(conn):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT attack_type, COUNT(*) as cnt, AVG(risk_score) as avg_risk
        FROM attack_logs
        WHERE detected_at >= NOW() - INTERVAL 7 DAY
        GROUP BY attack_type
        ORDER BY cnt DESC
    """)
    attack_stats = cursor.fetchall()

    recommendations = []
    for stat in attack_stats:
        at = stat['attack_type']
        cnt = stat['cnt']
        avg_risk = stat['avg_risk'] or 0
        strategies = MITIGATION_STRATEGIES.get(at, ['Monitor and investigate'])
        priority = 'Critical' if avg_risk > 70 or cnt > 10 else 'High' if avg_risk > 50 or cnt > 5 else 'Medium'

        recommendations.append({
            'attack_type': at,
            'description': ATTACK_DESCRIPTIONS.get(at, 'Unknown attack type'),
            'occurrences': cnt,
            'avg_risk': round(avg_risk, 1),
            'priority': priority,
            'strategies': strategies,
            'severity': SEVERITY_MAP.get(at, 'Medium')
        })

    if not recommendations:
        recommendations.append({
            'attack_type': 'System Secure',
            'description': 'No significant threats detected in the last 7 days.',
            'occurrences': 0,
            'avg_risk': 0,
            'priority': 'Low',
            'strategies': ['Continue monitoring', 'Keep systems updated', 'Review security policies'],
            'severity': 'Low'
        })

    return recommendations

def compute_attack_correlation(conn):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a1.attack_type as type1, a2.attack_type as type2, COUNT(*) as co_count
        FROM attack_logs a1
        JOIN attack_logs a2 ON a1.source_ip = a2.source_ip AND a1.id != a2.id
            AND ABS(TIMESTAMPDIFF(MINUTE, a1.detected_at, a2.detected_at)) < 60
        GROUP BY a1.attack_type, a2.attack_type
        ORDER BY co_count DESC
        LIMIT 20
    """)
    correlations = []
    for row in cursor.fetchall():
        correlations.append({
            'type1': row['type1'],
            'type2': row['type2'],
            'count': row['co_count'],
            'strength': min(1.0, row['co_count'] / 10.0)
        })

    if not correlations:
        types = ATTACK_TYPES[:5]
        for i in range(len(types)):
            for j in range(i+1, len(types)):
                correlations.append({
                    'type1': types[i],
                    'type2': types[j],
                    'count': random.randint(0, 5),
                    'strength': round(random.uniform(0.1, 0.8), 2)
                })

    return correlations

def compute_risk_forecast(conn):
    cursor = conn.cursor()
    forecast = []
    for i in range(7):
        date = (datetime.now() + timedelta(days=i)).strftime('%Y-%m-%d')
        day_name = (datetime.now() + timedelta(days=i)).strftime('%a %d')

        past_date = (datetime.now() - timedelta(days=7-i)).strftime('%Y-%m-%d')
        cursor.execute("SELECT COUNT(*) as c, AVG(risk_score) as r FROM attack_logs WHERE DATE(detected_at)=%s", (past_date,))
        row = cursor.fetchone()
        base_attacks = row['c'] if row['c'] else 0
        base_risk = row['r'] if row['r'] else 20

        trend_factor = 1.0 + (i * 0.05) + random.uniform(-0.15, 0.15)
        predicted_attacks = max(0, int(base_attacks * trend_factor + random.randint(0, 3)))
        predicted_risk = min(100, max(5, base_risk * trend_factor + random.uniform(-10, 10)))

        forecast.append({
            'date': date,
            'label': day_name,
            'predicted_attacks': predicted_attacks,
            'predicted_risk': round(predicted_risk, 1),
            'confidence': round(max(50, 95 - i * 7 + random.uniform(-3, 3)), 1)
        })

    return forecast

def predict_attack(features):
    try:
        features_array = np.array(features, dtype=float).reshape(1, -1)

        if scaler is not None:
            features_scaled = scaler.transform(features_array)
        else:
            features_scaled = features_array

        xgb_prediction = None
        xgb_confidence = 0.0
        xgb_proba_list = []
        if xgboost_model is not None:
            xgb_pred = xgboost_model.predict(features_scaled)[0]
            xgb_proba = xgboost_model.predict_proba(features_scaled)[0]
            xgb_confidence = float(max(xgb_proba))
            xgb_proba_list = xgb_proba.tolist()
            xgb_prediction = "Attack" if xgb_pred == 0 else "Normal"

        iso_prediction = None
        anomaly_score = 0.0
        if isolation_forest_model is not None:
            iso_pred = isolation_forest_model.predict(features_scaled)[0]
            anomaly_score = float(isolation_forest_model.score_samples(features_scaled)[0])
            iso_prediction = "Attack" if iso_pred == -1 else "Normal"

        if xgb_prediction and iso_prediction:
            if xgb_prediction == "Attack" or iso_prediction == "Attack":
                final_prediction = "Attack"
                if xgb_prediction == "Attack" and iso_prediction == "Attack":
                    confidence = min(1.0, xgb_confidence * 1.05)
                else:
                    confidence = xgb_confidence * 0.85 if xgb_prediction == "Attack" else 0.7
            else:
                final_prediction = "Normal"
                confidence = xgb_confidence
        elif xgb_prediction:
            final_prediction = xgb_prediction
            confidence = xgb_confidence
        elif iso_prediction:
            final_prediction = iso_prediction
            confidence = 0.75
        else:
            final_prediction = "Unknown"
            confidence = 0.0

        is_attack = final_prediction == "Attack"
        attack_type = classify_attack_type(features_array, confidence) if is_attack else "N/A"
        severity = SEVERITY_MAP.get(attack_type, "Low") if is_attack else "N/A"
        risk_score = compute_risk_score(confidence, anomaly_score, is_attack)

        shap_values = None
        top_features = []
        if xgboost_model is not None and model_feature_importance:
            top_features = [{'feature': f, 'importance': round(float(imp), 4)} for f, imp in model_feature_importance[:10]]

        result = {
            'prediction': final_prediction,
            'confidence': round(confidence, 4),
            'xgboost_result': xgb_prediction,
            'isolation_forest_result': iso_prediction,
            'attack_type': attack_type,
            'severity': severity,
            'anomaly_score': round(anomaly_score, 4),
            'risk_score': risk_score,
            'top_features': top_features,
            'probabilities': xgb_proba_list
        }

        return result

    except Exception as e:
        print(f"Error in prediction: {e}")
        import traceback
        traceback.print_exc()
        return {
            'prediction': 'Error',
            'confidence': 0.0,
            'error': str(e)
        }

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM system_stats LIMIT 1")
    stats = cursor.fetchone()

    cursor.execute("""
        SELECT p.*, u.username
        FROM predictions p
        LEFT JOIN users u ON p.user_id = u.id
        ORDER BY p.prediction_time DESC
        LIMIT 10
    """)
    recent_predictions = cursor.fetchall()

    cursor.execute("SELECT * FROM attack_logs ORDER BY detected_at DESC LIMIT 10")
    attack_logs = cursor.fetchall()

    cursor.execute("SELECT * FROM model_performance ORDER BY evaluation_date DESC")
    model_perf = cursor.fetchall()

    threat_level = compute_threat_level(conn)

    cursor.execute("""
        SELECT attack_type, COUNT(*) as cnt FROM attack_logs
        GROUP BY attack_type ORDER BY cnt DESC
    """)
    attack_type_dist = [dict(r) for r in cursor.fetchall()]

    cursor.close()
    conn.close()

    return render_template('dashboard.html',
                         stats=stats,
                         predictions=recent_predictions,
                         attacks=attack_logs,
                         model_perf=model_perf,
                         threat_level=threat_level,
                         attack_type_dist=attack_type_dist)

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if request.method == 'POST':
        try:
            if request.is_json:
                data = request.get_json()
                features = data.get('features', [])
            else:
                features = []
                for i in range(len(feature_names) if feature_names else 0):
                    feature_value = request.form.get(f'feature_{i}', '0')
                    feature_value = str(feature_value)
                    for ar, en in zip('٠١٢٣٤٥٦٧٨٩', '0123456789'):
                        feature_value = feature_value.replace(ar, en)
                    for ar, en in zip('۰۱۲۳۴۵۶۷۸۹', '0123456789'):
                        feature_value = feature_value.replace(ar, en)
                    feature_value = feature_value.replace('٫', '.').replace('٬', '')
                    features.append(float(feature_value))

            result = predict_attack(features)

            if 'user_id' in session:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO predictions (user_id, prediction_result, attack_type, severity,
                        confidence, xgboost_result, isolation_forest_result, anomaly_score,
                        risk_score, model_used, features_data, shap_values)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (session['user_id'], result['prediction'],
                      result.get('attack_type', 'N/A'),
                      result.get('severity', 'N/A'),
                      result['confidence'],
                      result.get('xgboost_result'),
                      result.get('isolation_forest_result'),
                      result.get('anomaly_score', 0),
                      result.get('risk_score', 0),
                      'XGBoost+IsolationForest',
                      json.dumps(features),
                      json.dumps(result.get('top_features', []))))

                is_attack = 1 if result['prediction'] == 'Attack' else 0
                is_normal = 1 if result['prediction'] == 'Normal' else 0
                cursor.execute("""
                    UPDATE system_stats
                    SET total_predictions = total_predictions + 1,
                        total_attacks_detected = total_attacks_detected + %s,
                        total_normal_traffic = total_normal_traffic + %s
                """, (is_attack, is_normal))

                if result['prediction'] == 'Attack':
                    protocol_names = ['tcp', 'udp', 'icmp', 'arp', 'ospf']
                    proto_val = int(features[1]) if len(features) > 1 else 0
                    proto_name = protocol_names[proto_val % len(protocol_names)] if proto_val < len(protocol_names) else 'tcp'
                    cursor.execute("""
                        INSERT INTO attack_logs (attack_type, severity, source_ip, destination_ip,
                            protocol, confidence, risk_score, anomaly_score, features_summary)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (result.get('attack_type', 'Unknown'),
                          result.get('severity', 'Medium'),
                          generate_ip(), generate_ip(),
                          proto_name,
                          result['confidence'],
                          result.get('risk_score', 0),
                          result.get('anomaly_score', 0),
                          json.dumps({'features_count': len(features)})))

                conn.commit()
                cursor.close()
                conn.close()

            if request.is_json:
                return jsonify(result)
            else:
                return render_template('predict.html',
                                     result=result,
                                     features=feature_names)

        except Exception as e:
            import traceback
            traceback.print_exc()
            error_msg = str(e)
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                return render_template('predict.html',
                                     error=error_msg,
                                     features=feature_names)

    return render_template('predict.html', features=feature_names)

@app.route('/analyze')
def analyze():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('analyze.html')

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM attack_logs")
    total = cursor.fetchone()['total']
    cursor.execute("SELECT COUNT(*) as c FROM attack_logs WHERE severity IN ('High','Critical')")
    high_sev = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM attack_logs WHERE status = 'resolved'")
    resolved = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM attack_logs WHERE detected_at >= NOW() - INTERVAL 1 DAY")
    last24 = cursor.fetchone()['c']

    cursor.execute("SELECT * FROM attack_logs ORDER BY detected_at DESC LIMIT 50")
    attacks = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('history.html',
                         total_attacks=total,
                         high_severity=high_sev,
                         resolved_count=resolved,
                         last24h=last24,
                         attacks=attacks)

@app.route('/monitor')
def monitor():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM system_stats LIMIT 1")
    stats = cursor.fetchone()
    cursor.execute("SELECT * FROM attack_logs WHERE status = 'detected' ORDER BY detected_at DESC LIMIT 5")
    active_threats = cursor.fetchall()
    cursor.execute("SELECT * FROM predictions ORDER BY prediction_time DESC LIMIT 10")
    recent = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('monitor.html', stats=stats, active_threats=active_threats, recent_activity=recent)

@app.route('/xai_report')
def xai_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    fi_data = []
    if model_feature_importance:
        fi_data = [{'feature': f, 'importance': round(float(imp), 4)} for f, imp in model_feature_importance[:15]]

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM model_performance ORDER BY evaluation_date DESC")
    model_perf = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) as c FROM predictions")
    total_preds = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM predictions WHERE shap_values IS NOT NULL AND shap_values != '[]'")
    verified = cursor.fetchone()['c']
    cursor.execute("""
        SELECT p.*, u.username FROM predictions p
        LEFT JOIN users u ON p.user_id = u.id
        WHERE p.prediction_result = 'Attack'
        ORDER BY p.prediction_time DESC LIMIT 10
    """)
    recent_reports = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('xai_report.html',
                         feature_importance=fi_data,
                         model_perf=model_perf,
                         total_predictions=total_preds,
                         verified_predictions=verified,
                         recent_reports=recent_reports)

@app.route('/threat_intelligence')
def threat_intelligence():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    threat_level = compute_threat_level(conn)
    recommendations = generate_security_recommendations(conn)
    forecast = compute_risk_forecast(conn)

    cursor = conn.cursor()
    cursor.execute("""
        SELECT attack_type, COUNT(*) as cnt, AVG(confidence) as avg_conf,
               AVG(risk_score) as avg_risk, MAX(detected_at) as last_seen
        FROM attack_logs
        GROUP BY attack_type
        ORDER BY cnt DESC
    """)
    attack_breakdown = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT COUNT(*) as c FROM attack_logs")
    total_attacks = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM attack_logs WHERE detected_at >= NOW() - INTERVAL 24 HOUR")
    attacks_24h = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(DISTINCT source_ip) as c FROM attack_logs")
    unique_sources = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM attack_logs WHERE status = 'detected'")
    unresolved = cursor.fetchone()['c']

    cursor.close()
    conn.close()

    return render_template('threat_intelligence.html',
                         threat_level=threat_level,
                         recommendations=recommendations,
                         forecast=forecast,
                         attack_breakdown=attack_breakdown,
                         total_attacks=total_attacks,
                         attacks_24h=attacks_24h,
                         unique_sources=unique_sources,
                         unresolved=unresolved,
                         severity_map=SEVERITY_MAP)

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM system_settings")
    rows = cursor.fetchall()
    settings_dict = {r['setting_key']: r['setting_value'] for r in rows}
    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.execute("SELECT * FROM model_performance ORDER BY evaluation_date DESC LIMIT 1")
    perf = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template('settings.html', settings=settings_dict, user=user, model_perf=perf)

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/analyze', methods=['POST'])
@login_required_api
def api_analyze():
    try:
        data = request.get_json()
        file_data = data.get('data', [])

        results = []
        attacks = 0
        normal = 0
        for row in file_data:
            prediction = predict_attack(row)
            results.append(prediction)
            if prediction.get('prediction') == 'Attack':
                attacks += 1
            else:
                normal += 1

        if 'user_id' in session:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE system_stats
                SET total_predictions = total_predictions + %s,
                    total_attacks_detected = total_attacks_detected + %s,
                    total_normal_traffic = total_normal_traffic + %s
            """, (len(results), attacks, normal))

            for i, r in enumerate(results):
                if r.get('prediction') == 'Attack':
                    cursor.execute("""
                        INSERT INTO attack_logs (attack_type, severity, source_ip, destination_ip,
                            protocol, confidence, risk_score, anomaly_score)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (r.get('attack_type', 'Unknown'), r.get('severity', 'Medium'),
                          generate_ip(), generate_ip(), 'tcp',
                          r.get('confidence', 0), r.get('risk_score', 0),
                          r.get('anomaly_score', 0)))

            conn.commit()
            cursor.close()
            conn.close()

        attack_types_count = {}
        severity_count = {}
        for r in results:
            if r.get('prediction') == 'Attack':
                at = r.get('attack_type', 'Unknown')
                attack_types_count[at] = attack_types_count.get(at, 0) + 1
                sv = r.get('severity', 'Unknown')
                severity_count[sv] = severity_count.get(sv, 0) + 1

        return jsonify({
            'success': True,
            'total': len(results),
            'attacks': attacks,
            'normal': normal,
            'attack_rate': round(attacks / max(len(results), 1) * 100, 2),
            'attack_types': attack_types_count,
            'severity_distribution': severity_count,
            'results': results
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/predict', methods=['POST'])
@login_required_api
def api_predict():
    try:
        data = request.get_json()
        features = data.get('features', [])
        result = predict_attack(features)

        if 'user_id' in session:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO predictions (user_id, prediction_result, attack_type, severity,
                    confidence, xgboost_result, isolation_forest_result, anomaly_score,
                    risk_score, model_used, features_data, shap_values)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (session['user_id'], result['prediction'],
                  result.get('attack_type', 'N/A'), result.get('severity', 'N/A'),
                  result['confidence'], result.get('xgboost_result'),
                  result.get('isolation_forest_result'), result.get('anomaly_score', 0),
                  result.get('risk_score', 0), 'XGBoost+IsolationForest',
                  json.dumps(features), json.dumps(result.get('top_features', []))))

            is_attack = 1 if result['prediction'] == 'Attack' else 0
            cursor.execute("""
                UPDATE system_stats
                SET total_predictions = total_predictions + 1,
                    total_attacks_detected = total_attacks_detected + %s,
                    total_normal_traffic = total_normal_traffic + %s
            """, (is_attack, 1 - is_attack))

            if result['prediction'] == 'Attack':
                cursor.execute("""
                    INSERT INTO attack_logs (attack_type, severity, source_ip, destination_ip,
                        protocol, confidence, risk_score, anomaly_score)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (result.get('attack_type', 'Unknown'), result.get('severity', 'Medium'),
                      generate_ip(), generate_ip(), 'tcp',
                      result['confidence'], result.get('risk_score', 0),
                      result.get('anomaly_score', 0)))

            conn.commit()
            cursor.close()
            conn.close()

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/stats')
@login_required_api
def api_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM system_stats LIMIT 1")
    stats = cursor.fetchone()
    cursor.close()
    conn.close()
    if stats:
        return jsonify(dict(stats))
    return jsonify({'error': 'No stats available'}), 500

@app.route('/api/recent-attacks')
@login_required_api
def api_recent_attacks():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM attack_logs ORDER BY detected_at DESC LIMIT 20")
    attacks = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([dict(a) for a in attacks])

@app.route('/api/predictions')
@login_required_api
def api_predictions():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT p.*, u.username
        FROM predictions p
        LEFT JOIN users u ON p.user_id = u.id
        ORDER BY p.prediction_time DESC
        LIMIT 50
    """)
    preds = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([dict(p) for p in preds])

@app.route('/api/dashboard-trend')
@login_required_api
def api_dashboard_trend():
    conn = get_db_connection()
    cursor = conn.cursor()
    trend_data = {'labels': [], 'attacks': [], 'normal': []}
    for i in range(6, -1, -1):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        day_name = (datetime.now() - timedelta(days=i)).strftime('%a')
        trend_data['labels'].append(day_name)
        cursor.execute("SELECT COUNT(*) as c FROM predictions WHERE prediction_result='Attack' AND DATE(prediction_time)=%s", (date,))
        trend_data['attacks'].append(cursor.fetchone()['c'])
        cursor.execute("SELECT COUNT(*) as c FROM predictions WHERE prediction_result='Normal' AND DATE(prediction_time)=%s", (date,))
        trend_data['normal'].append(cursor.fetchone()['c'])
    cursor.close()
    conn.close()
    return jsonify(trend_data)

@app.route('/api/feature-importance')
@login_required_api
def api_feature_importance():
    if model_feature_importance:
        top = model_feature_importance[:15]
        return jsonify({
            'labels': [f for f, _ in top],
            'values': [round(float(v), 4) for _, v in top]
        })
    return jsonify({'labels': [], 'values': []})

@app.route('/api/model-performance')
@login_required_api
def api_model_performance():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM model_performance ORDER BY evaluation_date DESC")
    perf = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([dict(p) for p in perf])

@app.route('/api/monitor-data')
@login_required_api
def api_monitor_data():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM system_stats LIMIT 1")
    stats = cursor.fetchone()
    cursor.execute("SELECT COUNT(*) as c FROM attack_logs WHERE status = 'detected'")
    active = cursor.fetchone()['c']
    cursor.execute("SELECT * FROM attack_logs WHERE status = 'detected' ORDER BY detected_at DESC LIMIT 5")
    threats = [dict(t) for t in cursor.fetchall()]
    cursor.execute("SELECT * FROM predictions ORDER BY prediction_time DESC LIMIT 5")
    recent = [dict(r) for r in cursor.fetchall()]
    cursor.close()
    conn.close()
    total_preds = stats['total_predictions'] if stats else 0
    return jsonify({
        'total_predictions': total_preds,
        'active_threats': active,
        'threats_list': threats,
        'recent_activity': recent,
        'system_status': 'Active',
        'network_traffic': f"{random.randint(10,100)} MB/s"
    })

@app.route('/api/history')
@login_required_api
def api_history():
    severity = request.args.get('severity', 'all')
    attack_type = request.args.get('attack_type', 'all')
    status = request.args.get('status', 'all')
    date_range = request.args.get('date_range', 'all')

    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM attack_logs WHERE 1=1"
    params = []

    if severity != 'all':
        query += " AND severity = %s"
        params.append(severity)
    if attack_type != 'all':
        query += " AND attack_type = %s"
        params.append(attack_type)
    if status != 'all':
        query += " AND status = %s"
        params.append(status)
    if date_range == '24h':
        query += " AND detected_at >= NOW() - INTERVAL 1 DAY"
    elif date_range == '7d':
        query += " AND detected_at >= NOW() - INTERVAL 7 DAY"
    elif date_range == '30d':
        query += " AND detected_at >= NOW() - INTERVAL 30 DAY"
    elif date_range == '90d':
        query += " AND detected_at >= NOW() - INTERVAL 90 DAY"

    query += " ORDER BY detected_at DESC LIMIT 100"
    cursor.execute(query, params)
    attacks = [dict(a) for a in cursor.fetchall()]

    cursor.execute("SELECT COUNT(*) as c FROM attack_logs")
    total = cursor.fetchone()['c']
    cursor.close()
    conn.close()

    return jsonify({'attacks': attacks, 'total': total, 'showing': len(attacks)})

@app.route('/api/settings', methods=['GET', 'POST'])
@login_required_api
def api_settings():

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        data = request.get_json()
        for key, val in data.items():
            cursor.execute("""
                INSERT INTO system_settings (setting_key, setting_value)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE setting_value=%s, updated_at=CURRENT_TIMESTAMP
            """, (key, str(val), str(val)))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Settings saved successfully'})
    else:
        cursor.execute("SELECT * FROM system_settings")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({r['setting_key']: r['setting_value'] for r in rows})

@app.route('/api/update-account', methods=['POST'])
@login_required_api
def api_update_account():
    data = request.get_json()
    conn = get_db_connection()
    cursor = conn.cursor()

    updates = []
    params = []
    if data.get('full_name') is not None:
        updates.append("full_name = %s")
        params.append(data['full_name'])
    if data.get('username'):
        updates.append("username = %s")
        params.append(data['username'])
    if data.get('email'):
        updates.append("email = %s")
        params.append(data['email'])
    if data.get('password') and data['password'] == data.get('confirm_password'):
        updates.append("password = %s")
        params.append(hash_password(data['password']))

    if updates:
        params.append(session['user_id'])
        try:
            cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = %s", params)
            conn.commit()
            if data.get('username'):
                session['username'] = data['username']
            if data.get('full_name') is not None:
                session['full_name'] = data['full_name'] or session.get('username', '')
            cursor.close()
            conn.close()
            return jsonify({'success': True, 'message': 'Account updated successfully'})
        except Exception as e:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': str(e)}), 400

    cursor.close()
    conn.close()
    return jsonify({'success': False, 'error': 'No changes provided'}), 400

@app.route('/api/attack-log/<int:log_id>/resolve', methods=['POST'])
@login_required_api
def api_resolve_attack(log_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE attack_logs SET status = 'resolved' WHERE id = %s", (log_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'success': True, 'message': f'Attack #{log_id} marked as resolved'})

@app.route('/api/export-history')
@login_required_api
def api_export_history():
    date_range = request.args.get('date_range', 'all')
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM attack_logs WHERE 1=1"
    if date_range == '24h':
        query += " AND detected_at >= NOW() - INTERVAL 1 DAY"
    elif date_range == '7d':
        query += " AND detected_at >= NOW() - INTERVAL 7 DAY"
    elif date_range == '30d':
        query += " AND detected_at >= NOW() - INTERVAL 30 DAY"
    elif date_range == '90d':
        query += " AND detected_at >= NOW() - INTERVAL 90 DAY"
    query += " ORDER BY detected_at DESC"
    cursor.execute(query)
    attacks = cursor.fetchall()
    cursor.close()
    conn.close()

    rows = []
    for a in attacks:
        d = dict(a)
        for k, v in d.items():
            if hasattr(v, 'isoformat'):
                d[k] = v.isoformat()
        rows.append(d)
    return jsonify({'data': rows, 'total': len(rows)})

@app.route('/api/clear-history', methods=['POST'])
@login_required_api
def api_clear_history():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'}), 403
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM attack_logs")
    cursor.execute("UPDATE system_stats SET total_attacks_detected=0, total_predictions=0, total_normal_traffic=0")
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'success': True, 'message': 'All attack logs have been cleared'})

@app.route('/api/reset-settings', methods=['POST'])
@login_required_api
def api_reset_settings():
    if session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Admin access required'}), 403
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM system_settings")
    defaults = {
        'detection_threshold': '75',
        'auto_block': 'true',
        'alert_level': 'all',
        'active_model': 'hybrid',
        'system_name': 'CloudAtk-ML',
        'language': 'English',
        'timezone': 'UTC+3'
    }
    for k, v in defaults.items():
        cursor.execute("INSERT INTO system_settings (setting_key, setting_value) VALUES (%s, %s)", (k, v))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'success': True, 'message': 'All settings reset to defaults'})

@app.route('/api/threat-intelligence')
@login_required_api
def api_threat_intelligence():
    conn = get_db_connection()
    threat_level = compute_threat_level(conn)
    recommendations = generate_security_recommendations(conn)
    forecast = compute_risk_forecast(conn)
    conn.close()
    return jsonify({
        'threat_level': threat_level,
        'recommendations': recommendations,
        'forecast': forecast
    })

@app.route('/api/attack-correlation')
@login_required_api
def api_attack_correlation():
    conn = get_db_connection()
    correlations = compute_attack_correlation(conn)
    conn.close()
    return jsonify({'correlations': correlations})

@app.route('/api/risk-forecast')
@login_required_api
def api_risk_forecast():
    conn = get_db_connection()
    forecast = compute_risk_forecast(conn)
    conn.close()
    return jsonify({
        'labels': [f['label'] for f in forecast],
        'predicted_attacks': [f['predicted_attacks'] for f in forecast],
        'predicted_risk': [f['predicted_risk'] for f in forecast],
        'confidence': [f['confidence'] for f in forecast],
        'forecast': forecast
    })

@app.route('/api/attack-simulation', methods=['POST'])
@login_required_api
def api_attack_simulation():
    try:
        data = request.get_json()
        attack_type = data.get('attack_type', 'Generic')
        count = min(int(data.get('count', 1)), 20)

        results = []
        for i in range(count):
            profile = ATTACK_SIMULATION_PROFILES.get(attack_type, ATTACK_SIMULATION_PROFILES['Generic'])
            noisy = [v + random.uniform(-abs(v) * 0.1, abs(v) * 0.1) if v != 0 else v for v in profile]
            prediction = predict_attack(noisy)
            prediction['simulated_type'] = attack_type
            prediction['simulation_index'] = i + 1
            prediction['features'] = noisy
            results.append(prediction)

        detected = sum(1 for r in results if r['prediction'] == 'Attack')
        return jsonify({
            'success': True,
            'attack_type': attack_type,
            'total': count,
            'detected': detected,
            'missed': count - detected,
            'detection_rate': round(detected / max(count, 1) * 100, 1),
            'results': results
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/security-recommendations')
@login_required_api
def api_security_recommendations():
    conn = get_db_connection()
    recommendations = generate_security_recommendations(conn)
    conn.close()
    return jsonify({'recommendations': recommendations})

@app.route('/api/attack-heatmap')
@login_required_api
def api_attack_heatmap():
    conn = get_db_connection()
    cursor = conn.cursor()

    heatmap = []
    for day in range(7):
        day_data = []
        date = (datetime.now() - timedelta(days=6-day)).strftime('%Y-%m-%d')
        day_name = (datetime.now() - timedelta(days=6-day)).strftime('%a')
        for hour in range(24):
            cursor.execute("""
                SELECT COUNT(*) as c FROM attack_logs
                WHERE DATE(detected_at) = %s AND HOUR(detected_at) = %s
            """, (date, hour))
            count = cursor.fetchone()['c']
            day_data.append(count)
        heatmap.append({'day': day_name, 'date': date, 'hours': day_data})

    cursor.close()
    conn.close()
    return jsonify({'heatmap': heatmap})

@app.route('/api/attack-timeline')
@login_required_api
def api_attack_timeline():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, attack_type, severity, source_ip, destination_ip,
               protocol, confidence, risk_score, detected_at, status
        FROM attack_logs
        ORDER BY detected_at DESC
        LIMIT 30
    """)
    timeline = [dict(r) for r in cursor.fetchall()]
    cursor.close()
    conn.close()
    return jsonify({'timeline': timeline})

@app.route('/api/network-topology')
@login_required_api
def api_network_topology():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT source_ip, destination_ip, attack_type, severity, COUNT(*) as cnt
        FROM attack_logs
        GROUP BY source_ip, destination_ip
        ORDER BY cnt DESC
        LIMIT 30
    """)
    edges = []
    nodes_set = set()
    for row in cursor.fetchall():
        src = row['source_ip']
        dst = row['destination_ip']
        nodes_set.add(src)
        nodes_set.add(dst)
        edges.append({
            'source': src,
            'target': dst,
            'attack_type': row['attack_type'],
            'severity': row['severity'],
            'count': row['cnt']
        })

    nodes = []
    for ip in nodes_set:
        cursor.execute("SELECT COUNT(*) as c FROM attack_logs WHERE source_ip = %s", (ip,))
        as_source = cursor.fetchone()['c']
        cursor.execute("SELECT COUNT(*) as c FROM attack_logs WHERE destination_ip = %s", (ip,))
        as_target = cursor.fetchone()['c']
        role = 'attacker' if as_source > as_target else 'target'
        nodes.append({'id': ip, 'role': role, 'connections': as_source + as_target})

    cursor.close()
    conn.close()
    return jsonify({'nodes': nodes, 'edges': edges})

@app.route('/api/model-explain', methods=['POST'])
@login_required_api
def api_model_explain():
    try:
        data = request.get_json()
        features = data.get('features', [])
        result = predict_attack(features)

        explanation = {
            'prediction': result,
            'feature_contributions': [],
            'decision_path': [],
            'model_agreement': result.get('xgboost_result') == result.get('isolation_forest_result')
        }

        if model_feature_importance and feature_names:
            features_array = np.array(features, dtype=float)
            for fname, importance in model_feature_importance[:15]:
                idx = feature_names.index(fname) if fname in feature_names else -1
                if idx >= 0 and idx < len(features_array):
                    val = float(features_array[idx])
                    imp_val = float(importance)
                    contribution = imp_val * (1 if result['prediction'] == 'Attack' else -1)
                    explanation['feature_contributions'].append({
                        'feature': fname,
                        'value': round(val, 4),
                        'importance': round(imp_val, 4),
                        'contribution': round(float(contribution), 4),
                        'direction': 'Attack' if contribution > 0 else 'Normal'
                    })

        explanation['decision_path'] = [
            {'step': 'Feature Scaling', 'detail': 'StandardScaler normalization applied'},
            {'step': 'XGBoost Classification', 'detail': f'Result: {result.get("xgboost_result", "N/A")} ({(result.get("confidence", 0)*100):.1f}%)'},
            {'step': 'Isolation Forest Anomaly Detection', 'detail': f'Result: {result.get("isolation_forest_result", "N/A")} (score: {result.get("anomaly_score", 0):.4f})'},
            {'step': 'Hybrid Decision Engine', 'detail': f'Final: {result["prediction"]} (risk: {result.get("risk_score", 0):.1f}/100)'},
        ]
        if result['prediction'] == 'Attack':
            explanation['decision_path'].append(
                {'step': 'Attack Classification', 'detail': f'Type: {result.get("attack_type", "N/A")} | Severity: {result.get("severity", "N/A")}'}
            )

        return jsonify(explanation)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/system-health')
@login_required_api
def api_system_health():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as c FROM predictions")
    total_preds = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM attack_logs")
    total_attacks = cursor.fetchone()['c']
    cursor.execute("SELECT COUNT(*) as c FROM users")
    total_users = cursor.fetchone()['c']

    models_loaded = {
        'xgboost': xgboost_model is not None,
        'isolation_forest': isolation_forest_model is not None,
        'scaler': scaler is not None,
        'label_encoder': label_encoder is not None
    }
    all_models = all(models_loaded.values())

    cursor.execute("SELECT MAX(detected_at) as last FROM attack_logs")
    row = cursor.fetchone()
    last_attack = row['last'] if row['last'] else 'No attacks'

    cursor.close()
    conn.close()

    return jsonify({
        'status': 'Operational' if all_models else 'Degraded',
        'uptime': 'Active',
        'models': models_loaded,
        'all_models_loaded': all_models,
        'total_predictions': total_preds,
        'total_attacks': total_attacks,
        'total_users': total_users,
        'features_count': len(feature_names) if feature_names else 0,
        'last_attack': last_attack,
        'database': 'Connected'
    })

# ============================================================================
# NEW PAGES - Security Score, Attack Encyclopedia, Geo Map
# ============================================================================

ATTACK_ENCYCLOPEDIA = {
    'DoS': {
        'full_name': 'Denial of Service',
        'icon': 'fa-server',
        'color': '#ef4444',
        'severity': 'High',
        'description': 'Denial of Service attacks aim to overwhelm a system, server, or network with excessive traffic, making it unavailable to legitimate users.',
        'how_it_works': 'Attackers flood the target with superfluous requests to overload systems and prevent legitimate requests from being fulfilled. This can involve SYN floods, UDP floods, HTTP floods, or amplification attacks.',
        'indicators': ['Unusually high network traffic', 'Slow network performance', 'Unavailability of websites', 'Increase in spam emails', 'Disconnection of wireless/wired connections'],
        'prevention': ['Implement rate limiting and traffic shaping', 'Deploy DDoS mitigation services (Cloudflare, AWS Shield)', 'Configure load balancers with health checks', 'Use CDN to distribute traffic', 'Set up network monitoring and alerting'],
        'real_world': 'In 2018, GitHub was hit by the largest DDoS attack ever recorded at 1.35 Tbps, using memcached amplification.',
        'risk_level': 85
    },
    'Exploits': {
        'full_name': 'Vulnerability Exploits',
        'icon': 'fa-unlock',
        'color': '#dc2626',
        'severity': 'Critical',
        'description': 'Exploitation of known or zero-day vulnerabilities in software, operating systems, or hardware to gain unauthorized access or execute arbitrary code.',
        'how_it_works': 'Attackers identify vulnerabilities (CVEs) in target systems and craft specific payloads to trigger these flaws. This includes buffer overflows, SQL injection, command injection, and privilege escalation.',
        'indicators': ['Unexpected system behavior', 'Unknown processes running', 'Modified system files', 'Unusual outbound connections', 'Security log anomalies'],
        'prevention': ['Keep all systems patched and updated', 'Deploy Web Application Firewalls (WAF)', 'Conduct regular vulnerability assessments', 'Implement principle of least privilege', 'Use virtual patching for critical systems'],
        'real_world': 'The EternalBlue exploit (CVE-2017-0144) was used in the WannaCry ransomware attack, affecting over 200,000 computers across 150 countries.',
        'risk_level': 95
    },
    'Fuzzers': {
        'full_name': 'Fuzz Testing Attacks',
        'icon': 'fa-random',
        'color': '#f59e0b',
        'severity': 'Low',
        'description': 'Automated attacks that send random, malformed, or unexpected data to find software vulnerabilities, crashes, or memory leaks.',
        'how_it_works': 'Fuzzing tools generate thousands of mutated inputs and send them to target applications, monitoring for crashes, hangs, or unusual behavior that indicates exploitable vulnerabilities.',
        'indicators': ['Application crashes or restarts', 'Memory consumption spikes', 'High volume of malformed requests', 'Error log overflow', 'Unusual input patterns in logs'],
        'prevention': ['Implement strict input validation', 'Deploy rate limiting on all endpoints', 'Use request size limitations', 'Enable anomaly-based intrusion detection', 'Implement application-level firewalls'],
        'real_world': 'Google Project Zero uses fuzzing extensively, discovering hundreds of critical vulnerabilities in Chrome, Windows, and Linux kernels.',
        'risk_level': 45
    },
    'Reconnaissance': {
        'full_name': 'Network Reconnaissance',
        'icon': 'fa-eye',
        'color': '#3b82f6',
        'severity': 'Low',
        'description': 'Systematic scanning and probing of networks to gather information about target systems, services, and potential vulnerabilities.',
        'how_it_works': 'Attackers use tools like Nmap, Shodan, or custom scripts to map network topology, identify open ports, detect running services, and fingerprint operating systems before launching targeted attacks.',
        'indicators': ['Port scan patterns in firewall logs', 'DNS enumeration attempts', 'Sequential connection attempts', 'ICMP sweep activity', 'Banner grabbing attempts'],
        'prevention': ['Disable unnecessary services and ports', 'Implement port knocking mechanisms', 'Deploy honeypots and decoy systems', 'Enable stealth mode on firewalls', 'Monitor for scanning patterns'],
        'real_world': 'The Mirai botnet scanned the internet for IoT devices with default credentials, building a massive botnet used to launch record-breaking DDoS attacks.',
        'risk_level': 35
    },
    'Analysis': {
        'full_name': 'Analysis & Probing Attacks',
        'icon': 'fa-search',
        'color': '#06b6d4',
        'severity': 'Low',
        'description': 'Advanced probing techniques including port analysis, spam attacks, and web-based analysis used for intelligence gathering and vulnerability assessment.',
        'how_it_works': 'Combines multiple techniques including automated web crawling, port analysis, service fingerprinting, and response analysis to build detailed profiles of target infrastructure.',
        'indicators': ['Unusual web crawler activity', 'Systematic URL probing', 'Header manipulation attempts', 'Automated form submissions', 'API endpoint enumeration'],
        'prevention': ['Implement robots.txt and crawl limits', 'Use CAPTCHA for sensitive endpoints', 'Enable threat intelligence feeds', 'Deploy behavioral analytics', 'Rate limit API endpoints'],
        'real_world': 'Advanced Persistent Threat (APT) groups spend months in the analysis phase, mapping entire corporate networks before launching targeted attacks.',
        'risk_level': 40
    },
    'Backdoor': {
        'full_name': 'Backdoor Access',
        'icon': 'fa-door-open',
        'color': '#7c3aed',
        'severity': 'Critical',
        'description': 'Hidden access points installed in systems that bypass normal authentication, allowing persistent unauthorized remote access.',
        'how_it_works': 'Attackers install covert software or modify existing programs to create persistent access channels. These can be rootkits, remote access trojans (RATs), or modified system binaries that communicate with command-and-control servers.',
        'indicators': ['Unknown network connections', 'Modified system binaries', 'Unusual scheduled tasks', 'Registry modifications', 'Encrypted traffic to unknown IPs'],
        'prevention': ['Conduct regular system integrity checks', 'Monitor all outbound connections', 'Implement application whitelisting', 'Deploy endpoint detection and response', 'Use file integrity monitoring'],
        'real_world': 'The SolarWinds supply chain attack (2020) inserted a backdoor into Orion software updates, compromising 18,000+ organizations including US government agencies.',
        'risk_level': 92
    },
    'Shellcode': {
        'full_name': 'Shellcode Injection',
        'icon': 'fa-terminal',
        'color': '#e11d48',
        'severity': 'Critical',
        'description': 'Injection of machine code into running processes, typically exploiting buffer overflow vulnerabilities to execute arbitrary commands.',
        'how_it_works': 'Attackers craft specific byte sequences (shellcode) that, when injected into a vulnerable process memory space, execute commands such as spawning a shell, downloading malware, or establishing reverse connections.',
        'indicators': ['Buffer overflow attempts in logs', 'NOP sled patterns in network traffic', 'Unexpected process spawning', 'Memory access violations', 'Unusual system call patterns'],
        'prevention': ['Enable DEP (Data Execution Prevention)', 'Use ASLR (Address Space Layout Randomization)', 'Implement code integrity verification', 'Deploy memory protection solutions', 'Use compiler-level protections (stack canaries)'],
        'real_world': 'The Code Red worm (2001) used shellcode to exploit a buffer overflow in Microsoft IIS, infecting over 350,000 servers in 14 hours.',
        'risk_level': 90
    },
    'Worms': {
        'full_name': 'Network Worms',
        'icon': 'fa-virus',
        'color': '#dc2626',
        'severity': 'High',
        'description': 'Self-replicating malware that spreads autonomously across networks without requiring user interaction or host files.',
        'how_it_works': 'Worms exploit network vulnerabilities to propagate from system to system automatically. They can carry payloads including ransomware, keyloggers, or botnet agents, and can spread via email, file shares, or direct network exploitation.',
        'indicators': ['Rapid increase in network traffic', 'Multiple systems showing identical symptoms', 'Automated connection attempts', 'Bandwidth saturation', 'Mass email generation'],
        'prevention': ['Segment networks with VLANs', 'Keep all systems patched', 'Disable unnecessary network services', 'Implement network quarantine procedures', 'Deploy next-gen antivirus solutions'],
        'real_world': 'Stuxnet (2010) was a sophisticated worm that targeted Iranian nuclear facilities, destroying approximately 1,000 uranium enrichment centrifuges.',
        'risk_level': 88
    },
    'Generic': {
        'full_name': 'Generic Attacks',
        'icon': 'fa-shield-alt',
        'color': '#f97316',
        'severity': 'Medium',
        'description': 'General attack patterns that combine multiple techniques or do not fit into specific categories. Often involve protocol abuse or multi-vector attacks.',
        'how_it_works': 'These attacks use a combination of techniques including protocol manipulation, traffic manipulation, and multi-stage attack chains that do not cleanly fit into a single category.',
        'indicators': ['Mixed attack signatures', 'Protocol anomalies', 'Unusual traffic patterns', 'Multiple alert types triggered', 'Cross-protocol activity'],
        'prevention': ['Implement defense-in-depth strategy', 'Deploy multi-layer security controls', 'Enable comprehensive logging', 'Use SIEM for correlation', 'Conduct regular security audits'],
        'real_world': 'Modern APT campaigns often combine reconnaissance, exploitation, and backdoor techniques in multi-stage attacks lasting months.',
        'risk_level': 65
    }
}

GEO_ATTACK_SOURCES = [
    {'country': 'China', 'code': 'CN', 'lat': 35.86, 'lng': 104.19, 'attacks': 0, 'color': '#ef4444'},
    {'country': 'Russia', 'code': 'RU', 'lat': 61.52, 'lng': 105.32, 'attacks': 0, 'color': '#dc2626'},
    {'country': 'United States', 'code': 'US', 'lat': 37.09, 'lng': -95.71, 'attacks': 0, 'color': '#f59e0b'},
    {'country': 'Brazil', 'code': 'BR', 'lat': -14.24, 'lng': -51.93, 'attacks': 0, 'color': '#f97316'},
    {'country': 'India', 'code': 'IN', 'lat': 20.59, 'lng': 78.96, 'attacks': 0, 'color': '#8b5cf6'},
    {'country': 'Germany', 'code': 'DE', 'lat': 51.17, 'lng': 10.45, 'attacks': 0, 'color': '#3b82f6'},
    {'country': 'Iran', 'code': 'IR', 'lat': 32.43, 'lng': 53.69, 'attacks': 0, 'color': '#ec4899'},
    {'country': 'North Korea', 'code': 'KP', 'lat': 40.34, 'lng': 127.51, 'attacks': 0, 'color': '#ef4444'},
    {'country': 'Vietnam', 'code': 'VN', 'lat': 14.06, 'lng': 108.28, 'attacks': 0, 'color': '#14b8a6'},
    {'country': 'Nigeria', 'code': 'NG', 'lat': 9.08, 'lng': 8.68, 'attacks': 0, 'color': '#6366f1'},
    {'country': 'Ukraine', 'code': 'UA', 'lat': 48.38, 'lng': 31.17, 'attacks': 0, 'color': '#06b6d4'},
    {'country': 'Turkey', 'code': 'TR', 'lat': 38.96, 'lng': 35.24, 'attacks': 0, 'color': '#f43f5e'},
    {'country': 'Indonesia', 'code': 'ID', 'lat': -0.79, 'lng': 113.92, 'attacks': 0, 'color': '#a855f7'},
    {'country': 'South Korea', 'code': 'KR', 'lat': 35.91, 'lng': 127.77, 'attacks': 0, 'color': '#0ea5e9'},
    {'country': 'Japan', 'code': 'JP', 'lat': 36.20, 'lng': 138.25, 'attacks': 0, 'color': '#84cc16'},
    {'country': 'United Kingdom', 'code': 'GB', 'lat': 55.38, 'lng': -3.44, 'attacks': 0, 'color': '#eab308'},
    {'country': 'France', 'code': 'FR', 'lat': 46.23, 'lng': 2.21, 'attacks': 0, 'color': '#22d3ee'},
    {'country': 'Pakistan', 'code': 'PK', 'lat': 30.38, 'lng': 69.35, 'attacks': 0, 'color': '#fb923c'},
    {'country': 'Romania', 'code': 'RO', 'lat': 45.94, 'lng': 24.97, 'attacks': 0, 'color': '#c084fc'},
    {'country': 'Saudi Arabia', 'code': 'SA', 'lat': 23.89, 'lng': 45.08, 'attacks': 0, 'color': '#19C2A6'},
]

GEO_TARGETS = [
    {'name': 'Saudi Arabia (Riyadh)', 'lat': 24.71, 'lng': 46.67},
    {'name': 'UAE (Dubai)', 'lat': 25.20, 'lng': 55.27},
    {'name': 'AWS US-East', 'lat': 39.04, 'lng': -77.49},
    {'name': 'Azure EU-West', 'lat': 53.35, 'lng': -6.26},
    {'name': 'GCP Asia', 'lat': 1.35, 'lng': 103.82},
    {'name': 'AWS EU-Frankfurt', 'lat': 50.11, 'lng': 8.68},
    {'name': 'Azure US-West', 'lat': 37.78, 'lng': -122.42},
    {'name': 'Bahrain Cloud', 'lat': 26.07, 'lng': 50.56},
]


def compute_security_score(conn):
    cursor = conn.cursor()
    score = 100
    details = []

    cursor.execute("SELECT COUNT(*) as c FROM attack_logs WHERE status != 'resolved'")
    unresolved = cursor.fetchone()['c']
    penalty = min(unresolved * 5, 30)
    score -= penalty
    details.append({'category': 'Unresolved Threats', 'score': max(0, 100 - penalty * 3), 'impact': f'-{penalty}', 'detail': f'{unresolved} unresolved threats'})

    cursor.execute("SELECT COUNT(*) as c FROM attack_logs WHERE severity IN ('Critical','High') AND status != 'resolved'")
    critical = cursor.fetchone()['c']
    penalty = min(critical * 10, 25)
    score -= penalty
    details.append({'category': 'Critical Vulnerabilities', 'score': max(0, 100 - penalty * 4), 'impact': f'-{penalty}', 'detail': f'{critical} critical/high severity issues'})

    cursor.execute("SELECT COUNT(*) as c FROM attack_logs WHERE detected_at > NOW() - INTERVAL 1 HOUR")
    recent = cursor.fetchone()['c']
    penalty = min(recent * 8, 20)
    score -= penalty
    details.append({'category': 'Recent Attack Activity', 'score': max(0, 100 - penalty * 5), 'impact': f'-{penalty}', 'detail': f'{recent} attacks in last hour'})

    cursor.execute("SELECT COUNT(DISTINCT attack_type) as c FROM attack_logs WHERE detected_at > NOW() - INTERVAL 24 HOUR")
    diversity = cursor.fetchone()['c']
    penalty = min(diversity * 3, 15)
    score -= penalty
    details.append({'category': 'Attack Diversity', 'score': max(0, 100 - penalty * 6), 'impact': f'-{penalty}', 'detail': f'{diversity} different attack types in 24h'})

    models_ok = all([xgboost_model is not None, isolation_forest_model is not None, scaler is not None])
    if not models_ok:
        score -= 15
        details.append({'category': 'ML Model Status', 'score': 0, 'impact': '-15', 'detail': 'Some ML models are not loaded'})
    else:
        details.append({'category': 'ML Model Status', 'score': 100, 'impact': '+0', 'detail': 'All models operational'})

    cursor.execute("SELECT setting_value FROM system_settings WHERE setting_key = 'auto_block'")
    row = cursor.fetchone()
    auto_block = row['setting_value'] if row else 'false'
    if auto_block != 'true':
        score -= 5
        details.append({'category': 'Auto-Block Policy', 'score': 50, 'impact': '-5', 'detail': 'Auto-blocking is disabled'})
    else:
        details.append({'category': 'Auto-Block Policy', 'score': 100, 'impact': '+0', 'detail': 'Auto-blocking is enabled'})

    cursor.close()
    score = max(0, min(100, score))

    if score >= 80:
        grade = 'A'
        label = 'Excellent'
        color = '#10b981'
    elif score >= 60:
        grade = 'B'
        label = 'Good'
        color = '#19C2A6'
    elif score >= 40:
        grade = 'C'
        label = 'Fair'
        color = '#f59e0b'
    elif score >= 20:
        grade = 'D'
        label = 'Poor'
        color = '#f97316'
    else:
        grade = 'F'
        label = 'Critical'
        color = '#ef4444'

    return {'score': score, 'grade': grade, 'label': label, 'color': color, 'details': details}


@app.route('/security_score')
def security_score():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    score_data = compute_security_score(conn)
    conn.close()
    return render_template('security_score.html', score_data=score_data)


@app.route('/attack_encyclopedia')
def attack_encyclopedia():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT attack_type, COUNT(*) as cnt FROM attack_logs GROUP BY attack_type")
    counts = {r['attack_type']: r['cnt'] for r in cursor.fetchall()}
    cursor.close()
    conn.close()
    encyclopedia = {}
    for atype, info in ATTACK_ENCYCLOPEDIA.items():
        entry = dict(info)
        entry['detected_count'] = counts.get(atype, 0)
        encyclopedia[atype] = entry
    return render_template('attack_encyclopedia.html', encyclopedia=encyclopedia)


@app.route('/geo_map')
def geo_map():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as c FROM attack_logs")
    total_attacks = cursor.fetchone()['c']
    cursor.execute("SELECT attack_type, COUNT(*) as cnt FROM attack_logs GROUP BY attack_type ORDER BY cnt DESC")
    attack_dist = [dict(r) for r in cursor.fetchall()]
    cursor.execute("SELECT COUNT(*) as c FROM attack_logs WHERE detected_at > NOW() - INTERVAL 24 HOUR")
    attacks_24h = cursor.fetchone()['c']
    cursor.close()
    conn.close()

    geo_data = []
    for src in GEO_ATTACK_SOURCES:
        entry = dict(src)
        entry['attacks'] = random.randint(max(0, total_attacks // 3), max(1, total_attacks)) if total_attacks > 0 else random.randint(0, 5)
        geo_data.append(entry)
    geo_data.sort(key=lambda x: x['attacks'], reverse=True)

    return render_template('geo_map.html',
                         geo_data=geo_data,
                         targets=GEO_TARGETS,
                         total_attacks=total_attacks,
                         attacks_24h=attacks_24h,
                         attack_dist=attack_dist)


@app.route('/api/security-score')
@login_required_api
def api_security_score():
    conn = get_db_connection()
    score_data = compute_security_score(conn)
    conn.close()
    return jsonify(score_data)


@app.route('/api/geo-attacks')
@login_required_api
def api_geo_attacks():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as c FROM attack_logs")
    total = cursor.fetchone()['c']
    cursor.close()
    conn.close()

    geo_data = []
    for src in GEO_ATTACK_SOURCES:
        entry = dict(src)
        entry['attacks'] = random.randint(max(0, total // 3), max(1, total)) if total > 0 else random.randint(0, 5)
        geo_data.append(entry)
    geo_data.sort(key=lambda x: x['attacks'], reverse=True)
    return jsonify({'sources': geo_data, 'total': total})


# ============================================================================
# AUTH ROUTES
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and verify_password(password, user['password']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user.get('full_name', '') or user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (username, email, password, full_name, role)
                VALUES (%s, %s, %s, %s, 'user')
            """, (username, email, hash_password(password), full_name))
            conn.commit()
            new_user_id = cursor.lastrowid
            cursor.close()
            conn.close()
            session['user_id'] = new_user_id
            session['username'] = username
            session['full_name'] = full_name or username
            session['role'] = 'user'
            return redirect(url_for('dashboard'))
        except Exception:
            cursor.close()
            conn.close()
            return render_template('register.html', error='Username or email already exists')

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ============================================================================
# INITIALIZATION
# ============================================================================

def ensure_mysql_database():
    try:
        conn = pymysql.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            port=MYSQL_PORT,
            unix_socket=MYSQL_SOCKET if os.path.exists(MYSQL_SOCKET) else None,
            cursorclass=pymysql.cursors.DictCursor,
            charset='utf8mb4'
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DATABASE}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        conn.commit()
        cursor.close()
        conn.close()
        print(f"MySQL database '{MYSQL_DATABASE}' is ready.")
    except Exception as e:
        print(f"Error ensuring MySQL database: {e}")
        print("Make sure MySQL server is running and credentials are correct.")
        sys.exit(1)

def initialize_app():
    print("\n" + "="*80)
    print("CLOUD ATTACK DETECTION SYSTEM - INITIALIZATION")
    print("="*80 + "\n")

    print("[1/3] Ensuring MySQL database exists...")
    ensure_mysql_database()
    print("Database ready!\n")

    print("[2/3] Creating database tables...")
    create_tables()
    print("Tables ready!\n")

    print("[3/3] Loading ML models...")
    load_models()
    print("Models loading complete!\n")

    print("="*80)
    print("INITIALIZATION COMPLETE!")
    print("="*80 + "\n")

    return True

if __name__ == '__main__':
    initialize_app()
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting Flask server on port {port}...")
    print(f"Default admin credentials: username=admin, password=admin123")
    app.run(debug=False, host='0.0.0.0', port=port)
