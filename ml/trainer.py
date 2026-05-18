#!/usr/bin/env python3
"""
Train ML models for IDS
Trains Isolation Forest and Random Forest on collected traffic data
"""

import pandas as pd
import numpy as np
import os
from datetime import datetime
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from ml.feature_extractor import FeatureExtractor
from ml.isolation_model import IsolationForestModel
from ml.random_forest_model import RandomForestModel

def load_training_data():
    """Load traffic logs for training"""
    print("\n[*] Loading training data...")
    
    csv_path = Config.NORMAL_CSV
    csv_path = Config.SUSPICIOUS_CSV
    csv_path = Config.LARGE_CSV    
    if not os.path.exists(csv_path):
        print(f"[!] Training data not found: {csv_path}")
        print("[!] Run the IDS to collect traffic data first")
        return None
    
    df = pd.read_csv(csv_path)
    print(f"[+] Loaded {len(df)} traffic samples")
    
    return df

def generate_labels(df):
    """
    Generate labels for training
    0 = normal, 1 = anomaly
    """
    print("\n[*] Generating labels...")
    
    # Simple heuristic: mark as anomaly if:
    # - Status code is 403, 404, 500
    # - Response time > 2 seconds
    # - Path contains suspicious keywords
    
    suspicious_keywords = [
        'admin', 'config', '.env', '.git', 
        'union', 'select', 'script', '..',
        'etc/passwd', 'cmd', 'exec'
    ]
    
    labels = []
    
    for idx, row in df.iterrows():
        is_anomaly = False
        
        # Check status code
        status = row.get('status', 200)
        if status in [403, 404, 500]:
            is_anomaly = True
        
        # Check response time
        response_time = row.get('response_time', 0)
        if response_time > 2.0:
            is_anomaly = True
        
        # Check path for suspicious keywords
        path = str(row.get('path', '')).lower()
        if any(keyword in path for keyword in suspicious_keywords):
            is_anomaly = True
        
        labels.append(1 if is_anomaly else 0)
    
    anomaly_count = sum(labels)
    normal_count = len(labels) - anomaly_count
    
    print(f"[+] Normal samples: {normal_count}")
    print(f"[+] Anomaly samples: {anomaly_count}")
    print(f"[+] Anomaly rate: {anomaly_count/len(labels)*100:.1f}%")
    
    return np.array(labels)

def train_models():
    """Train all ML models"""
    print("\n" + "="*60)
    print("ML MODEL TRAINING")
    print("="*60)
    
    # Load data
    df = load_training_data()
    if df is None:
        return False
    
    if len(df) < 100:
        print(f"[!] Not enough data: {len(df)} samples")
        print("[!] Collect at least 100 samples (1000+ recommended)")
        return False
    
    # Generate labels
    y = generate_labels(df)
    
    # Extract features
    print("\n[*] Extracting features...")
    feature_extractor = FeatureExtractor()
    
    try:
        features_df = feature_extractor.extract_features(df)
        X = feature_extractor.prepare_for_training(features_df)
        
        print(f"[+] Feature shape: {X.shape}")
    except Exception as e:
        print(f"[!] Feature extraction failed: {e}")
        return False
    
    # Train Isolation Forest
    print("\n[*] Training Isolation Forest...")
    if_model = IsolationForestModel()
    
    try:
        if_model.train(X, y)
        
        if_model_path = Config.IF_MODEL_PATH
        if_scaler_path = Config.SCALER_PATH.replace('.pkl', '_if.pkl')
        
        if_model.save(if_model_path, if_scaler_path)
        print(f"[+] Isolation Forest saved to {if_model_path}")
    except Exception as e:
        print(f"[!] Isolation Forest training failed: {e}")
    
    # Train Random Forest
    print("\n[*] Training Random Forest...")
    rf_model = RandomForestModel()
    
    try:
        rf_model.train(X, y)
        
        rf_model_path = Config.RF_MODEL_PATH
        rf_scaler_path = Config.SCALER_PATH.replace('.pkl', '_rf.pkl')
        
        rf_model.save(rf_model_path, rf_scaler_path)
        print(f"[+] Random Forest saved to {rf_model_path}")
    except Exception as e:
        print(f"[!] Random Forest training failed: {e}")
    
    # Test models
    print("\n[*] Testing models...")
    
    if_model.load(if_model_path, if_scaler_path)
    predictions = if_model.predict(X[:10])
    print(f"[+] Isolation Forest predictions: {predictions}")
    
    rf_model.load(rf_model_path, rf_scaler_path)
    predictions = rf_model.predict(X[:10])
    print(f"[+] Random Forest predictions: {predictions}")
    
    print("\n" + "="*60)
    print("✓ TRAINING COMPLETE!")
    print("="*60)
    print("\nRestart the IDS server to load the new models:")
    print("  python app.py")
    print("\n" + "="*60)
    
    return True

if __name__ == '__main__':
    train_models()