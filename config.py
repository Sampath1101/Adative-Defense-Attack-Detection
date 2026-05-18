import os

class Config:
    """Application configuration"""
    
    # Base directory
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    # Directory paths
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')
    DATA_DIR = os.path.join(BASE_DIR, 'test_sample')
    DATAA_DIR = os.path.join(BASE_DIR, 'data')
    ML_DIR = os.path.join(BASE_DIR, 'ml')
    
    # File paths
    TRAFFIC_LOG = os.path.join(LOGS_DIR, 'traffic.log')
    RAW_LOGS_CSV = os.path.join(DATA_DIR, 'raw_logs.csv')
    SUSPICIOUS_CSV = os.path.join(DATA_DIR, 'suspicious_activity.csv')
    NORMAL_CSV = os.path.join(DATA_DIR, 'normal_activity.csv')
    LARGE_CSV=os.path.join(DATAA_DIR,'NF-UQ-NIDS-v2.csv')
    
    # Model paths
    RF_MODEL_PATH = os.path.join(ML_DIR, 'random_forest_model.pkl')
    IF_MODEL_PATH = os.path.join(ML_DIR, 'isolation_forest_model.pkl')
    SCALER_PATH = os.path.join(ML_DIR, 'scaler.pkl')
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEBUG = True
    
    # ML settings
    ANOMALY_THRESHOLD = 0.6  # Threshold for anomaly detection
    RETRAIN_INTERVAL = 3600  # Retrain every hour (in seconds)
    
    # Alert settings
    ALERT_EMAIL = os.environ.get('ALERT_EMAIL') or 'admin@example.com'
    MAX_ALERTS_PER_MINUTE = 10
    
    # Rule-based thresholds
    MAX_REQUESTS_PER_MINUTE = 100
    SUSPICIOUS_PATHS = ['/admin', '/wp-admin', '/.env', '/config', '/phpMyAdmin']
    SUSPICIOUS_USER_AGENTS = ['sqlmap', 'nikto', 'nmap', 'masscan']
    
    @staticmethod
    def init_app(app):
        """Initialize application with config"""
        # Create necessary directories
        os.makedirs(Config.LOGS_DIR, exist_ok=True)
        os.makedirs(Config.DATA_DIR, exist_ok=True)
        os.makedirs(Config.ML_DIR, exist_ok=True)