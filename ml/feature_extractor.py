import pandas as pd
import numpy as np
from datetime import datetime
from urllib.parse import urlparse
import re
from collections import Counter

class FeatureExtractor:
    """Extract features from raw traffic logs for ML models"""
    
    def __init__(self):
        self.suspicious_keywords = [
            'script', 'select', 'union', 'drop', 'insert', 'update', 'delete',
            'exec', 'execute', 'cmd', 'eval', '../', '..\\', 'passwd', 'shadow'
        ]
    
    def extract_features(self, df):
        """
        Extract features from raw log DataFrame
        
        Args:
            df: DataFrame with columns [timestamp, ip, method, path, status, user_agent, response_time]
        
        Returns:
            DataFrame with extracted features
        """
        features = pd.DataFrame()
        
        # IP-based features
        features['ip'] = df['ip']
        features['request_count'] = df.groupby('ip')['ip'].transform('count')
        features['unique_paths'] = df.groupby('ip')['path'].transform('nunique')
        features['error_rate'] = df.groupby('ip')['status'].transform(
            lambda x: (x >= 400).sum() / len(x)
        )
        
        # Time-based features
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        features['hour'] = df['timestamp'].dt.hour
        features['day_of_week'] = df['timestamp'].dt.dayofweek
        features['is_night'] = ((df['timestamp'].dt.hour >= 22) | 
                                (df['timestamp'].dt.hour <= 6)).astype(int)
        
        # Request rate features
        df_sorted = df.sort_values('timestamp')
        features['requests_per_minute'] = df_sorted.groupby('ip')['timestamp'].transform(
            lambda x: self._calculate_rate(x, window_minutes=1)
        )
        features['requests_per_5min'] = df_sorted.groupby('ip')['timestamp'].transform(
            lambda x: self._calculate_rate(x, window_minutes=5)
        )
        
        # Path-based features
        features['path_length'] = df['path'].str.len()
        features['path_depth'] = df['path'].str.count('/')
        features['has_query_params'] = df['path'].str.contains('\?').astype(int)
        features['suspicious_path'] = df['path'].apply(self._is_suspicious_path).astype(int)
        features['sql_injection_score'] = df['path'].apply(self._sql_injection_score)
        features['xss_score'] = df['path'].apply(self._xss_score)
        
        # Method features
        features['is_post'] = (df['method'] == 'POST').astype(int)
        features['is_get'] = (df['method'] == 'GET').astype(int)
        features['is_unusual_method'] = df['method'].isin(
            ['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE']
        ).astype(int)
        
        # Status code features
        features['status_code'] = df['status']
        features['is_error'] = (df['status'] >= 400).astype(int)
        features['is_server_error'] = (df['status'] >= 500).astype(int)
        
        # User agent features
        features['user_agent_length'] = df['user_agent'].str.len()
        features['is_bot'] = df['user_agent'].str.lower().str.contains(
            'bot|crawler|spider|scraper', na=False
        ).astype(int)
        features['suspicious_user_agent'] = df['user_agent'].apply(
            self._is_suspicious_user_agent
        ).astype(int)
        
        # Response time features
        features['response_time'] = df['response_time']
        features['response_time_zscore'] = (
            df['response_time'] - df['response_time'].mean()
        ) / df['response_time'].std()
        
        # Entropy features
        features['path_entropy'] = df['path'].apply(self._calculate_entropy)
        
        return features
    
    def _calculate_rate(self, timestamps, window_minutes=1):
        """Calculate request rate within a time window"""
        if len(timestamps) == 0:
            return 0
        
        window = pd.Timedelta(minutes=window_minutes)
        latest = timestamps.iloc[-1]
        recent = timestamps[timestamps >= (latest - window)]
        return len(recent)
    
    def _is_suspicious_path(self, path):
        """Check if path contains suspicious patterns"""
        path_lower = path.lower()
        return any(keyword in path_lower for keyword in self.suspicious_keywords)
    
    def _sql_injection_score(self, path):
        """Calculate SQL injection likelihood score"""
        sql_keywords = ['select', 'union', 'from', 'where', 'drop', 'insert', 'update', 'delete']
        path_lower = path.lower()
        score = sum(1 for keyword in sql_keywords if keyword in path_lower)
        
        # Additional patterns
        if re.search(r"['\";]|--|\*|\/\*", path):
            score += 2
        if re.search(r"(union.*select|select.*from)", path_lower):
            score += 3
            
        return min(score, 10)  # Cap at 10
    
    def _xss_score(self, path):
        """Calculate XSS attack likelihood score"""
        xss_patterns = [
            r'<script', r'javascript:', r'onerror', r'onload', r'alert\(',
            r'document\.cookie', r'eval\(', r'<iframe'
        ]
        path_lower = path.lower()
        score = sum(1 for pattern in xss_patterns if re.search(pattern, path_lower))
        return min(score, 10)  # Cap at 10
    
    def _is_suspicious_user_agent(self, user_agent):
        """Check for suspicious user agent strings"""
        if pd.isna(user_agent):
            return 1  # Empty user agent is suspicious
        
        suspicious_agents = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'dirbuster', 'havij',
            'acunetix', 'nessus', 'burp', 'metasploit'
        ]
        user_agent_lower = user_agent.lower()
        return any(agent in user_agent_lower for agent in suspicious_agents)
    
    def _calculate_entropy(self, string):
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        
        counts = Counter(string)
        length = len(string)
        entropy = -sum(count/length * np.log2(count/length) for count in counts.values())
        return entropy
    
    def prepare_for_training(self, features_df, labels=None):
        """
        Prepare features for model training
        
        Args:
            features_df: DataFrame with extracted features
            labels: Optional labels (0=normal, 1=suspicious)
        
        Returns:
            X, y (if labels provided) or just X
        """
        # Drop non-numeric columns
        numeric_features = features_df.select_dtypes(include=[np.number]).copy()
        
        # Remove IP column if present
        if 'ip' in numeric_features.columns:
            numeric_features = numeric_features.drop('ip', axis=1)
        
        # Handle missing values
        numeric_features = numeric_features.fillna(0)
        
        X = numeric_features.values
        
        if labels is not None:
            y = labels.values
            return X, y
        
        return X