# import numpy as np
# import pandas as pd
# from datetime import datetime
# import os
# import sys

# sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# from config import Config
# from ml.feature_extractor import FeatureExtractor
# from ml.isolation_model import IsolationForestModel
# from ml.random_forest_model import RandomForestModel
# from detection.rules import RuleBasedDetector

# class AnomalyDetector:
#     """Combined anomaly detection using ML models and rules"""
    
#     def __init__(self):
#         self.feature_extractor = FeatureExtractor()
#         self.rule_detector = RuleBasedDetector()
        
#         # Initialize ML models
#         self.if_model = IsolationForestModel()
#         self.rf_model = RandomForestModel()
        
#         # Load pre-trained models
#         self.load_models()
    
#     def load_models(self):
#         """Load pre-trained ML models"""
#         # Load Isolation Forest
#         if_model_path = Config.IF_MODEL_PATH
#         if_scaler_path = Config.SCALER_PATH.replace('.pkl', '_if.pkl')
        
#         if os.path.exists(if_model_path) and os.path.exists(if_scaler_path):
#             self.if_model.load(if_model_path, if_scaler_path)
#             self.if_loaded = True
#         else:
#             print("⚠ Isolation Forest model not found. Run training first.")
#             self.if_loaded = False
        
#         # Load Random Forest
#         rf_model_path = Config.RF_MODEL_PATH
#         rf_scaler_path = Config.SCALER_PATH.replace('.pkl', '_rf.pkl')
        
#         if os.path.exists(rf_model_path) and os.path.exists(rf_scaler_path):
#             self.rf_model.load(rf_model_path, rf_scaler_path)
#             self.rf_loaded = True
#         else:
#             print("⚠ Random Forest model not found. Using Isolation Forest only.")
#             self.rf_loaded = False
    
#     def detect(self, request_data):
#         """                                    # ekkada sarting comment code nenu change chasaa......
#         Detect anomalies in a request
        
#         Args:
#             request_data: Dict or DataFrame with request info
        
#         Returns:
#             {
#                 'is_suspicious': bool,
#                 'confidence': float (0-1),
#                 'detection_method': 'rule'|'ml'|'hybrid',
#                 'reasons': list of reasons,
#                 'severity': 'low'|'medium'|'high',
#                 'ml_scores': dict with model scores
#             }
#               """                                          # ending code comment chasadu
#         # Convert to DataFrame if needed
#         if isinstance(request_data, dict):
#             df = pd.DataFrame([request_data])
#         else:
#             df = request_data.copy()
        
#         # Rule-based detection
#         rule_result = self.rule_detector.analyze_request(request_data if isinstance(request_data, dict) else request_data.iloc[0].to_dict())
        
#         # ML-based detection
#         ml_suspicious = False
#         ml_confidence = 0.0
#         ml_scores = {}
        
#         try:
#             # Extract features
#             features_df = self.feature_extractor.extract_features(df)
#             X = self.feature_extractor.prepare_for_training(features_df)
            
#             # Get predictions from available models
#             if self.if_loaded:
#                 if_proba = self.if_model.predict_proba(X)[0]
#                 ml_scores['isolation_forest'] = float(if_proba)
            
#             if self.rf_loaded:
#                 rf_proba = self.rf_model.predict_proba(X)[0]
#                 ml_scores['random_forest'] = float(rf_proba)
            
#             # Combine ML scores
#             if ml_scores:
#                 ml_confidence = np.mean(list(ml_scores.values()))
#                 ml_suspicious = ml_confidence > Config.ANOMALY_THRESHOLD
        
#         except Exception as e:
#             print(f"⚠ ML detection failed: {e}")
        
#         # Combine results
#         is_suspicious = rule_result['is_suspicious'] or ml_suspicious
#         reasons = rule_result['reasons'].copy()
        
#         if ml_suspicious:
#             reasons.append(f"ML models detected anomaly (confidence: {ml_confidence:.2f})")
        
#         # Determine detection method
#         if rule_result['is_suspicious'] and ml_suspicious:
#             detection_method = 'hybrid'
#         elif rule_result['is_suspicious']:
#             detection_method = 'rule'
#         elif ml_suspicious:
#             detection_method = 'ml'
#         else:
#             detection_method = 'none'
        
#         # Calculate overall confidence
#         if detection_method == 'hybrid':
#             confidence = min(1.0, (ml_confidence + 0.8) / 2)  # Rules have high confidence
#         elif detection_method == 'rule':
#             confidence = 0.8
#         elif detection_method == 'ml':
#             confidence = ml_confidence
#         else:
#             confidence = 1.0 - ml_confidence  # Confidence in being normal
        
#         # Adjust severity based on ML confidence
#         severity = rule_result['severity']
#         if ml_suspicious and ml_confidence > 0.9:
#             severity = 'high'
#         elif ml_suspicious and ml_confidence > 0.75 and severity == 'low':
#             severity = 'medium'
        
#         return {
#             'is_suspicious': is_suspicious,
#             'confidence': confidence,
#             'detection_method': detection_method,
#             'reasons': reasons,
#             'severity': severity,
#             'ml_scores': ml_scores
#         }
    
#     def detect_batch(self, requests_df):
#         """
#         Detect anomalies in a batch of requests
        
#         Args:
#             requests_df: DataFrame with multiple requests
        
#         Returns:
#             List of detection results
#         """
#         results = []
        
#         for idx, row in requests_df.iterrows():
#             result = self.detect(row.to_dict())
#             results.append(result)
        
#         return results
    
#     def get_statistics(self):
#         """Get detection statistics"""
#         return {
#             'models_loaded': {
#                 'isolation_forest': self.if_loaded,
#                 'random_forest': self.rf_loaded
#             },
#             'blocked_ips': len(self.rule_detector.blocked_ips),
#             'active_connections': len(self.rule_detector.request_counts)
#         }

#---------------------option2--------------------------------------------------------------------------------------

# import numpy as np
# import pandas as pd
# from datetime import datetime
# import os
# import sys
# import re

# sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# from config import Config
# from detection.rules import RuleBasedDetector

# # Try to import ML components (optional)
# try:
#     from ml.feature_extractor import FeatureExtractor
#     from ml.isolation_model import IsolationForestModel
#     from ml.random_forest_model import RandomForestModel
#     ML_AVAILABLE = True
# except ImportError:
#     ML_AVAILABLE = False
#     print("⚠️  ML models not available - using rule-based detection only")

# class AnomalyDetector:
#     """
#     Combined anomaly detection using pattern matching and ML models
#     Enhanced with immediate threat detection
#     """
    
#     def __init__(self):
#         print("[*] Initializing Anomaly Detector...")
        
#         # Rule-based detector
#         self.rule_detector = RuleBasedDetector()
        
#         # ML components (if available)
#         self.ml_available = ML_AVAILABLE
#         if self.ml_available:
#             try:
#                 self.feature_extractor = FeatureExtractor()
#                 self.if_model = IsolationForestModel()
#                 self.rf_model = RandomForestModel()
#                 self.load_models()
#             except Exception as e:
#                 print(f"⚠️  ML initialization failed: {e}")
#                 self.ml_available = False
        
#         # Attack pattern database
#         self.sql_injection_patterns = [
#             r"('\s*or\s*'1'\s*=\s*'1)", r"('\s*or\s*1\s*=\s*1)",
#             r"(admin'\s*--)", r"(admin'--)", r"('\s*or\s*''\s*=\s*')",
#             r"(union\s+select)", r"(union\s+all\s+select)",
#             r"('\s*union)", r"(select\s+.*\s+from)", r"(drop\s+table)",
#             r"(insert\s+into)", r"(delete\s+from)", r"(exec\s*\()",
#             r"(execute\s*\()", r"(xp_cmdshell)", r"(sp_executesql)",
#             r"(';\s*drop)", r"(';\s*delete)", r"(';\s*insert)",
#             r"(0x27)", r"(0x3d)", r"(char\s*\()", r"(ascii\s*\()",
#             r"(substring\s*\()", r"(waitfor\s+delay)", r"(benchmark\s*\()",
#             r"(sleep\s*\()", r"(pg_sleep)", r"(1'\s*and\s*'1'\s*=\s*'1)"
#         ]
        
#         self.xss_patterns = [
#             r"<script[^>]*>", r"</script>", r"javascript\s*:",
#             r"onerror\s*=", r"onload\s*=", r"<img[^>]*>",
#             r"<iframe[^>]*>", r"<svg[^>]*>", r"alert\s*\(",
#             r"prompt\s*\(", r"confirm\s*\(", r"document\.cookie",
#             r"document\.location", r"eval\s*\(", r"expression\s*\(",
#             r"<object[^>]*>", r"<embed[^>]*>", r"onmouseover\s*=",
#             r"onclick\s*=", r"onfocus\s*=", r"onblur\s*=",
#             r"<body[^>]*onload", r"<input[^>]*onfocus"
#         ]
        
#         self.path_traversal_patterns = [
#             r"\.\./", r"\.\.\\", r"\.\.%2f", r"\.\.%5c",
#             r"%2e%2e/", r"%2e%2e\\", r"/etc/passwd", r"/etc/shadow",
#             r"c:\\windows", r"c:/windows", r"\\windows\\system32",
#             r"\.\.%252f", r"\.\.%255c"
#         ]
        
#         self.command_injection_patterns = [
#             r"\|\s*\w+", r";\s*\w+", r"&\s*\w+", r"&&\s*\w+",
#             r"\|\|\s*\w+", r"\$\(", r"`\w+", r"\$\{",
#             r"cat\s+", r"ls\s+", r"whoami", r"\bid\b",
#             r"wget\s+", r"curl\s+", r"/bin/", r"/usr/bin/",
#             r"cmd\.exe", r"powershell", r"bash\s+-c"
#         ]
        
#         self.admin_paths = [
#             '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
#             '/cpanel', '/webmail', '/manager', '/config',
#             '/.env', '/.git', '/.svn', '/backup', '/.htaccess',
#             '/web.config', '/database', '/.aws', '/.ssh'
#         ]
        
#         self.scanner_user_agents = [
#             'sqlmap', 'nikto', 'nmap', 'masscan', 'nessus',
#             'openvas', 'w3af', 'acunetix', 'burp', 'zap',
#             'metasploit', 'havij', 'pangolin'
#         ]
        
#         self.dangerous_extensions = [
#             '.php', '.asp', '.aspx', '.jsp', '.cgi',
#             '.sh', '.bat', '.cmd', '.exe', '.dll'
#         ]
        
#         print("[+] Anomaly Detector ready")
#         print(f"    - SQL Injection patterns: {len(self.sql_injection_patterns)}")
#         print(f"    - XSS patterns: {len(self.xss_patterns)}")
#         print(f"    - Path Traversal patterns: {len(self.path_traversal_patterns)}")
#         print(f"    - Command Injection patterns: {len(self.command_injection_patterns)}")
#         print(f"    - ML models: {'Enabled' if self.ml_available else 'Disabled'}")
    
#     def load_models(self):
#         """Load pre-trained ML models"""
#         try:
#             # Load Isolation Forest
#             if_model_path = Config.IF_MODEL_PATH
#             if_scaler_path = Config.SCALER_PATH.replace('.pkl', '_if.pkl')
            
#             if os.path.exists(if_model_path) and os.path.exists(if_scaler_path):
#                 self.if_model.load(if_model_path, if_scaler_path)
#                 self.if_loaded = True
#                 print("[+] Isolation Forest model loaded")
#             else:
#                 self.if_loaded = False
            
#             # Load Random Forest
#             rf_model_path = Config.RF_MODEL_PATH
#             rf_scaler_path = Config.SCALER_PATH.replace('.pkl', '_rf.pkl')
            
#             if os.path.exists(rf_model_path) and os.path.exists(rf_scaler_path):
#                 self.rf_model.load(rf_model_path, rf_scaler_path)
#                 self.rf_loaded = True
#                 print("[+] Random Forest model loaded")
#             else:
#                 self.rf_loaded = False
#         except Exception as e:
#             print(f"⚠️  Model loading failed: {e}")
#             self.if_loaded = False
#             self.rf_loaded = False
    
#     def check_sql_injection(self, text):
#         """Check for SQL injection patterns"""
#         if not text:
#             return False, []
        
#         text_lower = text.lower()
#         matches = []
        
#         for pattern in self.sql_injection_patterns:
#             if re.search(pattern, text_lower, re.IGNORECASE):
#                 matches.append(f"SQL pattern: {pattern}")
        
#         return len(matches) > 0, matches
    
#     def check_xss(self, text):
#         """Check for XSS patterns"""
#         if not text:
#             return False, []
        
#         text_lower = text.lower()
#         matches = []
        
#         for pattern in self.xss_patterns:
#             if re.search(pattern, text_lower, re.IGNORECASE):
#                 matches.append(f"XSS pattern: {pattern}")
        
#         return len(matches) > 0, matches
    
#     def check_path_traversal(self, text):
#         """Check for path traversal patterns"""
#         if not text:
#             return False, []
        
#         text_lower = text.lower()
#         matches = []
        
#         for pattern in self.path_traversal_patterns:
#             if re.search(pattern, text_lower, re.IGNORECASE):
#                 matches.append(f"Path traversal: {pattern}")
        
#         return len(matches) > 0, matches
    
#     def check_command_injection(self, text):
#         """Check for command injection patterns"""
#         if not text:
#             return False, []
        
#         text_lower = text.lower()
#         matches = []
        
#         for pattern in self.command_injection_patterns:
#             if re.search(pattern, text_lower, re.IGNORECASE):
#                 matches.append(f"Command injection: {pattern}")
        
#         return len(matches) > 0, matches
    
#     def check_admin_access(self, path):
#         """Check for admin path access"""
#         if not path:
#             return False, []
        
#         path_lower = path.lower()
#         matches = []
        
#         for admin_path in self.admin_paths:
#             if admin_path in path_lower:
#                 matches.append(f"Admin path access: {admin_path}")
        
#         return len(matches) > 0, matches
    
#     def check_scanner(self, user_agent):
#         """Check for security scanner user agents"""
#         if not user_agent:
#             return False, []
        
#         ua_lower = user_agent.lower()
#         matches = []
        
#         for scanner in self.scanner_user_agents:
#             if scanner in ua_lower:
#                 matches.append(f"Scanner detected: {scanner}")
        
#         return len(matches) > 0, matches
    
#     def check_dangerous_extension(self, path):
#         """Check for dangerous file extensions"""
#         if not path:
#             return False, []
        
#         path_lower = path.lower()
#         matches = []
        
#         for ext in self.dangerous_extensions:
#             if path_lower.endswith(ext):
#                 matches.append(f"Dangerous extension: {ext}")
        
#         return len(matches) > 0, matches
    
#     def analyze_request_patterns(self, request_data):
#         """
#         Analyze request for attack patterns
#         Returns: detection result with detailed findings
#         """
#         path = request_data.get('path', '')
#         query_string = request_data.get('query_string', '')
#         user_agent = request_data.get('user_agent', '')
#         method = request_data.get('method', 'GET')
        
#         # Combine path and query for analysis
#         full_url = f"{path}?{query_string}" if query_string else path
        
#         attack_types = []
#         reasons = []
#         pattern_matches = []
#         severity = 'low'
#         confidence = 0.0
        
#         # Check SQL Injection
#         sql_detected, sql_matches = self.check_sql_injection(full_url)
#         if sql_detected:
#             attack_types.append('sql_injection')
#             reasons.append("SQL injection pattern detected")
#             pattern_matches.extend(sql_matches[:3])  # Limit to 3
#             severity = 'high'
#             confidence = max(confidence, 0.95)
        
#         # Check XSS
#         xss_detected, xss_matches = self.check_xss(full_url)
#         if xss_detected:
#             attack_types.append('xss')
#             reasons.append("XSS pattern detected")
#             pattern_matches.extend(xss_matches[:3])
#             severity = 'high'
#             confidence = max(confidence, 0.90)
        
#         # Check Path Traversal
#         traversal_detected, traversal_matches = self.check_path_traversal(full_url)
#         if traversal_detected:
#             attack_types.append('path_traversal')
#             reasons.append("Path traversal pattern detected")
#             pattern_matches.extend(traversal_matches[:3])
#             severity = 'high' if severity == 'low' else severity
#             confidence = max(confidence, 0.85)
        
#         # Check Command Injection
#         cmd_detected, cmd_matches = self.check_command_injection(full_url)
#         if cmd_detected:
#             attack_types.append('command_injection')
#             reasons.append("Command injection pattern detected")
#             pattern_matches.extend(cmd_matches[:3])
#             severity = 'high'
#             confidence = max(confidence, 0.90)
        
#         # Check Admin Access
#         admin_detected, admin_matches = self.check_admin_access(path)
#         if admin_detected:
#             attack_types.append('admin_access')
#             reasons.append("Sensitive path access attempt")
#             pattern_matches.extend(admin_matches)
#             severity = 'medium' if severity == 'low' else severity
#             confidence = max(confidence, 0.80)
        
#         # Check Scanner
#         scanner_detected, scanner_matches = self.check_scanner(user_agent)
#         if scanner_detected:
#             attack_types.append('scanner')
#             reasons.append("Security scanner detected")
#             pattern_matches.extend(scanner_matches)
#             severity = 'medium' if severity == 'low' else severity
#             confidence = max(confidence, 0.95)
        
#         # Check Dangerous Extension
#         ext_detected, ext_matches = self.check_dangerous_extension(path)
#         if ext_detected:
#             attack_types.append('dangerous_file')
#             reasons.append("Dangerous file extension")
#             pattern_matches.extend(ext_matches)
#             severity = 'medium' if severity == 'low' else severity
#             confidence = max(confidence, 0.75)
        
#         is_suspicious = len(attack_types) > 0
        
#         return {
#             'is_suspicious': is_suspicious,
#             'attack_types': attack_types,
#             'reasons': reasons,
#             'pattern_matches': pattern_matches,
#             'severity': severity,
#             'confidence': confidence,
#             'detection_method': 'pattern' if is_suspicious else 'none'
#         }
    
#     def detect(self, request_data):
#         """
#         Main detection method - analyzes request for threats
        
#         Args:
#             request_data: Dict with request info (path, query_string, user_agent, etc.)
        
#         Returns:
#             Dict with detection results
#         """
#         # Convert to DataFrame if needed
#         if isinstance(request_data, dict):
#             df = pd.DataFrame([request_data])
#         else:
#             df = request_data.copy()
#             request_data = df.iloc[0].to_dict()
        
#         # Step 1: Pattern-based detection (immediate)
#         pattern_result = self.analyze_request_patterns(request_data)
        
#         # Step 2: Rule-based detection
#         try:
#             rule_result = self.rule_detector.analyze_request(request_data)
            
#             # Merge rule results with pattern results
#             if rule_result['is_suspicious']:
#                 pattern_result['is_suspicious'] = True
#                 pattern_result['attack_types'].extend(rule_result.get('attack_types', []))
#                 pattern_result['reasons'].extend(rule_result.get('reasons', []))
                
#                 # Update severity if rule detection found higher severity
#                 if rule_result.get('severity') == 'high':
#                     pattern_result['severity'] = 'high'
#                 elif rule_result.get('severity') == 'medium' and pattern_result['severity'] == 'low':
#                     pattern_result['severity'] = 'medium'
#         except Exception as e:
#             print(f"⚠️  Rule detection failed: {e}")
        
#         # Step 3: ML-based detection (if available)
#         ml_scores = {}
#         if self.ml_available:
#             try:
#                 features_df = self.feature_extractor.extract_features(df)
#                 X = self.feature_extractor.prepare_for_training(features_df)
                
#                 if hasattr(self, 'if_loaded') and self.if_loaded:
#                     if_proba = self.if_model.predict_proba(X)[0]
#                     ml_scores['isolation_forest'] = float(if_proba)
                
#                 if hasattr(self, 'rf_loaded') and self.rf_loaded:
#                     rf_proba = self.rf_model.predict_proba(X)[0]
#                     ml_scores['random_forest'] = float(rf_proba)
                
#                 # If ML detects anomaly
#                 if ml_scores:
#                     ml_confidence = np.mean(list(ml_scores.values()))
#                     if ml_confidence > Config.ANOMALY_THRESHOLD:
#                         pattern_result['is_suspicious'] = True
#                         pattern_result['reasons'].append(
#                             f"ML anomaly detected (confidence: {ml_confidence:.2f})"
#                         )
#                         pattern_result['confidence'] = max(
#                             pattern_result['confidence'], ml_confidence
#                         )
            
#             except Exception as e:
#                 print(f"⚠️  ML detection failed: {e}")
        
#         pattern_result['ml_scores'] = ml_scores
        
#         # Remove duplicates
#         pattern_result['attack_types'] = list(set(pattern_result['attack_types']))
#         pattern_result['reasons'] = list(set(pattern_result['reasons']))
        
#         return pattern_result
    
#     def detect_batch(self, requests_df):
#         """
#         Detect anomalies in a batch of requests
        
#         Args:
#             requests_df: DataFrame with multiple requests
        
#         Returns:
#             List of detection results
#         """
#         results = []
        
#         for idx, row in requests_df.iterrows():
#             result = self.detect(row.to_dict())
#             results.append(result)
        
#         return results
    
#     def get_statistics(self):
#         """Get detection statistics"""
#         stats = {
#             'models_loaded': self.ml_available,
#             'pattern_detection': True,
#             'sql_patterns': len(self.sql_injection_patterns),
#             'xss_patterns': len(self.xss_patterns),
#             'path_traversal_patterns': len(self.path_traversal_patterns),
#             'command_injection_patterns': len(self.command_injection_patterns)
#         }
        
#         if self.ml_available and hasattr(self, 'if_loaded') and hasattr(self, 'rf_loaded'):
#             stats['models_loaded'] = {
#                 'isolation_forest': self.if_loaded,
#                 'random_forest': self.rf_loaded
#             }
        
#         try:
#             stats['blocked_ips'] = len(self.rule_detector.blocked_ips)
#             stats['active_connections'] = len(self.rule_detector.request_counts)
#         except:
#             pass
        
#         return stats
    
#     def add_custom_pattern(self, attack_type, pattern):
#         """Add custom attack pattern"""
#         if attack_type == 'sql_injection':
#             self.sql_injection_patterns.append(pattern)
#         elif attack_type == 'xss':
#             self.xss_patterns.append(pattern)
#         elif attack_type == 'path_traversal':
#             self.path_traversal_patterns.append(pattern)
#         elif attack_type == 'command_injection':
#             self.command_injection_patterns.append(pattern)
        
#         print(f"[+] Added custom pattern for {attack_type}")

#------------------------------optioon3----------------------------(encoding work for xss perpusoos)-----

import numpy as np
import pandas as pd
from datetime import datetime
import os
import sys
import re
import urllib.parse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from detection.rules import RuleBasedDetector

# Try to import ML components (optional)
try:
    from ml.feature_extractor import FeatureExtractor
    from ml.isolation_model import IsolationForestModel
    from ml.random_forest_model import RandomForestModel
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("⚠️  ML models not available - using rule-based detection only")

class AnomalyDetector:
    """
    Combined anomaly detection using pattern matching and ML models
    Enhanced with URL decoding and comprehensive pattern matching
    """
    
    def __init__(self):
        print("[*] Initializing Anomaly Detector...")
        
        # Rule-based detector
        self.rule_detector = RuleBasedDetector()
        
        # ML components (if available)
        self.ml_available = ML_AVAILABLE
        if self.ml_available:
            try:
                self.feature_extractor = FeatureExtractor()
                self.if_model = IsolationForestModel()
                self.rf_model = RandomForestModel()
                self.load_models()
            except Exception as e:
                print(f"⚠️  ML initialization failed: {e}")
                self.ml_available = False
        
        # Attack pattern database
        self.sql_injection_patterns = [
            r"('\s*or\s*'1'\s*=\s*'1)", r"('\s*or\s*1\s*=\s*1)",
            r"(admin'\s*--)", r"(admin'--)", r"('\s*or\s*''\s*=\s*')",
            r"(union\s+select)", r"(union\s+all\s+select)",
            r"('\s*union)", r"(select\s+.*\s+from)", r"(drop\s+table)",
            r"(insert\s+into)", r"(delete\s+from)", r"(exec\s*\()",
            r"(execute\s*\()", r"(xp_cmdshell)", r"(sp_executesql)",
            r"(';\s*drop)", r"(';\s*delete)", r"(';\s*insert)",
            r"(0x27)", r"(0x3d)", r"(char\s*\()", r"(ascii\s*\()",
            r"(substring\s*\()", r"(waitfor\s+delay)", r"(benchmark\s*\()",
            r"(sleep\s*\()", r"(pg_sleep)", r"(1'\s*and\s*'1'\s*=\s*'1)",
            r"('\s*--)", r"(--\s*$)", r"(#\s*$)"
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>", r"</script>", r"javascript\s*:",
            r"onerror\s*=", r"onload\s*=", r"<img[^>]*>",
            r"<iframe[^>]*>", r"<svg[^>]*>", r"alert\s*\(",
            r"prompt\s*\(", r"confirm\s*\(", r"document\.cookie",
            r"document\.location", r"eval\s*\(", r"expression\s*\(",
            r"<object[^>]*>", r"<embed[^>]*>", r"onmouseover\s*=",
            r"onclick\s*=", r"onfocus\s*=", r"onblur\s*=",
            r"<body[^>]*onload", r"<input[^>]*onfocus"
        ]
        
        self.path_traversal_patterns = [
            r"\.\./", r"\.\.\\", r"\.\.%2f", r"\.\.%5c",
            r"%2e%2e/", r"%2e%2e\\", r"/etc/passwd", r"/etc/shadow",
            r"c:\\windows", r"c:/windows", r"\\windows\\system32",
            r"\.\.%252f", r"\.\.%255c"
        ]
        
        self.command_injection_patterns = [
            r"\|\s*\w+", r";\s*\w+", r"&\s*\w+", r"&&\s*\w+",
            r"\|\|\s*\w+", r"\$\(", r"`\w+", r"\$\{",
            r"cat\s+", r"ls\s+", r"whoami", r"\bid\b",
            r"wget\s+", r"curl\s+", r"/bin/", r"/usr/bin/",
            r"cmd\.exe", r"powershell", r"bash\s+-c"
        ]
        
        self.admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
            '/cpanel', '/webmail', '/manager', '/config',
            '/.env', '/.git', '/.svn', '/backup', '/.htaccess',
            '/web.config', '/database', '/.aws', '/.ssh'
        ]
        
        self.scanner_user_agents = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'nessus',
            'openvas', 'w3af', 'acunetix', 'burp', 'zap',
            'metasploit', 'havij', 'pangolin'
        ]
        
        self.dangerous_extensions = [
            '.php', '.asp', '.aspx', '.jsp', '.cgi',
            '.sh', '.bat', '.cmd', '.exe', '.dll'
        ]
        
        print("[+] Anomaly Detector ready")
        print(f"    - SQL Injection patterns: {len(self.sql_injection_patterns)}")
        print(f"    - XSS patterns: {len(self.xss_patterns)}")
        print(f"    - Path Traversal patterns: {len(self.path_traversal_patterns)}")
        print(f"    - Command Injection patterns: {len(self.command_injection_patterns)}")
        print(f"    - URL decoding: ENABLED")
        print(f"    - ML models: {'Enabled' if self.ml_available else 'Disabled'}")
    
    def load_models(self):
        """Load pre-trained ML models"""
        try:
            if_model_path = Config.IF_MODEL_PATH
            if_scaler_path = Config.SCALER_PATH.replace('.pkl', '_if.pkl')
            
            if os.path.exists(if_model_path) and os.path.exists(if_scaler_path):
                self.if_model.load(if_model_path, if_scaler_path)
                self.if_loaded = True
                print("[+] Isolation Forest model loaded")
            else:
                self.if_loaded = False
            
            rf_model_path = Config.RF_MODEL_PATH
            rf_scaler_path = Config.SCALER_PATH.replace('.pkl', '_rf.pkl')
            
            if os.path.exists(rf_model_path) and os.path.exists(rf_scaler_path):
                self.rf_model.load(rf_model_path, rf_scaler_path)
                self.rf_loaded = True
                print("[+] Random Forest model loaded")
            else:
                self.rf_loaded = False
        except Exception as e:
            print(f"⚠️  Model loading failed: {e}")
            self.if_loaded = False
            self.rf_loaded = False
    
    def url_decode(self, text):
        """
        Decode URL-encoded strings
        CRITICAL: Decode %27 -> ', %20 -> space, etc.
        """
        if not text:
            return text
        
        try:
            # Decode multiple times to handle double encoding
            decoded = text
            for _ in range(3):  # Max 3 levels of encoding
                new_decoded = urllib.parse.unquote(decoded)
                if new_decoded == decoded:
                    break
                decoded = new_decoded
            
            return decoded
        except:
            return text
    
    def check_sql_injection(self, text):
        """Check for SQL injection patterns"""
        if not text:
            return False, []
        
        # CRITICAL: Decode URL encoding first
        decoded_text = self.url_decode(text)
        text_lower = decoded_text.lower()
        
        print(f"[DEBUG SQL] Original: {text}")
        print(f"[DEBUG SQL] Decoded: {decoded_text}")
        
        matches = []
        
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                matches.append(f"SQL pattern: {pattern}")
                print(f"[DEBUG SQL] MATCHED: {pattern}")
        
        return len(matches) > 0, matches
    
    def check_xss(self, text):
        """Check for XSS patterns"""
        if not text:
            return False, []
        
        # Decode URL encoding
        decoded_text = self.url_decode(text)
        text_lower = decoded_text.lower()
        
        matches = []
        
        for pattern in self.xss_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                matches.append(f"XSS pattern: {pattern}")
        
        return len(matches) > 0, matches
    
    def check_path_traversal(self, text):
        """Check for path traversal patterns"""
        if not text:
            return False, []
        
        decoded_text = self.url_decode(text)
        text_lower = decoded_text.lower()
        
        matches = []
        
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                matches.append(f"Path traversal: {pattern}")
        
        return len(matches) > 0, matches
    
    def check_command_injection(self, text):
        """Check for command injection patterns"""
        if not text:
            return False, []
        
        decoded_text = self.url_decode(text)
        text_lower = decoded_text.lower()
        
        matches = []
        
        for pattern in self.command_injection_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                matches.append(f"Command injection: {pattern}")
        
        return len(matches) > 0, matches
    
    def check_admin_access(self, path):
        """Check for admin path access"""
        if not path:
            return False, []
        
        path_lower = path.lower()
        matches = []
        
        for admin_path in self.admin_paths:
            if admin_path in path_lower:
                matches.append(f"Admin path access: {admin_path}")
        
        return len(matches) > 0, matches
    
    def check_scanner(self, user_agent):
        """Check for security scanner user agents"""
        if not user_agent:
            return False, []
        
        ua_lower = user_agent.lower()
        matches = []
        
        for scanner in self.scanner_user_agents:
            if scanner in ua_lower:
                matches.append(f"Scanner detected: {scanner}")
        
        return len(matches) > 0, matches
    
    def check_dangerous_extension(self, path):
        """Check for dangerous file extensions"""
        if not path:
            return False, []
        
        path_lower = path.lower()
        matches = []
        
        for ext in self.dangerous_extensions:
            if path_lower.endswith(ext):
                matches.append(f"Dangerous extension: {ext}")
        
        return len(matches) > 0, matches
    
    def analyze_request_patterns(self, request_data):
        """
        Analyze request for attack patterns
        CRITICAL: URL decode before checking
        """
        path = request_data.get('path', '')
        query_string = request_data.get('query_string', '')
        user_agent = request_data.get('user_agent', '')
        method = request_data.get('method', 'GET')
        
        # Combine path and query for analysis
        full_url = f"{path}?{query_string}" if query_string else path
        
        print(f"\n[DEBUG PATTERN] Analyzing full URL: {full_url}")
        
        attack_types = []
        reasons = []
        pattern_matches = []
        severity = 'low'
        confidence = 0.0
        
        # Check SQL Injection
        sql_detected, sql_matches = self.check_sql_injection(full_url)
        if sql_detected:
            attack_types.append('sql_injection')
            reasons.append("SQL injection pattern detected")
            pattern_matches.extend(sql_matches[:3])
            severity = 'high'
            confidence = max(confidence, 0.95)
            print(f"[DEBUG PATTERN] SQL Injection DETECTED!")
        
        # Check XSS
        xss_detected, xss_matches = self.check_xss(full_url)
        if xss_detected:
            attack_types.append('xss')
            reasons.append("XSS pattern detected")
            pattern_matches.extend(xss_matches[:3])
            severity = 'high'
            confidence = max(confidence, 0.90)
            print(f"[DEBUG PATTERN] XSS DETECTED!")
        
        # Check Path Traversal
        traversal_detected, traversal_matches = self.check_path_traversal(full_url)
        if traversal_detected:
            attack_types.append('path_traversal')
            reasons.append("Path traversal pattern detected")
            pattern_matches.extend(traversal_matches[:3])
            severity = 'high' if severity == 'low' else severity
            confidence = max(confidence, 0.85)
        
        # Check Command Injection
        cmd_detected, cmd_matches = self.check_command_injection(full_url)
        if cmd_detected:
            attack_types.append('command_injection')
            reasons.append("Command injection pattern detected")
            pattern_matches.extend(cmd_matches[:3])
            severity = 'high'
            confidence = max(confidence, 0.90)
        
        # Check Admin Access
        admin_detected, admin_matches = self.check_admin_access(path)
        if admin_detected:
            attack_types.append('admin_access')
            reasons.append("Sensitive path access attempt")
            pattern_matches.extend(admin_matches)
            severity = 'medium' if severity == 'low' else severity
            confidence = max(confidence, 0.80)
        
        # Check Scanner
        scanner_detected, scanner_matches = self.check_scanner(user_agent)
        if scanner_detected:
            attack_types.append('scanner')
            reasons.append("Security scanner detected")
            pattern_matches.extend(scanner_matches)
            severity = 'medium' if severity == 'low' else severity
            confidence = max(confidence, 0.95)
        
        # Check Dangerous Extension
        ext_detected, ext_matches = self.check_dangerous_extension(path)
        if ext_detected:
            attack_types.append('dangerous_file')
            reasons.append("Dangerous file extension")
            pattern_matches.extend(ext_matches)
            severity = 'medium' if severity == 'low' else severity
            confidence = max(confidence, 0.75)
        
        is_suspicious = len(attack_types) > 0
        
        print(f"[DEBUG PATTERN] is_suspicious: {is_suspicious}")
        print(f"[DEBUG PATTERN] attack_types: {attack_types}")
        
        return {
            'is_suspicious': is_suspicious,
            'attack_types': attack_types,
            'reasons': reasons,
            'pattern_matches': pattern_matches,
            'severity': severity,
            'confidence': confidence,
            'detection_method': 'pattern' if is_suspicious else 'none'
        }
    
    def detect(self, request_data):
        """
        Main detection method - analyzes request for threats
        """
        if isinstance(request_data, dict):
            df = pd.DataFrame([request_data])
        else:
            df = request_data.copy()
            request_data = df.iloc[0].to_dict()
        
        # Pattern-based detection (with URL decoding)
        pattern_result = self.analyze_request_patterns(request_data)
        
        # Rule-based detection
        try:
            rule_result = self.rule_detector.analyze_request(request_data)
            
            if rule_result['is_suspicious']:
                pattern_result['is_suspicious'] = True
                pattern_result['attack_types'].extend(rule_result.get('attack_types', []))
                pattern_result['reasons'].extend(rule_result.get('reasons', []))
                
                if rule_result.get('severity') == 'high':
                    pattern_result['severity'] = 'high'
                elif rule_result.get('severity') == 'medium' and pattern_result['severity'] == 'low':
                    pattern_result['severity'] = 'medium'
        except Exception as e:
            print(f"⚠️  Rule detection failed: {e}")
        
        # ML-based detection (if available)
        ml_scores = {}
        if self.ml_available:
            try:
                features_df = self.feature_extractor.extract_features(df)
                X = self.feature_extractor.prepare_for_training(features_df)
                
                if hasattr(self, 'if_loaded') and self.if_loaded:
                    if_proba = self.if_model.predict_proba(X)[0]
                    ml_scores['isolation_forest'] = float(if_proba)
                
                if hasattr(self, 'rf_loaded') and self.rf_loaded:
                    rf_proba = self.rf_model.predict_proba(X)[0]
                    ml_scores['random_forest'] = float(rf_proba)
                
                if ml_scores:
                    ml_confidence = np.mean(list(ml_scores.values()))
                    if ml_confidence > Config.ANOMALY_THRESHOLD:
                        pattern_result['is_suspicious'] = True
                        pattern_result['reasons'].append(
                            f"ML anomaly detected (confidence: {ml_confidence:.2f})"
                        )
                        pattern_result['confidence'] = max(
                            pattern_result['confidence'], ml_confidence
                        )
            
            except Exception as e:
                print(f"⚠️  ML detection failed: {e}")
        
        pattern_result['ml_scores'] = ml_scores
        
        # Remove duplicates
        pattern_result['attack_types'] = list(set(pattern_result['attack_types']))
        pattern_result['reasons'] = list(set(pattern_result['reasons']))
        
        return pattern_result
    
    def detect_batch(self, requests_df):
        """Detect anomalies in a batch of requests"""
        results = []
        for idx, row in requests_df.iterrows():
            result = self.detect(row.to_dict())
            results.append(result)
        return results
    
    def get_statistics(self):
        """Get detection statistics"""
        stats = {
            'models_loaded': self.ml_available,
            'pattern_detection': True,
            'url_decoding': True,
            'sql_patterns': len(self.sql_injection_patterns),
            'xss_patterns': len(self.xss_patterns),
            'path_traversal_patterns': len(self.path_traversal_patterns),
            'command_injection_patterns': len(self.command_injection_patterns)
        }
        
        if self.ml_available and hasattr(self, 'if_loaded') and hasattr(self, 'rf_loaded'):
            stats['models_loaded'] = {
                'isolation_forest': self.if_loaded,
                'random_forest': self.rf_loaded
            }
        
        try:
            stats['blocked_ips'] = len(self.rule_detector.blocked_ips)
            stats['active_connections'] = len(self.rule_detector.request_counts)
        except:
            pass
        
        return stats
    
    def add_custom_pattern(self, attack_type, pattern):
        """Add custom attack pattern"""
        if attack_type == 'sql_injection':
            self.sql_injection_patterns.append(pattern)
        elif attack_type == 'xss':
            self.xss_patterns.append(pattern)
        elif attack_type == 'path_traversal':
            self.path_traversal_patterns.append(pattern)
        elif attack_type == 'command_injection':
            self.command_injection_patterns.append(pattern)
        
        print(f"[+] Added custom pattern for {attack_type}")