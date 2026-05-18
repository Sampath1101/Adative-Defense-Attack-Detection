# """
# Unified Threat Analyzer
# Analyzes both web-based attacks (SQL, XSS, DDoS) and network-based attacks (NIDS)
# Intelligently detects file type and applies appropriate analysis
# """

# import pandas as pd
# import numpy as np
# import logging
# import re
# import os
# from datetime import datetime
# from collections import Counter
# import ipaddress
# import hashlib

# logger = logging.getLogger(__name__)

# class UnifiedThreatAnalyzer:
#     """
#     Unified analyzer for:
#     1. Web-based attacks: SQL Injection, XSS, DDoS, Command Injection, etc.
#     2. Network-based attacks: Port scans, IP floods, suspicious traffic
#     3. Shell scripts: Malicious commands, backdoors
#     """
    
#     def __init__(self, anomaly_detector=None, data_dir='data'):
#         self.anomaly_detector = anomaly_detector
#         self.data_dir = data_dir
        
#         # Load reference dataset
#         self.reference_data = None
#         self.load_reference_data()
        
#         # Web-based attack patterns (SQL, XSS, etc.)
#         self.web_attack_patterns = {
#             'sql_injection': [
#                 r"('|\")(\s)*(or|OR|Or)(\s)*('|\")(\s)*=(\s)*('|\")",
#                 r"union(\s)+(all(\s)+)?select",
#                 r"drop(\s)+table",
#                 r"insert(\s)+into",
#                 r"delete(\s)+from",
#                 r"update(\s)+.*set",
#                 r"exec(\s)*\(",
#                 r"execute(\s)*\(",
#                 r"xp_cmdshell",
#                 r";(\s)*shutdown",
#                 r"'(\s)*;(\s)*--",
#                 r"1(\s)*=(\s)*1",
#                 r"' or 1=1",
#                 r"admin'--",
#             ],
#             'xss': [
#                 r"<script[^>]*>.*?</script>",
#                 r"javascript:",
#                 r"onerror\s*=",
#                 r"onload\s*=",
#                 r"onclick\s*=",
#                 r"onmouseover\s*=",
#                 r"<iframe[^>]*>",
#                 r"<embed[^>]*>",
#                 r"<object[^>]*>",
#                 r"alert\s*\(",
#                 r"document\.cookie",
#                 r"document\.write",
#                 r"<img[^>]*onerror",
#                 r"<svg[^>]*onload",
#             ],
#             'command_injection': [
#                 r";\s*(ls|cat|pwd|whoami|id|uname)",
#                 r"\|\s*(ls|cat|pwd|whoami)",
#                 r"&&\s*(ls|cat|pwd)",
#                 r"`.*`",
#                 r"\$\(.*\)",
#                 r"cmd\.exe",
#                 r"bash\s+-c",
#                 r"/bin/(sh|bash)",
#                 r"powershell",
#                 r"wget\s+",
#                 r"curl\s+",
#             ],
#             'path_traversal': [
#                 r"\.\./",
#                 r"\.\.\\",
#                 r"/etc/passwd",
#                 r"/etc/shadow",
#                 r"c:\\windows",
#                 r"\.\.%2f",
#                 r"\.\.%5c",
#                 r"%2e%2e%2f",
#                 r"%2e%2e/",
#             ],
#             'ldap_injection': [
#                 r"\*\)\(\|",
#                 r"\)\(\&\(",
#                 r"\*\|",
#                 r"admin\*",
#             ],
#             'xml_injection': [
#                 r"<\?xml",
#                 r"<!DOCTYPE",
#                 r"<!ENTITY",
#                 r"SYSTEM\s+\"",
#             ],
#             'ssrf': [
#                 r"http://localhost",
#                 r"http://127\.0\.0\.1",
#                 r"http://169\.254\.169\.254",
#                 r"file://",
#                 r"dict://",
#                 r"gopher://",
#             ]
#         }
        
#         # Network-based indicators
#         self.suspicious_ports = [21, 22, 23, 25, 53, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 8080]
#         self.backdoor_ports = [4444, 5555, 6666, 7777, 8888, 9999, 12345, 31337]
        
#         # Attack thresholds
#         self.connection_flood_threshold = 100
#         self.port_scan_threshold = 10
#         self.bandwidth_threshold = 1000000
        
#         # CSV column mappings
#         self.column_mappings = {
#             'src_ip': ['src', 'source', 'src_ip', 'source_ip', 'ipv4_src_addr', 'source_addr'],
#             'dst_ip': ['dst', 'dest', 'destination', 'dst_ip', 'dest_ip', 'ipv4_dst_addr', 'destination_addr'],
#             'src_port': ['sport', 'src_port', 'source_port', 'l4_src_port'],
#             'dst_port': ['dport', 'dst_port', 'dest_port', 'destination_port', 'l4_dst_port'],
#             'bytes': ['bytes', 'in_bytes', 'out_bytes', 'pkts_out_bytes', 'total_bytes'],
#             'protocol': ['protocol', 'proto', 'l7_proto', 'ip_protocol'],
#         }
    
#     def load_reference_data(self):
#         """Load reference dataset"""
#         try:
#             features_path = os.path.join(self.data_dir, 'features.csv')
#             raw_logs_path = os.path.join(self.data_dir, 'raw_logs.csv')
            
#             if os.path.exists(features_path):
#                 self.reference_data = pd.read_csv(features_path)
#                 logger.info(f"Loaded reference dataset: {len(self.reference_data)} records")
#             elif os.path.exists(raw_logs_path):
#                 self.reference_data = pd.read_csv(raw_logs_path)
#                 logger.info(f"Loaded raw logs: {len(self.reference_data)} records")
#         except Exception as e:
#             logger.error(f"Error loading reference data: {e}")
    
#     def analyze(self, filepath, filename):
#         """
#         Main analysis function - determines file type and applies appropriate analysis
#         """
#         results = {
#             'is_suspicious': False,
#             'is_safe': True,
#             'threat_level': 'safe',
#             'confidence': 0.0,
#             'risk_score': 0.0,
#             'severity': 'low',
#             'file_type': 'unknown',
#             'detection_method': 'unified_analysis',
#             'file_info': {},
#             'web_attacks': {},
#             'network_attacks': {},
#             'threats_detected': [],
#             'reasons': [],
#             'visual_data': {},
#             'recommendations': []
#         }
        
#         try:
#             # Determine file type
#             file_extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            
#             if file_extension == 'csv':
#                 # CSV file - could be NIDS logs or web logs
#                 results = self._analyze_csv(filepath, filename, results)
#             elif file_extension in ['sh', 'bash', 'bat', 'cmd', 'ps1']:
#                 # Shell script
#                 results = self._analyze_script(filepath, filename, results)
#             else:
#                 # Regular file (text, code, etc.)
#                 results = self._analyze_text_file(filepath, filename, results)
            
#             # Calculate final threat level
#             results = self._calculate_threat_level(results)
            
#             # Generate visual data
#             results['visual_data'] = self._generate_visual_data(results)
            
#             # Generate recommendations
#             results['recommendations'] = self._generate_recommendations(results)
        
#         except Exception as e:
#             logger.error(f"Analysis error: {e}")
#             results['reasons'].append(f'Analysis error: {str(e)}')
#             results['is_suspicious'] = True
#             results['threat_level'] = 'unknown'
        
#         return results
    
#     def _analyze_csv(self, filepath, filename, results):
#         """Analyze CSV file (NIDS logs or web logs)"""
#         try:
#             df = pd.read_csv(filepath)
#             results['file_info'] = self._get_csv_info(df, filename)
#             results['file_type'] = 'csv'
            
#             # Detect if it's network logs or web logs
#             has_network_cols = any(
#                 self._find_column(df, self.column_mappings['src_ip']) and
#                 self._find_column(df, self.column_mappings['dst_ip'])
#             )
            
#             if has_network_cols:
#                 # Network-based analysis (NIDS logs)
#                 results['file_type'] = 'network_traffic_csv'
#                 results = self._analyze_network_csv(df, results)
#             else:
#                 # Web-based analysis (web server logs, request logs)
#                 results['file_type'] = 'web_logs_csv'
#                 results = self._analyze_web_csv(df, results)
            
#         except Exception as e:
#             logger.error(f"CSV analysis error: {e}")
#             results['reasons'].append(f'CSV parsing error: {str(e)}')
        
#         return results
    
#     def _analyze_network_csv(self, df, results):
#         """Analyze network traffic CSV (NIDS logs)"""
#         results['network_attacks'] = {
#             'ip_analysis': {},
#             'port_analysis': {},
#             'traffic_patterns': {},
#             'attack_detection': {},
#             'dataset_comparison': {}
#         }
        
#         # Find columns
#         src_col = self._find_column(df, self.column_mappings['src_ip'])
#         dst_col = self._find_column(df, self.column_mappings['dst_ip'])
#         sport_col = self._find_column(df, self.column_mappings['src_port'])
#         dport_col = self._find_column(df, self.column_mappings['dst_port'])
#         bytes_col = self._find_column(df, self.column_mappings['bytes'])
#         proto_col = self._find_column(df, self.column_mappings['protocol'])
        
#         # Network statistics
#         stats = {
#             'total_records': len(df),
#             'unique_sources': df[src_col].nunique() if src_col else 0,
#             'unique_destinations': df[dst_col].nunique() if dst_col else 0,
#             'total_bytes': df[bytes_col].sum() if bytes_col else 0,
#         }
#         results['network_statistics'] = stats
        
#         # IP Analysis
#         if src_col:
#             ip_analysis = self._analyze_ips_from_csv(df, src_col, dst_col)
#             results['network_attacks']['ip_analysis'] = ip_analysis
#             results['threats_detected'].extend(ip_analysis['threats'])
#             results['risk_score'] += ip_analysis['risk_score']
        
#         # Port Analysis
#         if dport_col:
#             port_analysis = self._analyze_ports_from_csv(df, src_col, dport_col)
#             results['network_attacks']['port_analysis'] = port_analysis
#             results['threats_detected'].extend(port_analysis['threats'])
#             results['risk_score'] += port_analysis['risk_score']
        
#         # Attack Detection (DDoS, Scans)
#         if src_col and dst_col:
#             attack_detection = self._detect_network_attacks(df, src_col, dst_col, dport_col)
#             results['network_attacks']['attack_detection'] = attack_detection
#             results['threats_detected'].extend(attack_detection['threats'])
#             results['risk_score'] += attack_detection['risk_score']
        
#         # Dataset Comparison
#         if self.reference_data is not None and src_col:
#             comparison = self._compare_network_dataset(df, src_col)
#             results['network_attacks']['dataset_comparison'] = comparison
#             results['threats_detected'].extend(comparison['threats'])
#             results['risk_score'] += comparison['risk_score']
        
#         # ML Analysis
#         if self.anomaly_detector and self.anomaly_detector.is_ready():
#             ml_results = self._ml_network_analysis(df, src_col)
#             results['ml_predictions'] = ml_results
#             results['threats_detected'].extend(ml_results['threats'])
#             results['risk_score'] += ml_results['risk_score']
        
#         return results
    
#     def _analyze_web_csv(self, df, results):
#         """Analyze web logs CSV (HTTP requests, SQL queries, etc.)"""
#         results['web_attacks'] = {
#             'sql_injection': [],
#             'xss': [],
#             'command_injection': [],
#             'path_traversal': [],
#             'other': []
#         }
        
#         # Analyze each row for web attack patterns
#         suspicious_count = 0
        
#         for idx, row in df.iterrows():
#             # Convert row to string for pattern matching
#             row_str = ' '.join(str(val) for val in row.values)
            
#             # Check for web attack patterns
#             for attack_type, patterns in self.web_attack_patterns.items():
#                 for pattern in patterns:
#                     matches = re.findall(pattern, row_str, re.IGNORECASE)
#                     if matches:
#                         if attack_type not in results['web_attacks']:
#                             results['web_attacks'][attack_type] = []
                        
#                         results['web_attacks'][attack_type].append({
#                             'row': idx,
#                             'pattern': pattern,
#                             'match': str(matches[0]) if matches else ''
#                         })
                        
#                         suspicious_count += 1
#                         results['risk_score'] += 0.1
        
#         # Generate threats from web attacks
#         for attack_type, detections in results['web_attacks'].items():
#             if detections:
#                 count = len(detections)
#                 results['threats_detected'].append(
#                     f"{attack_type.replace('_', ' ').title()}: {count} occurrence(s) detected"
#                 )
#                 results['reasons'].append(
#                     f"Found {count} {attack_type.replace('_', ' ')} pattern(s) in CSV data"
#                 )
        
#         return results
    
#     def _analyze_script(self, filepath, filename, results):
#         """Analyze shell scripts for malicious commands"""
#         results['file_type'] = 'shell_script'
#         results['script_analysis'] = {
#             'dangerous_commands': [],
#             'suspicious_patterns': [],
#             'network_activity': []
#         }
        
#         try:
#             with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
#                 content = f.read()
            
#             results['file_info'] = {
#                 'name': filename,
#                 'size': len(content),
#                 'lines': content.count('\n'),
#                 'hash_md5': hashlib.md5(content.encode()).hexdigest()
#             }
            
#             # Dangerous commands
#             dangerous_commands = [
#                 (r'rm\s+-rf\s+/', 'Recursive delete from root'),
#                 (r':()\{:\|:&\};:', 'Fork bomb'),
#                 (r'dd\s+if=', 'Direct disk access'),
#                 (r'mkfs\.', 'Format filesystem'),
#                 (r'>/dev/sd', 'Direct disk write'),
#                 (r'nc\s+-[el]', 'Netcat backdoor'),
#                 (r'curl.*\|\s*bash', 'Remote code execution'),
#                 (r'wget.*\|\s*sh', 'Remote code execution'),
#                 (r'eval\s*\(', 'Dynamic code execution'),
#                 (r'base64\s+-d.*\|\s*bash', 'Encoded payload execution'),
#             ]
            
#             for pattern, description in dangerous_commands:
#                 matches = re.findall(pattern, content, re.IGNORECASE)
#                 if matches:
#                     results['script_analysis']['dangerous_commands'].append({
#                         'command': pattern,
#                         'description': description,
#                         'count': len(matches)
#                     })
#                     results['threats_detected'].append(f"Dangerous command: {description}")
#                     results['risk_score'] += 0.4
            
#             # Network activity
#             network_patterns = [
#                 (r'curl\s+', 'HTTP request'),
#                 (r'wget\s+', 'HTTP download'),
#                 (r'nc\s+', 'Netcat connection'),
#                 (r'telnet\s+', 'Telnet connection'),
#                 (r'ssh\s+', 'SSH connection'),
#                 (r'/dev/tcp/', 'TCP socket'),
#             ]
            
#             for pattern, description in network_patterns:
#                 matches = re.findall(pattern, content)
#                 if matches:
#                     results['script_analysis']['network_activity'].append({
#                         'pattern': pattern,
#                         'description': description,
#                         'count': len(matches)
#                     })
#                     results['threats_detected'].append(f"Network activity: {description}")
#                     results['risk_score'] += 0.2
        
#         except Exception as e:
#             logger.error(f"Script analysis error: {e}")
        
#         return results
    
#     def _analyze_text_file(self, filepath, filename, results):
#         """Analyze regular text files for web attack patterns"""
#         results['file_type'] = 'text_file'
#         results['web_attacks'] = {}
        
#         try:
#             with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
#                 content = f.read(50000)  # Read first 50KB
            
#             results['file_info'] = {
#                 'name': filename,
#                 'size': len(content),
#                 'hash_md5': hashlib.md5(content.encode()).hexdigest(),
#                 'hash_sha256': hashlib.sha256(content.encode()).hexdigest()
#             }
            
#             # Check for web attack patterns
#             for attack_type, patterns in self.web_attack_patterns.items():
#                 matches = []
#                 for pattern in patterns:
#                     found = re.findall(pattern, content, re.IGNORECASE)
#                     if found:
#                         matches.extend(found)
                
#                 if matches:
#                     results['web_attacks'][attack_type] = {
#                         'count': len(matches),
#                         'samples': [str(m)[:50] for m in matches[:3]]
#                     }
#                     results['threats_detected'].append(
#                         f"{attack_type.replace('_', ' ').title()}: {len(matches)} pattern(s)"
#                     )
#                     results['risk_score'] += len(matches) * 0.15
        
#         except Exception as e:
#             logger.error(f"Text file analysis error: {e}")
        
#         return results
    
#     def _analyze_ips_from_csv(self, df, src_col, dst_col):
#         """Analyze IP addresses from CSV"""
#         analysis = {
#             'suspicious_ips': [],
#             'top_talkers': [],
#             'threats': [],
#             'risk_score': 0.0
#         }
        
#         try:
#             ip_counts = df[src_col].value_counts()
            
#             # Top talkers
#             analysis['top_talkers'] = [
#                 {'ip': ip, 'connections': int(count)}
#                 for ip, count in ip_counts.head(10).items()
#             ]
            
#             # Check for connection floods
#             for ip, count in ip_counts.items():
#                 if count > self.connection_flood_threshold:
#                     analysis['suspicious_ips'].append({
#                         'ip': ip,
#                         'reason': f'Connection flood: {count} connections',
#                         'count': int(count)
#                     })
#                     analysis['threats'].append(f"Suspicious IP: {ip} ({count} connections)")
#                     analysis['risk_score'] += 0.3
        
#         except Exception as e:
#             logger.error(f"IP analysis error: {e}")
        
#         return analysis
    
#     def _analyze_ports_from_csv(self, df, src_col, dport_col):
#         """Analyze ports from CSV"""
#         analysis = {
#             'suspicious_ports': [],
#             'backdoor_ports': [],
#             'port_scan_detected': False,
#             'threats': [],
#             'risk_score': 0.0
#         }
        
#         try:
#             port_counts = df[dport_col].value_counts()
            
#             # Check for suspicious ports
#             for port in df[dport_col].unique()[:50]:
#                 try:
#                     port = int(port)
                    
#                     if port in self.suspicious_ports:
#                         count = port_counts.get(port, 0)
#                         analysis['suspicious_ports'].append({
#                             'port': port,
#                             'connections': int(count)
#                         })
#                         analysis['threats'].append(f"Suspicious port: {port} ({count} connections)")
#                         analysis['risk_score'] += 0.15
                    
#                     if port in self.backdoor_ports:
#                         analysis['backdoor_ports'].append(port)
#                         analysis['threats'].append(f"BACKDOOR PORT: {port}")
#                         analysis['risk_score'] += 0.5
#                 except:
#                     continue
            
#             # Port scan detection
#             if src_col:
#                 for src_ip in df[src_col].unique()[:20]:
#                     ports_contacted = df[df[src_col] == src_ip][dport_col].nunique()
#                     if ports_contacted > self.port_scan_threshold:
#                         analysis['port_scan_detected'] = True
#                         analysis['threats'].append(f"Port scan from {src_ip}: {ports_contacted} ports")
#                         analysis['risk_score'] += 0.4
#                         break
        
#         except Exception as e:
#             logger.error(f"Port analysis error: {e}")
        
#         return analysis
    
#     def _detect_network_attacks(self, df, src_col, dst_col, dport_col):
#         """Detect DDoS and scanning attacks"""
#         detection = {
#             'attacks_found': [],
#             'threats': [],
#             'risk_score': 0.0
#         }
        
#         try:
#             # DDoS detection
#             dst_counts = df[dst_col].value_counts()
#             for dst_ip, count in dst_counts.items():
#                 if count > 500:
#                     unique_sources = df[df[dst_col] == dst_ip][src_col].nunique()
#                     if unique_sources > 50:
#                         detection['attacks_found'].append({
#                             'type': 'DDoS',
#                             'target': dst_ip,
#                             'connections': int(count),
#                             'sources': unique_sources
#                         })
#                         detection['threats'].append(
#                             f"DDoS Attack on {dst_ip}: {count} connections from {unique_sources} sources"
#                         )
#                         detection['risk_score'] += 0.6
            
#             # Network scan detection
#             src_counts = df[src_col].value_counts()
#             for src_ip, count in src_counts.head(5).items():
#                 unique_dests = df[df[src_col] == src_ip][dst_col].nunique()
#                 if unique_dests > 20:
#                     detection['attacks_found'].append({
#                         'type': 'Network Scan',
#                         'source': src_ip,
#                         'targets': unique_dests
#                     })
#                     detection['threats'].append(
#                         f"Network scan from {src_ip}: {unique_dests} targets"
#                     )
#                     detection['risk_score'] += 0.4
        
#         except Exception as e:
#             logger.error(f"Attack detection error: {e}")
        
#         return detection
    
#     def _compare_network_dataset(self, df, src_col):
#         """Compare with reference dataset"""
#         comparison = {
#             'match_percentage': 0.0,
#             'unknown_ips': 0,
#             'threats': [],
#             'risk_score': 0.0
#         }
        
#         try:
#             if self.reference_data is None:
#                 return comparison
            
#             ref_src_col = self._find_column(
#                 self.reference_data,
#                 self.column_mappings['src_ip']
#             )
            
#             if ref_src_col:
#                 uploaded_ips = set(df[src_col].unique())
#                 reference_ips = set(self.reference_data[ref_src_col].unique())
                
#                 new_ips = uploaded_ips - reference_ips
#                 common_ips = uploaded_ips & reference_ips
                
#                 comparison['unknown_ips'] = len(new_ips)
#                 comparison['match_percentage'] = (
#                     len(common_ips) / len(uploaded_ips) * 100
#                     if uploaded_ips else 0
#                 )
                
#                 if len(new_ips) > 10:
#                     comparison['threats'].append(
#                         f"{len(new_ips)} unknown IPs not in reference dataset"
#                     )
#                     comparison['risk_score'] += 0.3
        
#         except Exception as e:
#             logger.error(f"Dataset comparison error: {e}")
        
#         return comparison
    
#     def _ml_network_analysis(self, df, src_col):
#         """ML analysis on network data"""
#         analysis = {
#             'suspicious_percentage': 0.0,
#             'threats': [],
#             'risk_score': 0.0
#         }
        
#         try:
#             sample_size = min(100, len(df))
#             sample_df = df.sample(n=sample_size) if len(df) > sample_size else df
            
#             suspicious_count = 0
            
#             for idx, row in sample_df.iterrows():
#                 request_data = {
#                     'timestamp': datetime.now().isoformat(),
#                     'ip': str(row.get(src_col, '127.0.0.1')),
#                     'method': 'NETWORK',
#                     'path': '/network',
#                     'status': 200,
#                     'user_agent': 'Monitor',
#                     'response_time': 0
#                 }
                
#                 detection = self.anomaly_detector.detect(request_data)
#                 if detection['is_suspicious']:
#                     suspicious_count += 1
            
#             analysis['suspicious_percentage'] = (
#                 suspicious_count / sample_size * 100
#                 if sample_size > 0 else 0
#             )
            
#             if analysis['suspicious_percentage'] > 20:
#                 analysis['threats'].append(
#                     f"ML flagged {analysis['suspicious_percentage']:.1f}% as suspicious"
#                 )
#                 analysis['risk_score'] += 0.4
        
#         except Exception as e:
#             logger.error(f"ML analysis error: {e}")
        
#         return analysis
    
#     def _calculate_threat_level(self, results):
#         """Calculate final threat level"""
#         risk_score = results['risk_score']
        
#         if risk_score >= 2.0:
#             results['threat_level'] = 'critical'
#             results['severity'] = 'high'
#             results['is_suspicious'] = True
#             results['is_safe'] = False
#         elif risk_score >= 1.5:
#             results['threat_level'] = 'high'
#             results['severity'] = 'high'
#             results['is_suspicious'] = True
#             results['is_safe'] = False
#         elif risk_score >= 0.8:
#             results['threat_level'] = 'medium'
#             results['severity'] = 'medium'
#             results['is_suspicious'] = True
#             results['is_safe'] = False
#         elif risk_score >= 0.4:
#             results['threat_level'] = 'low'
#             results['severity'] = 'low'
#             results['is_suspicious'] = True
#             results['is_safe'] = False
#         else:
#             results['threat_level'] = 'safe'
#             results['severity'] = 'low'
#             results['is_suspicious'] = False
#             results['is_safe'] = True
        
#         results['confidence'] = min(risk_score / 2.0, 1.0)
        
#         return results
    
#     def _generate_visual_data(self, results):
#         """Generate visualization data"""
#         visual = {
#             'risk_ratio': {'safe': 50, 'at_risk': 50},
#             'threat_breakdown': []
#         }
        
#         try:
#             # Risk ratio
#             total = max(results['risk_score'], 0.1)
#             at_risk = min((total / 3.0) * 100, 100)
#             visual['risk_ratio'] = {
#                 'safe': round(100 - at_risk, 2),
#                 'at_risk': round(at_risk, 2)
#             }
            
#             # Threat breakdown
#             threat_types = Counter()
#             for threat in results['threats_detected']:
#                 if 'ddos' in threat.lower():
#                     threat_types['DDoS'] += 1
#                 elif 'sql' in threat.lower():
#                     threat_types['SQL Injection'] += 1
#                 elif 'xss' in threat.lower():
#                     threat_types['XSS'] += 1
#                 elif 'scan' in threat.lower():
#                     threat_types['Port Scan'] += 1
#                 elif 'backdoor' in threat.lower():
#                     threat_types['Backdoor'] += 1
#                 elif 'command' in threat.lower():
#                     threat_types['Command Injection'] += 1
#                 else:
#                     threat_types['Other'] += 1
            
#             visual['threat_breakdown'] = [
#                 {'type': k, 'count': v}
#                 for k, v in threat_types.items()
#             ]
        
#         except Exception as e:
#             logger.error(f"Visual data error: {e}")
        
#         return visual
    
#     def _generate_recommendations(self, results):
#         """Generate security recommendations"""
#         recommendations = []
        
#         if results['is_safe']:
#             recommendations.append("✓ File appears safe")
#             recommendations.append("✓ No immediate threats detected")
#             recommendations.append("✓ Continue monitoring")
#         else:
#             recommendations.append("⚠ IMMEDIATE ACTION REQUIRED")
            
#             # Network-based recommendations
#             if results['file_type'] == 'network_traffic_csv':
#                 if results['network_attacks'].get('attack_detection', {}).get('attacks_found'):
#                     recommendations.append("⚠ Network attack detected - Isolate affected systems")
#                 if results['network_attacks'].get('port_analysis', {}).get('backdoor_ports'):
#                     recommendations.append("⚠ CRITICAL: Backdoor ports detected - Close immediately")
#                 if results['network_attacks'].get('ip_analysis', {}).get('suspicious_ips'):
#                     recommendations.append("⚠ Block suspicious IPs at firewall")
            
#             # Web-based recommendations
#             if results['web_attacks']:
#                 if 'sql_injection' in results['web_attacks']:
#                     recommendations.append("⚠ SQL Injection - Sanitize database inputs")
#                 if 'xss' in results['web_attacks']:
#                     recommendations.append("⚠ XSS - Encode output, validate input")
#                 if 'command_injection' in results['web_attacks']:
#                     recommendations.append("⚠ Command Injection - Do not execute system commands")
            
#             # Critical level
#             if results['threat_level'] in ['high', 'critical']:
#                 recommendations.append("⚠ CRITICAL: Report to security team")
#                 recommendations.append("⚠ CRITICAL: Preserve evidence")
        
#         return recommendations
    
#     def _get_csv_info(self, df, filename):
#         """Get CSV file info"""
#         return {
#             'name': filename,
#             'rows': len(df),
#             'columns': len(df.columns),
#             'column_names': list(df.columns),
#             'size_mb': round(df.memory_usage(deep=True).sum() / 1024 / 1024, 2)
#         }
    
#     def _find_column(self, df, possible_names):
#         """Find column by possible names"""
#         for name in possible_names:
#             if name in df.columns:
#                 return name
#         return None

#--------------------------------op2-------------------------------------------------------------------

# """
# Unified Threat Analyzer
# Analyzes both web-based attacks (SQL, XSS, DDoS) and network-based attacks (NIDS)
# Intelligently detects file type and applies appropriate analysis
# """

# import pandas as pd
# import numpy as np
# import logging
# import re
# import os
# from datetime import datetime
# from collections import Counter
# import ipaddress
# import hashlib

# logger = logging.getLogger(__name__)

# class UnifiedThreatAnalyzer:
#     """
#     Unified analyzer for:
#     1. Web-based attacks: SQL Injection, XSS, DDoS, Command Injection, etc.
#     2. Network-based attacks: Port scans, IP floods, suspicious traffic
#     3. Shell scripts: Malicious commands, backdoors
#     """
    
#     def __init__(self, anomaly_detector=None, data_dir='data'):
#         self.anomaly_detector = anomaly_detector
#         self.data_dir = data_dir
        
#         # Load reference dataset
#         self.reference_data = None
#         self.load_reference_data()
        
#         # Web-based attack patterns (SQL, XSS, etc.)
#         self.web_attack_patterns = {
#             'sql_injection': [
#                 r"('|\")(\s)*(or|OR|Or)(\s)*('|\")(\s)*=(\s)*('|\")",
#                 r"union(\s)+(all(\s)+)?select",
#                 r"drop(\s)+table",
#                 r"insert(\s)+into",
#                 r"delete(\s)+from",
#                 r"update(\s)+.*set",
#                 r"exec(\s)*\(",
#                 r"execute(\s)*\(",
#                 r"xp_cmdshell",
#                 r";(\s)*shutdown",
#                 r"'(\s)*;(\s)*--",
#                 r"1(\s)*=(\s)*1",
#                 r"' or 1=1",
#                 r"admin'--",
#             ],
#             'xss': [
#                 r"<script[^>]*>.*?</script>",
#                 r"javascript:",
#                 r"onerror\s*=",
#                 r"onload\s*=",
#                 r"onclick\s*=",
#                 r"onmouseover\s*=",
#                 r"<iframe[^>]*>",
#                 r"<embed[^>]*>",
#                 r"<object[^>]*>",
#                 r"alert\s*\(",
#                 r"document\.cookie",
#                 r"document\.write",
#                 r"<img[^>]*onerror",
#                 r"<svg[^>]*onload",
#             ],
#             'command_injection': [
#                 r";\s*(ls|cat|pwd|whoami|id|uname)",
#                 r"\|\s*(ls|cat|pwd|whoami)",
#                 r"&&\s*(ls|cat|pwd)",
#                 r"`.*`",
#                 r"\$\(.*\)",
#                 r"cmd\.exe",
#                 r"bash\s+-c",
#                 r"/bin/(sh|bash)",
#                 r"powershell",
#                 r"wget\s+",
#                 r"curl\s+",
#             ],
#             'path_traversal': [
#                 r"\.\./",
#                 r"\.\.\\",
#                 r"/etc/passwd",
#                 r"/etc/shadow",
#                 r"c:\\windows",
#                 r"\.\.%2f",
#                 r"\.\.%5c",
#                 r"%2e%2e%2f",
#                 r"%2e%2e/",
#             ],
#             'ldap_injection': [
#                 r"\*\)\(\|",
#                 r"\)\(\&\(",
#                 r"\*\|",
#                 r"admin\*",
#             ],
#             'xml_injection': [
#                 r"<\?xml",
#                 r"<!DOCTYPE",
#                 r"<!ENTITY",
#                 r"SYSTEM\s+\"",
#             ],
#             'ssrf': [
#                 r"http://localhost",
#                 r"http://127\.0\.0\.1",
#                 r"http://169\.254\.169\.254",
#                 r"file://",
#                 r"dict://",
#                 r"gopher://",
#             ]
#         }
        
#         # Network-based indicators
#         self.suspicious_ports = [21, 22, 23, 25, 53, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 8080]
#         self.backdoor_ports = [4444, 5555, 6666, 7777, 8888, 9999, 12345, 31337]
        
#         # Attack thresholds (lowered for better detection)
#         self.connection_flood_threshold = 20  # 20+ connections (was 100)
#         self.port_scan_threshold = 5  # 5+ ports (was 10)
#         self.bandwidth_threshold = 1000000
        
#         # CSV column mappings
#         self.column_mappings = {
#             'src_ip': ['src', 'source', 'src_ip', 'source_ip', 'ipv4_src_addr', 'source_addr'],
#             'dst_ip': ['dst', 'dest', 'destination', 'dst_ip', 'dest_ip', 'ipv4_dst_addr', 'destination_addr'],
#             'src_port': ['sport', 'src_port', 'source_port', 'l4_src_port'],
#             'dst_port': ['dport', 'dst_port', 'dest_port', 'destination_port', 'l4_dst_port'],
#             'bytes': ['bytes', 'in_bytes', 'out_bytes', 'pkts_out_bytes', 'total_bytes'],
#             'protocol': ['protocol', 'proto', 'l7_proto', 'ip_protocol'],
#         }
    
#     def load_reference_data(self):
#         """Load reference dataset"""
#         try:
#             features_path = os.path.join(self.data_dir, 'features.csv')
#             raw_logs_path = os.path.join(self.data_dir, 'raw_logs.csv')
            
#             if os.path.exists(features_path):
#                 self.reference_data = pd.read_csv(features_path)
#                 logger.info(f"Loaded reference dataset: {len(self.reference_data)} records")
#             elif os.path.exists(raw_logs_path):
#                 self.reference_data = pd.read_csv(raw_logs_path)
#                 logger.info(f"Loaded raw logs: {len(self.reference_data)} records")
#         except Exception as e:
#             logger.error(f"Error loading reference data: {e}")
    
#     def analyze(self, filepath, filename):
#         """
#         Main analysis function - determines file type and applies appropriate analysis
#         """
#         results = {
#             'is_suspicious': False,
#             'is_safe': True,
#             'threat_level': 'safe',
#             'confidence': 0.0,
#             'risk_score': 0.0,
#             'severity': 'low',
#             'file_type': 'unknown',
#             'detection_method': 'unified_analysis',
#             'file_info': {},
#             'web_attacks': {},
#             'network_attacks': {},
#             'threats_detected': [],
#             'reasons': [],
#             'visual_data': {},
#             'recommendations': []
#         }
        
#         try:
#             # Determine file type
#             file_extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            
#             if file_extension == 'csv':
#                 # CSV file - could be NIDS logs or web logs
#                 results = self._analyze_csv(filepath, filename, results)
#             elif file_extension in ['sh', 'bash', 'bat', 'cmd', 'ps1']:
#                 # Shell script
#                 results = self._analyze_script(filepath, filename, results)
#             else:
#                 # Regular file (text, code, etc.)
#                 results = self._analyze_text_file(filepath, filename, results)
            
#             # Calculate final threat level
#             results = self._calculate_threat_level(results)
            
#             # Generate visual data
#             results['visual_data'] = self._generate_visual_data(results)
            
#             # Generate recommendations
#             results['recommendations'] = self._generate_recommendations(results)
        
#         except Exception as e:
#             logger.error(f"Analysis error: {e}")
#             results['reasons'].append(f'Analysis error: {str(e)}')
#             results['is_suspicious'] = True
#             results['threat_level'] = 'unknown'
        
#         return results
    
#     def _analyze_csv(self, filepath, filename, results):
#         """Analyze CSV file (NIDS logs or web logs)"""
#         try:
#             df = pd.read_csv(filepath)
#             results['file_info'] = self._get_csv_info(df, filename)
#             results['file_type'] = 'csv'
            
#             # Detect if it's network logs or web logs
#             has_network_cols = bool(
#                 self._find_column(df, self.column_mappings['src_ip']) and
#                 self._find_column(df, self.column_mappings['dst_ip'])
#             )
            
#             # Also check for port columns as indicator of network data
#             has_port_cols = bool(
#                 self._find_column(df, self.column_mappings['dst_port']) or
#                 self._find_column(df, self.column_mappings['src_port'])
#             )
            
#             # Debug logging
#             logger.info(f"CSV Analysis - Network cols: {has_network_cols}, Port cols: {has_port_cols}")
            
#             if has_network_cols or has_port_cols:
#                 # Network-based analysis (NIDS logs)
#                 results['file_type'] = 'network_traffic_csv'
#                 results = self._analyze_network_csv(df, results)
#             else:
#                 # Web-based analysis (web server logs, request logs)
#                 results['file_type'] = 'web_logs_csv'
#                 results = self._analyze_web_csv(df, results)
            
#         except Exception as e:
#             logger.error(f"CSV analysis error: {e}")
#             results['reasons'].append(f'CSV parsing error: {str(e)}')
        
#         return results
    
#     def _analyze_network_csv(self, df, results):
#         """Analyze network traffic CSV (NIDS logs)"""
#         results['network_attacks'] = {
#             'ip_analysis': {},
#             'port_analysis': {},
#             'traffic_patterns': {},
#             'attack_detection': {},
#             'dataset_comparison': {}
#         }
        
#         # Find columns
#         src_col = self._find_column(df, self.column_mappings['src_ip'])
#         dst_col = self._find_column(df, self.column_mappings['dst_ip'])
#         sport_col = self._find_column(df, self.column_mappings['src_port'])
#         dport_col = self._find_column(df, self.column_mappings['dst_port'])
#         bytes_col = self._find_column(df, self.column_mappings['bytes'])
#         proto_col = self._find_column(df, self.column_mappings['protocol'])
        
#         # Network statistics
#         stats = {
#             'total_records': len(df),
#             'unique_sources': df[src_col].nunique() if src_col else 0,
#             'unique_destinations': df[dst_col].nunique() if dst_col else 0,
#             'total_bytes': df[bytes_col].sum() if bytes_col else 0,
#         }
#         results['network_statistics'] = stats
        
#         # IP Analysis
#         if src_col:
#             ip_analysis = self._analyze_ips_from_csv(df, src_col, dst_col)
#             results['network_attacks']['ip_analysis'] = ip_analysis
#             results['threats_detected'].extend(ip_analysis['threats'])
#             results['risk_score'] += ip_analysis['risk_score']
        
#         # Port Analysis
#         if dport_col:
#             port_analysis = self._analyze_ports_from_csv(df, src_col, dport_col)
#             results['network_attacks']['port_analysis'] = port_analysis
#             results['threats_detected'].extend(port_analysis['threats'])
#             results['risk_score'] += port_analysis['risk_score']
        
#         # Attack Detection (DDoS, Scans)
#         if src_col and dst_col:
#             attack_detection = self._detect_network_attacks(df, src_col, dst_col, dport_col)
#             results['network_attacks']['attack_detection'] = attack_detection
#             results['threats_detected'].extend(attack_detection['threats'])
#             results['risk_score'] += attack_detection['risk_score']
        
#         # Dataset Comparison
#         if self.reference_data is not None and src_col:
#             comparison = self._compare_network_dataset(df, src_col)
#             results['network_attacks']['dataset_comparison'] = comparison
#             results['threats_detected'].extend(comparison['threats'])
#             results['risk_score'] += comparison['risk_score']
        
#         # ML Analysis
#         if self.anomaly_detector and self.anomaly_detector.is_ready():
#             ml_results = self._ml_network_analysis(df, src_col)
#             results['ml_predictions'] = ml_results
#             results['threats_detected'].extend(ml_results['threats'])
#             results['risk_score'] += ml_results['risk_score']
        
#         return results
    
#     def _analyze_web_csv(self, df, results):
#         """Analyze web logs CSV (HTTP requests, SQL queries, etc.)"""
#         results['web_attacks'] = {
#             'sql_injection': [],
#             'xss': [],
#             'command_injection': [],
#             'path_traversal': [],
#             'other': []
#         }
        
#         # Analyze each row for web attack patterns
#         suspicious_count = 0
        
#         for idx, row in df.iterrows():
#             # Convert row to string for pattern matching
#             row_str = ' '.join(str(val) for val in row.values)
            
#             # Check for web attack patterns
#             for attack_type, patterns in self.web_attack_patterns.items():
#                 for pattern in patterns:
#                     matches = re.findall(pattern, row_str, re.IGNORECASE)
#                     if matches:
#                         if attack_type not in results['web_attacks']:
#                             results['web_attacks'][attack_type] = []
                        
#                         results['web_attacks'][attack_type].append({
#                             'row': idx,
#                             'pattern': pattern,
#                             'match': str(matches[0]) if matches else ''
#                         })
                        
#                         suspicious_count += 1
#                         results['risk_score'] += 0.1
        
#         # Generate threats from web attacks
#         for attack_type, detections in results['web_attacks'].items():
#             if detections:
#                 count = len(detections)
#                 results['threats_detected'].append(
#                     f"{attack_type.replace('_', ' ').title()}: {count} occurrence(s) detected"
#                 )
#                 results['reasons'].append(
#                     f"Found {count} {attack_type.replace('_', ' ')} pattern(s) in CSV data"
#                 )
        
#         return results
    
#     def _analyze_script(self, filepath, filename, results):
#         """Analyze shell scripts for malicious commands"""
#         results['file_type'] = 'shell_script'
#         results['script_analysis'] = {
#             'dangerous_commands': [],
#             'suspicious_patterns': [],
#             'network_activity': []
#         }
        
#         try:
#             with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
#                 content = f.read()
            
#             results['file_info'] = {
#                 'name': filename,
#                 'size': len(content),
#                 'lines': content.count('\n'),
#                 'hash_md5': hashlib.md5(content.encode()).hexdigest()
#             }
            
#             # Dangerous commands
#             dangerous_commands = [
#                 (r'rm\s+-rf\s+/', 'Recursive delete from root'),
#                 (r':()\{:\|:&\};:', 'Fork bomb'),
#                 (r'dd\s+if=', 'Direct disk access'),
#                 (r'mkfs\.', 'Format filesystem'),
#                 (r'>/dev/sd', 'Direct disk write'),
#                 (r'nc\s+-[el]', 'Netcat backdoor'),
#                 (r'curl.*\|\s*bash', 'Remote code execution'),
#                 (r'wget.*\|\s*sh', 'Remote code execution'),
#                 (r'eval\s*\(', 'Dynamic code execution'),
#                 (r'base64\s+-d.*\|\s*bash', 'Encoded payload execution'),
#             ]
            
#             for pattern, description in dangerous_commands:
#                 matches = re.findall(pattern, content, re.IGNORECASE)
#                 if matches:
#                     results['script_analysis']['dangerous_commands'].append({
#                         'command': pattern,
#                         'description': description,
#                         'count': len(matches)
#                     })
#                     results['threats_detected'].append(f"Dangerous command: {description}")
#                     results['risk_score'] += 0.4
            
#             # Network activity
#             network_patterns = [
#                 (r'curl\s+', 'HTTP request'),
#                 (r'wget\s+', 'HTTP download'),
#                 (r'nc\s+', 'Netcat connection'),
#                 (r'telnet\s+', 'Telnet connection'),
#                 (r'ssh\s+', 'SSH connection'),
#                 (r'/dev/tcp/', 'TCP socket'),
#             ]
            
#             for pattern, description in network_patterns:
#                 matches = re.findall(pattern, content)
#                 if matches:
#                     results['script_analysis']['network_activity'].append({
#                         'pattern': pattern,
#                         'description': description,
#                         'count': len(matches)
#                     })
#                     results['threats_detected'].append(f"Network activity: {description}")
#                     results['risk_score'] += 0.2
        
#         except Exception as e:
#             logger.error(f"Script analysis error: {e}")
        
#         return results
    
#     def _analyze_text_file(self, filepath, filename, results):
#         """Analyze regular text files for web attack patterns"""
#         results['file_type'] = 'text_file'
#         results['web_attacks'] = {}
        
#         try:
#             with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
#                 content = f.read(50000)  # Read first 50KB
            
#             results['file_info'] = {
#                 'name': filename,
#                 'size': len(content),
#                 'hash_md5': hashlib.md5(content.encode()).hexdigest(),
#                 'hash_sha256': hashlib.sha256(content.encode()).hexdigest()
#             }
            
#             # Check for web attack patterns
#             for attack_type, patterns in self.web_attack_patterns.items():
#                 matches = []
#                 for pattern in patterns:
#                     found = re.findall(pattern, content, re.IGNORECASE)
#                     if found:
#                         matches.extend(found)
                
#                 if matches:
#                     results['web_attacks'][attack_type] = {
#                         'count': len(matches),
#                         'samples': [str(m)[:50] for m in matches[:3]]
#                     }
#                     results['threats_detected'].append(
#                         f"{attack_type.replace('_', ' ').title()}: {len(matches)} pattern(s)"
#                     )
#                     results['risk_score'] += len(matches) * 0.15
        
#         except Exception as e:
#             logger.error(f"Text file analysis error: {e}")
        
#         return results
    
#     def _analyze_ips_from_csv(self, df, src_col, dst_col):
#         """Analyze IP addresses from CSV"""
#         analysis = {
#             'suspicious_ips': [],
#             'top_talkers': [],
#             'threats': [],
#             'risk_score': 0.0
#         }
        
#         try:
#             ip_counts = df[src_col].value_counts()
            
#             # Top talkers
#             analysis['top_talkers'] = [
#                 {'ip': ip, 'connections': int(count)}
#                 for ip, count in ip_counts.head(10).items()
#             ]
            
#             # Check for connection floods
#             for ip, count in ip_counts.items():
#                 if count > self.connection_flood_threshold:
#                     analysis['suspicious_ips'].append({
#                         'ip': ip,
#                         'reason': f'Connection flood: {count} connections',
#                         'count': int(count)
#                     })
#                     analysis['threats'].append(f"Suspicious IP: {ip} ({count} connections)")
#                     analysis['risk_score'] += 0.3
        
#         except Exception as e:
#             logger.error(f"IP analysis error: {e}")
        
#         return analysis
    
#     def _analyze_ports_from_csv(self, df, src_col, dport_col):
#         """Analyze ports from CSV"""
#         analysis = {
#             'suspicious_ports': [],
#             'backdoor_ports': [],
#             'port_scan_detected': False,
#             'threats': [],
#             'risk_score': 0.0
#         }
        
#         try:
#             port_counts = df[dport_col].value_counts()
            
#             # Check for suspicious ports
#             for port in df[dport_col].unique()[:50]:
#                 try:
#                     port = int(port)
                    
#                     if port in self.suspicious_ports:
#                         count = port_counts.get(port, 0)
#                         analysis['suspicious_ports'].append({
#                             'port': port,
#                             'connections': int(count)
#                         })
#                         analysis['threats'].append(f"Suspicious port: {port} ({count} connections)")
#                         analysis['risk_score'] += 0.15
                    
#                     if port in self.backdoor_ports:
#                         analysis['backdoor_ports'].append(port)
#                         analysis['threats'].append(f"BACKDOOR PORT: {port}")
#                         analysis['risk_score'] += 0.5
#                 except:
#                     continue
            
#             # Port scan detection
#             if src_col:
#                 for src_ip in df[src_col].unique()[:20]:
#                     ports_contacted = df[df[src_col] == src_ip][dport_col].nunique()
#                     if ports_contacted > self.port_scan_threshold:
#                         analysis['port_scan_detected'] = True
#                         analysis['threats'].append(f"Port scan from {src_ip}: {ports_contacted} ports")
#                         analysis['risk_score'] += 0.4
#                         break
        
#         except Exception as e:
#             logger.error(f"Port analysis error: {e}")
        
#         return analysis
    
#     def _detect_network_attacks(self, df, src_col, dst_col, dport_col):
#         """Detect DDoS and scanning attacks"""
#         detection = {
#             'attacks_found': [],
#             'threats': [],
#             'risk_score': 0.0
#         }
        
#         try:
#             # DDoS detection
#             dst_counts = df[dst_col].value_counts()
#             for dst_ip, count in dst_counts.items():
#                 if count > 500:
#                     unique_sources = df[df[dst_col] == dst_ip][src_col].nunique()
#                     if unique_sources > 50:
#                         detection['attacks_found'].append({
#                             'type': 'DDoS',
#                             'target': dst_ip,
#                             'connections': int(count),
#                             'sources': unique_sources
#                         })
#                         detection['threats'].append(
#                             f"DDoS Attack on {dst_ip}: {count} connections from {unique_sources} sources"
#                         )
#                         detection['risk_score'] += 0.6
            
#             # Network scan detection
#             src_counts = df[src_col].value_counts()
#             for src_ip, count in src_counts.head(5).items():
#                 unique_dests = df[df[src_col] == src_ip][dst_col].nunique()
#                 if unique_dests > 20:
#                     detection['attacks_found'].append({
#                         'type': 'Network Scan',
#                         'source': src_ip,
#                         'targets': unique_dests
#                     })
#                     detection['threats'].append(
#                         f"Network scan from {src_ip}: {unique_dests} targets"
#                     )
#                     detection['risk_score'] += 0.4
        
#         except Exception as e:
#             logger.error(f"Attack detection error: {e}")
        
#         return detection
    
#     def _compare_network_dataset(self, df, src_col):
#         """Compare with reference dataset"""
#         comparison = {
#             'match_percentage': 0.0,
#             'unknown_ips': 0,
#             'threats': [],
#             'risk_score': 0.0
#         }
        
#         try:
#             if self.reference_data is None:
#                 return comparison
            
#             ref_src_col = self._find_column(
#                 self.reference_data,
#                 self.column_mappings['src_ip']
#             )
            
#             if ref_src_col:
#                 uploaded_ips = set(df[src_col].unique())
#                 reference_ips = set(self.reference_data[ref_src_col].unique())
                
#                 new_ips = uploaded_ips - reference_ips
#                 common_ips = uploaded_ips & reference_ips
                
#                 comparison['unknown_ips'] = len(new_ips)
#                 comparison['match_percentage'] = (
#                     len(common_ips) / len(uploaded_ips) * 100
#                     if uploaded_ips else 0
#                 )
                
#                 if len(new_ips) > 10:
#                     comparison['threats'].append(
#                         f"{len(new_ips)} unknown IPs not in reference dataset"
#                     )
#                     comparison['risk_score'] += 0.3
        
#         except Exception as e:
#             logger.error(f"Dataset comparison error: {e}")
        
#         return comparison
    
#     def _ml_network_analysis(self, df, src_col):
#         """ML analysis on network data"""
#         analysis = {
#             'suspicious_percentage': 0.0,
#             'threats': [],
#             'risk_score': 0.0
#         }
        
#         try:
#             sample_size = min(100, len(df))
#             sample_df = df.sample(n=sample_size) if len(df) > sample_size else df
            
#             suspicious_count = 0
            
#             for idx, row in sample_df.iterrows():
#                 request_data = {
#                     'timestamp': datetime.now().isoformat(),
#                     'ip': str(row.get(src_col, '127.0.0.1')),
#                     'method': 'NETWORK',
#                     'path': '/network',
#                     'status': 200,
#                     'user_agent': 'Monitor',
#                     'response_time': 0
#                 }
                
#                 detection = self.anomaly_detector.detect(request_data)
#                 if detection['is_suspicious']:
#                     suspicious_count += 1
            
#             analysis['suspicious_percentage'] = (
#                 suspicious_count / sample_size * 100
#                 if sample_size > 0 else 0
#             )
            
#             if analysis['suspicious_percentage'] > 20:
#                 analysis['threats'].append(
#                     f"ML flagged {analysis['suspicious_percentage']:.1f}% as suspicious"
#                 )
#                 analysis['risk_score'] += 0.4
        
#         except Exception as e:
#             logger.error(f"ML analysis error: {e}")
        
#         return analysis
    
#     def _calculate_threat_level(self, results):
#         """Calculate final threat level"""
#         risk_score = results['risk_score']
        
#         if risk_score >= 2.0:
#             results['threat_level'] = 'critical'
#             results['severity'] = 'high'
#             results['is_suspicious'] = True
#             results['is_safe'] = False
#         elif risk_score >= 1.5:
#             results['threat_level'] = 'high'
#             results['severity'] = 'high'
#             results['is_suspicious'] = True
#             results['is_safe'] = False
#         elif risk_score >= 0.8:
#             results['threat_level'] = 'medium'
#             results['severity'] = 'medium'
#             results['is_suspicious'] = True
#             results['is_safe'] = False
#         elif risk_score >= 0.4:
#             results['threat_level'] = 'low'
#             results['severity'] = 'low'
#             results['is_suspicious'] = True
#             results['is_safe'] = False
#         else:
#             results['threat_level'] = 'safe'
#             results['severity'] = 'low'
#             results['is_suspicious'] = False
#             results['is_safe'] = True
        
#         results['confidence'] = min(risk_score / 2.0, 1.0)
        
#         return results
    
#     def _generate_visual_data(self, results):
#         """Generate visualization data"""
#         visual = {
#             'risk_ratio': {'safe': 50, 'at_risk': 50},
#             'threat_breakdown': []
#         }
        
#         try:
#             # Risk ratio
#             total = max(results['risk_score'], 0.1)
#             at_risk = min((total / 3.0) * 100, 100)
#             visual['risk_ratio'] = {
#                 'safe': round(100 - at_risk, 2),
#                 'at_risk': round(at_risk, 2)
#             }
            
#             # Threat breakdown
#             threat_types = Counter()
#             for threat in results['threats_detected']:
#                 if 'ddos' in threat.lower():
#                     threat_types['DDoS'] += 1
#                 elif 'sql' in threat.lower():
#                     threat_types['SQL Injection'] += 1
#                 elif 'xss' in threat.lower():
#                     threat_types['XSS'] += 1
#                 elif 'scan' in threat.lower():
#                     threat_types['Port Scan'] += 1
#                 elif 'backdoor' in threat.lower():
#                     threat_types['Backdoor'] += 1
#                 elif 'command' in threat.lower():
#                     threat_types['Command Injection'] += 1
#                 else:
#                     threat_types['Other'] += 1
            
#             visual['threat_breakdown'] = [
#                 {'type': k, 'count': v}
#                 for k, v in threat_types.items()
#             ]
        
#         except Exception as e:
#             logger.error(f"Visual data error: {e}")
        
#         return visual
    
#     def _generate_recommendations(self, results):
#         """Generate security recommendations"""
#         recommendations = []
        
#         if results['is_safe']:
#             recommendations.append("✓ File appears safe")
#             recommendations.append("✓ No immediate threats detected")
#             recommendations.append("✓ Continue monitoring")
#         else:
#             recommendations.append("⚠ IMMEDIATE ACTION REQUIRED")
            
#             # Network-based recommendations
#             if results['file_type'] == 'network_traffic_csv':
#                 if results['network_attacks'].get('attack_detection', {}).get('attacks_found'):
#                     recommendations.append("⚠ Network attack detected - Isolate affected systems")
#                 if results['network_attacks'].get('port_analysis', {}).get('backdoor_ports'):
#                     recommendations.append("⚠ CRITICAL: Backdoor ports detected - Close immediately")
#                 if results['network_attacks'].get('ip_analysis', {}).get('suspicious_ips'):
#                     recommendations.append("⚠ Block suspicious IPs at firewall")
            
#             # Web-based recommendations
#             if results['web_attacks']:
#                 if 'sql_injection' in results['web_attacks']:
#                     recommendations.append("⚠ SQL Injection - Sanitize database inputs")
#                 if 'xss' in results['web_attacks']:
#                     recommendations.append("⚠ XSS - Encode output, validate input")
#                 if 'command_injection' in results['web_attacks']:
#                     recommendations.append("⚠ Command Injection - Do not execute system commands")
            
#             # Critical level
#             if results['threat_level'] in ['high', 'critical']:
#                 recommendations.append("⚠ CRITICAL: Report to security team")
#                 recommendations.append("⚠ CRITICAL: Preserve evidence")
        
#         return recommendations
    
#     def _get_csv_info(self, df, filename):
#         """Get CSV file info"""
#         return {
#             'name': filename,
#             'rows': len(df),
#             'columns': len(df.columns),
#             'column_names': list(df.columns),
#             'size_mb': round(df.memory_usage(deep=True).sum() / 1024 / 1024, 2)
#         }
    
#     def _find_column(self, df, possible_names):
#         """Find column by possible names (case-insensitive)"""
#         # Create lowercase mapping of actual columns
#         df_columns_lower = {col.lower(): col for col in df.columns}
        
#         for name in possible_names:
#             # Check lowercase version
#             if name.lower() in df_columns_lower:
#                 return df_columns_lower[name.lower()]
#         return None
#-----------------------------op3------------------------------------------------------------------

"""
Simple Network Analyzer - Guaranteed Detection
Specifically designed to catch network attacks in CSV files
"""

import pandas as pd
import logging
from collections import Counter

logger = logging.getLogger(__name__)

class SimpleNetworkAnalyzer:
    """
    Simplified analyzer focused on network attack detection
    Guaranteed to detect backdoor ports, scans, floods
    """
    
    def __init__(self):
        # Backdoor ports - ALWAYS flag these
        self.backdoor_ports = [4444, 5555, 6666, 7777, 8888, 9999, 12345, 31337]
        
        # Suspicious ports
        self.suspicious_ports = [21, 22, 23, 25, 53, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 8080]
        
        # Thresholds
        self.flood_threshold = 20  # 20+ connections = flood
        self.scan_threshold = 5    # 5+ ports = scan
    
    def analyze(self, filepath, filename):
        """Analyze CSV file for network threats"""
        results = {
            'is_suspicious': False,
            'is_safe': True,
            'threat_level': 'safe',
            'confidence': 0.0,
            'risk_score': 0.0,
            'severity': 'low',
            'file_type': 'network_csv',
            'detection_method': 'simple_network_analysis',
            'file_info': {'name': filename},
            'threats_detected': [],
            'reasons': [],
            'recommendations': [],
            'visual_data': {}
        }
        
        try:
            # Read CSV
            df = pd.read_csv(filepath)
            results['file_info']['rows'] = len(df)
            results['file_info']['columns'] = len(df.columns)
            
            print(f"\n[ANALYZER] Processing {filename}")
            print(f"[ANALYZER] Columns: {list(df.columns)}")
            print(f"[ANALYZER] Rows: {len(df)}")
            
            # Find port column (case-insensitive)
            port_col = self._find_port_column(df)
            src_col = self._find_src_column(df)
            dst_col = self._find_dst_column(df)
            
            print(f"[ANALYZER] Found port column: {port_col}")
            print(f"[ANALYZER] Found src column: {src_col}")
            print(f"[ANALYZER] Found dst column: {dst_col}")
            
            # DETECTION 1: Backdoor Ports (CRITICAL)
            if port_col:
                backdoor_detections = self._detect_backdoor_ports(df, port_col)
                if backdoor_detections['found']:
                    results['threats_detected'].extend(backdoor_detections['threats'])
                    results['risk_score'] += backdoor_detections['risk']
                    print(f"[ANALYZER] Backdoor ports found: {backdoor_detections['ports']}")
            
            # DETECTION 2: Suspicious Ports
            if port_col:
                suspicious_detections = self._detect_suspicious_ports(df, port_col)
                if suspicious_detections['found']:
                    results['threats_detected'].extend(suspicious_detections['threats'])
                    results['risk_score'] += suspicious_detections['risk']
                    print(f"[ANALYZER] Suspicious ports found: {suspicious_detections['ports']}")
            
            # DETECTION 3: Port Scanning
            if port_col and src_col:
                scan_detections = self._detect_port_scans(df, src_col, port_col)
                if scan_detections['found']:
                    results['threats_detected'].extend(scan_detections['threats'])
                    results['risk_score'] += scan_detections['risk']
                    print(f"[ANALYZER] Port scans detected: {scan_detections['scanners']}")
            
            # DETECTION 4: Connection Floods
            if src_col and dst_col:
                flood_detections = self._detect_floods(df, src_col, dst_col)
                if flood_detections['found']:
                    results['threats_detected'].extend(flood_detections['threats'])
                    results['risk_score'] += flood_detections['risk']
                    print(f"[ANALYZER] Floods detected: {flood_detections['flooders']}")
            
            # DETECTION 5: Network Scans
            if src_col and dst_col:
                network_scan_detections = self._detect_network_scans(df, src_col, dst_col)
                if network_scan_detections['found']:
                    results['threats_detected'].extend(network_scan_detections['threats'])
                    results['risk_score'] += network_scan_detections['risk']
                    print(f"[ANALYZER] Network scans detected")
            
            # Calculate threat level
            results = self._calculate_threat_level(results)
            
            # Generate recommendations
            results['recommendations'] = self._generate_recommendations(results)
            
            # Generate visual data
            results['visual_data'] = self._generate_visual_data(results)
            
            # Generate detailed reasons
            if results['is_suspicious']:
                results['reasons'] = results['threats_detected'].copy()
            else:
                results['reasons'] = [
                    "No malicious patterns detected",
                    f"Analyzed {len(df)} network connections",
                    "All ports and IPs appear normal"
                ]
            
            print(f"[ANALYZER] Final risk score: {results['risk_score']}")
            print(f"[ANALYZER] Threat level: {results['threat_level']}")
            print(f"[ANALYZER] Threats: {len(results['threats_detected'])}")
            
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            print(f"[ANALYZER ERROR] {e}")
            results['reasons'].append(f'Analysis error: {str(e)}')
        
        return results
    
    def _find_port_column(self, df):
        """Find port column (case-insensitive) -PRIORITZE DST PORT"""
        port_names = ['dport', 'dst_port', 'dest_port', 'destination_port', 
                      'l4_dst_port', 'port', 'dst port', 'destport']
        
        for col in df.columns:
            col_lower = col.lower().replace('_', '').replace(' ', '')
            for name in port_names:
                name_clean = name.lower().replace('_', '').replace(' ', '')
                if name_clean in col_lower or col_lower in name_clean:
                    print(f"[ANALYZER] Using DESTINATION PORT COLUMN :{col}")
                    return col
        for col in df.columns:
            if 'port' in col.lower():
                print(f"[ANALYZER] Using generic port column: {col}")
                return col
        return None
    
    def _find_src_column(self, df):
        """Find source IP column (case-insensitive)"""
        src_names = ['src', 'source', 'src_ip', 'source_ip', 'srcip', 'sourceip',
                     'ipv4_src_addr', 'ipv4srcaddr', 'source_addr']
        
        for col in df.columns:
            col_lower = col.lower().replace('_', '').replace(' ', '')
            for name in src_names:
                name_clean = name.lower().replace('_', '').replace(' ', '')
                if name_clean in col_lower or col_lower in name_clean:
                    return col
        return None
    
    def _find_dst_column(self, df):
        """Find destination IP column (case-insensitive)"""
        dst_names = ['dst', 'dest', 'destination', 'dst_ip', 'dest_ip', 'dstip', 'destip',
                     'ipv4_dst_addr', 'ipv4dstaddr', 'dest_addr', 'destination_addr']
        
        for col in df.columns:
            col_lower = col.lower().replace('_', '').replace(' ', '')
            for name in dst_names:
                name_clean = name.lower().replace('_', '').replace(' ', '')
                if name_clean in col_lower or col_lower in name_clean:
                    return col
        return None
    
    def _detect_backdoor_ports(self, df, port_col):
        """Detect backdoor ports - CRITICAL"""
        detection = {
            'found': False,
            'threats': [],
            'risk': 0.0,
            'ports': []
        }
        
        try:
            unique_ports = df[port_col].unique()
            
            for port in unique_ports:
                try:
                    port_int = int(port)
                    if port_int in self.backdoor_ports:
                        count = len(df[df[port_col] == port])
                        detection['found'] = True
                        detection['ports'].append(port_int)
                        detection['threats'].append(
                            f"🚨 CRITICAL: Backdoor port {port_int} detected ({count} connections)"
                        )
                        detection['risk'] += 0.8  # High risk per backdoor port
                except:
                    continue
        
        except Exception as e:
            logger.error(f"Backdoor detection error: {e}")
        
        return detection
    
    def _detect_suspicious_ports(self, df, port_col):
        """Detect suspicious ports"""
        detection = {
            'found': False,
            'threats': [],
            'risk': 0.0,
            'ports': []
        }
        
        try:
            unique_ports = df[port_col].unique()
            
            for port in unique_ports:
                try:
                    port_int = int(port)
                    if port_int in self.suspicious_ports:
                        count = len(df[df[port_col] == port])
                        detection['found'] = True
                        detection['ports'].append(port_int)
                        detection['threats'].append(
                            f"⚠️ Suspicious port {port_int} activity ({count} connections)"
                        )
                        detection['risk'] += 0.2  # Medium risk per suspicious port
                except:
                    continue
        
        except Exception as e:
            logger.error(f"Suspicious port detection error: {e}")
        
        return detection
    
    def _detect_port_scans(self, df, src_col, port_col):
        """Detect port scanning"""
        detection = {
            'found': False,
            'threats': [],
            'risk': 0.0,
            'scanners': []
        }
        
        try:
            # Group by source IP and count unique ports
            for src_ip in df[src_col].unique():
                src_data = df[df[src_col] == src_ip]
                unique_ports = src_data[port_col].nunique()
                
                if unique_ports >= self.scan_threshold:
                    detection['found'] = True
                    detection['scanners'].append(src_ip)
                    detection['threats'].append(
                        f"🔍 Port scan detected from {src_ip}: {unique_ports} ports scanned"
                    )
                    detection['risk'] += 0.5
        
        except Exception as e:
            logger.error(f"Port scan detection error: {e}")
        
        return detection
    
    def _detect_floods(self, df, src_col, dst_col):
        """Detect connection floods"""
        detection = {
            'found': False,
            'threats': [],
            'risk': 0.0,
            'flooders': []
        }
        
        try:
            # Count connections per source IP
            src_counts = df[src_col].value_counts()
            
            for src_ip, count in src_counts.items():
                if count >= self.flood_threshold:
                    detection['found'] = True
                    detection['flooders'].append(src_ip)
                    detection['threats'].append(
                        f"💥 Connection flood from {src_ip}: {count} connections"
                    )
                    detection['risk'] += 0.4
        
        except Exception as e:
            logger.error(f"Flood detection error: {e}")
        
        return detection
    
    def _detect_network_scans(self, df, src_col, dst_col):
        """Detect network scanning (many targets from one source)"""
        detection = {
            'found': False,
            'threats': [],
            'risk': 0.0
        }
        
        try:
            # Count unique destinations per source
            for src_ip in df[src_col].unique():
                src_data = df[df[src_col] == src_ip]
                unique_dests = src_data[dst_col].nunique()
                
                if unique_dests >= 10:  # Scanning 10+ targets
                    detection['found'] = True
                    detection['threats'].append(
                        f"🎯 Network scan from {src_ip}: {unique_dests} targets"
                    )
                    detection['risk'] += 0.5
        
        except Exception as e:
            logger.error(f"Network scan detection error: {e}")
        
        return detection
    
    def _calculate_threat_level(self, results):
        """Calculate threat level based on risk score"""
        risk = results['risk_score']
        
        if risk >= 3.0:
            results['threat_level'] = 'critical'
            results['severity'] = 'high'
            results['is_suspicious'] = True
            results['is_safe'] = False
        elif risk >= 1.5:
            results['threat_level'] = 'high'
            results['severity'] = 'high'
            results['is_suspicious'] = True
            results['is_safe'] = False
        elif risk >= 0.8:
            results['threat_level'] = 'medium'
            results['severity'] = 'medium'
            results['is_suspicious'] = True
            results['is_safe'] = False
        elif risk >= 0.3:
            results['threat_level'] = 'low'
            results['severity'] = 'low'
            results['is_suspicious'] = True
            results['is_safe'] = False
        else:
            results['threat_level'] = 'safe'
            results['severity'] = 'low'
            results['is_suspicious'] = False
            results['is_safe'] = True
        
        results['confidence'] = min(risk / 3.0, 1.0)
        
        return results
    
    def _generate_recommendations(self, results):
        """Generate security recommendations"""
        recommendations = []
        
        if results['is_safe']:
            recommendations.append("✓ Traffic appears normal")
            recommendations.append("✓ Continue monitoring")
        else:
            recommendations.append("⚠️ IMMEDIATE ACTION REQUIRED")
            
            # Check for backdoor ports
            for threat in results['threats_detected']:
                if 'Backdoor' in threat or 'CRITICAL' in threat:
                    recommendations.append("⚠️ CRITICAL: Isolate affected systems immediately")
                    recommendations.append("⚠️ CRITICAL: Block attacker IPs at firewall")
                    recommendations.append("⚠️ CRITICAL: Close all backdoor ports")
                    break
            
            # Check for scans
            if any('scan' in t.lower() for t in results['threats_detected']):
                recommendations.append("⚠️ Review firewall rules and access controls")
                recommendations.append("⚠️ Enable IDS/IPS protection")
            
            # Check for floods
            if any('flood' in t.lower() for t in results['threats_detected']):
                recommendations.append("⚠️ Enable rate limiting and DDoS protection")
            
            if results['threat_level'] in ['high', 'critical']:
                recommendations.append("⚠️ Contact security team immediately")
                recommendations.append("⚠️ Preserve logs for forensic analysis")
        
        return recommendations
    
    def _generate_visual_data(self, results):
        """Generate visualization data"""
        risk = results['risk_score']
        at_risk = min((risk / 5.0) * 100, 100)
        safe = max(100 - at_risk, 0)
        
        return {
            'risk_ratio': {
                'safe': round(safe, 2),
                'at_risk': round(at_risk, 2)
            },
            'threat_count': len(results['threats_detected'])
        }