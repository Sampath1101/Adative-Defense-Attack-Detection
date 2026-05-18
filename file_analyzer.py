"""
Complete File Analyzer - Integrated Solution
Handles CSV, image, text, and script file analysis
"""

import os
import pandas as pd
from collections import Counter, defaultdict
import logging

logger = logging.getLogger(__name__)


class FileAnalyzer:
    """
    Complete file analyzer that handles multiple file types and
    properly integrates with the API response format
    """
    
    def __init__(self):
        # Known backdoor/C2 ports - CRITICAL THREATS
        self.backdoor_ports = {
            4444: "Metasploit default backdoor",
            5555: "Android Debug Bridge / Backdoor",
            6666: "IRC/Backdoor",
            7777: "Common backdoor port",
            8888: "Alternative HTTP / Backdoor",
            9999: "Common backdoor port",
            31337: "Elite/leet backdoor (BackOrifice)",
            1337: "Elite/leet backdoor",
            12345: "NetBus backdoor",
            12346: "NetBus backdoor",
            20034: "NetBus Pro",
            27374: "SubSeven backdoor",
            6667: "IRC (C2 channel)",
            6668: "IRC",
            6669: "IRC",
            1234: "Common backdoor"
        }
        
        # Commonly targeted ports
        self.target_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            80: "HTTP", 135: "MS RPC", 139: "NetBIOS", 443: "HTTPS",
            445: "SMB", 1433: "MS SQL", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP Proxy"
        }
        
        # Known malicious IP patterns
        self.malicious_ip_patterns = [
            "45.142.", "185.220.", "103.224."
        ]
    
    def analyze_csv(self, filepath, filename):
        """
        Analyze CSV file for network traffic threats
        Returns properly formatted response for API
        """
        try:
            logger.info(f"🔍 Analyzing CSV: {filename}")
            
            # Read CSV
            df = pd.read_csv(filepath)
            
            if df.empty:
                return self._safe_response(filename, "Empty CSV file")
            
            logger.info(f"📊 Loaded {len(df)} rows")
            
            # Standardize column names
            df = self._standardize_columns(df)
            
            # Run all detections
            all_threats = []
            stats = {
                'backdoor_ports': 0,
                'port_scans': 0,
                'network_scans': 0,
                'connection_floods': 0,
                'suspicious_ports': 0,
                'malicious_ips': 0
            }
            
            # 1. BACKDOOR DETECTION (Highest Priority)
            backdoor_threats = self._detect_backdoors(df)
            all_threats.extend(backdoor_threats)
            stats['backdoor_ports'] = len(backdoor_threats)
            logger.info(f"🚨 Found {len(backdoor_threats)} backdoor connections")
            
            # 2. PORT SCANNING
            port_scan_threats = self._detect_port_scans(df)
            all_threats.extend(port_scan_threats)
            stats['port_scans'] = len(port_scan_threats)
            logger.info(f"⚠️ Found {len(port_scan_threats)} port scans")
            
            # 3. NETWORK SCANNING
            network_scan_threats = self._detect_network_scans(df)
            all_threats.extend(network_scan_threats)
            stats['network_scans'] = len(network_scan_threats)
            
            # 4. CONNECTION FLOODING
            flood_threats = self._detect_floods(df)
            all_threats.extend(flood_threats)
            stats['connection_floods'] = len(flood_threats)
            
            # 5. MALICIOUS IPs
            malicious_ip_threats = self._detect_malicious_ips(df)
            all_threats.extend(malicious_ip_threats)
            stats['malicious_ips'] = len(malicious_ip_threats)
            
            # Calculate metrics
            total_entries = len(df)
            suspicious_count = len(all_threats)
            threat_percentage = (suspicious_count / total_entries * 100) if total_entries > 0 else 0
            
            # Calculate risk score
            risk_score = self._calculate_risk(stats)
            
            # Determine threat level and severity
            threat_level, overall_severity = self._determine_threat_level(stats, risk_score)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(stats)
            
            # Create severity breakdown
            severity_counts = {
                'high': stats['backdoor_ports'] + stats['malicious_ips'] + stats['connection_floods'],
                'medium': stats['port_scans'] + stats['network_scans'],
                'low': stats['suspicious_ports']
            }
            
            # Format threats for display
            threat_messages = [t['message'] for t in all_threats[:10]]
            
            logger.info(f"✅ Analysis complete: {suspicious_count} threats | Risk: {risk_score}")
            
            return {
                'success': True,
                'is_suspicious': threat_level != 'safe',
                'is_safe': threat_level == 'safe',
                'severity': overall_severity,
                'threat_level': threat_level,
                'confidence': min(risk_score / 100.0, 1.0),
                'detection_method': 'network_traffic_analysis',
                'filename': filename,
                'file_type': 'csv',
                'analysis': {
                    'total_entries': total_entries,
                    'suspicious_entries': suspicious_count,
                    'threat_percentage': round(threat_percentage, 2),
                    'risk_score': risk_score,
                    'statistics': stats,
                    'severity_breakdown': severity_counts
                },
                'severity_counts': severity_counts,
                'alerts': {
                    'high': severity_counts['high'],
                    'medium': severity_counts['medium'],
                    'low': severity_counts['low'],
                    'total': sum(severity_counts.values())
                },
                'reasons': threat_messages if threat_messages else ['No threats detected in this file'],
                'recommendations': recommendations,
                'threats_detected': all_threats[:50]
            }
            
        except Exception as e:
            logger.error(f"❌ CSV analysis error: {str(e)}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Analysis failed: {str(e)}'
            }
    
    def _standardize_columns(self, df):
        """Map various column names to standard format"""
        mappings = {
            'src': ['src', 'IPV4_SRC_ADDR', 'source_ip', 'src_ip', 'source'],
            'dst': ['dst', 'IPV4_DST_ADDR', 'dest_ip', 'dst_ip', 'destination'],
            'dport': ['dport', 'L4_DST_PORT', 'dest_port', 'dst_port'],
            'sport': ['sport', 'L4_SRC_PORT', 'source_port', 'src_port'],
            'protocol': ['protocol', 'PROTOCOL', 'proto']
        }
        
        for std_name, possible_names in mappings.items():
            for name in possible_names:
                if name in df.columns:
                    df[std_name] = df[name]
                    break
        
        return df
    
    def _detect_backdoors(self, df):
        """Detect backdoor port connections - CRITICAL"""
        threats = []
        
        if 'dport' not in df.columns:
            logger.warning("⚠️ No 'dport' column found")
            return threats
        
        for idx, row in df.iterrows():
            try:
                port = int(row['dport'])
                
                if port in self.backdoor_ports:
                    src = row.get('src', 'Unknown')
                    dst = row.get('dst', 'Unknown')
                    desc = self.backdoor_ports[port]
                    
                    threats.append({
                        'type': 'BACKDOOR',
                        'severity': 'HIGH',
                        'port': port,
                        'source': src,
                        'destination': dst,
                        'message': f"🚨 BACKDOOR DETECTED: Port {port} ({desc}) | {src} → {dst}"
                    })
                    
            except (ValueError, KeyError, TypeError) as e:
                continue
        
        return threats
    
    def _detect_port_scans(self, df):
        """Detect port scanning activity"""
        threats = []
        
        if 'src' not in df.columns or 'dport' not in df.columns:
            return threats
        
        # Track ports per source IP
        ip_ports = defaultdict(set)
        
        for idx, row in df.iterrows():
            try:
                src = row['src']
                port = int(row['dport'])
                ip_ports[src].add(port)
            except (ValueError, KeyError, TypeError):
                continue
        
        # Flag IPs scanning 5+ different ports
        for src_ip, ports in ip_ports.items():
            if len(ports) >= 5:
                threats.append({
                    'type': 'PORT_SCAN',
                    'severity': 'MEDIUM',
                    'source': src_ip,
                    'port_count': len(ports),
                    'message': f"⚠️ PORT SCAN: {src_ip} scanned {len(ports)} different ports"
                })
        
        return threats
    
    def _detect_network_scans(self, df):
        """Detect network scanning (multiple IPs)"""
        threats = []
        
        if 'src' not in df.columns or 'dst' not in df.columns:
            return threats
        
        # Track destinations per source
        ip_targets = defaultdict(set)
        
        for idx, row in df.iterrows():
            try:
                src = row['src']
                dst = row['dst']
                ip_targets[src].add(dst)
            except KeyError:
                continue
        
        # Flag IPs contacting 10+ different hosts
        for src_ip, targets in ip_targets.items():
            if len(targets) >= 10:
                threats.append({
                    'type': 'NETWORK_SCAN',
                    'severity': 'MEDIUM',
                    'source': src_ip,
                    'target_count': len(targets),
                    'message': f"⚠️ NETWORK SCAN: {src_ip} contacted {len(targets)} hosts"
                })
        
        return threats
    
    def _detect_floods(self, df):
        """Detect connection flooding (DDoS indicators)"""
        threats = []
        
        if 'src' not in df.columns:
            return threats
        
        # Count connections per source
        connection_counts = Counter()
        connection_details = defaultdict(lambda: {'ports': set()})
        
        for idx, row in df.iterrows():
            try:
                src = row['src']
                port = int(row.get('dport', 0))
                connection_counts[src] += 1
                connection_details[src]['ports'].add(port)
            except (ValueError, KeyError, TypeError):
                continue
        
        # Flag high connection counts
        for src_ip, count in connection_counts.items():
            if count >= 10:
                ports = connection_details[src_ip]['ports']
                if len(ports) <= 3:  # Focused on few ports = attack
                    severity = 'HIGH' if count >= 20 else 'MEDIUM'
                    threats.append({
                        'type': 'FLOOD',
                        'severity': severity,
                        'source': src_ip,
                        'count': count,
                        'message': f"🚨 CONNECTION FLOOD: {src_ip} made {count} connections"
                    })
        
        return threats
    
    def _detect_malicious_ips(self, df):
        """Detect known malicious IP sources"""
        threats = []
        
        if 'src' not in df.columns:
            return threats
        
        checked = set()
        
        for idx, row in df.iterrows():
            try:
                src = row['src']
                
                if src in checked:
                    continue
                
                checked.add(src)
                
                # Check against malicious patterns
                for pattern in self.malicious_ip_patterns:
                    if src.startswith(pattern):
                        dst = row.get('dst', 'Unknown')
                        threats.append({
                            'type': 'MALICIOUS_IP',
                            'severity': 'HIGH',
                            'source': src,
                            'destination': dst,
                            'message': f"🚨 MALICIOUS IP: {src} (known threat source)"
                        })
                        break
                        
            except KeyError:
                continue
        
        return threats
    
    def _calculate_risk(self, stats):
        """Calculate risk score (0-100)"""
        score = 0
        score += stats['backdoor_ports'] * 20       # Critical
        score += stats['malicious_ips'] * 15        # Critical
        score += stats['connection_floods'] * 12    # High
        score += stats['port_scans'] * 6            # Medium
        score += stats['network_scans'] * 6         # Medium
        score += stats['suspicious_ports'] * 2      # Low
        
        return min(100, score)
    
    def _determine_threat_level(self, stats, risk_score):
        """Determine threat level and severity"""
        # Critical: backdoors or malicious IPs
        if stats['backdoor_ports'] > 0 or stats['malicious_ips'] > 0:
            return 'critical', 'high'
        
        # High: floods or high risk score
        if stats['connection_floods'] > 0 or risk_score >= 50:
            return 'high', 'high'
        
        # Medium: scans detected
        if stats['port_scans'] > 0 or stats['network_scans'] > 0 or risk_score >= 20:
            return 'medium', 'medium'
        
        # Low: minor issues
        if risk_score >= 5:
            return 'low', 'low'
        
        # Safe
        return 'safe', 'safe'
    
    def _generate_recommendations(self, stats):
        """Generate security recommendations"""
        recs = []
        
        if stats['backdoor_ports'] > 0:
            recs.append("🚨 CRITICAL: Backdoor activity detected! Investigate compromised systems immediately")
            recs.append("Block backdoor ports: 4444, 5555, 6666, 7777, 8888, 9999, 31337")
            recs.append("Perform full system scan and forensic analysis")
        
        if stats['malicious_ips'] > 0:
            recs.append("🚨 CRITICAL: Traffic from known malicious IPs - Block at firewall")
        
        if stats['connection_floods'] > 0:
            recs.append("⚠️ HIGH: Connection flooding detected - Enable rate limiting")
        
        if stats['port_scans'] > 0:
            recs.append("⚠️ MEDIUM: Port scanning detected - Enable IPS/IDS rules")
        
        if stats['network_scans'] > 0:
            recs.append("⚠️ MEDIUM: Network scanning detected - Restrict network access")
        
        if not recs:
            recs.append("✅ No immediate threats detected")
            recs.append("Continue monitoring network traffic")
        
        return recs
    
    def _safe_response(self, filename, message):
        """Return safe/clean response"""
        return {
            'success': True,
            'is_suspicious': False,
            'is_safe': True,
            'severity': 'safe',
            'threat_level': 'safe',
            'confidence': 1.0,
            'detection_method': 'network_traffic_analysis',
            'filename': filename,
            'file_type': 'csv',
            'analysis': {
                'total_entries': 0,
                'suspicious_entries': 0,
                'threat_percentage': 0,
                'risk_score': 0,
                'statistics': {},
                'severity_breakdown': {'high': 0, 'medium': 0, 'low': 0}
            },
            'severity_counts': {'high': 0, 'medium': 0, 'low': 0},
            'alerts': {'high': 0, 'medium': 0, 'low': 0, 'total': 0},
            'reasons': [message],
            'recommendations': ['File is clean'],
            'threats_detected': []
        }


# Create singleton instance
file_analyzer = FileAnalyzer()


def analyze_file(filepath, filename):
    """
    Main entry point for file analysis
    Determines file type and routes to appropriate analyzer
    """
    file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if file_ext == 'csv':
        return file_analyzer.analyze_csv(filepath, filename)
    else:
        return {
            'success': False,
            'error': 'Unsupported file type'
        }