"""
Network Traffic Analyzer for CSV Files
Analyzes network traffic data and detects threats
"""

import pandas as pd
import numpy as np
import json
import logging
from datetime import datetime
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkTrafficAnalyzer:
    """Analyzes network traffic from CSV files and detects threats"""
    
    def __init__(self):
        """Initialize the analyzer with threat detection rules"""
        
        # Known backdoor ports
        self.backdoor_ports = {
            31337, 12345, 27374, 6667, 6666, 1337, 
            31338, 31339, 54320, 54321, 9999, 12346
        }
        
        # Common service ports (legitimate)
        self.common_ports = {
            80, 443, 22, 21, 25, 53, 110, 143, 
            3306, 5432, 8080, 8443, 3389, 5900
        }
        
        # Suspicious port ranges
        self.suspicious_port_ranges = [
            (1024, 1100),   # Common trojan range
            (6660, 6670),   # IRC bots
            (31330, 31340), # Back Orifice range
            (12340, 12350), # NetBus range
        ]
        
        # Private IP ranges
        self.private_ip_ranges = [
            '10.',
            '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.',
            '192.168.'
        ]
        
        logger.info("✅ NetworkTrafficAnalyzer initialized")
    
    def is_private_ip(self, ip):
        """Check if IP address is private"""
        try:
            return any(ip.startswith(prefix) for prefix in self.private_ip_ranges)
        except:
            return False
    
    def is_backdoor_port(self, port):
        """Check if port is a known backdoor port"""
        try:
            return int(port) in self.backdoor_ports
        except:
            return False
    
    def is_suspicious_port(self, port):
        """Check if port is in suspicious range"""
        try:
            port_num = int(port)
            for start, end in self.suspicious_port_ranges:
                if start <= port_num <= end:
                    return True
            return False
        except:
            return False
    
    def detect_port_scan(self, df):
        """Detect port scanning behavior"""
        threats = []
        
        try:
            # Group by source IP and count unique destination ports
            if 'Source' in df.columns and 'Destination Port' in df.columns:
                port_scans = df.groupby('Source')['Destination Port'].nunique()
                
                # If a single source contacts many different ports, it's likely a scan
                for ip, port_count in port_scans.items():
                    if port_count > 10:  # Threshold for port scan
                        threats.append({
                            'type': 'port_scan',
                            'severity': 'medium',
                            'source_ip': ip,
                            'port_count': int(port_count),
                            'data': f"Port scan detected from {ip} - {port_count} ports scanned"
                        })
        except Exception as e:
            logger.error(f"Error detecting port scans: {e}")
        
        return threats
    
    def detect_network_scan(self, df):
        """Detect network scanning behavior"""
        threats = []
        
        try:
            # Group by source IP and count unique destination IPs
            if 'Source' in df.columns and 'Destination' in df.columns:
                network_scans = df.groupby('Source')['Destination'].nunique()
                
                # If a single source contacts many different IPs, it's likely a network scan
                for ip, dest_count in network_scans.items():
                    if dest_count > 20:  # Threshold for network scan
                        threats.append({
                            'type': 'network_scan',
                            'severity': 'medium',
                            'source_ip': ip,
                            'destination_count': int(dest_count),
                            'data': f"Network scan detected from {ip} - {dest_count} destinations contacted"
                        })
        except Exception as e:
            logger.error(f"Error detecting network scans: {e}")
        
        return threats
    
    def detect_connection_flood(self, df):
        """Detect connection flooding / DDoS attempts"""
        threats = []
        
        try:
            if 'Source' in df.columns:
                # Count connections per source IP
                connection_counts = df['Source'].value_counts()
                
                # High connection count from single IP indicates potential flood
                for ip, count in connection_counts.items():
                    if count > 50:  # Threshold for connection flood
                        threats.append({
                            'type': 'connection_flood',
                            'severity': 'high',
                            'source_ip': ip,
                            'connection_count': int(count),
                            'data': f"Connection flood detected from {ip} - {count} connections"
                        })
        except Exception as e:
            logger.error(f"Error detecting connection floods: {e}")
        
        return threats
    
    def detect_backdoor_communication(self, df):
        """Detect communication on known backdoor ports"""
        threats = []
        
        try:
            if 'Destination Port' in df.columns:
                for idx, row in df.iterrows():
                    port = row.get('Destination Port', 0)
                    if self.is_backdoor_port(port):
                        source = row.get('Source', 'Unknown')
                        dest = row.get('Destination', 'Unknown')
                        threats.append({
                            'type': 'backdoor_port',
                            'severity': 'high',
                            'source_ip': source,
                            'destination_ip': dest,
                            'port': int(port),
                            'data': f"Backdoor port {port} used: {source} → {dest}"
                        })
        except Exception as e:
            logger.error(f"Error detecting backdoor communication: {e}")
        
        return threats
    
    def detect_suspicious_ports(self, df):
        """Detect communication on suspicious port ranges"""
        threats = []
        
        try:
            if 'Destination Port' in df.columns:
                for idx, row in df.iterrows():
                    port = row.get('Destination Port', 0)
                    if self.is_suspicious_port(port):
                        source = row.get('Source', 'Unknown')
                        dest = row.get('Destination', 'Unknown')
                        threats.append({
                            'type': 'suspicious_port',
                            'severity': 'low',
                            'source_ip': source,
                            'destination_ip': dest,
                            'port': int(port),
                            'data': f"Suspicious port {port} used: {source} → {dest}"
                        })
        except Exception as e:
            logger.error(f"Error detecting suspicious ports: {e}")
        
        return threats
    
    def analyze_file(self, filepath, filename):
        """
        Main analysis function for CSV files
        
        Args:
            filepath: Path to the CSV file
            filename: Original filename
            
        Returns:
            dict: Analysis results with threats, statistics, and recommendations
        """
        logger.info(f"Starting analysis of {filename}")
        
        try:
            # Read CSV file
            df = pd.read_csv(filepath)
            total_entries = len(df)
            
            logger.info(f"Loaded {total_entries} entries from CSV")
            logger.info(f"Columns: {list(df.columns)}")
            
            # Run all threat detection methods
            all_threats = []
            
            # Detect various threat types
            all_threats.extend(self.detect_port_scan(df))
            all_threats.extend(self.detect_network_scan(df))
            all_threats.extend(self.detect_connection_flood(df))
            all_threats.extend(self.detect_backdoor_communication(df))
            all_threats.extend(self.detect_suspicious_ports(df))
            
            # Count threats by type
            threat_counts = {
                'port_scans': len([t for t in all_threats if t['type'] == 'port_scan']),
                'network_scans': len([t for t in all_threats if t['type'] == 'network_scan']),
                'connection_floods': len([t for t in all_threats if t['type'] == 'connection_flood']),
                'backdoor_ports': len([t for t in all_threats if t['type'] == 'backdoor_port']),
                'suspicious_ports': len([t for t in all_threats if t['type'] == 'suspicious_port'])
            }
            
            suspicious_entries = len(all_threats)
            threat_percentage = (suspicious_entries / total_entries * 100) if total_entries > 0 else 0
            
            # Calculate risk score (0-10)
            risk_score = min(10, (
                threat_counts['connection_floods'] * 2.0 +
                threat_counts['backdoor_ports'] * 1.5 +
                threat_counts['port_scans'] * 0.5 +
                threat_counts['network_scans'] * 0.5 +
                threat_counts['suspicious_ports'] * 0.3
            ))
            
            # Determine threat level
            if risk_score >= 7:
                threat_level = 'critical'
            elif risk_score >= 5:
                threat_level = 'high'
            elif risk_score >= 3:
                threat_level = 'medium'
            elif risk_score >= 1:
                threat_level = 'low'
            else:
                threat_level = 'safe'
            
            # Generate recommendations
            recommendations = []
            
            if threat_counts['connection_floods'] > 0:
                recommendations.append("⚠️  Connection flooding detected - implement rate limiting")
            
            if threat_counts['backdoor_ports'] > 0:
                recommendations.append("🚨 Backdoor port activity detected - investigate immediately")
            
            if threat_counts['port_scans'] > 0:
                recommendations.append("🔍 Port scanning detected - enable firewall rules")
            
            if threat_counts['network_scans'] > 0:
                recommendations.append("🌐 Network scanning detected - monitor source IPs")
            
            if threat_counts['suspicious_ports'] > 0:
                recommendations.append("⚡ Suspicious port usage - review traffic patterns")
            
            if threat_level == 'safe':
                recommendations.append("✅ Traffic appears normal - continue monitoring")
            
            # Build result
            result = {
                'filename': filename,
                'total_entries': total_entries,
                'suspicious_entries': suspicious_entries,
                'threat_percentage': round(threat_percentage, 2),
                'risk_score': round(risk_score, 2),
                'threat_level': threat_level,
                'threats_found': all_threats,
                'statistics': threat_counts,
                'recommendations': recommendations
            }
            
            logger.info("=" * 70)
            logger.info(f"📊 ANALYSIS COMPLETE: {filename}")
            logger.info(f"   Total Entries: {total_entries}")
            logger.info(f"   Suspicious: {suspicious_entries} ({threat_percentage:.2f}%)")
            logger.info(f"   Risk Score: {risk_score:.2f}/10")
            logger.info(f"   Threat Level: {threat_level.upper()}")
            logger.info("=" * 70)
            logger.info("🎯 THREAT BREAKDOWN:")
            logger.info(f"   🔴 Connection Floods: {threat_counts['connection_floods']}")
            logger.info(f"   🟠 Backdoor Ports: {threat_counts['backdoor_ports']}")
            logger.info(f"   🟡 Port Scans: {threat_counts['port_scans']}")
            logger.info(f"   🟡 Network Scans: {threat_counts['network_scans']}")
            logger.info(f"   🟢 Suspicious Ports: {threat_counts['suspicious_ports']}")
            logger.info("=" * 70)
            
            return result
            
        except pd.errors.EmptyDataError:
            logger.error(f"CSV file is empty: {filename}")
            return {
                'filename': filename,
                'total_entries': 0,
                'suspicious_entries': 0,
                'threat_percentage': 0,
                'risk_score': 0,
                'threat_level': 'safe',
                'threats_found': [],
                'statistics': {
                    'port_scans': 0,
                    'network_scans': 0,
                    'connection_floods': 0,
                    'backdoor_ports': 0,
                    'suspicious_ports': 0
                },
                'recommendations': ['⚠️  File is empty or invalid']
            }
        
        except Exception as e:
            logger.error(f"Error analyzing file: {str(e)}")
            import traceback
            traceback.print_exc()
            
            return {
                'filename': filename,
                'total_entries': 0,
                'suspicious_entries': 0,
                'threat_percentage': 0,
                'risk_score': 0,
                'threat_level': 'error',
                'threats_found': [],
                'statistics': {
                    'port_scans': 0,
                    'network_scans': 0,
                    'connection_floods': 0,
                    'backdoor_ports': 0,
                    'suspicious_ports': 0
                },
                'recommendations': [f'❌ Analysis failed: {str(e)}']
            }


# Test function
def test_analyzer():
    """Test the network traffic analyzer"""
    
    print("\n" + "="*70)
    print("🧪 TESTING NETWORK TRAFFIC ANALYZER")
    print("="*70 + "\n")
    
    # Create test data
    test_data = {
        'Source': ['192.168.1.100', '192.168.1.100', '192.168.1.100', '10.0.0.50', '172.16.0.10'] * 20,
        'Destination': ['8.8.8.8', '1.1.1.1', '192.168.1.1', '192.168.1.1', '8.8.4.4'] * 20,
        'Destination Port': [80, 443, 31337, 22, 12345] * 20,
        'Protocol': ['TCP', 'TCP', 'TCP', 'SSH', 'TCP'] * 20
    }
    
    df = pd.DataFrame(test_data)
    
    # Save test CSV
    test_file = 'test_traffic.csv'
    df.to_csv(test_file, index=False)
    
    # Analyze
    analyzer = NetworkTrafficAnalyzer()
    result = analyzer.analyze_file(test_file, test_file)
    
    print("\n📊 TEST RESULTS:")
    print(f"   Total Entries: {result['total_entries']}")
    print(f"   Suspicious: {result['suspicious_entries']}")
    print(f"   Risk Score: {result['risk_score']}/10")
    print(f"   Threat Level: {result['threat_level'].upper()}")
    
    print("\n🎯 THREATS FOUND:")
    for threat in result['threats_found'][:5]:  # Show first 5
        print(f"   • {threat['data']}")
    
    print("\n💡 RECOMMENDATIONS:")
    for rec in result['recommendations']:
        print(f"   {rec}")
    
    print("\n" + "="*70)
    print("✅ TEST COMPLETE")
    print("="*70 + "\n")
    
    # Clean up
    import os
    try:
        os.remove(test_file)
    except:
        pass


if __name__ == '__main__':
    test_analyzer()