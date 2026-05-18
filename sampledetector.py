"""
WINDOWS-COMPATIBLE THREAT DETECTOR TEST
Place this file in: D:\fyproject\ZeroDay_NIDS_Flask\webattack\
Place your CSV files in the same directory or update the paths below
"""

import pandas as pd
from collections import defaultdict, Counter
import os

def analyze_csv_file(filepath, filename):
    """
    SIMPLE AND DIRECT threat detection
    Returns response in exact format needed by your UI
    """
    
    # Known backdoor ports
    BACKDOOR_PORTS = {
        4444, 5555, 6666, 7777, 8888, 9999, 31337,
        1337, 12345, 12346, 27374
    }
    
    # Malicious IP patterns
    MALICIOUS_IPS = ["45.142.", "185.220.", "103.224."]
    
    try:
        print(f"\n[DEBUG] Attempting to read file: {filepath}")
        
        # Check if file exists
        if not os.path.exists(filepath):
            print(f"[ERROR] File not found: {filepath}")
            return {
                'success': False,
                'error': f'File not found: {filepath}'
            }
        
        # Read CSV
        df = pd.read_csv(filepath)
        
        if df.empty:
            return create_safe_response(filename)
        
        print(f"[DEBUG] Loaded {len(df)} rows from {filename}")
        print(f"[DEBUG] Columns: {list(df.columns)}")
        
        # Find the port column
        port_col = None
        for col in ['dport', 'L4_DST_PORT', 'dest_port', 'dst_port']:
            if col in df.columns:
                port_col = col
                break
        
        if port_col is None:
            print("[ERROR] No port column found!")
            return create_safe_response(filename)
        
        # Find source IP column
        src_col = None
        for col in ['src', 'IPV4_SRC_ADDR', 'source_ip', 'src_ip']:
            if col in df.columns:
                src_col = col
                break
        
        # Find dest IP column
        dst_col = None
        for col in ['dst', 'IPV4_DST_ADDR', 'dest_ip', 'dst_ip']:
            if col in df.columns:
                dst_col = col
                break
        
        print(f"[DEBUG] Using port column: {port_col}")
        print(f"[DEBUG] Using src column: {src_col}")
        print(f"[DEBUG] Using dst column: {dst_col}")
        
        # Detection arrays
        threats = []
        backdoor_count = 0
        malicious_ip_count = 0
        port_scan_count = 0
        flood_count = 0
        
        # CHECK 1: BACKDOOR PORTS (Most important!)
        print(f"\n[CHECKING] Backdoor ports...")
        for idx, row in df.iterrows():
            try:
                port = int(row[port_col])
                
                if port in BACKDOOR_PORTS:
                    backdoor_count += 1
                    src = row[src_col] if src_col else "Unknown"
                    dst = row[dst_col] if dst_col else "Unknown"
                    
                    msg = f"🚨 BACKDOOR: Port {port} connection from {src} to {dst}"
                    threats.append(msg)
                    print(f"[DETECTION] {msg}")
                    
            except (ValueError, KeyError, TypeError) as e:
                continue
        
        print(f"[RESULT] Found {backdoor_count} backdoor connections")
        
        # CHECK 2: MALICIOUS IPs
        print(f"\n[CHECKING] Malicious IPs...")
        if src_col:
            checked_ips = set()
            for idx, row in df.iterrows():
                try:
                    src = str(row[src_col])
                    if src not in checked_ips:
                        checked_ips.add(src)
                        for pattern in MALICIOUS_IPS:
                            if src.startswith(pattern):
                                malicious_ip_count += 1
                                msg = f"🚨 MALICIOUS IP: {src} (known threat)"
                                threats.append(msg)
                                print(f"[DETECTION] {msg}")
                                break
                except (KeyError, TypeError):
                    continue
        
        print(f"[RESULT] Found {malicious_ip_count} malicious IPs")
        
        # CHECK 3: PORT SCANNING
        print(f"\n[CHECKING] Port scans...")
        if src_col and port_col:
            ip_ports = defaultdict(set)
            for idx, row in df.iterrows():
                try:
                    src = str(row[src_col])
                    port = int(row[port_col])
                    ip_ports[src].add(port)
                except (ValueError, KeyError, TypeError):
                    continue
            
            for ip, ports in ip_ports.items():
                if len(ports) >= 5:
                    port_scan_count += 1
                    msg = f"⚠️ PORT SCAN: {ip} scanned {len(ports)} ports"
                    threats.append(msg)
                    print(f"[DETECTION] {msg}")
        
        print(f"[RESULT] Found {port_scan_count} port scans")
        
        # CHECK 4: CONNECTION FLOODS
        print(f"\n[CHECKING] Connection floods...")
        if src_col:
            ip_counts = Counter()
            for idx, row in df.iterrows():
                try:
                    src = str(row[src_col])
                    ip_counts[src] += 1
                except (KeyError, TypeError):
                    continue
            
            for ip, count in ip_counts.items():
                if count >= 10:
                    flood_count += 1
                    msg = f"🚨 FLOOD: {ip} made {count} connections"
                    threats.append(msg)
                    print(f"[DETECTION] {msg}")
        
        print(f"[RESULT] Found {flood_count} floods")
        
        # CALCULATE RESULTS
        total_entries = len(df)
        total_threats = len(threats)
        
        # Risk score
        risk_score = 0
        risk_score += backdoor_count * 20
        risk_score += malicious_ip_count * 15
        risk_score += flood_count * 10
        risk_score += port_scan_count * 5
        risk_score = min(100, risk_score)
        
        # Threat level
        if backdoor_count > 0 or malicious_ip_count > 0:
            threat_level = "critical"
            severity = "high"
        elif flood_count > 0 or risk_score >= 50:
            threat_level = "high"
            severity = "high"
        elif port_scan_count > 0 or risk_score >= 20:
            threat_level = "medium"
            severity = "medium"
        elif risk_score >= 5:
            threat_level = "low"
            severity = "low"
        else:
            threat_level = "safe"
            severity = "safe"
        
        # Severity breakdown
        high_severity = backdoor_count + malicious_ip_count + flood_count
        medium_severity = port_scan_count
        low_severity = 0
        
        # Recommendations
        recommendations = []
        if backdoor_count > 0:
            recommendations.append("🚨 CRITICAL: Backdoor ports detected! Investigate immediately!")
            recommendations.append("Block these ports: 4444, 5555, 6666, 7777, 8888, 9999, 31337")
        if malicious_ip_count > 0:
            recommendations.append("🚨 CRITICAL: Malicious IPs detected! Block at firewall")
        if flood_count > 0:
            recommendations.append("⚠️ HIGH: Connection flooding - Enable rate limiting")
        if port_scan_count > 0:
            recommendations.append("⚠️ MEDIUM: Port scanning - Enable IDS/IPS")
        if not recommendations:
            recommendations.append("✅ No critical threats detected")
        
        print(f"\n[FINAL RESULT] Threat Level: {threat_level.upper()}")
        print(f"[FINAL RESULT] Risk Score: {risk_score}")
        print(f"[FINAL RESULT] Total Threats: {total_threats}")
        print(f"[FINAL RESULT] Backdoors: {backdoor_count}")
        
        # Return response in EXACT format your UI expects
        return {
            'success': True,
            'is_suspicious': threat_level != 'safe',
            'is_safe': threat_level == 'safe',
            'severity': severity,
            'threat_level': threat_level,
            'confidence': min(risk_score / 100.0, 1.0),
            'detection_method': 'network_traffic_analysis',
            'filename': filename,
            'file_type': 'csv',
            'analysis': {
                'total_entries': total_entries,
                'suspicious_entries': total_threats,
                'threat_percentage': round((total_threats / total_entries * 100) if total_entries > 0 else 0, 2),
                'risk_score': risk_score,
                'statistics': {
                    'backdoor_ports': backdoor_count,
                    'malicious_ips': malicious_ip_count,
                    'connection_floods': flood_count,
                    'port_scans': port_scan_count,
                    'network_scans': 0,
                    'suspicious_ports': 0
                },
                'severity_breakdown': {
                    'high': high_severity,
                    'medium': medium_severity,
                    'low': low_severity
                }
            },
            'severity_counts': {
                'high': high_severity,
                'medium': medium_severity,
                'low': low_severity
            },
            'alerts': {
                'high': high_severity,
                'medium': medium_severity,
                'low': low_severity,
                'total': high_severity + medium_severity + low_severity
            },
            'reasons': threats[:10] if threats else ["No threats detected in this file"],
            'recommendations': recommendations,
            'threats_detected': [{'message': t} for t in threats[:50]]
        }
        
    except Exception as e:
        print(f"[ERROR] Analysis failed: {str(e)}")
        import traceback
        traceback.print_exc()
        
        return {
            'success': False,
            'error': f'Analysis failed: {str(e)}'
        }


def create_safe_response(filename):
    """Create a safe/clean response"""
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
        'reasons': ['Empty or unreadable file'],
        'recommendations': ['File appears clean'],
        'threats_detected': []
    }


# Test the analyzer
if __name__ == '__main__':
    print("="*70)
    print("TESTING SIMPLE THREAT DETECTOR - WINDOWS VERSION")
    print("="*70)
    
    # Get the current directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"\nCurrent directory: {current_dir}")
    
    # Test file - UPDATE THIS PATH to where your CSV file actually is
    test_file = "simple_backdoor_test.csv"
    
    # Check if file exists in current directory
    if os.path.exists(test_file):
        filepath = test_file
    else:
        # Try different possible locations
        possible_paths = [
            os.path.join(current_dir, test_file),
            os.path.join(current_dir, "..", test_file),
            os.path.join(current_dir, "uploads", test_file),
            r"D:\fyproject\ZeroDay_NIDS_Flask\simple_backdoor_test.csv",
            r"D:\fyproject\ZeroDay_NIDS_Flask\uploads\simple_backdoor_test.csv"
        ]
        
        filepath = None
        for path in possible_paths:
            if os.path.exists(path):
                filepath = path
                break
        
        if filepath is None:
            print(f"\n❌ ERROR: Could not find {test_file}")
            print(f"\nSearched in:")
            for path in possible_paths:
                print(f"  - {path}")
            print(f"\nPlease place {test_file} in one of these locations or update the path in this script.")
            exit(1)
    
    print(f"Testing file: {filepath}")
    
    result = analyze_csv_file(filepath, test_file)
    
    print("\n" + "="*70)
    print("FINAL RESULT:")
    print("="*70)
    
    if result.get('success'):
        print(f"✅ Success: {result['success']}")
        print(f"🔒 Threat Level: {result['threat_level'].upper()}")
        print(f"⚠️  Is Suspicious: {result['is_suspicious']}")
        print(f"✅ Is Safe: {result['is_safe']}")
        print(f"📊 Risk Score: {result['analysis']['risk_score']}/100")
        print(f"🚨 Backdoors Found: {result['analysis']['statistics']['backdoor_ports']}")
        print(f"🔥 High Alerts: {result['alerts']['high']}")
        print(f"⚠️  Medium Alerts: {result['alerts']['medium']}")
        
        print(f"\n📋 First 3 Threats:")
        for i, threat in enumerate(result['reasons'][:3], 1):
            print(f"  {i}. {threat}")
        
        print(f"\n💡 Recommendations:")
        for i, rec in enumerate(result['recommendations'][:3], 1):
            print(f"  {i}. {rec}")
    else:
        print(f"❌ Success: False")
        print(f"❌ Error: {result.get('error', 'Unknown error')}")
    
    print("="*70)