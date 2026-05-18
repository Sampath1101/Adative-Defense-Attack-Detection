#!/usr/bin/env python3
"""
Quick test to verify IDS detection is working
"""

import requests
import time

BASE_URL = "http://localhost:5000"

print("\n" + "="*60)
print("QUICK IDS TEST")
print("="*60)

# Check server
try:
    response = requests.get(f"{BASE_URL}/health", timeout=3)
    print("✓ Server running\n")
except:
    print("✗ Server not running!")
    print("Start server: python app.py\n")
    exit(1)

# Test 1: SQL Injection
print("Test 1: SQL Injection")
print("Sending: /login?user=admin' --")
try:
    response = requests.get(f"{BASE_URL}/login?user=admin' --", timeout=5)
    print(f"Response: {response.status_code}")
    
    # Wait for IDS to process
    time.sleep(0.5)
    
    # Check if alert created
    alerts = requests.get(f"{BASE_URL}/api/alerts/recent?limit=1", timeout=3).json()
    if alerts and len(alerts) > 0:
        alert = alerts[0]
        print(f"✓ DETECTED!")
        print(f"  Severity: {alert.get('severity', 'unknown').upper()}")
        print(f"  Attack: {', '.join(alert.get('attack_types', []))}")
    else:
        print("✗ NOT DETECTED")
    
except Exception as e:
    print(f"Error: {e}")

print()

# Test 2: XSS
print("Test 2: XSS Attack")
print("Sending: /search?q=<script>alert(1)</script>")
try:
    response = requests.get(f"{BASE_URL}/search?q=<script>alert(1)</script>", timeout=5)
    print(f"Response: {response.status_code}")
    
    time.sleep(0.5)
    
    alerts = requests.get(f"{BASE_URL}/api/alerts/recent?limit=1", timeout=3).json()
    if alerts and len(alerts) > 0:
        alert = alerts[0]
        if '<script>' in alert.get('path', '') or 'xss' in alert.get('attack_types', []):
            print(f"✓ DETECTED!")
            print(f"  Severity: {alert.get('severity', 'unknown').upper()}")
            print(f"  Attack: {', '.join(alert.get('attack_types', []))}")
        else:
            print("✗ NOT DETECTED")
    else:
        print("✗ NOT DETECTED")
    
except Exception as e:
    print(f"Error: {e}")

print()

# Test 3: Get stats
print("Test 3: System Stats")
try:
    stats = requests.get(f"{BASE_URL}/api/stats", timeout=3).json()
    alerts_data = stats.get('alerts', {})
    total = alerts_data.get('total_alerts', 0)
    
    print(f"Total Alerts: {total}")
    
    by_severity = alerts_data.get('by_severity', {})
    if by_severity:
        print(f"High: {by_severity.get('high', 0)}")
        print(f"Medium: {by_severity.get('medium', 0)}")
        print(f"Low: {by_severity.get('low', 0)}")
    
    if total > 0:
        print("\n✓ IDS IS WORKING!")
    else:
        print("\n✗ No alerts detected - IDS may not be working")

except Exception as e:
    print(f"Error: {e}")

print("\n" + "="*60 + "\n")