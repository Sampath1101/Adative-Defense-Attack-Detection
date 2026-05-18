#!/usr/bin/env python3
"""
Generate demo traffic to test the IDS system
This script simulates various types of attacks and normal traffic
"""

# import requests
# import time
# import random
# from datetime import datetime

# #BASE_URL = "http://localhost:5000"

# # Color codes for terminal output
# GREEN = "\033[92m"
# RED = "\033[91m"
# YELLOW = "\033[93m"
# BLUE = "\033[94m"
# RESET = "\033[0m"

# # Demo scenarios - Normal legitimate traffic
# NORMAL_REQUESTS = [
#     {"method": "GET", "path": "/"},
#     {"method": "GET", "path": "/test/normal"},
#     {"method": "GET", "path": "/health"},
#     {"method": "GET", "path": "/home"},
#     {"method": "GET", "path": "/about"},
#     {"method": "GET", "path": "/contact"},
#     {"method": "GET", "path": "/api/products"},
#     {"method": "GET", "path": "/api/users/profile"},
#     {"method": "POST", "path": "/api/test", "data": {"test": "data"}},
# ]

# # SQL Injection attacks
# SQL_INJECTION_REQUESTS = [
#     {"method": "GET", "path": "/api/users?id=1' OR '1'='1"},
#     {"method": "GET", "path": "/login?user=admin' --"},
#     {"method": "GET", "path": "/search?q=1' UNION SELECT NULL--"},
#     {"method": "POST", "path": "/search", "data": {"q": "test'; DROP TABLE users;--"}},
#     {"method": "GET", "path": "/api/data?id=1 AND 1=1"},
#     {"method": "GET", "path": "/user?name=admin'/**/OR/**/1=1--"},
#     {"method": "GET", "path": "/product?id=1' UNION SELECT password FROM users--"},
# ]

# # XSS (Cross-Site Scripting) attacks
# XSS_REQUESTS = [
#     {"method": "GET", "path": "/search?q=<script>alert('XSS')</script>"},
#     {"method": "GET", "path": "/profile?name=<img src=x onerror=alert(1)>"},
#     {"method": "GET", "path": "/comment?text=<script>document.location='http://evil.com'</script>"},
#     {"method": "GET", "path": "/user?bio=<iframe src=javascript:alert(1)>"},
#     {"method": "POST", "path": "/post", "data": {"content": "<script>alert(document.cookie)</script>"}},
#     {"method": "GET", "path": "/page?param=<svg/onload=alert(1)>"},
# ]

# # Path Traversal attacks
# PATH_TRAVERSAL_REQUESTS = [
#     {"method": "GET", "path": "/files/../../etc/passwd"},
#     {"method": "GET", "path": "/download?file=../../../etc/shadow"},
#     {"method": "GET", "path": "/view?page=../../../../var/www/config.php"},
#     {"method": "GET", "path": "/image?file=..\\..\\..\\windows\\system32\\config\\sam"},
#     {"method": "GET", "path": "/read?path=../../../../../../etc/hosts"},
# ]

# # Admin/Sensitive path access
# ADMIN_PATH_REQUESTS = [
#     {"method": "GET", "path": "/admin/users"},
#     {"method": "GET", "path": "/admin/config"},
#     {"method": "GET", "path": "/admin/dashboard"},
#     {"method": "GET", "path": "/.env"},
#     {"method": "GET", "path": "/config.php"},
#     {"method": "GET", "path": "/.git/config"},
#     {"method": "GET", "path": "/wp-admin/"},
#     {"method": "GET", "path": "/phpmyadmin/"},
#     {"method": "GET", "path": "/administrator/"},
# ]

# # Dangerous file access
# DANGEROUS_FILE_REQUESTS = [
#     {"method": "GET", "path": "/upload/shell.php"},
#     {"method": "GET", "path": "/files/backdoor.jsp"},
#     {"method": "GET", "path": "/scripts/webshell.asp"},
#     {"method": "GET", "path": "/upload/cmd.aspx"},
#     {"method": "POST", "path": "/upload/exploit.php", "data": {"file": "malicious"}},
# ]

# # Command Injection attempts
# COMMAND_INJECTION_REQUESTS = [
#     {"method": "GET", "path": "/ping?host=127.0.0.1|whoami"},
#     {"method": "GET", "path": "/exec?cmd=ls;cat /etc/passwd"},
#     {"method": "GET", "path": "/system?command=`id`"},
#     {"method": "GET", "path": "/run?script=test$(whoami)"},
# ]

# # Combine all suspicious requests
# SUSPICIOUS_REQUESTS = (
#     SQL_INJECTION_REQUESTS +
#     XSS_REQUESTS +
#     PATH_TRAVERSAL_REQUESTS +
#     ADMIN_PATH_REQUESTS +
#     DANGEROUS_FILE_REQUESTS +
#     COMMAND_INJECTION_REQUESTS
# )

# # Scanning user agents (security scanners and bots)
# SCANNER_USER_AGENTS = [
#     "sqlmap/1.0",
#     "nikto/2.1.6",
#     "nmap scripting engine",
#     "masscan/1.0",
#     "ZmEu",
#     "w3af.org",
#     "Arachni/1.5",
# ]

# def send_request(req_type, path, method="GET", data=None, user_agent=None):
#     """Send a request to the server"""
#     headers = {}
#     if user_agent:
#         headers["User-Agent"] = user_agent
#     else:
#         headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
#     try:
#         if method == "GET":
#             response = requests.get(BASE_URL + path, headers=headers, timeout=5)
#         elif method == "POST":
#             response = requests.post(BASE_URL + path, json=data, headers=headers, timeout=5)
#         else:
#             response = requests.request(method, BASE_URL + path, headers=headers, timeout=5)
        
#         # Color coding based on request type and status
#         if req_type == "NORMAL":
#             color = GREEN
#             symbol = "🟢"
#         elif req_type == "SUSPICIOUS":
#             color = RED
#             symbol = "🔴"
#         elif req_type == "ATTACK":
#             color = YELLOW
#             symbol = "🟡"
#         else:
#             color = BLUE
#             symbol = "🔵"
        
#         status_icon = "✓" if response.status_code < 400 else "✗"
        
#         # Truncate long paths for display
#         display_path = path if len(path) <= 60 else path[:57] + "..."
        
#         print(f"{color}{symbol} [{req_type}]{RESET} {status_icon} {method} {display_path} - Status: {response.status_code}")
        
#     except requests.exceptions.RequestException as e:
#         print(f"{RED}✗ [ERROR]{RESET} Failed to send request to {path}: {e}")

# def generate_normal_traffic(count=10):
#     """Generate normal traffic"""
#     print("\n" + "="*60)
#     print(f"{GREEN}🟢 Phase 1: Generating Normal Traffic{RESET}")
#     print("="*60)
    
#     for i in range(count):
#         req = random.choice(NORMAL_REQUESTS)
#         send_request("NORMAL", req["path"], req.get("method", "GET"), req.get("data"))
#         time.sleep(random.uniform(0.1, 0.5))
    
#     print(f"{GREEN}✓ Completed: {count} normal requests{RESET}")

# def generate_suspicious_traffic(count=10):
#     """Generate suspicious traffic"""
#     print("\n" + "="*60)
#     print(f"{RED}🔴 Phase 2: Generating Suspicious Traffic{RESET}")
#     print("="*60)
    
#     for i in range(count):
#         req = random.choice(SUSPICIOUS_REQUESTS)
        
#         # Randomly add scanner user agent to make it more suspicious
#         user_agent = random.choice(SCANNER_USER_AGENTS) if random.random() > 0.5 else None
        
#         send_request("SUSPICIOUS", req["path"], req.get("method", "GET"), req.get("data"), user_agent)
#         time.sleep(random.uniform(0.1, 0.5))
    
#     print(f"{RED}✓ Completed: {count} suspicious requests{RESET}")

# def generate_sql_injection_attack():
#     """Generate SQL injection attack sequence"""
#     print("\n" + "="*60)
#     print(f"{RED}💉 SQL Injection Attack Simulation{RESET}")
#     print("="*60)
    
#     for req in SQL_INJECTION_REQUESTS:
#         send_request("SUSPICIOUS", req["path"], req.get("method", "GET"), req.get("data"))
#         time.sleep(0.3)

# def generate_xss_attack():
#     """Generate XSS attack sequence"""
#     print("\n" + "="*60)
#     print(f"{RED}🎭 Cross-Site Scripting (XSS) Attack Simulation{RESET}")
#     print("="*60)
    
#     for req in XSS_REQUESTS:
#         send_request("SUSPICIOUS", req["path"], req.get("method", "GET"), req.get("data"))
#         time.sleep(0.3)

# def generate_path_traversal_attack():
#     """Generate path traversal attack sequence"""
#     print("\n" + "="*60)
#     print(f"{RED}📁 Path Traversal Attack Simulation{RESET}")
#     print("="*60)
    
#     for req in PATH_TRAVERSAL_REQUESTS:
#         send_request("SUSPICIOUS", req["path"], req.get("method", "GET"))
#         time.sleep(0.3)

# def generate_rate_limit_attack():
#     """Generate rate limit attack"""
#     print("\n" + "="*60)
#     print(f"{YELLOW}⚡ Rate Limit Attack Simulation{RESET}")
#     print("="*60)
#     print("Sending 150 rapid requests...")
    
#     for i in range(150):  # Exceed rate limit
#         if i % 10 == 0:
#             print(f"  Progress: {i}/150 requests sent", end='\r')
#         send_request("ATTACK", "/test/normal", "GET")
#         time.sleep(0.01)  # Very fast requests
    
#     print(f"\n{YELLOW}✓ Completed: 150 rapid requests{RESET}")

# def generate_scanner_activity():
#     """Simulate security scanner activity"""
#     print("\n" + "="*60)
#     print(f"{YELLOW}🔍 Security Scanner Activity Simulation{RESET}")
#     print("="*60)
    
#     scanner_paths = [
#         "/admin/", "/phpinfo.php", "/info.php", "/.git/", 
#         "/backup/", "/temp/", "/test/", "/dev/",
#         "/config/", "/db/", "/database/", "/.env"
#     ]
    
#     scanner_agent = random.choice(SCANNER_USER_AGENTS)
#     print(f"Using scanner: {scanner_agent}")
    
#     for path in scanner_paths:
#         send_request("SUSPICIOUS", path, "GET", user_agent=scanner_agent)
#         time.sleep(0.2)

# def run_demo():
#     """Run complete demo traffic generation"""
#     print("\n" + "="*70)
#     print(f"{BLUE}  🛡️  IDS Demo Traffic Generator{RESET}")
#     print("="*70)
#     print(f"Target: {BASE_URL}")
#     print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
#     print("="*70)
    
#     # Check if server is running
#     try:
#         response = requests.get(BASE_URL + "/health", timeout=5)
#         print(f"{GREEN}✓ Server is running (Status: {response.status_code}){RESET}")
#     except requests.exceptions.RequestException:
#         print(f"{RED}✗ Server is not running!{RESET}")
#         print("\nPlease start the server first:")
#         print(f"  {YELLOW}python app.py{RESET}")
#         return
    
#     # Generate traffic
#     print("\nStarting traffic generation in 3 seconds...")
#     time.sleep(3)
    
#     # Phase 1: Normal traffic
#     generate_normal_traffic(20)
#     time.sleep(2)
    
#     # Phase 2: Mixed traffic
#     print("\n" + "="*60)
#     print(f"{BLUE}🔄 Phase 3: Generating Mixed Traffic{RESET}")
#     print("="*60)
#     for i in range(15):
#         if random.random() > 0.4:
#             req = random.choice(NORMAL_REQUESTS)
#             send_request("NORMAL", req["path"], req.get("method", "GET"))
#         else:
#             req = random.choice(SUSPICIOUS_REQUESTS)
#             send_request("SUSPICIOUS", req["path"], req.get("method", "GET"))
#         time.sleep(random.uniform(0.2, 0.8))
    
#     time.sleep(2)
    
#     # Phase 3: Specific attack simulations
#     generate_sql_injection_attack()
#     time.sleep(1)
    
#     generate_xss_attack()
#     time.sleep(1)
    
#     generate_path_traversal_attack()
#     time.sleep(1)
    
#     # Phase 4: Scanner activity
#     generate_scanner_activity()
#     time.sleep(1)
    
#     # Phase 5: Rate limit attack
#     generate_rate_limit_attack()
    
#     # Summary
#     print("\n" + "="*70)
#     print(f"{GREEN}  ✓ Demo Complete!{RESET}")
#     print("="*70)
#     print("\n📊 Check the dashboard to see detected alerts:")
#     print(f"  {BLUE}{BASE_URL}{RESET}")
#     print("\n📈 Alert Statistics:")
    
#     try:
#         stats = requests.get(BASE_URL + "/api/stats", timeout=5).json()
#         total = stats['alerts']['total_alerts']
#         high = stats['alerts']['by_severity'].get('high', 0)
#         medium = stats['alerts']['by_severity'].get('medium', 0)
#         low = stats['alerts']['by_severity'].get('low', 0)
        
#         print(f"  {BLUE}Total Alerts:{RESET} {total}")
#         print(f"  {RED}High Severity:{RESET} {high}")
#         print(f"  {YELLOW}Medium Severity:{RESET} {medium}")
#         print(f"  {GREEN}Low Severity:{RESET} {low}")
        
#         if total > 0:
#             print(f"\n{GREEN}✓ IDS is working! Threats detected successfully.{RESET}")
#         else:
#             print(f"\n{YELLOW}⚠ No alerts detected. Make sure IDS is configured correctly.{RESET}")
#     except Exception as e:
#         print(f"  {YELLOW}(Could not fetch statistics: {e}){RESET}")
    
#     print("\n" + "="*70 + "\n")

# def show_help():
#     """Show usage help"""
#     print("\n" + "="*70)
#     print("  IDS Demo Traffic Generator - Usage")
#     print("="*70)
#     print("\nUsage: python demo_traffic.py [command]")
#     print("\nCommands:")
#     print(f"  {GREEN}(no arguments){RESET}    - Run complete demo (all phases)")
#     print(f"  {GREEN}normal{RESET}           - Generate only normal traffic (50 requests)")
#     print(f"  {GREEN}suspicious{RESET}       - Generate only suspicious traffic (50 requests)")
#     print(f"  {GREEN}attack{RESET}           - Generate rate limit attack")
#     print(f"  {GREEN}sql{RESET}              - Generate SQL injection attacks")
#     print(f"  {GREEN}xss{RESET}              - Generate XSS attacks")
#     print(f"  {GREEN}traversal{RESET}        - Generate path traversal attacks")
#     print(f"  {GREEN}scanner{RESET}          - Simulate security scanner activity")
#     print(f"  {GREEN}help{RESET}             - Show this help message")
#     print("\nExamples:")
#     print(f"  python demo_traffic.py              # Full demo")
#     print(f"  python demo_traffic.py normal       # Normal traffic only")
#     print(f"  python demo_traffic.py sql          # SQL injection test")
#     print("\n" + "="*70 + "\n")

# if __name__ == "__main__":
#     import sys
    
#     if len(sys.argv) > 1:
#         command = sys.argv[1].lower()
        
#         if command == "normal":
#             generate_normal_traffic(50)
#         elif command == "suspicious":
#             generate_suspicious_traffic(50)
#         elif command == "attack":
#             generate_rate_limit_attack()
#         elif command == "sql":
#             generate_sql_injection_attack()
#         elif command == "xss":
#             generate_xss_attack()
#         elif command == "traversal":
#             generate_path_traversal_attack()
#         elif command == "scanner":
#             generate_scanner_activity()
#         elif command == "help" or command == "-h" or command == "--help":
#             show_help()
#         else:
#             print(f"{RED}Unknown command: {command}{RESET}")
#             show_help()
#     else:
#         run_demo()

#------------------------------option2---------------------------------------------------------------

#!/usr/bin/env python3
"""
Generate demo traffic to test the IDS system
This script simulates various types of attacks and normal traffic
"""
#!/usr/bin/env python3
"""
Generate demo traffic to test the IDS system
This script simulates various types of attacks and normal traffic
"""

# import requests
# import time
# import random
# from datetime import datetime

# BASE_URL = "http://localhost:5000"

# GREEN = "\033[92m"
# RED = "\033[91m"
# YELLOW = "\033[93m"
# BLUE = "\033[94m"
# RESET = "\033[0m"


# class WebAnalyzer:
#     def __init__(self):
#         self.base_url = BASE_URL

#     def run(self):
#         print("\n" + "=" * 70)
#         print(f"{BLUE}🛡️  Web Analyzer Traffic Generator{RESET}")
#         print("=" * 70)

#         self.generate_normal_traffic(20)
#         self.generate_suspicious_traffic(20)

#         print(f"\n{GREEN}✓ Web Analyzer traffic completed{RESET}")
#         print("=" * 70 + "\n")

#     def send_request(self, req_type, path, method="GET", data=None, user_agent=None):
#         headers = {"User-Agent": user_agent or "Mozilla/5.0"}

#         try:
#             if method == "GET":
#                 response = requests.get(self.base_url + path, headers=headers, timeout=5)
#             elif method == "POST":
#                 response = requests.post(self.base_url + path, json=data, headers=headers, timeout=5)
#             else:
#                 response = requests.request(method, self.base_url + path, headers=headers, timeout=5)

#             color = GREEN if req_type == "NORMAL" else RED
#             symbol = "🟢" if req_type == "NORMAL" else "🔴"
#             status_icon = "✓" if response.status_code < 400 else "✗"

#             print(
#                 f"{color}{symbol} [{req_type}]{RESET} "
#                 f"{status_icon} {method} {path} - Status: {response.status_code}"
#             )

#         except requests.exceptions.RequestException as e:
#             print(f"{RED}✗ [ERROR]{RESET} Failed to send request to {path}: {e}")

#     def generate_normal_traffic(self, count):
#         for _ in range(count):
#             req = random.choice(NORMAL_REQUESTS)
#             self.send_request("NORMAL", req["path"], req.get("method"), req.get("data"))
#             time.sleep(random.uniform(0.1, 0.5))

#     def generate_suspicious_traffic(self, count):
#         for _ in range(count):
#             req = random.choice(SUSPICIOUS_REQUESTS)
#             user_agent = random.choice(SCANNER_USER_AGENTS) if random.random() > 0.5 else None
#             self.send_request(
#                 "SUSPICIOUS",
#                 req["path"],
#                 req.get("method"),
#                 req.get("data"),
#                 user_agent,
#             )
#             time.sleep(random.uniform(0.1, 0.5))


# # ================= TRAFFIC DATA (UNCHANGED) =================

# NORMAL_REQUESTS = [
#     {"method": "GET", "path": "/"},
#     {"method": "GET", "path": "/test/normal"},
#     {"method": "GET", "path": "/health"},
#     {"method": "GET", "path": "/home"},
#     {"method": "GET", "path": "/about"},
#     {"method": "GET", "path": "/contact"},
#     {"method": "GET", "path": "/api/products"},
#     {"method": "GET", "path": "/api/users/profile"},
#     {"method": "POST", "path": "/api/test", "data": {"test": "data"}},
# ]

# SQL_INJECTION_REQUESTS = [
#     {"method": "GET", "path": "/api/users?id=1' OR '1'='1"},
#     {"method": "GET", "path": "/login?user=admin' --"},
#     {"method": "GET", "path": "/search?q=1' UNION SELECT NULL--"},
#     {"method": "POST", "path": "/search", "data": {"q": "test'; DROP TABLE users;--"}},
# ]

# XSS_REQUESTS = [
#     {"method": "GET", "path": "/search?q=<script>alert('XSS')</script>"},
#     {"method": "GET", "path": "/profile?name=<img src=x onerror=alert(1)>"},
# ]

# PATH_TRAVERSAL_REQUESTS = [
#     {"method": "GET", "path": "/files/../../etc/passwd"},
# ]

# COMMAND_INJECTION_REQUESTS = [
#     {"method": "GET", "path": "/ping?host=127.0.0.1|whoami"},
# ]

# SUSPICIOUS_REQUESTS = (
#     SQL_INJECTION_REQUESTS
#     + XSS_REQUESTS
#     + PATH_TRAVERSAL_REQUESTS
#     + COMMAND_INJECTION_REQUESTS
# )

# SCANNER_USER_AGENTS = [
#     "sqlmap/1.0",
#     "nikto/2.1.6",
#     "nmap scripting engine",
# ]


# # Standalone execution (optional)
# # if __name__ == "__main__":
# #     WebAnalyzer().run()
#-------------------------------------option3-----------------------------------------------------------------

#!/usr/bin/env python3
"""
Minimal Demo Traffic Generator with IDS Communication
Tests if attacks are detected and shows results
"""

import requests
import time

BASE_URL = "http://localhost:5000"

# Attack tests
ATTACKS = [
    {"name": "SQL Injection 1", "path": "/api/users?id=1' OR '1'='1"},
    {"name": "SQL Injection 2", "path": "/login?user=admin' --"},
    {"name": "XSS Attack 1", "path": "/search?q=<script>alert(1)</script>"},
    {"name": "XSS Attack 2", "path": "/profile?name=<img src=x onerror=alert(1)>"},
    {"name": "Path Traversal", "path": "/files/../../etc/passwd"},
    {"name": "Admin Access", "path": "/admin/config"},
    
    { "name": "Home Page", "path": "/" },
    { "name": "Normal Test Endpoint", "path": "/test/normal" },
    { "name": "Health Check", "path": "/health" },
    { "name": "Home", "path": "/home" },
    { "name": "About Page", "path": "/about" },
    { "name": "Contact Page", "path": "/contact" },
    { "name": "Get Products API", "path": "/api/products" },
    { "name": "User Profile API", "path": "/api/users/profile" },
    { "name": "POST Test API", "path": "/api/test" },

    { "name": "SQL Injection 1", "path": "/api/users?id=1' OR '1'='1" },
    { "name": "SQL Injection 2", "path": "/login?user=admin' --" },
    { "name": "SQL Injection 3", "path": "/search?q=1' UNION SELECT NULL--" },
    { "name": "SQL Injection 4", "path": "/search?q=test'; DROP TABLE users;--" },

    { "name": "XSS Attack 1", "path": "/search?q=<script>alert('XSS')</script>" },
    { "name": "XSS Attack 2", "path": "/profile?name=<img src=x onerror=alert(1)>" },

    { "name": "Path Traversal", "path": "/files/../../etc/passwd" },

    { "name": "Command Injection", "path": "/ping?host=127.0.0.1|whoami" },

    { "name": "Admin Access Attempt", "path": "/admin/config" }


]


def check_if_detected(path):
    """Check if IDS detected the attack"""
    time.sleep(0.3)  # Wait for IDS
    
    try:
        response = requests.get(f"{BASE_URL}/api/alerts/recent?limit=5", timeout=2)
        if response.status_code == 200:
            alerts = response.json()
            for alert in alerts:
                if isinstance(alert, dict) and path in alert.get('path', ''):
                    return alert
    except:
        pass
    return None

def main():
    print("\n" + "="*70)
    print("  IDS ATTACK TEST - Real-time Detection")
    print("="*70)
    print(f"Target: {BASE_URL}\n")
    
    # Check server
    try:
        requests.get(f"{BASE_URL}/health", timeout=3)
        print("✓ Server running\n")
    except:
        print("✗ Server not running! Start with: python app.py\n")
        return
    
    detected = 0
    total = len(ATTACKS)
    
    print("Sending attacks...\n")
    
    for attack in ATTACKS:
        try:
            # Send attack
            response = requests.get(BASE_URL + attack['path'], timeout=5)
            
            print(f"🔴 {attack['name']}")
            print(f"   Path: {attack['path'][:60]}")
            print(f"   Status: {response.status_code}", end="")
            
            # Check detection
            alert = check_if_detected(attack['path'])
            
            if alert:
                detected += 1
                severity = alert.get('severity', 'unknown').upper()
                print(f" | ✓ DETECTED ({severity})")
            else:
                print(" | ✗ Not detected")
            
            print()
            time.sleep(0.8)
            
        except Exception as e:
            print(f"   Error: {e}\n")
    
    # Results
    print("="*70)
    print("RESULTS:")
    print(f"  Total Attacks:  {total}")
    print(f"  Detected:       {detected}")
    print(f"  Missed:         {total - detected}")
    
    if total > 0:
        rate = (detected / total) * 100
        print(f"  Detection Rate: {rate:.1f}%")
        
        if rate >= 80:
            print("  Status: ✓ Excellent!")
        elif rate >= 60:
            print("  Status: ⚠️  Good")
        else:
            print("  Status: ✗ Needs improvement")
    
    print("="*70 + "\n")

if __name__ == "__main__":
    main()