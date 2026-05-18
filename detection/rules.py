from config import Config
from collections import defaultdict
from datetime import datetime, timedelta

class RuleBasedDetector:
    """Rule-based anomaly detection system"""
    
    def __init__(self):
        self.request_counts = defaultdict(list)  # IP -> list of timestamps
        self.blocked_ips = set()
        
    def check_rate_limit(self, ip, timestamp):
        """
        Check if IP exceeds rate limit
        
        Args:
            ip: Client IP address
            timestamp: Request timestamp
        
        Returns:
            (is_suspicious, reason)
        """
        # Add current timestamp
        self.request_counts[ip].append(timestamp)
        
        # Clean old timestamps (keep only last minute)
        cutoff = timestamp - timedelta(minutes=1)
        self.request_counts[ip] = [
            ts for ts in self.request_counts[ip] if ts > cutoff
        ]
        
        # Check rate
        requests_per_minute = len(self.request_counts[ip])
        
        if requests_per_minute > Config.MAX_REQUESTS_PER_MINUTE:
            return True, f"Rate limit exceeded: {requests_per_minute} requests/min"
        
        return False, None
    
    def check_suspicious_path(self, path):
        """
        Check if path is suspicious
        
        Args:
            path: Request path
        
        Returns:
            (is_suspicious, reason)
        """
        path_lower = path.lower()
        
        for suspicious_path in Config.SUSPICIOUS_PATHS:
            if suspicious_path in path_lower:
                return True, f"Suspicious path accessed: {suspicious_path}"
        
        # Check for path traversal
        if '..' in path or '..' in path:
            return True, "Path traversal attempt detected"
        
        # Check for SQL injection patterns
        sql_patterns = ["'", '"', '--', ';', 'union', 'select', 'drop', 'insert']
        if any(pattern in path_lower for pattern in sql_patterns):
            return True, "Potential SQL injection in path"
        
        # Check for XSS patterns
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=']
        if any(pattern in path_lower for pattern in xss_patterns):
            return True, "Potential XSS attack in path"
        
        return False, None
    
    def check_user_agent(self, user_agent):
        """
        Check if user agent is suspicious
        
        Args:
            user_agent: User agent string
        
        Returns:
            (is_suspicious, reason)
        """
        if not user_agent or user_agent.strip() == '':
            return True, "Empty user agent"
        
        user_agent_lower = user_agent.lower()
        
        for suspicious_agent in Config.SUSPICIOUS_USER_AGENTS:
            if suspicious_agent in user_agent_lower:
                return True, f"Suspicious user agent: {suspicious_agent}"
        
        return False, None
    
    def check_method(self, method):
        """
        Check if HTTP method is unusual
        
        Args:
            method: HTTP method
        
        Returns:
            (is_suspicious, reason)
        """
        unusual_methods = ['TRACE', 'CONNECT', 'OPTIONS']
        
        if method in unusual_methods:
            return True, f"Unusual HTTP method: {method}"
        
        return False, None
    
    def check_status_pattern(self, ip, status_codes):
        """
        Check for suspicious status code patterns
        
        Args:
            ip: Client IP
            status_codes: List of recent status codes from this IP
        
        Returns:
            (is_suspicious, reason)
        """
        if len(status_codes) < 5:
            return False, None
        
        # Check for repeated 401/403 (possible brute force)
        auth_errors = sum(1 for code in status_codes[-10:] if code in [401, 403])
        if auth_errors >= 5:
            return True, f"Multiple authentication failures: {auth_errors}"
        
        # Check for scanning pattern (many 404s)
        not_found_errors = sum(1 for code in status_codes[-20:] if code == 404)
        if not_found_errors >= 10:
            return True, f"Possible scanning activity: {not_found_errors} 404 errors"
        
        return False, None
    
    def check_custom_pattern(self, path):
        """
        Check for custom attack patterns
        
        Args:
            path: Request path
        
        Returns:
            (is_suspicious, reason)
        """
        # Block specific file extensions
        dangerous_ext = ['.php', '.jsp', '.asp', '.aspx', '.cgi']
        if any(path.endswith(ext) for ext in dangerous_ext):
            return True, f"Dangerous file type accessed: {path}"
        
        # Block specific keywords
        malicious_keywords = ['malicious', 'exploit', 'payload', 'shellcode']
        path_lower = path.lower()
        for keyword in malicious_keywords:
            if keyword in path_lower:
                return True, f"Malicious keyword detected: {keyword}"
        
        # Check for encoded characters (potential obfuscation)
        if '%00' in path or '%0d%0a' in path.lower():
            return True, "Encoded characters detected (possible obfuscation)"
        
        # Check for command injection patterns
        cmd_patterns = ['|', '&', ';', '`', '$', '(', ')']
        if any(pattern in path for pattern in cmd_patterns):
            # Allow common safe uses
            if not any(safe in path for safe in ['?', '&page=', '&id=']):
                return True, "Potential command injection pattern detected"
        
        return False, None
    
    def analyze_request(self, request_data):
        """
        Analyze a single request using all rules
        
        Args:
            request_data: Dict with keys: ip, path, user_agent, method, timestamp, status
        
        Returns:
            {
                'is_suspicious': bool,
                'reasons': list of reasons,
                'severity': 'low'|'medium'|'high'
            }
        """
        reasons = []
        
        # Parse timestamp
        if isinstance(request_data['timestamp'], str):
            timestamp = datetime.fromisoformat(request_data['timestamp'])
        else:
            timestamp = request_data['timestamp']
        
        # Check rate limit
        is_rate_limited, reason = self.check_rate_limit(
            request_data['ip'], timestamp
        )
        if is_rate_limited:
            reasons.append(reason)
        
        # Check path
        is_suspicious_path, reason = self.check_suspicious_path(
            request_data['path']
        )
        if is_suspicious_path:
            reasons.append(reason)
        
        # Check custom patterns
        is_custom_threat, reason = self.check_custom_pattern(
            request_data['path']
        )
        if is_custom_threat:
            reasons.append(reason)
        
        # Check user agent
        is_suspicious_ua, reason = self.check_user_agent(
            request_data['user_agent']
        )
        if is_suspicious_ua:
            reasons.append(reason)
        
        # Check method
        is_unusual_method, reason = self.check_method(
            request_data['method']
        )
        if is_unusual_method:
            reasons.append(reason)
        
        # Determine severity
        severity = 'low'
        if len(reasons) >= 3:
            severity = 'high'
        elif len(reasons) >= 2:
            severity = 'medium'
        elif len(reasons) == 1:
            # Check specific patterns for severity
            if any('SQL injection' in r or 'XSS' in r or 'command injection' in r for r in reasons):
                severity = 'high'
            elif any('Rate limit' in r or 'Dangerous file type' in r for r in reasons):
                severity = 'medium'
        
        return {
            'is_suspicious': len(reasons) > 0,
            'reasons': reasons,
            'severity': severity
        }
    
    def block_ip(self, ip):
        """Add IP to blocked list"""
        self.blocked_ips.add(ip)
    
    def unblock_ip(self, ip):
        """Remove IP from blocked list"""
        self.blocked_ips.discard(ip)
    
    def is_blocked(self, ip):
        """Check if IP is blocked"""
        return ip in self.blocked_ips