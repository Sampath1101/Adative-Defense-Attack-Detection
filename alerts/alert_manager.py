from datetime import datetime, timedelta
from collections import deque
import json
import os

class AlertManager:
    """Manage and track security alerts"""
    
    def __init__(self):
        self.alerts = deque(maxlen=1000)  # Store last 1000 alerts
        self.alert_counts = {}  # IP -> count of alerts
        self.alert_history_file = 'data/alert_history.json'
        
        # Rate limiting
        self.recent_alerts = deque(maxlen=100)
        
        # Load historical alerts
        self.load_history()
    
    def create_alert(self, request_data, detection_result):
        """
        Create a new alert
        
        Args:
            request_data: Dict with request information
            detection_result: Result from anomaly detector
        
        Returns:
            alert: Dict with alert information
        """
        # Check rate limiting
        if not self._should_create_alert():
            return None
        
        alert = {
            'id': self._generate_alert_id(),
            'timestamp': datetime.now().isoformat(),
            'ip': request_data.get('ip', 'unknown'),
            'path': request_data.get('path', 'unknown'),
            'method': request_data.get('method', 'unknown'),
            'user_agent': request_data.get('user_agent', 'unknown'),
            'status': request_data.get('status', 0),
            'is_suspicious': detection_result['is_suspicious'],
            'confidence': detection_result['confidence'],
            'detection_method': detection_result['detection_method'],
            'reasons': detection_result['reasons'],
            'severity': detection_result['severity'],
            'ml_scores': detection_result.get('ml_scores', {}),
            'acknowledged': False,
            'notes': ''
        }
        
        # Add to alert queues
        self.alerts.append(alert)
        self.recent_alerts.append(datetime.now())
        
        # Update IP alert count
        ip = alert['ip']
        self.alert_counts[ip] = self.alert_counts.get(ip, 0) + 1
        
        # Save to history
        self.save_alert(alert)
        
        return alert
    
    def _should_create_alert(self):
        """Check if we should create an alert (rate limiting)"""
        from config import Config
        
        now = datetime.now()
        cutoff = now - timedelta(minutes=1)
        
        # Remove old alerts
        while self.recent_alerts and self.recent_alerts[0] < cutoff:
            self.recent_alerts.popleft()
        
        # Check if we're within the rate limit
        return len(self.recent_alerts) < Config.MAX_ALERTS_PER_MINUTE
    
    def _generate_alert_id(self):
        """Generate unique alert ID"""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')
        return f"ALERT-{timestamp}"
    
    def get_alerts(self, limit=100, severity=None, acknowledged=None):
        """
        Get alerts with optional filtering
        
        Args:
            limit: Maximum number of alerts to return
            severity: Filter by severity ('low', 'medium', 'high')
            acknowledged: Filter by acknowledgment status
        
        Returns:
            List of alerts
        """
        alerts = list(self.alerts)
        
        # Apply filters
        if severity:
            alerts = [a for a in alerts if a['severity'] == severity]
        
        if acknowledged is not None:
            alerts = [a for a in alerts if a['acknowledged'] == acknowledged]
        
        # Sort by timestamp (newest first) and limit
        alerts.sort(key=lambda x: x['timestamp'], reverse=True)
        return alerts[:limit]
    
    def get_alert_by_id(self, alert_id):
        """Get a specific alert by ID"""
        for alert in self.alerts:
            if alert['id'] == alert_id:
                return alert
        return None
    
    def acknowledge_alert(self, alert_id, notes=''):
        """Acknowledge an alert"""
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['acknowledged'] = True
                alert['notes'] = notes
                alert['acknowledged_at'] = datetime.now().isoformat()
                self.save_alert(alert)
                return True
        return False
    
    def get_statistics(self):
        """Get alert statistics"""
        if not self.alerts:
            return {
                'total_alerts': 0,
                'by_severity': {},
                'by_ip': {},
                'recent_count': 0
            }
        
        # Count by severity
        severity_counts = {'low': 0, 'medium': 0, 'high': 0}
        for alert in self.alerts:
            severity_counts[alert['severity']] = severity_counts.get(alert['severity'], 0) + 1
        
        # Top IPs
        ip_counts = {}
        for alert in self.alerts:
            ip = alert['ip']
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        # Sort and get top 10
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Recent alerts (last hour)
        now = datetime.now()
        one_hour_ago = now - timedelta(hours=1)
        recent_count = sum(
            1 for alert in self.alerts 
            if datetime.fromisoformat(alert['timestamp']) > one_hour_ago
        )
        
        return {
            'total_alerts': len(self.alerts),
            'by_severity': severity_counts,
            'by_ip': dict(top_ips),
            'recent_count': recent_count,
            'acknowledged_count': sum(1 for a in self.alerts if a.get('acknowledged', False)),
            'unacknowledged_count': sum(1 for a in self.alerts if not a.get('acknowledged', False))
        }
    
    def save_alert(self, alert):
        """Save alert to history file"""
        try:
            # Load existing history
            history = []
            if os.path.exists(self.alert_history_file):
                with open(self.alert_history_file, 'r') as f:
                    history = json.load(f)
            
            # Add new alert
            history.append(alert)
            
            # Keep only last 10000 alerts
            history = history[-10000:]
            
            # Save
            os.makedirs(os.path.dirname(self.alert_history_file), exist_ok=True)
            with open(self.alert_history_file, 'w') as f:
                json.dump(history, f, indent=2)
        
        except Exception as e:
            print(f"⚠ Failed to save alert history: {e}")
    
    def load_history(self):
        """Load alert history from file"""
        try:
            if os.path.exists(self.alert_history_file):
                with open(self.alert_history_file, 'r') as f:
                    history = json.load(f)
                    
                # Load last 1000 alerts into memory
                for alert in history[-1000:]:
                    self.alerts.append(alert)
                    
                print(f"✓ Loaded {len(self.alerts)} alerts from history")
        
        except Exception as e:
            print(f"⚠ Failed to load alert history: {e}")
    
    def clear_old_alerts(self, days=30):
        """Clear alerts older than specified days"""
        cutoff = datetime.now() - timedelta(days=days)
        
        # Filter alerts
        self.alerts = deque(
            [a for a in self.alerts 
             if datetime.fromisoformat(a['timestamp']) > cutoff],
            maxlen=1000
        )
        
        print(f"✓ Cleared alerts older than {days} days")