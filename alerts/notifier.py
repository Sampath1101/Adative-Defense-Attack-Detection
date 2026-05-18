import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import os

class AlertNotifier:
    """Send alert notifications via email and other channels"""
    
    def __init__(self):
        self.email_enabled = False
        self.setup_email()
    
    def setup_email(self):
        """Setup email configuration"""
        self.smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.environ.get('SMTP_PORT', 587))
        self.smtp_username = os.environ.get('SMTP_USERNAME', '')
        self.smtp_password = os.environ.get('SMTP_PASSWORD', '')
        self.from_email = os.environ.get('FROM_EMAIL', 'ids@example.com')
        self.to_email = os.environ.get('ALERT_EMAIL', 'admin@example.com')
        
        # Enable email only if credentials are provided
        if self.smtp_username and self.smtp_password:
            self.email_enabled = True
            print("✓ Email notifications enabled")
        else:
            print("⚠ Email notifications disabled (no credentials)")
    
    def send_alert(self, alert):
        """
        Send alert notification
        
        Args:
            alert: Alert dictionary
        """
        # Log to console
        self.log_to_console(alert)
        
        # Send email if enabled
        if self.email_enabled and alert['severity'] in ['high', 'medium']:
            self.send_email(alert)
    
    def log_to_console(self, alert):
        """Log alert to console"""
        severity_emoji = {
            'low': '🟡',
            'medium': '🟠',
            'high': '🔴'
        }
        
        emoji = severity_emoji.get(alert['severity'], '⚠️')
        
        print(f"\n{emoji} SECURITY ALERT [{alert['severity'].upper()}] {emoji}")
        print(f"  ID: {alert['id']}")
        print(f"  Time: {alert['timestamp']}")
        print(f"  IP: {alert['ip']}")
        print(f"  Path: {alert['path']}")
        print(f"  Method: {alert['method']}")
        print(f"  Detection: {alert['detection_method']} (confidence: {alert['confidence']:.2f})")
        print(f"  Reasons:")
        for reason in alert['reasons']:
            print(f"    • {reason}")
        print()
    
    def send_email(self, alert):
        """Send email notification"""
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[IDS Alert - {alert['severity'].upper()}] Suspicious Activity Detected"
            msg['From'] = self.from_email
            msg['To'] = self.to_email
            
            # Create HTML body
            html_body = self._create_email_html(alert)
            
            # Create plain text body
            text_body = self._create_email_text(alert)
            
            # Attach both versions
            part1 = MIMEText(text_body, 'plain')
            part2 = MIMEText(html_body, 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            print(f"✓ Email alert sent to {self.to_email}")
        
        except Exception as e:
            print(f"✗ Failed to send email alert: {e}")
    
    def _create_email_text(self, alert):
        """Create plain text email body"""
        text = f"""
Security Alert Detected

Severity: {alert['severity'].upper()}
Alert ID: {alert['id']}
Timestamp: {alert['timestamp']}

Request Details:
- IP Address: {alert['ip']}
- Path: {alert['path']}
- Method: {alert['method']}
- User Agent: {alert['user_agent']}
- Status Code: {alert['status']}

Detection Information:
- Method: {alert['detection_method']}
- Confidence: {alert['confidence']:.2%}

Reasons for Alert:
"""
        for reason in alert['reasons']:
            text += f"  • {reason}\n"
        
        if alert.get('ml_scores'):
            text += "\nML Scores:\n"
            for model, score in alert['ml_scores'].items():
                text += f"  • {model}: {score:.2f}\n"
        
        text += """
---
This is an automated security alert from your IDS system.
Please investigate and take appropriate action.
"""
        return text
    
    def _create_email_html(self, alert):
        """Create HTML email body"""
        severity_colors = {
            'low': '#FFA500',
            'medium': '#FF8C00',
            'high': '#FF4500'
        }
        color = severity_colors.get(alert['severity'], '#808080')
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: {color}; color: white; padding: 20px; border-radius: 5px; }}
        .content {{ background-color: #f9f9f9; padding: 20px; margin-top: 20px; border-radius: 5px; }}
        .section {{ margin-bottom: 15px; }}
        .label {{ font-weight: bold; color: #555; }}
        .value {{ color: #333; }}
        ul {{ list-style-type: none; padding-left: 0; }}
        li {{ padding: 5px 0; }}
        .footer {{ margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #777; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🚨 Security Alert Detected</h2>
            <p>Severity: <strong>{alert['severity'].upper()}</strong></p>
        </div>
        
        <div class="content">
            <div class="section">
                <span class="label">Alert ID:</span> <span class="value">{alert['id']}</span><br>
                <span class="label">Timestamp:</span> <span class="value">{alert['timestamp']}</span>
            </div>
            
            <div class="section">
                <h3>Request Details</h3>
                <span class="label">IP Address:</span> <span class="value">{alert['ip']}</span><br>
                <span class="label">Path:</span> <span class="value">{alert['path']}</span><br>
                <span class="label">Method:</span> <span class="value">{alert['method']}</span><br>
                <span class="label">User Agent:</span> <span class="value">{alert['user_agent']}</span><br>
                <span class="label">Status Code:</span> <span class="value">{alert['status']}</span>
            </div>
            
            <div class="section">
                <h3>Detection Information</h3>
                <span class="label">Method:</span> <span class="value">{alert['detection_method']}</span><br>
                <span class="label">Confidence:</span> <span class="value">{alert['confidence']:.2%}</span>
            </div>
            
            <div class="section">
                <h3>Reasons for Alert</h3>
                <ul>
"""
        for reason in alert['reasons']:
            html += f"                    <li>• {reason}</li>\n"
        
        html += """
                </ul>
            </div>
"""
        
        if alert.get('ml_scores'):
            html += """
            <div class="section">
                <h3>ML Model Scores</h3>
                <ul>
"""
            for model, score in alert['ml_scores'].items():
                html += f"                    <li>• {model}: {score:.2f}</li>\n"
            
            html += """
                </ul>
            </div>
"""
        
        html += """
        </div>
        
        <div class="footer">
            <p>This is an automated security alert from your IDS system.</p>
            <p>Please investigate and take appropriate action.</p>
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def send_summary(self, statistics):
        """Send daily/hourly summary of alerts"""
        if not self.email_enabled:
            return
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[IDS Summary] Alert Statistics - {datetime.now().strftime('%Y-%m-%d')}"
            msg['From'] = self.from_email
            msg['To'] = self.to_email
            
            text_body = f"""
IDS Alert Summary

Total Alerts: {statistics['total_alerts']}
Recent (Last Hour): {statistics['recent_count']}

By Severity:
- High: {statistics['by_severity'].get('high', 0)}
- Medium: {statistics['by_severity'].get('medium', 0)}
- Low: {statistics['by_severity'].get('low', 0)}

Top Offending IPs:
"""
            for ip, count in list(statistics['by_ip'].items())[:5]:
                text_body += f"- {ip}: {count} alerts\n"
            
            part = MIMEText(text_body, 'plain')
            msg.attach(part)
            
            # Send
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            print(f"✓ Summary email sent to {self.to_email}")
        
        except Exception as e:
            print(f"✗ Failed to send summary email: {e}")