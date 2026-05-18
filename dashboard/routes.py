from flask import Blueprint, render_template, jsonify, request
from datetime import datetime, timedelta
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

dashboard_bp = Blueprint('dashboard', __name__)

# These will be injected by app.py
alert_manager = None
anomaly_detector = None

@dashboard_bp.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@dashboard_bp.route('/api/stats')
def get_stats():
    """Get system statistics"""
    alert_stats = alert_manager.get_statistics()
    detector_stats = anomaly_detector.get_statistics()
    
    return jsonify({
        'alerts': alert_stats,
        'detector': detector_stats,
        'timestamp': datetime.now().isoformat()
    })

@dashboard_bp.route('/api/alerts')
def get_alerts():
    """Get alerts with filtering"""
    limit = request.args.get('limit', 100, type=int)
    severity = request.args.get('severity', None)
    acknowledged = request.args.get('acknowledged', None)
    
    if acknowledged is not None:
        acknowledged = acknowledged.lower() == 'true'
    
    alerts = alert_manager.get_alerts(
        limit=limit,
        severity=severity,
        acknowledged=acknowledged
    )
    
    return jsonify({
        'alerts': alerts,
        'count': len(alerts)
    })

@dashboard_bp.route('/api/alerts/<alert_id>')
def get_alert_detail(alert_id):
    """Get specific alert details"""
    alert = alert_manager.get_alert_by_id(alert_id)
    
    if alert:
        return jsonify(alert)
    else:
        return jsonify({'error': 'Alert not found'}), 404

@dashboard_bp.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    data = request.get_json() or {}
    notes = data.get('notes', '')
    
    success = alert_manager.acknowledge_alert(alert_id, notes)
    
    if success:
        return jsonify({'success': True, 'message': 'Alert acknowledged'})
    else:
        return jsonify({'success': False, 'error': 'Alert not found'}), 404

@dashboard_bp.route('/api/timeline')
def get_timeline():
    """Get alert timeline data"""
    hours = request.args.get('hours', 24, type=int)
    
    # Get alerts from the last N hours
    cutoff = datetime.now() - timedelta(hours=hours)
    all_alerts = alert_manager.get_alerts(limit=1000)
    
    # Filter by time
    recent_alerts = [
        a for a in all_alerts
        if datetime.fromisoformat(a['timestamp']) > cutoff
    ]
    
    # Group by hour
    timeline = {}
    for alert in recent_alerts:
        hour = datetime.fromisoformat(alert['timestamp']).strftime('%Y-%m-%d %H:00')
        if hour not in timeline:
            timeline[hour] = {'total': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        timeline[hour]['total'] += 1
        timeline[hour][alert['severity']] += 1
    
    # Convert to list and sort
    timeline_list = [
        {'hour': hour, **counts}
        for hour, counts in sorted(timeline.items())
    ]
    
    return jsonify({
        'timeline': timeline_list,
        'hours': hours
    })

@dashboard_bp.route('/api/top-ips')
def get_top_ips():
    """Get top offending IPs"""
    limit = request.args.get('limit', 10, type=int)
    
    stats = alert_manager.get_statistics()
    top_ips = list(stats['by_ip'].items())[:limit]
    
    return jsonify({
        'top_ips': [
            {'ip': ip, 'count': count}
            for ip, count in top_ips
        ]
    })

@dashboard_bp.route('/api/detection-methods')
def get_detection_methods():
    """Get breakdown of detection methods"""
    all_alerts = alert_manager.get_alerts(limit=1000)
    
    methods = {'rule': 0, 'ml': 0, 'hybrid': 0, 'none': 0}
    for alert in all_alerts:
        method = alert.get('detection_method', 'none')
        methods[method] = methods.get(method, 0) + 1
    
    return jsonify({
        'detection_methods': methods
    })