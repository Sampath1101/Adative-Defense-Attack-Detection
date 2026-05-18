import pandas as pd
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from config import Config
from detection.anomaly_detector import AnomalyDetector
from alerts.alert_manager import AlertManager
from alerts.notifier import AlertNotifier
from dashboard.routes import dashboard_bp
from file_analyzer import FileAnalyzer
import logging
from datetime import datetime, timedelta
import os
import traceback
import json
import re
from collections import Counter, defaultdict, deque

# Import the security scanner
try:
    from scanner import WebSecurityScanner
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False
    print("⚠️  Warning: scanner.py not found. Scanner functionality will be disabled.")

# Import network analyzer
try:
    from uploadfileanalysis import NetworkTrafficAnalyzer
    network_analyzer = NetworkTrafficAnalyzer()
    NETWORK_ANALYZER_AVAILABLE = True
except ImportError:
    network_analyzer = None
    NETWORK_ANALYZER_AVAILABLE = False
    print("⚠️  Warning: uploadfileanalysis.py not found. File analysis disabled.")

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'  # CHANGE THIS!

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '1234',
    'database': 'zeroday_nids',
    'charset': 'utf8mb4',
    'port': 3306
}

# File upload configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv', 'txt', 'log', 'json', 'ps1', 'sh', 'bash', 'bat', 'cmd', 'py', 'png', 'jpg', 'jpeg'}

# Create upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Initialize Scanner if available
scanner = None
if SCANNER_AVAILABLE:
    try:
        scanner = WebSecurityScanner()
        logger.info("✅ Security scanner initialized successfully")
    except Exception as e:
        logger.error(f"❌ Failed to initialize scanner: {e}")
        SCANNER_AVAILABLE = False

# Threat tracking (in-memory storage)
recent_threats = deque(maxlen=100)
threat_stats = {
    'total_threats': 0,
    'sql_injection': 0,
    'xss': 0,
    'path_traversal': 0,
    'command_injection': 0,
    'admin_access': 0,
    'other': 0
}

# ============================================================================
# DASHBOARD ACCESS TRACKING - Track dashboard button clicks
# ============================================================================

# In-memory tracking of dashboard clicks (not URL access)
dashboard_click_tracking = {}
DASHBOARD_CLICK_LIMIT = 5
CLICK_WINDOW_MINUTES = 30  # Reset after 30 minutes

def track_dashboard_clicks(user_id, ip_address):
    """
    Track dashboard button clicks for non-admin users
    Returns: (should_redirect, click_count)
    """
    current_time = datetime.now()
    key = f"{user_id}_{ip_address}"
    
    # Initialize or get existing clicks
    if key not in dashboard_click_tracking:
        dashboard_click_tracking[key] = {
            'count': 0,
            'first_click': current_time,
            'last_click': current_time
        }
    
    click_data = dashboard_click_tracking[key]
    
    # Check if click window has expired (30 minutes)
    time_diff = current_time - click_data['first_click']
    if time_diff > timedelta(minutes=CLICK_WINDOW_MINUTES):
        # Reset if outside window
        click_data['count'] = 0
        click_data['first_click'] = current_time
    
    # Increment click count
    click_data['count'] += 1
    click_data['last_click'] = current_time
    
    # Check if should redirect to search
    should_redirect = click_data['count'] >= DASHBOARD_CLICK_LIMIT
    
    if should_redirect:
        logger.warning(
            f"🔄 User {user_id} from {ip_address} clicked dashboard {click_data['count']} times - "
            f"redirecting to search page"
        )
    
    return should_redirect, click_data['count']

# ============================================================================
# USER MODEL & AUTHENTICATION
# ============================================================================

class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role
    
    def is_admin(self):
        return self.role == 'admin'

def row_to_dict(cursor, row):
    """Convert a row tuple to dictionary using cursor description"""
    if not row:
        return None
    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        user_data = row_to_dict(cursor, row)
        cursor.close()
        conn.close()
        
        if user_data:
            return User(
                id=user_data['id'],
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role']
            )
    except Exception as e:
        logger.error(f"Error loading user: {str(e)}")
    return None

# ============================================================================
# DATABASE FUNCTIONS
# ============================================================================

def get_db_connection():
    """Create and return a database connection"""
    try:
        connection = pymysql.connect(**DB_CONFIG)
        return connection
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        raise

def init_database():
    """Initialize database tables"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(30) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                role VARCHAR(20) DEFAULT 'user'
            )
        """)
        
        # Create threat_log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip VARCHAR(45),
                method VARCHAR(10),
                path TEXT,
                threat_type VARCHAR(50),
                severity VARCHAR(20),
                details JSON
            )
        """)
        
        # Create audit log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                action VARCHAR(100),
                details TEXT,
                ip_address VARCHAR(45),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Create scan history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                url TEXT NOT NULL,
                risk_score FLOAT,
                classification VARCHAR(50),
                scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_results TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Check if admin exists
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        if not cursor.fetchone():
            admin_password = generate_password_hash('admin123')
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES (%s, %s, %s, %s)
            """, ('admin', 'admin@example.com', admin_password, 'admin'))
            logger.info("✅ Default admin user created")
        
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("✅ Database initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")
        return False

def log_audit(user_id, action, details, ip_address):
    """Log user actions to audit log"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, %s, %s, %s)
        """, (user_id, action, details, ip_address))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        logger.error(f"Audit log error: {str(e)}")

def save_scan_result(user_id, url, result):
    """Save scan results to database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_history (user_id, url, risk_score, classification, scan_results)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, url, result.get('risk_score'), result.get('classification'), json.dumps(result)))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        logger.error(f"Error saving scan result: {str(e)}")

def save_threat_to_db(threat_data):
    """Save threat to database"""
    try:
        print(f"[DEBUG] save_threat_to_db() called")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        timestamp = threat_data.get('timestamp', datetime.now().isoformat())
        ip = threat_data.get('ip', 'unknown')
        method = threat_data.get('method', 'GET')
        path = threat_data.get('path', '/')
        
        threat_type = threat_data.get('threat_type')
        if isinstance(threat_type, list):
            threat_type = threat_type[0] if threat_type else 'unknown'
        elif not threat_type:
            threat_type = 'unknown'
        
        severity = threat_data.get('severity', 'medium')
        details = json.dumps({
            'user_agent': threat_data.get('user_agent', 'Unknown'),
            'all_threats': threat_data.get('all_threats', []),
            'payload': threat_data.get('payload', path)
        })
        
        cursor.execute("""
            INSERT INTO threat_log (timestamp, ip, method, path, threat_type, severity, details)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (timestamp, ip, method, path, threat_type, severity, details))
        
        conn.commit()
        threat_id = cursor.lastrowid
        
        cursor.close()
        conn.close()
        
        print(f"[DEBUG] ✅ Threat saved successfully! ID: {threat_id}")
        return True
        
    except Exception as e:
        print(f"[DEBUG] ❌ Failed to save threat: {e}")
        traceback.print_exc()
        return False

def log_threat(threat_data):
    """Log detected threat"""
    global threat_stats
    
    recent_threats.append(threat_data)
    threat_stats['total_threats'] += 1
    
    threat_type = threat_data.get('threat_type')
    if isinstance(threat_type, list):
        threat_type = threat_type[0] if threat_type else 'other'
    
    if threat_type in threat_stats:
        threat_stats[threat_type] += 1
    else:
        threat_stats['other'] += 1
    
    print("\n" + "="*70)
    print("🚨 THREAT DETECTED!")
    print("="*70)
    print(f"Time:        {threat_data.get('timestamp')}")
    print(f"IP:          {threat_data.get('ip')}")
    print(f"Method:      {threat_data.get('method')}")
    print(f"Path:        {threat_data.get('path')}")
    print(f"Threats:     {threat_data.get('threat_type', 'Unknown')}")
    print(f"Severity:    {threat_data.get('severity', 'Unknown')}")
    print(f"Payload:     {threat_data.get('payload', 'N/A')}")
    print("="*70)
    
    print(f"[DEBUG] Calling save_threat_to_db()...")
    success = save_threat_to_db(threat_data)
    
    if success:
        print(f"[DEBUG] ✅ Threat successfully saved to database")
    else:
        print(f"[DEBUG] ❌ Failed to save threat to database")
    
    print("")

# ============================================================================
# DECORATORS
# ============================================================================

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash('⚠️ Access Denied: Admin privileges required', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ============================================================================
# REQUEST INTERCEPTION AND THREAT DETECTION
# ============================================================================

@app.before_request
def capture():
    """Capture and analyze all requests for threats"""
    # Skip static files
    if request.path.startswith('/static/'):
        return
    
    request_path = request.full_path if request.full_path else request.path
    
    # Define attack patterns
    ATTACK_PATTERNS = {
        'sql_injection': [
            r"(\bUNION\b.*\bSELECT\b)", r"(\bOR\b.*=.*)", 
            r"'.*--", r"1=1", r"admin'--", r"';.*DROP",
            r"' OR '1'='1", r"1' OR '1' = '1"
        ],
        'xss': [
            r"<script", r"javascript:", r"onerror=", 
            r"alert\(", r"<iframe", r"onload="
        ],
        'path_traversal': [
            r"\.\./", r"/etc/passwd", r"c:\\windows", r"%2e%2e/"
        ],
        'command_injection': [
            r"\|whoami", r";whoami", r"`.*`", r"\$\(.*\)", r"bash -c"
        ],
        'admin_access': [
            r"/admin", r"/dashboard", r"/config", r"/panel"
        ]
    }
    
    # Check for threats
    detected_threats = []
    
    for threat_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, request_path, re.IGNORECASE):
                detected_threats.append(threat_type)
                break
    
    # If threats detected, log them
    if detected_threats:
        # Determine severity
        if 'sql_injection' in detected_threats or 'command_injection' in detected_threats:
            severity = 'high'
        elif 'xss' in detected_threats or 'path_traversal' in detected_threats:
            severity = 'high'
        elif 'admin_access' in detected_threats:
            severity = 'medium'
        else:
            severity = 'low'
        
        # Create threat data
        threat_data = {
            'timestamp': datetime.now().isoformat(),
            'ip': request.remote_addr,
            'method': request.method,
            'path': request_path,
            'threat_type': detected_threats[0],
            'all_threats': detected_threats,
            'severity': severity,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'referer': request.headers.get('Referer', 'None'),
            'payload': request_path  # Store the malicious payload
        }
        
        # Log threat
        log_threat(threat_data)

# ============================================================================
# CORS HANDLING
# ============================================================================

@app.after_request
def add_cors(response):
    """Add CORS headers to all responses"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

# ============================================================================
# PUBLIC ROUTES
# ============================================================================

@app.route('/')
def index():
    """Landing page - EVERYONE sees index.html (even after login)"""
    # Always show index.html for everyone
    return render_template('index.html')

@app.route('/home')
def home():
    """Alternative home route - also shows index.html"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if current_user.is_authenticated:
        # After login, redirect to index (home page)
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            data = request.get_json() if request.is_json else request.form
            username = data.get('username')
            password = data.get('password')
            
            if not username or not password:
                if request.is_json:
                    return jsonify({'error': 'Username and password required'}), 400
                flash('Username and password are required', 'danger')
                return render_template('login.html')
            
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            row = cursor.fetchone()
            user_data = row_to_dict(cursor, row)
            cursor.close()
            conn.close()
            
            if not user_data or not check_password_hash(user_data['password_hash'], password):
                if request.is_json:
                    return jsonify({'error': 'Invalid username or password'}), 401
                flash('Invalid username or password', 'danger')
                return render_template('login.html')
            
            user = User(
                id=user_data['id'],
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role']
            )
            login_user(user, remember=True)
            log_audit(user.id, 'login', f'User {username} logged in', request.remote_addr)
            
            # Everyone goes to index after login
            redirect_url = url_for('index')
            
            if request.is_json:
                return jsonify({
                    'success': True,
                    'redirect': redirect_url
                })
            
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(redirect_url)
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            if request.is_json:
                return jsonify({'error': 'An error occurred during login'}), 500
            flash('An error occurred. Please try again.', 'danger')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            data = request.get_json() if request.is_json else request.form
            username = data.get('username', '').strip()
            email = data.get('email', '').strip()
            password = data.get('password')
            confirm_password = data.get('confirm_password')
            
            if not all([username, email, password, confirm_password]):
                error_msg = 'All fields are required'
                if request.is_json:
                    return jsonify({'error': error_msg}), 400
                flash(error_msg, 'danger')
                return render_template('register.html')
            
            if password != confirm_password:
                error_msg = 'Passwords do not match'
                if request.is_json:
                    return jsonify({'error': error_msg}), 400
                flash(error_msg, 'danger')
                return render_template('register.html')
            
            if len(password) < 6:
                error_msg = 'Password must be at least 6 characters'
                if request.is_json:
                    return jsonify({'error': error_msg}), 400
                flash(error_msg, 'danger')
                return render_template('register.html')
            
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
            if cursor.fetchone():
                cursor.close()
                conn.close()
                error_msg = 'Username or email already exists'
                if request.is_json:
                    return jsonify({'error': error_msg}), 400
                flash(error_msg, 'danger')
                return render_template('register.html')
            
            password_hash = generate_password_hash(password)
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES (%s, %s, %s, %s)
            """, (username, email, password_hash, 'user'))
            conn.commit()
            user_id = cursor.lastrowid
            cursor.close()
            conn.close()
            
            log_audit(user_id, 'register', f'New user registered: {username}', request.remote_addr)
            
            if request.is_json:
                return jsonify({
                    'success': True,
                    'redirect': url_for('login')
                })
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            if request.is_json:
                return jsonify({'error': 'An error occurred during registration'}), 500
            flash('An error occurred. Please try again.', 'danger')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    log_audit(current_user.id, 'logout', f'User {current_user.username} logged out', request.remote_addr)
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

# ============================================================================
# PROTECTED ROUTES (Require Login)
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard - Admin gets access, Normal user gets tracked and redirected after 5 clicks"""
    
    # Check if user is admin
    if not current_user.is_admin():
        # Track dashboard button clicks for non-admin users
        should_redirect, click_count = track_dashboard_clicks(
            current_user.id,
            request.remote_addr
        )
        
        # Log the click attempt
        log_audit(
            current_user.id,
            'dashboard_click',
            f"Dashboard click attempt {click_count}/{DASHBOARD_CLICK_LIMIT}",
            request.remote_addr
        )
        
        # Check if should redirect to search
        if should_redirect:
            # User has clicked 5+ times - redirect to search
            flash(
                f'🔍 You have clicked the dashboard button {click_count} times. '
                f'Redirecting you to the search page for better access.',
                'info'
            )
            logger.info(
                f"🔄 User '{current_user.username}' (ID: {current_user.id}) clicked dashboard "
                f"{click_count} times - redirecting to search"
            )
            return redirect(url_for('search_page'))
        else:
            # Still under limit - show access denied
            remaining = DASHBOARD_CLICK_LIMIT - click_count
            flash(
                f'⚠️ ACCESS DENIED: Dashboard is for administrators only. '
                f'Click {remaining} more times to be redirected to search page.',
                'warning'
            )
            logger.warning(
                f"⚠️ Dashboard click {click_count}/{DASHBOARD_CLICK_LIMIT}: "
                f"User '{current_user.username}' (ID: {current_user.id})"
            )
            return redirect(url_for('index'))
    
    # User is admin - allow access
    return render_template('dashboard.html')

@app.route('/status-page')
@login_required
def status_page():
    """Status page"""
    return render_template('status.html')

@app.route('/search')
@login_required
def search_page():
    """Search/Scanner page"""
    return render_template('search.html', scanner_available=SCANNER_AVAILABLE)

# ============================================================================
# DASHBOARD API ENDPOINTS (Admin Only)
# ============================================================================

@app.route('/api/dashboard/full-stats')
@login_required
@admin_required
def api_dashboard_full_stats():
    """Get all dashboard statistics - ADMIN ONLY"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total alerts
        cursor.execute("SELECT COUNT(*) FROM threat_log")
        total_alerts = cursor.fetchone()[0]
        
        # Severity breakdown
        cursor.execute("SELECT severity, COUNT(*) FROM threat_log GROUP BY severity")
        severity_results = cursor.fetchall()
        severity_data = {'high': 0, 'medium': 0, 'low': 0}
        for row in severity_results:
            if row[0] in severity_data:
                severity_data[row[0]] = row[1]
        
        # Recent alerts (last hour)
        cursor.execute("SELECT COUNT(*) FROM threat_log WHERE timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)")
        recent_alerts = cursor.fetchone()[0]
        
        # Timeline (last 24 hours)
        cursor.execute("""
            SELECT DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00') as hour, severity, COUNT(*) as count
            FROM threat_log WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY hour, severity ORDER BY hour
        """)
        timeline_results = cursor.fetchall()
        timeline_data = {}
        for row in timeline_results:
            hour = str(row[0])
            if hour not in timeline_data:
                timeline_data[hour] = {'high': 0, 'medium': 0, 'low': 0}
            timeline_data[hour][row[1]] = row[2]
        timeline_array = [{'hour': h, 'high': c['high'], 'medium': c['medium'], 'low': c['low']} for h, c in sorted(timeline_data.items())]
        
        # Threat types
        cursor.execute("SELECT threat_type, COUNT(*) FROM threat_log GROUP BY threat_type")
        detection_results = cursor.fetchall()
        detection_data = {row[0] or 'unknown': row[1] for row in detection_results}
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'stats': {
                'total_alerts': total_alerts,
                'high_severity': severity_data['high'],
                'medium_severity': severity_data['medium'],
                'low_severity': severity_data['low'],
                'recent_alerts': recent_alerts
            },
            'timeline': timeline_array,
            'detection_methods': detection_data,
            'severity_distribution': severity_data
        })
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'stats': {'total_alerts': 0, 'high_severity': 0, 'medium_severity': 0, 'low_severity': 0, 'recent_alerts': 0},
            'timeline': [],
            'detection_methods': {},
            'severity_distribution': {'high': 0, 'medium': 0, 'low': 0}
        }), 500

@app.route('/api/threats/recent')
@login_required
@admin_required
def api_threats_recent():
    """Get recent threats - ADMIN ONLY"""
    try:
        limit = request.args.get('limit', 50, type=int)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, ip, method, path, threat_type, severity FROM threat_log ORDER BY timestamp DESC LIMIT %s", (limit,))
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        threats = [{'id': r[0], 'timestamp': str(r[1]), 'ip': r[2], 'method': r[3], 'path': r[4], 'threat_type': r[5], 'severity': r[6]} for r in results]
        return jsonify({'success': True, 'threats': threats})
    except Exception as e:
        logger.error(f"Recent threats error: {e}")
        return jsonify({'success': False, 'threats': []}), 500

# ============================================================================
# SCANNER API ENDPOINTS (All logged-in users)
# ============================================================================

@app.route('/api/scan', methods=['POST', 'OPTIONS'])
@login_required
def api_scan():
    """URL security scanning - accessible to all logged-in users"""
    if request.method == 'OPTIONS':
        return '', 204
    
    if not SCANNER_AVAILABLE or scanner is None:
        return jsonify({'success': False, 'error': 'Security scanner is not available'}), 503
    
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'success': False, 'error': 'URL is required'}), 400
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        logger.info(f"🔗 Scanning: {url}")
        result = scanner.scan(url)
        
        save_scan_result(current_user.id, url, result)
        log_audit(current_user.id, 'url_scan', f"Scanned: {url}", request.remote_addr)
        
        return jsonify({'success': True, 'data': result}), 200
        
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': f'Scan failed: {str(e)}'}), 500
    
def analyze_csv_threat_detection(filepath, filename):
    """Direct CSV threat detection"""
    
    BACKDOOR_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 31337, 1337, 12345, 12346, 27374}
    MALICIOUS_IPS = ["45.142.", "185.220.", "103.224."]
    
    try:
        print(f"\n{'='*70}")
        print(f"ANALYZING: {filename}")
        print(f"{'='*70}")
        
        df = pd.read_csv(filepath)
        print(f"✓ Loaded {len(df)} rows")
        print(f"✓ Columns: {list(df.columns)}")
        
        if df.empty:
            return {'success': True, 'is_suspicious': False, 'is_safe': True, 
                   'severity': 'safe', 'threat_level': 'safe', 
                   'reasons': ['Empty file'], 'recommendations': ['File is clean'],
                   'alerts': {'high': 0, 'medium': 0, 'low': 0, 'total': 0}, 
                   'severity_counts': {'high': 0, 'medium': 0, 'low': 0}}
        
        # Find columns
        port_col = next((c for c in ['dport', 'L4_DST_PORT', 'dest_port'] if c in df.columns), None)
        src_col = next((c for c in ['src', 'IPV4_SRC_ADDR', 'source_ip'] if c in df.columns), None)
        dst_col = next((c for c in ['dst', 'IPV4_DST_ADDR', 'dest_ip'] if c in df.columns), None)
        
        print(f"✓ Port column: {port_col}")
        print(f"✓ Source column: {src_col}")
        print(f"✓ Dest column: {dst_col}")
        
        if not port_col:
            return {'success': False, 'error': 'No port column found in CSV'}
        
        threats = []
        backdoor_count = malicious_ip_count = port_scan_count = flood_count = 0
        
        # Detect backdoors
        print(f"\n🔍 Checking for backdoor ports...")
        for idx, row in df.iterrows():
            try:
                port = int(row[port_col])
                if port in BACKDOOR_PORTS:
                    backdoor_count += 1
                    src = row[src_col] if src_col else "Unknown"
                    dst = row[dst_col] if dst_col else "Unknown"
                    msg = f"🚨 BACKDOOR: Port {port} from {src} to {dst}"
                    threats.append(msg)
                    print(f"  DETECTED: {msg}")
            except:
                continue
        
        print(f"✓ Found {backdoor_count} backdoor connections")
        
        # Detect malicious IPs
        print(f"\n🔍 Checking for malicious IPs...")
        if src_col:
            checked_ips = set()
            for idx, row in df.iterrows():
                try:
                    src = str(row[src_col])
                    if src not in checked_ips:
                        checked_ips.add(src)
                        if any(src.startswith(p) for p in MALICIOUS_IPS):
                            malicious_ip_count += 1
                            msg = f"🚨 MALICIOUS IP: {src}"
                            threats.append(msg)
                            print(f"  DETECTED: {msg}")
                except:
                    continue
        
        print(f"✓ Found {malicious_ip_count} malicious IPs")
        
        # Detect port scans
        print(f"\n🔍 Checking for port scans...")
        if src_col and port_col:
            ip_ports = defaultdict(set)
            for idx, row in df.iterrows():
                try:
                    ip_ports[str(row[src_col])].add(int(row[port_col]))
                except:
                    continue
            for ip, ports in ip_ports.items():
                if len(ports) >= 5:
                    port_scan_count += 1
                    msg = f"⚠️ PORT SCAN: {ip} scanned {len(ports)} ports"
                    threats.append(msg)
                    print(f"  DETECTED: {msg}")
        
        print(f"✓ Found {port_scan_count} port scans")
        
        # Detect floods
        print(f"\n🔍 Checking for connection floods...")
        if src_col:
            ip_counts = Counter(str(row[src_col]) for idx, row in df.iterrows() if src_col in row)
            for ip, count in ip_counts.items():
                if count >= 10:
                    flood_count += 1
                    msg = f"🚨 FLOOD: {ip} made {count} connections"
                    threats.append(msg)
                    print(f"  DETECTED: {msg}")
        
        print(f"✓ Found {flood_count} floods")
        
        # Calculate risk
        risk_score = min(100, backdoor_count * 20 + malicious_ip_count * 15 + flood_count * 10 + port_scan_count * 5)
        
        if backdoor_count > 0 or malicious_ip_count > 0:
            threat_level, severity = "critical", "high"
        elif flood_count > 0 or risk_score >= 50:
            threat_level, severity = "high", "high"
        elif port_scan_count > 0 or risk_score >= 20:
            threat_level, severity = "medium", "medium"
        else:
            threat_level, severity = "safe", "safe"
        
        high_sev = backdoor_count + malicious_ip_count + flood_count
        med_sev = port_scan_count
        
        recommendations = []
        if backdoor_count > 0:
            recommendations.extend(["🚨 CRITICAL: Backdoor detected! Investigate immediately!", 
                                   "Block ports: 4444, 5555, 6666, 7777, 8888, 9999, 31337"])
        if malicious_ip_count > 0:
            recommendations.append("🚨 CRITICAL: Malicious IPs detected! Block at firewall")
        if flood_count > 0:
            recommendations.append("⚠️ Connection flooding - Enable rate limiting")
        if not recommendations:
            recommendations.append("✅ No critical threats detected")
        
        print(f"\n{'='*70}")
        print(f"FINAL RESULTS:")
        print(f"  Threat Level: {threat_level.upper()}")
        print(f"  Risk Score: {risk_score}/100")
        print(f"  Total Threats: {len(threats)}")
        print(f"  High Alerts: {high_sev}")
        print(f"  Medium Alerts: {med_sev}")
        print(f"{'='*70}\n")
        
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
                'total_entries': len(df),
                'suspicious_entries': len(threats),
                'threat_percentage': round((len(threats) / len(df) * 100) if len(df) > 0 else 0, 2),
                'risk_score': risk_score,
                'statistics': {
                    'backdoor_ports': backdoor_count,
                    'malicious_ips': malicious_ip_count,
                    'connection_floods': flood_count,
                    'port_scans': port_scan_count,
                    'network_scans': 0,
                    'suspicious_ports': 0
                },
                'severity_breakdown': {'high': high_sev, 'medium': med_sev, 'low': 0}
            },
            'severity_counts': {'high': high_sev, 'medium': med_sev, 'low': 0},
            'alerts': {'high': high_sev, 'medium': med_sev, 'low': 0, 'total': high_sev + med_sev},
            'reasons': threats[:10] if threats else ["No threats detected"],
            'recommendations': recommendations,
            'threats_detected': [{'message': t} for t in threats[:50]]
        }
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return {'success': False, 'error': f'Analysis failed: {str(e)}'}

# @app.route('/api/upload-analyze', methods=['POST', 'OPTIONS'])
# @login_required
# def upload_analyze():
#     """File upload and analysis endpoint"""
#     if request.method == 'OPTIONS':
#         return '', 204
    
#     try:
#         if 'file' not in request.files:
#             return jsonify({'success': False, 'error': 'No file provided'}), 400
        
#         file = request.files['file']
        
#         if file.filename == '':
#             return jsonify({'success': False, 'error': 'No file selected'}), 400
        
#         if not allowed_file(file.filename):
#             return jsonify({'success': False, 'error': f'File type not allowed'}), 400
        
#         filename = secure_filename(file.filename)
#         file_extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        
#         timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
#         unique_filename = f"{timestamp}_{filename}"
#         filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
#         file.save(filepath)
#         logger.info(f"📁 File saved: {filepath}")
        
#         if file_extension == 'csv' and NETWORK_ANALYZER_AVAILABLE:
#             try:
#                 logger.info(f"🔍 Analyzing CSV file: {filename}")
#                 analysis_result = network_analyzer.analyze_file(filepath, filename)
                
#                 severity_counts = {'high': 0, 'medium': 0, 'low': 0}
#                 stats = analysis_result['statistics']
                
#                 if stats.get('backdoor_ports', 0) > 0:
#                     severity_counts['high'] += stats['backdoor_ports']
#                 if stats.get('connection_floods', 0) > 0:
#                     severity_counts['high'] += stats['connection_floods']
#                 if stats.get('port_scans', 0) > 0:
#                     severity_counts['medium'] += stats['port_scans']
#                 if stats.get('network_scans', 0) > 0:
#                     severity_counts['medium'] += stats['network_scans']
#                 if stats.get('suspicious_ports', 0) > 0:
#                     severity_counts['low'] += stats['suspicious_ports']
                
#                 overall_severity = 'safe'
#                 if severity_counts['high'] > 0:
#                     overall_severity = 'high'
#                 elif severity_counts['medium'] > 0:
#                     overall_severity = 'medium'
#                 elif severity_counts['low'] > 0:
#                     overall_severity = 'low'
                
#                 response = {
#                     'success': True,
#                     'is_suspicious': analysis_result['threat_level'] != 'safe',
#                     'is_safe': analysis_result['threat_level'] == 'safe',
#                     'severity': overall_severity,
#                     'threat_level': analysis_result['threat_level'],
#                     'confidence': min(analysis_result['risk_score'] / 5.0, 1.0),
#                     'detection_method': 'network_traffic_analysis',
#                     'filename': filename,
#                     'file_type': 'csv',
#                     'analysis': {
#                         'total_entries': analysis_result['total_entries'],
#                         'suspicious_entries': analysis_result['suspicious_entries'],
#                         'threat_percentage': analysis_result['threat_percentage'],
#                         'risk_score': analysis_result['risk_score'],
#                         'statistics': analysis_result['statistics'],
#                         'severity_breakdown': severity_counts
#                     },
#                     'severity_counts': severity_counts,
#                     'alerts': {
#                         'high': severity_counts['high'],
#                         'medium': severity_counts['medium'],
#                         'low': severity_counts['low'],
#                         'total': sum(severity_counts.values())
#                     },
#                     'reasons': [threat['data'] for threat in analysis_result['threats_found'][:10]],
#                     'recommendations': analysis_result['recommendations'],
#                     'threats_detected': analysis_result['threats_found']
#                 }
                
#                 log_audit(current_user.id, 'file_analysis', f"CSV: {filename} - {overall_severity.upper()}", request.remote_addr)
                
#             except Exception as e:
#                 logger.error(f"❌ CSV analysis error: {str(e)}")
#                 traceback.print_exc()
#                 response = {'success': False, 'error': f'Analysis failed: {str(e)}'}
        
#         elif file_extension in ['png', 'jpg', 'jpeg']:
#             response = {
#                 'success': True,
#                 'is_suspicious': False,
#                 'is_safe': True,
#                 'severity': 'info',
#                 'confidence': 0.5,
#                 'detection_method': 'image_analysis',
#                 'filename': filename,
#                 'file_type': 'image',
#                 'alerts': {'high': 0, 'medium': 0, 'low': 0, 'total': 0},
#                 'reasons': ['Image analysis not yet implemented'],
#                 'recommendations': ['Visual inspection recommended']
#             }
        
#         elif file_extension in ['txt', 'log']:
#             response = {
#                 'success': True,
#                 'is_suspicious': False,
#                 'is_safe': True,
#                 'severity': 'info',
#                 'confidence': 0.5,
#                 'detection_method': 'text_analysis',
#                 'filename': filename,
#                 'file_type': 'text',
#                 'alerts': {'high': 0, 'medium': 0, 'low': 0, 'total': 0},
#                 'reasons': ['Text analysis not yet implemented'],
#                 'recommendations': ['Manual review recommended']
#             }
        
#         elif file_extension in ['ps1', 'sh', 'bash', 'bat', 'cmd', 'py']:
#             response = {
#                 'success': True,
#                 'is_suspicious': False,
#                 'is_safe': True,
#                 'severity': 'warning',
#                 'confidence': 0.5,
#                 'detection_method': 'script_analysis',
#                 'filename': filename,
#                 'file_type': 'script',
#                 'alerts': {'high': 0, 'medium': 1, 'low': 0, 'total': 1},
#                 'reasons': ['Script analysis not yet implemented'],
#                 'recommendations': ['Manual code review strongly recommended']
#             }
        
#         else:
#             response = {'success': False, 'error': 'File type not supported for analysis'}
        
#         try:
#             if os.path.exists(filepath):
#                 os.remove(filepath)
#         except:
#             pass
        
#         return jsonify(response), 200
        
#     except Exception as e:
#         logger.error(f"❌ Upload/analysis error: {str(e)}")
#         traceback.print_exc()
#         return jsonify({'success': False, 'error': f'Upload failed: {str(e)}'}), 500
@app.route('/api/upload-analyze', methods=['POST', 'OPTIONS'])
@login_required
def upload_analyze():
    """File upload and analysis endpoint - FIXED VERSION"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        # Validate file upload
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'error': f'File type not allowed'}), 400
        
        # Save file
        filename = secure_filename(file.filename)
        file_extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        file.save(filepath)
        logger.info(f"📁 File saved: {filepath}")
        
        # ========================================================================
        # CSV FILE ANALYSIS - USES BUILT-IN analyze_csv_threat_detection()
        # ========================================================================
        if file_extension == 'csv':
            try:
                logger.info(f"🔍 Analyzing CSV file: {filename}")
                
                # Call the analyzer function that's already in your app.py (line ~1113)
                response = analyze_csv_threat_detection(filepath, filename)
                
                # Log the result
                if response.get('success'):
                    threat_level = response.get('threat_level', 'unknown').upper()
                    logger.info(f"✅ Analysis complete: {threat_level}")
                    log_audit(current_user.id, 'file_analysis', 
                             f"CSV: {filename} - {threat_level}", 
                             request.remote_addr)
                else:
                    logger.error(f"❌ Analysis failed: {response.get('error', 'Unknown error')}")
                
            except Exception as e:
                logger.error(f"❌ CSV analysis error: {str(e)}")
                traceback.print_exc()
                response = {
                    'success': False,
                    'error': f'Analysis failed: {str(e)}',
                    'is_suspicious': False,
                    'is_safe': True,
                    'severity': 'error',
                    'alerts': {'high': 0, 'medium': 0, 'low': 0, 'total': 0},
                    'severity_counts': {'high': 0, 'medium': 0, 'low': 0},
                    'reasons': [f'Error: {str(e)}'],
                    'recommendations': ['Check file format and try again']
                }
        
        # ========================================================================
        # IMAGE FILE ANALYSIS (Placeholder)
        # ========================================================================
        elif file_extension in ['png', 'jpg', 'jpeg']:
            response = {
                'success': True,
                'is_suspicious': False,
                'is_safe': True,
                'severity': 'info',
                'threat_level': 'info',
                'confidence': 0.5,
                'detection_method': 'image_analysis',
                'filename': filename,
                'file_type': 'image',
                'alerts': {'high': 0, 'medium': 0, 'low': 0, 'total': 0},
                'severity_counts': {'high': 0, 'medium': 0, 'low': 0},
                'reasons': ['Image analysis not yet implemented'],
                'recommendations': ['Visual inspection recommended']
            }
        
        # ========================================================================
        # TEXT/LOG FILE ANALYSIS (Placeholder)
        # ========================================================================
        elif file_extension in ['txt', 'log']:
            response = {
                'success': True,
                'is_suspicious': False,
                'is_safe': True,
                'severity': 'info',
                'threat_level': 'info',
                'confidence': 0.5,
                'detection_method': 'text_analysis',
                'filename': filename,
                'file_type': 'text',
                'alerts': {'high': 0, 'medium': 0, 'low': 0, 'total': 0},
                'severity_counts': {'high': 0, 'medium': 0, 'low': 0},
                'reasons': ['Text analysis not yet implemented'],
                'recommendations': ['Manual review recommended']
            }
        
        # ========================================================================
        # SCRIPT FILE ANALYSIS (Placeholder)
        # ========================================================================
        elif file_extension in ['ps1', 'sh', 'bash', 'bat', 'cmd', 'py']:
            response = {
                'success': True,
                'is_suspicious': True,
                'is_safe': False,
                'severity': 'warning',
                'threat_level': 'warning',
                'confidence': 0.5,
                'detection_method': 'script_analysis',
                'filename': filename,
                'file_type': 'script',
                'alerts': {'high': 0, 'medium': 1, 'low': 0, 'total': 1},
                'severity_counts': {'high': 0, 'medium': 1, 'low': 0},
                'reasons': ['Script files can execute code', 'Manual review required'],
                'recommendations': [
                    'Review script code before execution',
                    'Check for suspicious commands',
                    'Run in isolated environment if testing'
                ]
            }
        
        # ========================================================================
        # UNSUPPORTED FILE TYPE
        # ========================================================================
        else:
            response = {
                'success': False,
                'error': f'File type .{file_extension} not supported for analysis',
                'is_suspicious': False,
                'is_safe': True,
                'severity': 'info',
                'alerts': {'high': 0, 'medium': 0, 'low': 0, 'total': 0},
                'severity_counts': {'high': 0, 'medium': 0, 'low': 0}
            }
        
        # ========================================================================
        # CLEANUP: Remove uploaded file
        # ========================================================================
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                logger.info(f"🗑️ Cleaned up: {filepath}")
        except Exception as cleanup_error:
            logger.warning(f"⚠️ Cleanup failed: {str(cleanup_error)}")
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"❌ Upload/analysis error: {str(e)}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': f'Upload failed: {str(e)}',
            'is_suspicious': False,
            'is_safe': True,
            'severity': 'error',
            'alerts': {'high': 0, 'medium': 0, 'low': 0, 'total': 0},
            'severity_counts': {'high': 0, 'medium': 0, 'low': 0}
        }), 500


@app.route('/api/stats', methods=['GET', 'OPTIONS'])
def api_stats():
    """Statistics API"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM threat_log")
        total_alerts = cursor.fetchone()[0]
        
        cursor.execute("SELECT severity, COUNT(*) as count FROM threat_log GROUP BY severity")
        severity_results = cursor.fetchall()
        by_severity = {'high': 0, 'medium': 0, 'low': 0}
        for row in severity_results:
            if row[0] in by_severity:
                by_severity[row[0]] = row[1]
        
        cursor.execute("SELECT COUNT(*) FROM threat_log WHERE timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)")
        recent_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM threat_log WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)")
        last_24h = cursor.fetchone()[0]
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'total_users': 0,
            'admin_users': 0,
            'alerts': {
                'total_alerts': total_alerts,
                'by_severity': by_severity,
                'recent_count': recent_count,
                'last_24h': last_24h
            }
        })
    except Exception as e:
        logger.error(f"Stats API error: {str(e)}")
        return jsonify({
            'alerts': {
                'total_alerts': 0,
                'by_severity': {'high': 0, 'medium': 0, 'low': 0},
                'recent_count': 0,
                'last_24h': 0
            }
        }), 200

@app.route('/api/timeline', methods=['GET', 'OPTIONS'])
def api_timeline():
    """Timeline API - Fixed version"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        hours = request.args.get('hours', 24, type=int)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Step 1: Get actual data from DB
        cursor.execute("""
            SELECT 
                DATE_FORMAT(timestamp, '%%Y-%%m-%%dT%%H:00:00') as hour,
                severity,
                COUNT(*) as count
            FROM threat_log
            WHERE timestamp > DATE_SUB(NOW(), INTERVAL %s HOUR)
            GROUP BY hour, severity
            ORDER BY hour
        """, (hours,))
        
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        
        # Step 2: Build a lookup from DB results
        db_data = {}
        for row in results:
            hour = str(row[0])
            severity = row[1].lower() if row[1] else ''
            count = int(row[2])
            if hour not in db_data:
                db_data[hour] = {'high': 0, 'medium': 0, 'low': 0}
            if severity in db_data[hour]:
                db_data[hour][severity] = count
        
        # Step 3: Generate ALL hours in range (fill gaps with zeros)
        from datetime import datetime, timedelta
        now = datetime.now().replace(minute=0, second=0, microsecond=0)
        start = now - timedelta(hours=hours - 1)
        
        timeline = []
        current = start
        while current <= now:
            hour_key = current.strftime('%Y-%m-%dT%H:00:00')
            data = db_data.get(hour_key, {'high': 0, 'medium': 0, 'low': 0})
            timeline.append({
                'hour': hour_key,           # ISO format for easy JS parsing
                'label': current.strftime('%H:%M'),  # Display label
                'high': data['high'],
                'medium': data['medium'],
                'low': data['low']
            })
            current += timedelta(hours=1)
        
        return jsonify({'timeline': timeline})
        
    except Exception as e:
        logger.error(f"[TIMELINE ERROR] {str(e)}")
        traceback.print_exc()
        return jsonify({'timeline': []}), 200

@app.route('/api/detection-methods', methods=['GET', 'OPTIONS'])
def api_detection_methods():
    """Detection methods API"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT threat_type, COUNT(*) as count FROM threat_log GROUP BY threat_type ORDER BY count DESC")
        
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        
        detection_categories = {'rule': 0, 'ml': 0, 'hybrid': 0}
        
        for row in results:
            threat_type = row[0] if row[0] else 'unknown'
            count = row[1]
            
            if threat_type in ['sql_injection', 'xss', 'path_traversal', 'command_injection', 'lfi', 'rfi']:
                detection_categories['rule'] += count
            elif threat_type in ['anomaly', 'behavioral', 'pattern', 'ml_detection']:
                detection_categories['ml'] += count
            else:
                detection_categories['hybrid'] += count
        
        return jsonify({'detection_methods': detection_categories})
        
    except Exception as e:
        logger.error(f"[DETECTION ERROR] {str(e)}")
        traceback.print_exc()
        return jsonify({'detection_methods': {'rule': 0, 'ml': 0, 'hybrid': 0}}), 200

@app.route('/api/top-ips', methods=['GET', 'OPTIONS'])
def api_top_ips():
    """Top IPs API"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        limit = request.args.get('limit', 5, type=int)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT ip, COUNT(*) as count
            FROM threat_log
            GROUP BY ip
            ORDER BY count DESC
            LIMIT %s
        """, (limit,))
        
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        
        top_ips = [{'ip': row[0], 'count': row[1]} for row in results]
        
        return jsonify({'top_ips': top_ips})
        
    except Exception as e:
        logger.error(f"[TOP_IPS ERROR] {str(e)}")
        traceback.print_exc()
        return jsonify({'top_ips': []}), 200

# @app.route('/api/alerts', methods=['GET', 'OPTIONS'])
# def api_alerts():
#     """Get recent alerts with payload information"""
#     if request.method == 'OPTIONS':
#         return '', 204
    
#     try:
#         limit = request.args.get('limit', 50, type=int)
#         severity_filter = request.args.get('severity', 'all')
        
#         conn = get_db_connection()
#         cursor = conn.cursor()
        
#         if severity_filter and severity_filter != 'all':
#             query = """
#                 SELECT id, timestamp, ip, method, path, threat_type, severity, details
#                 FROM threat_log
#                 WHERE severity = %s
#                 ORDER BY timestamp DESC
#                 LIMIT %s
#             """
#             cursor.execute(query, (severity_filter, limit))
#         else:
#             query = """
#                 SELECT id, timestamp, ip, method, path, threat_type, severity, details
#                 FROM threat_log
#                 ORDER BY timestamp DESC
#                 LIMIT %s
#             """
#             cursor.execute(query, (limit,))
        
#         results = cursor.fetchall()
#         cursor.close()
#         conn.close()
        
#         alerts = []
#         for row in results:
#             # Parse details JSON to get payload
#             details = {}
#             try:
#                 if row[7]:
#                     details = json.loads(row[7])
#             except:
#                 pass
            
#             payload = details.get('payload', row[4])  # Use path if payload not in details
            
#             alerts.append({
#                 'id': row[0],
#                 'timestamp': str(row[1]),
#                 'ip': row[2],
#                 'method': row[3] if row[3] else 'GET',
#                 'path': row[4] if row[4] else '/',
#                 'threat_type': row[5] if row[5] else 'unknown',
#                 'severity': row[6] if row[6] else 'medium',
#                 'payload': payload
#             })
        
#         logger.info(f"✅ [API /api/alerts] Returning {len(alerts)} alerts")
        
#         return jsonify({
#             'success': True,
#             'alerts': alerts,
#             'count': len(alerts)
#         }), 200
        
#     except Exception as e:
#         logger.error(f"❌ [API /api/alerts ERROR] {str(e)}")
#         traceback.print_exc()
#         return jsonify({
#             'success': False,
#             'alerts': [],
#             'count': 0,
#             'error': str(e)
#         }), 500
@app.route('/api/alerts', methods=['GET', 'OPTIONS'])
def api_alerts():
    """Get recent alerts with payload information"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        limit = request.args.get('limit', 50, type=int)
        severity_filter = request.args.get('severity', 'all')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if severity_filter and severity_filter != 'all':
            query = """
                SELECT id, timestamp, ip, method, path, threat_type, severity, details
                FROM threat_log
                WHERE severity = %s
                ORDER BY timestamp DESC
                LIMIT %s
            """
            cursor.execute(query, (severity_filter, limit))
        else:
            query = """
                SELECT id, timestamp, ip, method, path, threat_type, severity, details
                FROM threat_log
                ORDER BY timestamp DESC
                LIMIT %s
            """
            cursor.execute(query, (limit,))
        
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        
        alerts = []
        for row in results:
            # Parse details JSON to get additional information
            details = {}
            try:
                if row[7]:
                    details = json.loads(row[7])
            except:
                pass
            
            # Extract payload from details or use path as fallback
            payload = details.get('payload', row[4])
            
            # Build alert object with all required fields
            alerts.append({
                'id': row[0],
                'timestamp': str(row[1]),
                'ip': row[2],
                'method': row[3] if row[3] else 'GET',
                'path': row[4] if row[4] else '/',
                'threat_type': row[5] if row[5] else 'unknown',
                'severity': row[6] if row[6] else 'medium',
                'payload': payload,
                'detection_method': details.get('detection_method', row[5] if row[5] else 'pattern_match'),
                'confidence': details.get('confidence', 0.85),
                'reasons': details.get('reasons', [f"{row[5]} pattern detected" if row[5] else "Suspicious activity detected"])
            })
        
        logger.info(f"✅ [API /api/alerts] Returning {len(alerts)} alerts")
        
        return jsonify({
            'success': True,
            'alerts': alerts,
            'count': len(alerts)
        }), 200
        
    except Exception as e:
        logger.error(f"❌ [API /api/alerts ERROR] {str(e)}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'alerts': [],
            'count': 0,
            'error': str(e)
        }), 500

@app.route('/api/recent-threats', methods=['GET', 'OPTIONS'])
def api_recent_threats():
    """Alternative endpoint for recent threats"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        limit = request.args.get('limit', 50, type=int)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, timestamp, ip, method, path, threat_type, severity
            FROM threat_log
            ORDER BY timestamp DESC
            LIMIT %s
        """, (limit,))
        
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        
        threats = []
        for row in results:
            threats.append({
                'id': row[0],
                'timestamp': str(row[1]),
                'ip': row[2],
                'method': row[3] if row[3] else 'N/A',
                'path': row[4] if row[4] else '/',
                'threat_type': row[5] if row[5] else 'unknown',
                'severity': row[6] if row[6] else 'medium'
            })
        
        return jsonify({
            'success': True,
            'threats': threats,
            'count': len(threats)
        })
        
    except Exception as e:
        logger.error(f"[RECENT THREATS ERROR] {str(e)}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'threats': [],
            'count': 0
        }), 200

@app.route('/api/scan-history')
@login_required
def api_scan_history():
    """Get user's scan history"""
    try:
        limit = request.args.get('limit', 10, type=int)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT url, risk_score, classification, scan_timestamp
            FROM scan_history WHERE user_id = %s ORDER BY scan_timestamp DESC LIMIT %s
        """, (current_user.id, limit))
        history = []
        for row in cursor.fetchall():
            history.append({'url': row[0], 'risk_score': row[1], 'classification': row[2], 'timestamp': str(row[3])})
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'history': history})
    except Exception as e:
        logger.error(f"Scan history error: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to fetch scan history'}), 500

@app.route('/api/health', methods=['GET', 'OPTIONS'])
def api_health():
    """Health check endpoint"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        cursor.close()
        conn.close()
        db_status = 'connected'
    except:
        db_status = 'disconnected'
    
    return jsonify({
        'status': 'healthy',
        'scanner': 'ready' if SCANNER_AVAILABLE else 'unavailable',
        'database': db_status,
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/api/status', methods=['GET', 'OPTIONS'])
def status_api():
    """System status API"""
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        status_data = {
            'system': 'Running',
            'timestamp': datetime.now().isoformat(),
            'ids': {
                'models_loaded': True,
                'total_samples': 1000,
                'total_detections': 5000,
                'suspicious_count': 150,
                'detection_rate': 0.03
            },
            'scanner': {
                'available': SCANNER_AVAILABLE,
                'status': 'ready' if SCANNER_AVAILABLE else 'unavailable'
            }
        }
        return jsonify(status_data)
    except Exception as e:
        logger.error(f"Status API error: {str(e)}")
        return jsonify({
            'system': 'Running',
            'timestamp': datetime.now().isoformat(),
            'ids': {'models_loaded': False, 'total_samples': 0, 'total_detections': 0, 'suspicious_count': 0, 'detection_rate': 0.0}
        }), 200

@app.route('/health', methods=['GET', 'OPTIONS'])
def health_check():
    """Health check"""
    if request.method == 'OPTIONS':
        return '', 204
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        cursor.close()
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected'
        })
    except Exception as e:
        logger.error(f"Health check error: {str(e)}")
        return jsonify({
            'status': 'degraded',
            'timestamp': datetime.now().isoformat(),
            'database': 'disconnected'
        }), 200

# ============================================================================
# TEST ROUTE
# ============================================================================

@app.route('/test-attacks')
def test_attacks():
    """Test page to generate sample attacks"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Attacks</title>
        <style>
            body { font-family: Arial; padding: 20px; background: #f0f0f0; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            button { padding: 10px 20px; margin: 5px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #5568d3; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🧪 Test Threat Detection</h1>
            <p>Click buttons to trigger different threat types:</p>
            <button onclick="location.href='/test?id=1\\' OR \\'1\\'=\\'1'">SQL Injection</button>
            <button onclick="location.href='/test?q=<script>alert(1)</script>'">XSS Attack</button>
            <button onclick="location.href='/files/../../etc/passwd'">Path Traversal</button>
            <button onclick="location.href='/admin/config'">Admin Access</button>
            <button onclick="location.href='/api/user?id=5 UNION SELECT password FROM users--'">SQL Union</button>
            <br><br>
            <p><strong>Note:</strong> All malicious payloads will be detected, logged to database, and shown in the dashboard!</p>
            <br>
            <a href="/">← Back to Home</a>
        </div>
    </body>
    </html>
    """
    return html

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return redirect(url_for('index'))

@app.errorhandler(403)
def forbidden(e):
    flash('Access denied', 'danger')
    return redirect(url_for('index'))

# ============================================================================
# APPLICATION STARTUP
# ============================================================================

def print_startup_info():
    """Print startup information"""
    logger.info("=" * 80)
    logger.info("🚀 INTEGRATED SECURITY SCANNER APPLICATION")
    logger.info("=" * 80)
    logger.info("")
    logger.info(f"🔐 Authentication: ✅ Active")
    logger.info(f"🔍 Scanner: {'✅ Active' if SCANNER_AVAILABLE else '❌ Unavailable'}")
    logger.info(f"📁 File Analysis: {'✅ Active' if NETWORK_ANALYZER_AVAILABLE else '❌ Unavailable'}")
    logger.info(f"🛡️  Payload Detection: ✅ Active (logs malicious URLs)")
    logger.info(f"🔄 Dashboard Clicks: ✅ Tracking (5-click redirect to search)")
    logger.info("")
    logger.info("=" * 80)
    logger.info("🌐 ROUTES:")
    logger.info("=" * 80)
    logger.info("  • Home:        http://127.0.0.1:5000/ (everyone sees index.html)")
    logger.info("  • Login:       http://127.0.0.1:5000/login (public)")
    logger.info("  • Register:    http://127.0.0.1:5000/register (public)")
    logger.info("  • Scanner:     http://127.0.0.1:5000/search (all users)")
    logger.info("  • Dashboard:   http://127.0.0.1:5000/dashboard (admin only)")
    logger.info("  • Status:      http://127.0.0.1:5000/status-page (all users)")
    logger.info("  • Test:        http://127.0.0.1:5000/test-attacks (public)")
    logger.info("")
    logger.info("=" * 80)
    logger.info("👤 DEFAULT ADMIN:")
    logger.info("=" * 80)
    logger.info("  Username: admin")
    logger.info("  Password: admin123")
    logger.info("")
    logger.info("=" * 80)
    logger.info("✅ NEW FEATURES:")
    logger.info("=" * 80)
    logger.info("  • Everyone sees index.html as home page (even after login)")
    logger.info("  • Normal users can access all pages EXCEPT dashboard")
    logger.info("  • Dashboard clicks tracked: 5 clicks → redirect to /search")
    logger.info("  • Malicious payloads detected and logged (SQL, XSS, etc)")
    logger.info("  • Payloads visible in dashboard Recent Alerts")
    logger.info("=" * 80)

if __name__ == '__main__':
    if init_database():
        print_startup_info()
        
        try:
            app.run(
                host='127.0.0.1',
                port=5000,
                debug=True,
                use_reloader=False
            )
        except KeyboardInterrupt:
            logger.info("\n\n👋 Server stopped")
        except Exception as e:
            logger.error(f"\n\n❌ Server error: {e}")
            traceback.print_exc()
    else:
        logger.error("❌ Failed to initialize database")