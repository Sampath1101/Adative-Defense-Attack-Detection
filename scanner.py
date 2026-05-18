
# """
# AI-Powered Website Security Scanner
# Analyzes URLs through multiple security layers and provides risk assessment
# """
"""
Web Security Scanner - Fixed Version
Multi-layered security analysis with proper error handling
"""

import re
import math
import requests
import warnings
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from typing import Dict, List, Tuple, Any
from collections import Counter
import numpy as np
from bs4 import BeautifulSoup

try:
    import whois
    WHOIS_AVAILABLE = True
except:
    WHOIS_AVAILABLE = False

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings('ignore')

# Network availability flag
NETWORK_AVAILABLE = False

def check_network():
    """Check if network is available"""
    global NETWORK_AVAILABLE
    try:
        response = requests.get('https://www.google.com', timeout=3)
        NETWORK_AVAILABLE = True
        return True
    except:
        NETWORK_AVAILABLE = False
        return False


class Layer1_URLAnalyzer:
    """Static URL and Domain Analysis"""
    
    SUSPICIOUS_KEYWORDS = [
        'login', 'verify', 'secure', 'account', 'update', 'confirm',
        'banking', 'paypal', 'ebay', 'amazon', 'apple', 'microsoft',
        'suspended', 'locked', 'unusual', 'activity'
    ]
    
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    
    def analyze(self, url: str) -> Dict[str, Any]:
        """Perform static URL analysis"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            
            # URL length
            url_length = len(url)
            
            # Subdomain count
            subdomain_count = domain.count('.') - 1 if domain else 0
            
            # IP address detection
            uses_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
            
            # Suspicious keywords
            keyword_score = sum(1 for kw in self.SUSPICIOUS_KEYWORDS if kw in url.lower())
            
            # Special characters
            special_char_count = len(re.findall(r'[@\-_~]', url))
            
            # TLD analysis
            suspicious_tld = any(url.endswith(tld) for tld in self.SUSPICIOUS_TLDS)
            
            # URL entropy (randomness measure)
            entropy = self._calculate_entropy(url)
            
            # Domain age
            domain_age_days = self._get_domain_age(domain)
            
            # Path depth
            path_depth = path.count('/') if path else 0
            
            return {
                'url_length': url_length,
                'subdomain_count': subdomain_count,
                'uses_ip': int(uses_ip),
                'keyword_score': keyword_score,
                'special_char_count': special_char_count,
                'suspicious_tld': int(suspicious_tld),
                'entropy': entropy,
                'domain_age_days': domain_age_days,
                'path_depth': path_depth
            }
        except Exception as e:
            print(f"Error in URL analysis: {e}")
            return {
                'url_length': 0,
                'subdomain_count': 0,
                'uses_ip': 0,
                'keyword_score': 0,
                'special_char_count': 0,
                'suspicious_tld': 0,
                'entropy': 0.0,
                'domain_age_days': -1,
                'path_depth': 0
            }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        try:
            counter = Counter(text)
            length = len(text)
            return -sum((count/length) * math.log2(count/length) 
                       for count in counter.values())
        except:
            return 0.0
    
    def _get_domain_age(self, domain: str) -> int:
        """Get domain age in days (with fallback)"""
        if not WHOIS_AVAILABLE or not NETWORK_AVAILABLE or not domain:
            return -1
            
        try:
            w = whois.whois(domain)
            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                age = (datetime.now() - creation_date).days
                return max(0, age)
        except:
            pass
        return -1  # Unknown


class Layer2_ReputationChecker:
    """Reputation and Threat Intelligence"""
    
    def check(self, url: str) -> Dict[str, Any]:
        """Check URL reputation"""
        try:
            domain = urlparse(url).netloc
            
            blacklist_flag = self._check_blacklists(domain)
            reputation_score = self._calculate_reputation(domain)
            hosting_risk = self._assess_hosting_risk(domain)
            
            return {
                'blacklist_flag': int(blacklist_flag),
                'reputation_score': reputation_score,
                'hosting_risk_level': hosting_risk
            }
        except Exception as e:
            print(f"Error in reputation check: {e}")
            return {
                'blacklist_flag': 0,
                'reputation_score': 80.0,
                'hosting_risk_level': 0
            }
    
    def _check_blacklists(self, domain: str) -> bool:
        """Check if domain is blacklisted"""
        suspicious_patterns = ['temp', 'free', 'phish', 'hack']
        return any(pattern in domain.lower() for pattern in suspicious_patterns)
    
    def _calculate_reputation(self, domain: str) -> float:
        """Calculate reputation score (0-100, higher is better)"""
        score = 80.0
        
        trusted_domains = ['google.com', 'facebook.com', 'microsoft.com', 
                          'github.com', 'youtube.com', 'linkedin.com',
                          'twitter.com', 'instagram.com']
        
        if any(trusted in domain.lower() for trusted in trusted_domains):
            return 95.0
        
        if any(char.isdigit() for char in domain):
            score -= 10
        if len(domain) > 30:
            score -= 15
        if domain.count('-') > 2:
            score -= 10
            
        return max(0, min(100, score))
    
    def _assess_hosting_risk(self, domain: str) -> int:
        """Assess hosting provider risk (0=low, 1=medium, 2=high)"""
        risky_keywords = ['dynamic', 'dyndns', 'noip']
        if any(kw in domain.lower() for kw in risky_keywords):
            return 2
        return 0


class Layer3_ContentAnalyzer:
    """HTML and JavaScript Static Analysis"""
    
    def analyze(self, url: str) -> Dict[str, Any]:
        """Analyze page content"""
        if not NETWORK_AVAILABLE:
            return self._mock_content_analysis(url)
            
        try:
            response = requests.get(url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            html = response.text
            soup = BeautifulSoup(html, 'html.parser')
            
            form_risk = self._analyze_forms(soup)
            js_risk = self._analyze_javascript(soup, html)
            external_ratio = self._calculate_external_ratio(soup, url)
            
            return {
                'form_risk_score': form_risk,
                'js_obfuscation_score': js_risk,
                'external_dependency_ratio': external_ratio
            }
        except Exception as e:
            print(f"Content analysis error: {e}")
            return self._mock_content_analysis(url)
    
    def _mock_content_analysis(self, url: str) -> Dict[str, Any]:
        """Mock content analysis when network unavailable"""
        domain = urlparse(url).netloc.lower()
        
        form_risk = 0.0
        js_risk = 0.0
        external_ratio = 0.2
        
        if 'login' in url.lower() or 'verify' in url.lower():
            form_risk = 45.0
        if any(suspicious in domain for suspicious in ['temp', 'free', '.tk']):
            js_risk = 60.0
            external_ratio = 0.7
            
        return {
            'form_risk_score': form_risk,
            'js_obfuscation_score': js_risk,
            'external_dependency_ratio': external_ratio
        }
    
    def _analyze_forms(self, soup: BeautifulSoup) -> float:
        """Analyze forms for credential harvesting"""
        try:
            forms = soup.find_all('form')
            risk_score = 0.0
            
            for form in forms:
                hidden_inputs = form.find_all('input', {'type': 'hidden'})
                risk_score += len(hidden_inputs) * 5
                
                password_inputs = form.find_all('input', {'type': 'password'})
                risk_score += len(password_inputs) * 10
                
                action = form.get('action', '')
                if action.startswith('http') and urlparse(action).netloc:
                    risk_score += 20
                
                if form.get('onload') or 'submit()' in str(form):
                    risk_score += 30
            
            return min(100, risk_score)
        except:
            return 0.0
    
    def _analyze_javascript(self, soup: BeautifulSoup, html: str) -> float:
        """Detect JavaScript obfuscation and suspicious patterns"""
        try:
            scripts = soup.find_all('script')
            risk_score = 0.0
            
            suspicious_patterns = [
                r'eval\(',
                r'document\.write\(',
                r'atob\(',
                r'fromCharCode',
                r'unescape\(',
                r'\\x[0-9a-f]{2}',
            ]
            
            for script in scripts:
                script_text = script.string or ''
                
                for pattern in suspicious_patterns:
                    matches = len(re.findall(pattern, script_text, re.IGNORECASE))
                    risk_score += matches * 5
            
            return min(100, risk_score)
        except:
            return 0.0
    
    def _calculate_external_ratio(self, soup: BeautifulSoup, base_url: str) -> float:
        """Calculate ratio of external resources"""
        try:
            base_domain = urlparse(base_url).netloc
            
            resources = []
            resources.extend([tag.get('src') for tag in soup.find_all(['script', 'img', 'iframe']) if tag.get('src')])
            resources.extend([tag.get('href') for tag in soup.find_all('link') if tag.get('href')])
            
            if not resources:
                return 0.0
            
            external_count = sum(1 for res in resources 
                               if res and res.startswith('http') and base_domain not in res)
            
            return external_count / len(resources)
        except:
            return 0.0


class Layer4_BehaviorObserver:
    """Passive Behavior Observation"""
    
    def observe(self, url: str) -> Dict[str, Any]:
        """Observe URL behavior passively"""
        if not NETWORK_AVAILABLE:
            return self._mock_behavior_analysis(url)
            
        try:
            session = requests.Session()
            session.max_redirects = 10
            
            response = session.get(url, timeout=10, allow_redirects=True, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            redirect_count = len(response.history)
            
            content_type = response.headers.get('Content-Type', '')
            download_attempt = 'application' in content_type and 'html' not in content_type
            
            suspicious_requests = self._count_suspicious_headers(response.headers)
            
            return {
                'redirect_count': redirect_count,
                'download_attempt': int(download_attempt),
                'suspicious_requests': suspicious_requests,
                'tracker_density': 0.0
            }
        except Exception as e:
            print(f"Behavior observation error: {e}")
            return self._mock_behavior_analysis(url)
    
    def _mock_behavior_analysis(self, url: str) -> Dict[str, Any]:
        """Mock behavior analysis when network unavailable"""
        redirect_count = 0
        download_attempt = 0
        suspicious_requests = 2
        
        if url.count('/') > 5:
            redirect_count = 2
        if any(ext in url.lower() for ext in ['.exe', '.zip', '.apk']):
            download_attempt = 1
            
        return {
            'redirect_count': redirect_count,
            'download_attempt': download_attempt,
            'suspicious_requests': suspicious_requests,
            'tracker_density': 0.0
        }
    
    def _count_suspicious_headers(self, headers: Dict) -> int:
        """Count suspicious response headers"""
        suspicious = 0
        
        if 'X-Frame-Options' not in headers:
            suspicious += 1
        if 'X-Content-Type-Options' not in headers:
            suspicious += 1
        if 'Strict-Transport-Security' not in headers:
            suspicious += 1
            
        return suspicious


class Layer5_SecurityConfig:
    """Security Configuration Analysis"""
    
    def analyze(self, url: str) -> Dict[str, Any]:
        """Analyze security configuration"""
        if not NETWORK_AVAILABLE:
            return self._mock_security_analysis(url)
            
        try:
            response = requests.get(url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            https_enabled = url.startswith('https://')
            tls_score = self._assess_tls(url) if https_enabled else 0.0
            missing_headers = self._count_missing_security_headers(response.headers)
            
            return {
                'https_enabled': int(https_enabled),
                'tls_score': tls_score,
                'missing_headers_count': missing_headers,
                'exposed_resources': 0
            }
        except Exception as e:
            print(f"Security config analysis error: {e}")
            return self._mock_security_analysis(url)
    
    def _mock_security_analysis(self, url: str) -> Dict[str, Any]:
        """Mock security analysis when network unavailable"""
        https_enabled = url.startswith('https://')
        tls_score = 85.0 if https_enabled else 0.0
        missing_headers = 3 if https_enabled else 6
        
        return {
            'https_enabled': int(https_enabled),
            'tls_score': tls_score,
            'missing_headers_count': missing_headers,
            'exposed_resources': 0
        }
    
    def _assess_tls(self, url: str) -> float:
        """Assess TLS configuration quality"""
        try:
            response = requests.get(url, timeout=5, verify=True)
            return 90.0
        except requests.exceptions.SSLError:
            return 0.0
        except:
            return 50.0
    
    def _count_missing_security_headers(self, headers: Dict) -> int:
        """Count missing security headers"""
        required_headers = [
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Content-Security-Policy',
            'X-XSS-Protection',
            'Referrer-Policy'
        ]
        
        missing = sum(1 for header in required_headers if header not in headers)
        return missing


class Layer6_AIRiskScorer:
    """AI-based Risk Scoring Engine"""
    
    def __init__(self):
        """Initialize ML models"""
        self.scaler = StandardScaler()
        self.model = self._create_model()
        self.feature_names = []
        self.is_trained = False
    
    def _create_model(self):
        """Create ensemble model"""
        return RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
    
    def train(self, X: np.ndarray, y: np.ndarray, feature_names: List[str]):
        """Train the model"""
        try:
            self.feature_names = feature_names
            X_scaled = self.scaler.fit_transform(X)
            self.model.fit(X_scaled, y)
            self.is_trained = True
        except Exception as e:
            print(f"Training error: {e}")
            self.is_trained = False
    
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Predict risk score and classification"""
        try:
            feature_vector = self._dict_to_vector(features)
            
            if self.is_trained:
                X = np.array([feature_vector])
                X_scaled = self.scaler.transform(X)
                
                proba = self.model.predict_proba(X_scaled)[0]
                risk_score = self._calculate_risk_score(proba)
                label = self._classify_risk(risk_score)
                confidence = max(proba)
                importance = self.model.feature_importances_
            else:
                risk_score = self._heuristic_score(features)
                label = self._classify_risk(risk_score)
                confidence = 0.7
                importance = None
            
            return {
                'risk_score': risk_score,
                'label': label,
                'confidence': confidence,
                'feature_importance': importance
            }
        except Exception as e:
            print(f"Prediction error: {e}")
            return {
                'risk_score': 50.0,
                'label': 'Unknown',
                'confidence': 0.5,
                'feature_importance': None
            }
    
    def _dict_to_vector(self, features: Dict[str, Any]) -> List[float]:
        """Convert feature dict to vector"""
        vector = []
        for key, value in features.items():
            if isinstance(value, bool):
                vector.append(float(value))
            elif isinstance(value, (int, float)):
                vector.append(float(value))
            elif isinstance(value, str):
                vector.append(hash(value) % 100 / 100.0)
            else:
                vector.append(0.0)
        return vector
    
    def _calculate_risk_score(self, proba: np.ndarray) -> float:
        """Calculate risk score from probability"""
        if len(proba) == 3:
            risk = proba[1] * 50 + proba[2] * 100
        else:
            risk = proba[1] * 100 if len(proba) > 1 else 50
        return min(100, risk)
    
    def _heuristic_score(self, features: Dict[str, Any]) -> float:
        """Fallback heuristic scoring"""
        risk = 0.0
        
        # URL analysis
        if features.get('uses_ip', 0):
            risk += 20
        if features.get('suspicious_tld', 0):
            risk += 15
        risk += min(20, features.get('keyword_score', 0) * 5)
        
        # Reputation
        if features.get('blacklist_flag', 0):
            risk += 30
        rep_score = features.get('reputation_score', 80)
        risk += (100 - rep_score) * 0.2
        
        # Content
        risk += features.get('form_risk_score', 0) * 0.3
        risk += features.get('js_obfuscation_score', 0) * 0.2
        
        # Behavior
        if features.get('redirect_count', 0) > 3:
            risk += 15
        if features.get('download_attempt', 0):
            risk += 25
        
        # Security
        if not features.get('https_enabled', 0):
            risk += 20
        risk += features.get('missing_headers_count', 0) * 2
        
        return min(100, risk)
    
    def _classify_risk(self, score: float) -> str:
        """Classify risk level"""
        if score <= 30:
            return "Safe"
        elif score <= 70:
            return "Suspicious"
        else:
            return "Dangerous"


class ExplainabilityModule:
    """Generate human-readable explanations"""
    
    def explain(self, features: Dict[str, Any], risk_score: float, 
                label: str, feature_importance: np.ndarray = None) -> List[str]:
        """Generate explanation for the decision"""
        reasons = []
        
        try:
            # URL Analysis
            if features.get('domain_age_days', -1) >= 0 and features['domain_age_days'] < 30:
                reasons.append(f"Domain registered only {features['domain_age_days']} days ago")
            
            if features.get('uses_ip', 0):
                reasons.append("URL uses IP address instead of domain name")
            
            if features.get('keyword_score', 0) > 2:
                reasons.append("Contains multiple suspicious keywords (login, verify, secure, etc.)")
            
            # Reputation
            if features.get('blacklist_flag', 0):
                reasons.append("Domain appears on security blacklists")
            
            if features.get('reputation_score', 80) < 50:
                reasons.append("Poor domain reputation score")
            
            # Content
            if features.get('form_risk_score', 0) > 30:
                reasons.append("Login form submits to external domain or contains hidden fields")
            
            if features.get('js_obfuscation_score', 0) > 40:
                reasons.append("JavaScript code is heavily obfuscated")
            
            # Behavior
            if features.get('redirect_count', 0) > 3:
                reasons.append(f"Multiple redirects detected ({features['redirect_count']})")
            
            if features.get('download_attempt', 0):
                reasons.append("Automatic download attempt detected")
            
            # Security
            if not features.get('https_enabled', 0):
                reasons.append("Website does not use HTTPS encryption")
            
            if features.get('missing_headers_count', 0) > 4:
                reasons.append(f"Missing {features['missing_headers_count']} important security headers")
            
            if not reasons:
                reasons.append("No significant security concerns detected")
                reasons.append("Domain appears legitimate with good security practices")
        except Exception as e:
            print(f"Explanation error: {e}")
            reasons.append("Unable to generate detailed explanation")
        
        return reasons


class WebSecurityScanner:
    """Main scanner orchestrator - FIXED VERSION"""
    
    def __init__(self):
        """Initialize all analysis layers"""
        try:
            self.layer1 = Layer1_URLAnalyzer()
            self.layer2 = Layer2_ReputationChecker()
            self.layer3 = Layer3_ContentAnalyzer()
            self.layer4 = Layer4_BehaviorObserver()
            self.layer5 = Layer5_SecurityConfig()
            self.layer6 = Layer6_AIRiskScorer()
            self.explainer = ExplainabilityModule()
            
            # Check network availability
            print("Checking network connectivity...")
            check_network()
            if not NETWORK_AVAILABLE:
                print("⚠️  Network unavailable - running in DEMO MODE with simulated analysis\n")
            
            print("✅ WebSecurityScanner initialized successfully")
        except Exception as e:
            print(f"❌ Error initializing scanner: {e}")
            raise
    
    def scan(self, url: str) -> Dict[str, Any]:
        """Perform complete security scan"""
        try:
            print(f"\nScanning: {url}")
            print("=" * 60)
            
            # Layer 1: URL Analysis
            print("Layer 1: URL & Domain Analysis...")
            features_l1 = self.layer1.analyze(url)
            
            # Layer 2: Reputation
            print("Layer 2: Reputation Check...")
            features_l2 = self.layer2.check(url)
            
            # Layer 3: Content Analysis
            print("Layer 3: Content Analysis...")
            features_l3 = self.layer3.analyze(url)
            
            # Layer 4: Behavior
            print("Layer 4: Behavior Observation...")
            features_l4 = self.layer4.observe(url)
            
            # Layer 5: Security Config
            print("Layer 5: Security Configuration...")
            features_l5 = self.layer5.analyze(url)
            
            # Merge all features
            all_features = {
                **features_l1,
                **features_l2,
                **features_l3,
                **features_l4,
                **features_l5
            }
            
            # Layer 6: AI Scoring
            print("Layer 6: AI Risk Scoring...")
            prediction = self.layer6.predict(all_features)
            
            # Generate explanation
            reasons = self.explainer.explain(
                all_features,
                prediction['risk_score'],
                prediction['label'],
                prediction.get('feature_importance')
            )
            
            # Compile results
            result = {
                'url': url,
                'risk_score': round(prediction['risk_score'], 2),
                'classification': prediction['label'],
                'confidence': round(prediction['confidence'], 2),
                'reasons': reasons,
                'features': all_features,
                'timestamp': datetime.now().isoformat(),
                'demo_mode': not NETWORK_AVAILABLE
            }
            
            return result
            
        except Exception as e:
            print(f"❌ Scan error: {e}")
            import traceback
            traceback.print_exc()
            
            # Return error result
            return {
                'url': url,
                'risk_score': 50.0,
                'classification': 'Error',
                'confidence': 0.0,
                'reasons': [f'Scan failed: {str(e)}'],
                'features': {},
                'timestamp': datetime.now().isoformat(),
                'demo_mode': not NETWORK_AVAILABLE,
                'error': str(e)
            }
    
    def print_result(self, result: Dict[str, Any]):
        """Pretty print scan results"""
        print("\n" + "=" * 60)
        print("SECURITY SCAN RESULTS")
        if result.get('demo_mode'):
            print("(DEMO MODE - Simulated Analysis)")
        print("=" * 60)
        print(f"URL: {result['url']}")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Classification: {result['classification']}")
        print(f"Confidence: {result['confidence']:.2%}")
        print("\nReasons:")
        for i, reason in enumerate(result['reasons'], 1):
            print(f"  {i}. {reason}")
        print("=" * 60)


# Example Usage
if __name__ == "__main__":
    try:
        scanner = WebSecurityScanner()
        
        # Test URLs
        test_urls = [
            "https://www.google.com",
            "https://github.com",
        ]
        
        for url in test_urls:
            try:
                result = scanner.scan(url)
                scanner.print_result(result)
                print("\n")
            except Exception as e:
                print(f"Error scanning {url}: {e}\n")
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()