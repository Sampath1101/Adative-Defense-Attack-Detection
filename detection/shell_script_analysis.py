"""
Shell Script Analyzer - Deep Malware Detection
Detects malicious patterns in PowerShell, Bash, CMD, and other scripts
"""

import re
import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class ShellScriptAnalyzer:
    """
    Comprehensive shell script malware detector
    Supports: PowerShell (.ps1), Bash (.sh), CMD (.bat, .cmd), Python (.py)
    """
    
    def __init__(self):
        # PowerShell malicious patterns
        self.powershell_patterns = {
            'obfuscation': [
                r'-enc\s+[A-Za-z0-9+/=]{20,}',  # Encoded commands
                r'FromBase64String',
                r'Convert::ToBase64',
                r'\[char\]\d+',  # Character obfuscation
                r'iex\s*\(',  # Invoke-Expression
                r'Invoke-Expression',
                r'IEX\s+',
                r'&\s*\(\s*[\'"]',  # Ampersand obfuscation
            ],
            'network': [
                r'Net\.WebClient',
                r'DownloadString',
                r'DownloadFile',
                r'Invoke-WebRequest',
                r'wget\s+',
                r'curl\s+',
                r'Start-BitsTransfer',
                r'System\.Net\.Sockets',
            ],
            'persistence': [
                r'New-ScheduledTask',
                r'Register-ScheduledTask',
                r'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                r'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                r'Set-ItemProperty.*Run',
                r'Startup.*\.lnk',
            ],
            'execution': [
                r'Start-Process.*-Hidden',
                r'-WindowStyle\s+Hidden',
                r'-NoProfile',
                r'-NonInteractive',
                r'-ExecutionPolicy\s+Bypass',
                r'powershell.*-enc',
                r'Invoke-Command',
                r'Invoke-Item',
            ],
            'credential_theft': [
                r'mimikatz',
                r'Get-Credential',
                r'ConvertTo-SecureString.*AsPlainText',
                r'Export-Clixml.*credential',
                r'LSASS',
                r'SAM\s+database',
            ],
            'anti_analysis': [
                r'Get-Process.*defender',
                r'Stop-Service.*WinDefend',
                r'Set-MpPreference.*-DisableRealtimeMonitoring',
                r'Add-MpPreference.*-ExclusionPath',
                r'Disable-WindowsOptionalFeature.*Defender',
            ],
            'dangerous_commands': [
                r'Remove-Item.*-Recurse.*-Force',
                r'rd\s+/s\s+/q',
                r'Format-Volume',
                r'Clear-RecycleBin.*-Force',
                r'takeown\s+/f',
                r'icacls.*grant',
            ]
        }
        
        # Bash/Linux malicious patterns
        self.bash_patterns = {
            'obfuscation': [
                r'eval\s*\$\(',
                r'base64\s+-d',
                r'echo\s+.*\|\s*base64',
                r'xxd\s+-r\s+-p',
                r'\$\(printf',
            ],
            'network': [
                r'curl\s+.*\|\s*bash',
                r'wget\s+.*\|\s*sh',
                r'nc\s+-e',
                r'/dev/tcp/',
                r'ncat\s+-e',
                r'socat.*EXEC',
            ],
            'persistence': [
                r'crontab\s+-',
                r'/etc/cron',
                r'\.bashrc',
                r'\.bash_profile',
                r'/etc/rc\.local',
                r'systemctl.*enable',
            ],
            'dangerous_commands': [
                r'rm\s+-rf\s+/',
                r':\(\)\{.*:\|:.*\};:',  # Fork bomb
                r'dd\s+if=/dev/zero\s+of=',
                r'mkfs\.',
                r'chmod\s+777',
                r'chmod\s+-R\s+777',
            ],
            'privilege_escalation': [
                r'sudo\s+-s',
                r'su\s+-',
                r'pkexec',
                r'/etc/passwd',
                r'/etc/shadow',
                r'SUID',
            ],
            'data_exfiltration': [
                r'tar.*\|\s*nc',
                r'tar.*\|\s*curl',
                r'dd.*\|\s*nc',
                r'cat\s+/etc/passwd.*\|',
            ]
        }
        
        # Windows CMD malicious patterns
        self.cmd_patterns = {
            'obfuscation': [
                r'for\s+/f.*delims',
                r'set\s+[a-z]+=.*&.*call',
                r'\^',  # Caret obfuscation
            ],
            'network': [
                r'powershell.*DownloadFile',
                r'certutil.*-urlcache',
                r'bitsadmin\s+/transfer',
            ],
            'execution': [
                r'start\s+/b',
                r'cmd\s+/c\s+start',
                r'mshta\s+',
                r'rundll32\s+',
                r'regsvr32\s+',
            ]
        }
        
        # Suspicious indicators (any script)
        self.universal_indicators = {
            'suspicious_ips': [
                r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',  # Private IPs
                r'\b(?:192\.168\.\d{1,3}\.\d{1,3})\b',
                r'\b(?:172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})\b',
            ],
            'suspicious_domains': [
                r'\.onion\b',
                r'\.bit\b',
                r'pastebin\.com',
                r'paste\.ee',
            ],
            'crypto': [
                r'bitcoin',
                r'wallet',
                r'cryptocurrency',
                r'mining',
                r'stratum\+tcp',
            ]
        }
    
    def analyze(self, filepath, filename):
        """Analyze shell script for malicious patterns"""
        results = {
            'is_suspicious': False,
            'is_safe': True,
            'threat_level': 'safe',
            'confidence': 0.0,
            'risk_score': 0.0,
            'severity': 'low',
            'file_type': 'shell_script',
            'script_type': self._detect_script_type(filename),
            'threats_detected': [],
            'patterns_found': {},
            'reasons': [],
            'recommendations': [],
            'visual_data': {},
            'file_info': {
                'name': filename,
                'size': 0,
                'hash': {}
            }
        }
        
        try:
            # Read file
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Empty file check
            if not content.strip():
                results['reasons'].append("Empty file - no content to analyze")
                results['recommendations'].append("⚠️ Empty script file")
                return results
            
            results['file_info']['size'] = len(content)
            results['file_info']['lines'] = content.count('\n') + 1
            
            # Calculate hashes
            results['file_info']['hash'] = {
                'md5': hashlib.md5(content.encode()).hexdigest(),
                'sha256': hashlib.sha256(content.encode()).hexdigest()
            }
            
            print(f"\n[SCRIPT ANALYZER] Processing: {filename}")
            print(f"[SCRIPT ANALYZER] Type: {results['script_type']}")
            print(f"[SCRIPT ANALYZER] Size: {len(content)} bytes, {results['file_info']['lines']} lines")
            
            # Analyze based on script type
            if results['script_type'] == 'powershell':
                self._analyze_powershell(content, results)
            elif results['script_type'] == 'bash':
                self._analyze_bash(content, results)
            elif results['script_type'] == 'cmd':
                self._analyze_cmd(content, results)
            else:
                self._analyze_generic(content, results)
            
            # Universal checks (for all scripts)
            self._check_universal_indicators(content, results)
            
            # Calculate threat level
            self._calculate_threat_level(results)
            
            # Generate recommendations
            results['recommendations'] = self._generate_recommendations(results)
            
            # Generate visual data
            results['visual_data'] = self._generate_visual_data(results)
            
            print(f"[SCRIPT ANALYZER] Risk Score: {results['risk_score']}")
            print(f"[SCRIPT ANALYZER] Threat Level: {results['threat_level']}")
            print(f"[SCRIPT ANALYZER] Patterns Found: {sum(len(v) for v in results['patterns_found'].values())}")
            
        except Exception as e:
            logger.error(f"Script analysis error: {e}")
            print(f"[SCRIPT ANALYZER ERROR] {e}")
            results['reasons'].append(f"Analysis error: {str(e)}")
        
        return results
    
    def _detect_script_type(self, filename):
        """Detect script type from extension"""
        ext = Path(filename).suffix.lower()
        
        if ext in ['.ps1', '.psm1', '.psd1']:
            return 'powershell'
        elif ext in ['.sh', '.bash', '.zsh']:
            return 'bash'
        elif ext in ['.bat', '.cmd']:
            return 'cmd'
        elif ext in ['.py']:
            return 'python'
        else:
            return 'unknown'
    
    def _analyze_powershell(self, content, results):
        """Analyze PowerShell script"""
        print("[SCRIPT ANALYZER] Running PowerShell pattern analysis...")
        
        for category, patterns in self.powershell_patterns.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, content, re.IGNORECASE)
                if found:
                    for match in found[:3]:  # Limit to 3 examples
                        matches.append({
                            'pattern': pattern,
                            'match': match[:100]  # Limit match length
                        })
                        results['risk_score'] += 0.5
            
            if matches:
                results['patterns_found'][category] = matches
                threat = f"🚨 {category.upper().replace('_', ' ')}: {len(matches)} pattern(s)"
                results['threats_detected'].append(threat)
                results['reasons'].append(threat)
                print(f"  • {threat}")
    
    def _analyze_bash(self, content, results):
        """Analyze Bash script"""
        print("[SCRIPT ANALYZER] Running Bash pattern analysis...")
        
        for category, patterns in self.bash_patterns.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, content, re.IGNORECASE)
                if found:
                    for match in found[:3]:
                        matches.append({
                            'pattern': pattern,
                            'match': match[:100]
                        })
                        results['risk_score'] += 0.5
            
            if matches:
                results['patterns_found'][category] = matches
                threat = f"🚨 {category.upper().replace('_', ' ')}: {len(matches)} pattern(s)"
                results['threats_detected'].append(threat)
                results['reasons'].append(threat)
                print(f"  • {threat}")
    
    def _analyze_cmd(self, content, results):
        """Analyze CMD script"""
        print("[SCRIPT ANALYZER] Running CMD pattern analysis...")
        
        for category, patterns in self.cmd_patterns.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, content, re.IGNORECASE)
                if found:
                    for match in found[:3]:
                        matches.append({
                            'pattern': pattern,
                            'match': match[:100]
                        })
                        results['risk_score'] += 0.5
            
            if matches:
                results['patterns_found'][category] = matches
                threat = f"🚨 {category.upper().replace('_', ' ')}: {len(matches)} pattern(s)"
                results['threats_detected'].append(threat)
                results['reasons'].append(threat)
                print(f"  • {threat}")
    
    def _analyze_generic(self, content, results):
        """Generic script analysis"""
        print("[SCRIPT ANALYZER] Running generic script analysis...")
        
        # Check for common dangerous patterns
        dangerous_patterns = {
            'eval': [r'eval\s*\(', r'exec\s*\('],
            'network': [r'socket\s*\(', r'connect\s*\('],
            'file_operations': [r'unlink\s*\(', r'remove\s*\('],
        }
        
        for category, patterns in dangerous_patterns.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, content, re.IGNORECASE)
                if found:
                    matches.append({'pattern': pattern, 'match': found[0][:100]})
                    results['risk_score'] += 0.3
            
            if matches:
                results['patterns_found'][category] = matches
                threat = f"⚠️ {category.upper()}: {len(matches)} pattern(s)"
                results['threats_detected'].append(threat)
    
    def _check_universal_indicators(self, content, results):
        """Check universal suspicious indicators"""
        for category, patterns in self.universal_indicators.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, content, re.IGNORECASE)
                if found:
                    for match in set(found)[:3]:  # Unique matches, limit 3
                        matches.append({
                            'pattern': category,
                            'match': match
                        })
                        results['risk_score'] += 0.2
            
            if matches:
                if 'universal' not in results['patterns_found']:
                    results['patterns_found']['universal'] = []
                results['patterns_found']['universal'].extend(matches)
                threat = f"⚠️ {category.upper()}: {len(matches)} found"
                results['threats_detected'].append(threat)
    
    def _calculate_threat_level(self, results):
        """Calculate overall threat level"""
        risk = results['risk_score']
        
        if risk >= 3.0:
            results['threat_level'] = 'critical'
            results['severity'] = 'high'
            results['is_suspicious'] = True
            results['is_safe'] = False
            results['confidence'] = 0.95
        elif risk >= 2.0:
            results['threat_level'] = 'high'
            results['severity'] = 'high'
            results['is_suspicious'] = True
            results['is_safe'] = False
            results['confidence'] = 0.85
        elif risk >= 1.0:
            results['threat_level'] = 'medium'
            results['severity'] = 'medium'
            results['is_suspicious'] = True
            results['is_safe'] = False
            results['confidence'] = 0.70
        elif risk >= 0.5:
            results['threat_level'] = 'low'
            results['severity'] = 'low'
            results['is_suspicious'] = True
            results['is_safe'] = False
            results['confidence'] = 0.50
        else:
            results['threat_level'] = 'safe'
            results['severity'] = 'low'
            results['is_suspicious'] = False
            results['is_safe'] = True
            results['confidence'] = 0.30
            results['reasons'] = ["No malicious patterns detected"]
    
    def _generate_recommendations(self, results):
        """Generate security recommendations"""
        recommendations = []
        
        if results['is_safe']:
            recommendations.append("✓ Script appears clean")
            recommendations.append("✓ No malicious patterns detected")
        else:
            recommendations.append("⚠️ DANGEROUS SCRIPT DETECTED")
            recommendations.append("⚠️ DO NOT EXECUTE THIS SCRIPT")
            
            patterns = results['patterns_found']
            
            if any('obfuscation' in k for k in patterns.keys()):
                recommendations.append("⚠️ Script uses obfuscation - typical of malware")
            
            if any('network' in k for k in patterns.keys()):
                recommendations.append("⚠️ Script makes network connections - possible C2 communication")
            
            if any('credential' in k.lower() for k in patterns.keys()):
                recommendations.append("⚠️ CRITICAL: Script attempts credential theft")
            
            if any('persistence' in k for k in patterns.keys()):
                recommendations.append("⚠️ Script creates persistence mechanisms")
            
            if any('dangerous' in k for k in patterns.keys()):
                recommendations.append("⚠️ CRITICAL: Script contains destructive commands")
            
            if results['threat_level'] in ['high', 'critical']:
                recommendations.append("⚠️ Submit to security team for analysis")
                recommendations.append("⚠️ Quarantine or delete this file")
        
        return recommendations
    
    def _generate_visual_data(self, results):
        """Generate visualization data"""
        risk = results['risk_score']
        confidence = results['confidence']
        
        # Risk ratio (0-100%)
        risk_percentage = min((risk / 5.0) * 100, 100)
        safe_percentage = max(100 - risk_percentage, 0)
        
        # Pattern breakdown
        pattern_counts = {}
        for category, matches in results['patterns_found'].items():
            pattern_counts[category] = len(matches)
        
        return {
            'risk_ratio': {
                'safe': round(safe_percentage, 1),
                'at_risk': round(risk_percentage, 1)
            },
            'confidence': round(confidence * 100, 1),
            'accuracy': round(confidence * 100, 1),
            'pattern_breakdown': pattern_counts,
            'total_patterns': sum(pattern_counts.values())
        }