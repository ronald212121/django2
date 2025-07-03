# FIXED: nikto_scanner/utils.py - UNIVERSAL Scanner Utilities
# ADDED: FIX Severity classification untuk HTTP methods ✅

"""
FIXED UNIVERSAL SCANNER UTILITIES
- Efficient scanning algorithms
- NO infinite loops
- UNIVERSAL untuk semua target
- Optimized untuk production
- ADDED: Fixed severity classification for HTTP methods ✅
"""

import subprocess
import json
import re
import time
import requests
import logging
from datetime import datetime
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class UniversalVulnerabilityScanner:
    """
    FIXED: Universal Vulnerability Scanner
    - Efficient scanning untuk semua jenis target
    - NO infinite loops atau redundant processing
    - Scalable untuk production use
    """
    
    def __init__(self, target_url: str, timeout: int = 15):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
    def scan_comprehensive_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        FIXED: Comprehensive vulnerability scan SEKALI SAJA
        UNIVERSAL untuk semua target (localhost, production, dll)
        """
        logger.info(f"Starting comprehensive vulnerability scan for {self.target_url}")
        
        vulnerabilities = []
        
        try:
            # 1. Basic connectivity check
            if not self._check_target_accessibility():
                logger.warning(f"Target {self.target_url} is not accessible")
                return vulnerabilities
            
            # 2. Scan for positive security features
            security_features = self._scan_security_features()
            vulnerabilities.extend(security_features)
            
            # 3. Scan for vulnerabilities
            vuln_findings = self._scan_vulnerabilities()
            vulnerabilities.extend(vuln_findings)
            
            # 4. Scan for configuration issues
            config_issues = self._scan_configuration_issues()
            vulnerabilities.extend(config_issues)
            
            logger.info(f"Comprehensive scan completed: {len(vulnerabilities)} findings")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error in comprehensive scan: {e}")
            return vulnerabilities
    
    def _check_target_accessibility(self) -> bool:
        """Check if target is accessible"""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            return response.status_code < 500
        except:
            return False
    
    def _scan_security_features(self) -> List[Dict[str, Any]]:
        """
        FIXED: Scan for positive security features SEKALI SAJA
        UNIVERSAL detection untuk semua jenis website
        """
        security_features = []
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            # Check security headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'XSS protection',
                'Referrer-Policy': 'Referrer control',
                'Permissions-Policy': 'Feature control',
                'X-XSS-Protection': 'XSS filtering'
            }
            
            present_headers = []
            for header, description in security_headers.items():
                if header in response.headers:
                    present_headers.append(header)
            
            # UNIVERSAL: Excellent security headers detection
            if len(present_headers) >= 5:
                security_features.append({
                    'type': 'Excellent Security Headers',
                    'severity': 'info',
                    'description': f'Comprehensive security headers implemented: {", ".join(present_headers)}',
                    'path': '/',
                    'method': 'GET',
                    'evidence': f'{len(present_headers)}/{len(security_headers)} critical headers present',
                    'impact': 'POSITIVE: Strong protection against multiple attack vectors',
                    'recommendation': 'Excellent security header implementation - maintain current configuration',
                    'cvss_score': 0.0,
                    'source': 'universal_scanner',
                    'confidence': 'high',
                    'is_positive': True
                })
                logger.info(f"POSITIVE: Excellent security headers detected ({len(present_headers)} headers)")
            
            # Check for rate limiting
            if self._test_rate_limiting_universal():
                security_features.append({
                    'type': 'Rate Limiting Protection',
                    'severity': 'info',
                    'description': 'Active rate limiting protection detected',
                    'path': '/login',
                    'method': 'POST',
                    'evidence': 'Rate limiting successfully blocks excessive requests',
                    'impact': 'POSITIVE: Excellent protection against brute force and DoS attacks',
                    'recommendation': 'Outstanding rate limiting implementation - maintain current settings',
                    'cvss_score': 0.0,
                    'source': 'universal_scanner',
                    'confidence': 'high',
                    'is_positive': True
                })
                logger.info("POSITIVE: Rate limiting protection detected")
            
            # Check for HTTPS enforcement
            if self.target_url.startswith('https://'):
                hsts_present = 'Strict-Transport-Security' in response.headers
                if hsts_present:
                    security_features.append({
                        'type': 'HTTPS Enforcement',
                        'severity': 'info',
                        'description': 'HTTPS with HSTS enforcement detected',
                        'path': '/',
                        'method': 'GET',
                        'evidence': 'HSTS header present with secure configuration',
                        'impact': 'POSITIVE: Strong transport layer security',
                        'recommendation': 'Excellent HTTPS implementation',
                        'cvss_score': 0.0,
                        'source': 'universal_scanner',
                        'confidence': 'high',
                        'is_positive': True
                    })
                    logger.info("POSITIVE: HTTPS enforcement detected")
                    
        except Exception as e:
            logger.error(f"Error scanning security features: {e}")
        
        return security_features
    
    def _test_rate_limiting_universal(self) -> bool:
        """
        FIXED: Test rate limiting UNIVERSAL untuk semua target
        """
        try:
            # Common login endpoints
            login_endpoints = ['/login', '/api/login', '/auth/login', '/signin', '/api/auth/login']
            
            for endpoint in login_endpoints:
                test_url = urljoin(self.target_url, endpoint)
                
                # Test rapid requests
                for attempt in range(5):
                    try:
                        response = self.session.post(
                            test_url,
                            data={'username': f'test{attempt}', 'password': f'test{attempt}'},
                            timeout=self.timeout
                        )
                        
                        # Check for rate limiting indicators
                        if (response.status_code == 429 or
                            'too many requests' in response.text.lower() or
                            'rate limit' in response.text.lower() or
                            'blocked' in response.text.lower() or
                            'throttled' in response.text.lower()):
                            return True
                        
                        time.sleep(0.1)  # Small delay between requests
                        
                    except requests.exceptions.RequestException:
                        continue
                
                # If we found a working endpoint, we tested it
                if test_url != urljoin(self.target_url, endpoint):
                    break
                    
        except Exception as e:
            logger.error(f"Error testing rate limiting: {e}")
        
        return False
    
    def _scan_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        FIXED: Scan for actual vulnerabilities SEKALI SAJA
        """
        vulnerabilities = []
        
        try:
            # Check for missing security headers
            missing_headers = self._check_missing_security_headers()
            vulnerabilities.extend(missing_headers)
            
            # Check for information disclosure
            info_disclosure = self._check_information_disclosure()
            vulnerabilities.extend(info_disclosure)
            
            # Check for insecure cookies
            insecure_cookies = self._check_insecure_cookies()
            vulnerabilities.extend(insecure_cookies)
            
        except Exception as e:
            logger.error(f"Error scanning vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _check_missing_security_headers(self) -> List[Dict[str, Any]]:
        """Check for missing critical security headers"""
        vulnerabilities = []
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            # Only check for CRITICAL missing headers
            critical_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection'
            }
            
            missing_critical = []
            for header, description in critical_headers.items():
                if header not in response.headers:
                    missing_critical.append(f"{header} ({description})")
            
            if missing_critical:
                vulnerabilities.append({
                    'type': 'Missing Critical Security Headers',
                    'severity': 'low',
                    'description': f'Missing critical security headers: {", ".join(missing_critical)}',
                    'path': '/',
                    'method': 'GET',
                    'evidence': f'Headers not present: {", ".join(missing_critical)}',
                    'impact': 'Reduced protection against common web attacks',
                    'recommendation': 'Implement missing critical security headers',
                    'cvss_score': 3.1,
                    'source': 'universal_scanner',
                    'confidence': 'high'
                })
                
        except Exception as e:
            logger.error(f"Error checking security headers: {e}")
        
        return vulnerabilities
    
    def _check_information_disclosure(self) -> List[Dict[str, Any]]:
        """Check for information disclosure"""
        vulnerabilities = []
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            # Check server header
            server_header = response.headers.get('Server', '')
            if server_header and ('/' in server_header or any(server in server_header.lower() for server in ['apache', 'nginx', 'iis'])):
                vulnerabilities.append({
                    'type': 'Server Information Disclosure',
                    'severity': 'info',
                    'description': 'Server version information disclosed in HTTP headers',
                    'path': '/',
                    'method': 'GET',
                    'evidence': f'Server header: {server_header}',
                    'impact': 'Information leakage that may aid attackers in fingerprinting',
                    'recommendation': 'Configure server to hide version information',
                    'cvss_score': 2.1,
                    'source': 'universal_scanner',
                    'confidence': 'medium'
                })
                
        except Exception as e:
            logger.error(f"Error checking information disclosure: {e}")
        
        return vulnerabilities
    
    def _check_insecure_cookies(self) -> List[Dict[str, Any]]:
        """Check for insecure cookie configurations"""
        vulnerabilities = []
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            # Check Set-Cookie headers
            cookies = response.headers.get('Set-Cookie', '')
            if cookies:
                cookie_issues = []
                
                # Check for critical cookie security attributes
                if 'httponly' not in cookies.lower():
                    cookie_issues.append('Missing HttpOnly flag')
                
                if self.target_url.startswith('https://') and 'secure' not in cookies.lower():
                    cookie_issues.append('Missing Secure flag for HTTPS')
                
                if cookie_issues:
                    vulnerabilities.append({
                        'type': 'Insecure Cookie Configuration',
                        'severity': 'low',
                        'description': 'Session cookies lack important security attributes',
                        'path': '/',
                        'method': 'GET',
                        'evidence': f'Cookie security issues: {", ".join(cookie_issues)}',
                        'impact': 'Increased risk of session hijacking and XSS attacks',
                        'recommendation': 'Add HttpOnly, Secure, and SameSite attributes to cookies',
                        'cvss_score': 4.3,
                        'source': 'universal_scanner',
                        'confidence': 'medium'
                    })
                    
        except Exception as e:
            logger.error(f"Error checking cookie security: {e}")
        
        return vulnerabilities
    
    def _scan_configuration_issues(self) -> List[Dict[str, Any]]:
        """Scan for configuration issues"""
        vulnerabilities = []
        
        try:
            # Check for debug mode indicators
            debug_issues = self._check_debug_mode()
            vulnerabilities.extend(debug_issues)
            
            # Check for directory listings
            directory_issues = self._check_directory_listing()
            vulnerabilities.extend(directory_issues)
            
        except Exception as e:
            logger.error(f"Error scanning configuration issues: {e}")
        
        return vulnerabilities
    
    def _check_debug_mode(self) -> List[Dict[str, Any]]:
        """Check for debug mode enabled"""
        vulnerabilities = []
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            # Check for debug mode indicators
            debug_indicators = [
                'debug = true', 'debug=true', 'flask_debug',
                'development mode', 'debug mode enabled',
                'werkzeug debugger', 'debugger is active'
            ]
            
            content_lower = response.text.lower()
            found_indicators = [indicator for indicator in debug_indicators if indicator in content_lower]
            
            if found_indicators:
                vulnerabilities.append({
                    'type': 'Debug Mode Enabled',
                    'severity': 'medium',
                    'description': 'Application appears to be running in debug mode',
                    'path': '/',
                    'method': 'GET',
                    'evidence': f'Debug indicators found: {", ".join(found_indicators)}',
                    'impact': 'Information disclosure and increased attack surface',
                    'recommendation': 'Disable debug mode in production environment',
                    'cvss_score': 5.3,
                    'source': 'universal_scanner',
                    'confidence': 'high'
                })
                
        except Exception as e:
            logger.error(f"Error checking debug mode: {e}")
        
        return vulnerabilities
    
    def _check_directory_listing(self) -> List[Dict[str, Any]]:
        """Check for directory listing vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test common directories
            test_dirs = ['/uploads/', '/files/', '/documents/', '/backup/']
            
            for directory in test_dirs:
                test_url = urljoin(self.target_url, directory)
                
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    # Check for directory listing indicators
                    if (response.status_code == 200 and
                        ('index of' in response.text.lower() or
                         'parent directory' in response.text.lower() or
                         '<title>Directory listing for' in response.text.lower())):
                        
                        vulnerabilities.append({
                            'type': 'Directory Listing Enabled',
                            'severity': 'low',
                            'description': f'Directory listing enabled for {directory}',
                            'path': directory,
                            'method': 'GET',
                            'evidence': 'Directory contents are publicly accessible',
                            'impact': 'Information disclosure, potential exposure of sensitive files',
                            'recommendation': 'Disable directory listings in web server configuration',
                            'cvss_score': 3.7,
                            'source': 'universal_scanner',
                            'confidence': 'high'
                        })
                        break  # Only report first instance
                        
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            logger.error(f"Error checking directory listing: {e}")
        
        return vulnerabilities

# FIXED: Utility functions for NIKTO integration
def run_nikto_scan_universal(target: str, scan_type: str = 'basic') -> List[Dict[str, Any]]:
    """
    FIXED: Run NIKTO scan dengan proper timeout dan error handling
    UNIVERSAL untuk semua target
    """
    try:
        # Build command
        if scan_type == 'full':
            cmd = f"nikto -h {target} -C all -timeout 15"
            timeout_seconds = 300
        else:
            cmd = f"nikto -h {target} -timeout 10"
            timeout_seconds = 180
        
        logger.info(f"Running NIKTO scan: {cmd}")
        
        # Execute command
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        
        if stdout and len(stdout.strip()) > 100:
            return parse_nikto_output_universal(stdout)
        else:
            logger.warning("NIKTO produced minimal output")
            return []
            
    except subprocess.TimeoutExpired:
        logger.warning(f"NIKTO scan timeout after {timeout_seconds} seconds")
        return []
    except Exception as e:
        logger.error(f"NIKTO scan error: {e}")
        return []

def parse_nikto_output_universal(output: str) -> List[Dict[str, Any]]:
    """
    FIXED: Parse NIKTO output UNIVERSAL untuk semua target
    - Proper filtering of non-vulnerability items
    - NO infinite loops
    """
    vulnerabilities = []
    lines = output.split('\n')
    
    for line in lines:
        if line.startswith('+ ') and len(line.strip()) > 15:
            description = line.replace('+ ', '').strip()
            
            # FIXED: Skip informational and positive security items
            skip_patterns = [
                # Informational items
                'target ip:', 'target hostname:', 'target port:', 'start time:', 'end time:',
                'server:', 'no cgi directories', 'items checked:', 'host(s) tested',
                # Security headers (these are POSITIVE, not vulnerabilities)
                'x-frame-options', 'x-content-type-options', 'strict-transport-security',
                'content-security-policy', 'referrer-policy', 'permissions-policy',
                'x-xss-protection', 'expect-ct', 'feature-policy'
            ]
            
            # Skip if matches any pattern
            if any(pattern in description.lower() for pattern in skip_patterns):
                continue
            
            # Only include if it's substantial content
            if len(description) > 10:
                severity = classify_nikto_severity_universal(description)
                
                vulnerability = {
                    'type': 'Infrastructure Finding',
                    'severity': severity,
                    'description': description,
                    'path': extract_path_from_line(line),
                    'method': 'GET',
                    'source': 'nikto',
                    'confidence': 'medium',
                    'recommendation': generate_nikto_recommendation(description)
                }
                
                vulnerabilities.append(vulnerability)
    
    logger.info(f"NIKTO parsed {len(vulnerabilities)} actual vulnerabilities")
    return vulnerabilities

# ADDED: FIX SEVERITY CLASSIFICATION ✅
def classify_nikto_severity_universal(description: str) -> str:
    """
    PERBAIKAN: Classify NIKTO severity UNIVERSAL dengan FIX HTTP methods
    HANYA memperbaiki klasifikasi HTTP methods
    """
    desc_lower = description.lower()
    
    # PERBAIKAN: HTTP methods normal seharusnya INFO
    if 'allowed http methods' in desc_lower:
        if all(method in desc_lower for method in ['head', 'options', 'get']) and 'post' not in desc_lower:
            return 'info'  # Safe methods = INFO
        else:
            return 'low'   # Mixed/dangerous methods = LOW
    
    # High severity patterns (TIDAK DIUBAH)
    high_patterns = ['admin', 'config', 'backup', 'database', 'phpinfo', 'server-status', 'server-info']
    
    # Medium severity patterns (TIDAK DIUBAH)  
    medium_patterns = ['version', 'banner', 'disclosure', 'directory', 'file']
    
    # Low severity patterns (TIDAK DIUBAH)
    low_patterns = ['header', 'options', 'trace', 'put', 'delete']
    
    if any(pattern in desc_lower for pattern in high_patterns):
        return 'medium'  # NIKTO high findings are typically medium severity
    elif any(pattern in desc_lower for pattern in medium_patterns):
        return 'low'
    elif any(pattern in desc_lower for pattern in low_patterns):
        return 'info'
    else:
        return 'info'  # Default to info for unknown patterns

def extract_path_from_line(line: str) -> str:
    """Extract path from NIKTO line"""
    path_match = re.search(r'(/[^\s,\)]*)', line)
    return path_match.group(1) if path_match else '/'

def generate_nikto_recommendation(description: str) -> str:
    """Generate recommendation for NIKTO finding"""
    desc_lower = description.lower()
    
    if 'admin' in desc_lower:
        return 'Secure admin interfaces with strong authentication and access controls'
    elif 'config' in desc_lower:
        return 'Remove or secure configuration files from web-accessible directories'
    elif 'version' in desc_lower or 'banner' in desc_lower:
        return 'Hide server version information to prevent fingerprinting'
    elif 'backup' in desc_lower:
        return 'Remove backup files from web-accessible locations'
    elif 'database' in desc_lower:
        return 'Ensure database files are not accessible via web'
    elif 'directory' in desc_lower:
        return 'Disable directory listings and secure directory access'
    else:
        return 'Review and secure the identified issue according to security best practices'

# FIXED: Vulnerability classification for all findings
def classify_vulnerabilities_by_severity_universal(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    FIXED: Classify vulnerabilities by severity UNIVERSAL
    - NO infinite loops
    - Proper positive feature detection
    """
    counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    }
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'info').lower()
        is_positive = vuln.get('is_positive', False)
        
        # Only count actual vulnerabilities (not positive features)
        if not is_positive and severity in counts:
            counts[severity] += 1
    
    logger.info(f"Vulnerability classification: {counts}")
    return counts