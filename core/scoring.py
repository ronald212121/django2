# FIXED: core/scoring.py - UNIVERSAL Simple Scoring tanpa infinite loop

"""
FIXED UNIVERSAL SECURITY SCORING SYSTEM
- NO infinite loops
- Efficient calculations
- Universal untuk semua target
- Industry standard results
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class UniversalSecurityScorer:
    """
    FIXED: Universal Security Scorer untuk semua jenis target
    - Simple dan efficient
    - Tidak ada infinite loop
    - Scalable untuk production
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def calculate_security_score(self, scan_result) -> int:
        """
        FIXED: Calculate security score SEKALI SAJA
        UNIVERSAL untuk semua target (localhost, production, dll)
        """
        try:
            # Base score
            base_score = 100
            
            # FIXED: Simple penalty calculation
            penalty = 0
            penalty += getattr(scan_result, 'critical_count', 0) * 25
            penalty += getattr(scan_result, 'high_count', 0) * 15
            penalty += getattr(scan_result, 'medium_count', 0) * 8
            penalty += getattr(scan_result, 'low_count', 0) * 3
            # Info count = 0 penalty
            
            # Apply penalty
            score_after_penalty = max(0, base_score - penalty)
            
            # FIXED: Detect positive features SEKALI SAJA
            positive_bonus = self._detect_positive_features(scan_result)
            
            # Apply bonus
            final_score = min(100, score_after_penalty + positive_bonus)
            
            # FIXED: Industry caps
            critical_count = getattr(scan_result, 'critical_count', 0)
            if critical_count >= 3:
                final_score = min(final_score, 5)
            elif critical_count >= 2:
                final_score = min(final_score, 15)
            elif critical_count >= 1:
                final_score = min(final_score, 30)
            
            return int(final_score)
            
        except Exception as e:
            self.logger.error(f"Error calculating security score: {e}")
            return 50  # Safe default
    
    def _detect_positive_features(self, scan_result) -> int:
        """
        FIXED: Detect positive features SEKALI SAJA
        UNIVERSAL detection untuk semua target
        """
        try:
            if not hasattr(scan_result, 'result'):
                return 0
                
            result_data = json.loads(scan_result.result)
            positive_bonus = 0
            
            # Collect all findings
            all_findings = []
            for key in ['vulnerabilities', 'application_vulnerabilities', 'nikto_vulnerabilities']:
                if key in result_data and isinstance(result_data[key], list):
                    all_findings.extend(result_data[key])
            
            # Track detected features
            features_detected = set()
            
            for finding in all_findings:
                description = str(finding.get('description', '')).lower()
                vuln_type = str(finding.get('type', '')).lower()
                is_positive = finding.get('is_positive', False)
                
                # UNIVERSAL positive feature detection
                if is_positive and 'positive' not in features_detected:
                    positive_bonus += 10
                    features_detected.add('positive')
                elif 'comprehensive security headers' in description and 'headers' not in features_detected:
                    positive_bonus += 25
                    features_detected.add('headers')
                elif 'excellent security headers' in vuln_type and 'headers' not in features_detected:
                    positive_bonus += 25
                    features_detected.add('headers')
                elif 'rate limiting protection' in description and 'rate_limit' not in features_detected:
                    positive_bonus += 30
                    features_detected.add('rate_limit')
                elif 'rate limiting' in vuln_type and 'rate_limit' not in features_detected:
                    positive_bonus += 30
                    features_detected.add('rate_limit')
                elif 'strong password hashing' in description and 'strong_auth' not in features_detected:
                    positive_bonus += 15
                    features_detected.add('strong_auth')
            
            return min(positive_bonus, 50)  # Max 50 points bonus
            
        except Exception as e:
            self.logger.error(f"Error detecting positive features: {e}")
            return 0
    
    def get_risk_level(self, score: int) -> str:
        """Get risk level from score"""
        if score >= 80:
            return "LOW"
        elif score >= 60:
            return "MODERATE"
        elif score >= 40:
            return "HIGH"
        else:
            return "VERY HIGH"
    
    def get_security_rating(self, score: int) -> str:
        """Get security rating from score"""
        if score >= 90:
            return "Excellent"
        elif score >= 80:
            return "Very Good"
        elif score >= 70:
            return "Good"
        elif score >= 55:
            return "Fair"
        elif score >= 40:
            return "Poor"
        elif score >= 25:
            return "Very Poor"
        elif score >= 10:
            return "Critical"
        else:
            return "Extremely Critical"
    
    def get_score_color(self, score: int) -> str:
        """Get CSS color class for score"""
        if score >= 80:
            return "text-success"
        elif score >= 70:
            return "text-info"
        elif score >= 55:
            return "text-warning"
        elif score >= 40:
            return "text-warning"
        else:
            return "text-danger"
    
    def get_comprehensive_analysis(self, scan_result) -> Dict[str, Any]:
        """
        FIXED: Get comprehensive analysis tanpa infinite loop
        """
        try:
            score = self.calculate_security_score(scan_result)
            
            return {
                'security_score': score,
                'risk_level': self.get_risk_level(score),
                'security_rating': self.get_security_rating(score),
                'score_color': self.get_score_color(score),
                'vulnerability_breakdown': {
                    'critical': getattr(scan_result, 'critical_count', 0),
                    'high': getattr(scan_result, 'high_count', 0),
                    'medium': getattr(scan_result, 'medium_count', 0),
                    'low': getattr(scan_result, 'low_count', 0),
                    'info': getattr(scan_result, 'info_count', 0),
                },
                'assessment_metadata': {
                    'methodology': 'FIXED Universal Scoring System',
                    'assessment_date': datetime.now().isoformat(),
                    'target': getattr(scan_result, 'target', 'Unknown'),
                    'tool': getattr(scan_result, 'tool', 'Unknown'),
                    'status': 'SUCCESS'
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error in comprehensive analysis: {e}")
            return {
                'security_score': 50,
                'risk_level': 'UNKNOWN',
                'security_rating': 'Unknown',
                'score_color': 'text-secondary',
                'error': str(e),
                'status': 'ERROR'
            }

# FIXED: Global instance
universal_scorer = UniversalSecurityScorer()

# FIXED: Main functions untuk backward compatibility
def calculate_security_score(scan_result) -> int:
    """
    FIXED: Main scoring function tanpa infinite loop
    UNIVERSAL untuk semua target
    """
    return universal_scorer.calculate_security_score(scan_result)

def get_detailed_security_analysis(scan_result) -> Dict[str, Any]:
    """
    FIXED: Get detailed analysis tanpa infinite loop
    """
    return universal_scorer.get_comprehensive_analysis(scan_result)

def get_security_rating(score: int) -> str:
    """Get security rating from score"""
    return universal_scorer.get_security_rating(score)

def get_risk_level(score: int) -> str:
    """Get risk level from score"""
    return universal_scorer.get_risk_level(score)

def get_score_color(score: int) -> str:
    """Get CSS color class for score"""
    return universal_scorer.get_score_color(score)

# FIXED: Quick validation function
def validate_scan_result(scan_result) -> bool:
    """
    Validate scan result object
    """
    try:
        required_attrs = ['critical_count', 'high_count', 'medium_count', 'low_count', 'info_count']
        return all(hasattr(scan_result, attr) for attr in required_attrs)
    except:
        return False

# FIXED: Emergency fallback scoring
def emergency_fallback_score(critical=0, high=0, medium=0, low=0, info=0) -> int:
    """
    Emergency fallback scoring when normal scoring fails
    """
    try:
        base_score = 100
        penalty = critical * 25 + high * 15 + medium * 8 + low * 3
        final_score = max(0, min(100, base_score - penalty))
        
        # Critical caps
        if critical >= 3:
            final_score = min(final_score, 5)
        elif critical >= 2:
            final_score = min(final_score, 15)
        elif critical >= 1:
            final_score = min(final_score, 30)
        
        return int(final_score)
        
    except:
        return 50  # Ultimate fallback

# FIXED: Performance monitoring
def log_scoring_performance(func):
    """Decorator untuk monitor performance"""
    def wrapper(*args, **kwargs):
        start_time = datetime.now()
        try:
            result = func(*args, **kwargs)
            duration = (datetime.now() - start_time).total_seconds()
            if duration > 1.0:  # Log slow scoring
                logger.warning(f"Slow scoring detected: {func.__name__} took {duration:.2f}s")
            return result
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            logger.error(f"Scoring error in {func.__name__} after {duration:.2f}s: {e}")
            raise
    return wrapper

# Apply performance monitoring to main functions
calculate_security_score = log_scoring_performance(calculate_security_score)
get_detailed_security_analysis = log_scoring_performance(get_detailed_security_analysis)