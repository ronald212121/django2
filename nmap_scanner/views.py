# COMPLETE FIX: nmap_scanner/views.py - Cohere API Integration
# 🚨 GUNAKAN INI UNTUK MENGGANTI VIEWS.PY ANDA!

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .utils import run_nmap_scan
import cohere
import json
import os
import re
from urllib.parse import urlparse
from django.conf import settings
import shutil

# Your Cohere API Key
COHERE_API_KEY = "l5txUpFu1GUbXnR3fXLbbTt6wRchJi5c9A8SYDZd"

nmap_path = shutil.which('nmap')

def validate_and_clean_target(target):
    """Validate and clean target for NMAP scanning"""
    if not target or not target.strip():
        raise ValueError("Target cannot be empty")
    
    target = target.strip()
    
    if '://' in target:
        try:
            parsed = urlparse(target)
            cleaned = parsed.hostname or parsed.netloc
            if not cleaned:
                cleaned = re.sub(r'^https?://', '', target)
                cleaned = re.sub(r'/.*$', '', cleaned)
            
            print(f"DEBUG: Target cleaned from {target} to {cleaned}")
            return cleaned.strip()
        except:
            cleaned = re.sub(r'^https?://', '', target)
            cleaned = re.sub(r'/.*$', '', cleaned)
            return cleaned.strip()
    
    return target

def calculate_realistic_security_score(critical, high, medium, low, info):
    """Calculate realistic security score based on vulnerability severity"""
    base_score = 100
    
    # Severity-based scoring weights
    critical_weight = 30  # Each critical = -30 points
    high_weight = 20      # Each high = -20 points  
    medium_weight = 10    # Each medium = -10 points
    low_weight = 5        # Each low = -5 points
    info_weight = 1       # Each info = -1 point
    
    # Calculate deductions
    deductions = (
        (critical * critical_weight) +
        (high * high_weight) +
        (medium * medium_weight) +
        (low * low_weight) +
        (info * info_weight)
    )
    
    # Calculate final score with minimum of 0
    final_score = max(base_score - deductions, 0)
    
    return int(final_score)

def determine_risk_level(security_score, critical, high, total_open_ports=0):
    """Determine risk level based on multiple factors"""
    
    # Critical vulnerabilities always mean critical risk
    if critical > 0:
        return "CRITICAL"
    
    # Many open ports indicate serious misconfiguration
    if total_open_ports > 500:
        return "CRITICAL"
    elif total_open_ports > 100:
        return "VERY HIGH"
    
    # Score-based assessment
    if security_score < 20 or high > 3:
        return "CRITICAL" 
    elif security_score < 40 or high > 1:
        return "VERY HIGH"
    elif security_score < 60 or high > 0:
        return "HIGH"
    elif security_score < 75:
        return "MEDIUM"
    elif security_score < 90:
        return "LOW"
    else:
        return "VERY LOW"

def detect_suspicious_results(target, scan_result):
    """Detect potentially suspicious scan results"""
    suspicious_flags = []
    
    # Check if target is enterprise/government domain
    enterprise_indicators = ['.gov', '.mil', '.edu', '.co.id', '.go.id', '.gov.id']
    is_enterprise = any(indicator in target.lower() for indicator in enterprise_indicators)
    
    try:
        result_data = json.loads(scan_result.result)
        
        # Count total open ports
        total_open_ports = 0
        suspicious_services = []
        
        if 'tcp' in result_data:
            tcp_open = len([port for port, data in result_data['tcp'].items() 
                          if isinstance(data, dict) and data.get('state') == 'open'])
            total_open_ports += tcp_open
            
            # Check for suspicious services
            for port, port_data in result_data['tcp'].items():
                if isinstance(port_data, dict) and port_data.get('state') == 'open':
                    service = port_data.get('name', '').lower()
                    
                    # Legacy/high-risk services
                    if service in ['telnet', 'ftp', 'rsh', 'rlogin']:
                        suspicious_services.append(f"{service} on port {port}")
                    elif service == 'snmp':
                        suspicious_services.append(f"SNMP on port {port}")
        
        if 'udp' in result_data:
            udp_open = len([port for port, data in result_data['udp'].items() 
                          if isinstance(data, dict) and data.get('state') == 'open'])
            total_open_ports += udp_open
        
        # Flag abnormal port counts
        if total_open_ports > 500:
            suspicious_flags.append(f"CRITICAL: {total_open_ports} open ports detected - extremely abnormal for any system")
            suspicious_flags.append("This likely indicates: misconfigured firewall/load balancer, honeypot, or serious compromise")
        elif total_open_ports > 100:
            suspicious_flags.append(f"SUSPICIOUS: {total_open_ports} open ports detected - highly unusual")
            suspicious_flags.append("Recommend immediate manual verification and investigation")
        
        # Flag enterprise targets with risky services
        if is_enterprise and suspicious_services:
            suspicious_flags.append(f"Enterprise target with high-risk services: {', '.join(suspicious_services)}")
            suspicious_flags.append("Government/enterprise systems should not expose these legacy services publicly")
        
        # Flag if too many services for a web server
        if 'www.' in target and total_open_ports > 10:
            suspicious_flags.append("Web server target with unusually many open ports - investigate configuration")
    
    except Exception as e:
        print(f"DEBUG: Error in suspicious detection: {e}")
    
    return suspicious_flags

def generate_enhanced_cohere_recommendation_nmap(scan_result, target, scan_type):
    """Generate enhanced recommendations with proper API usage"""
    
    # Calculate security metrics
    security_score = calculate_realistic_security_score(
        scan_result.critical_count,
        scan_result.high_count, 
        scan_result.medium_count,
        scan_result.low_count,
        scan_result.info_count
    )
    
    # Get total open ports for risk assessment
    try:
        result_data = json.loads(scan_result.result)
        total_open_ports = len(result_data.get('open_ports', {}).get('tcp', [])) + len(result_data.get('open_ports', {}).get('udp', []))
    except:
        total_open_ports = 0
    
    risk_level = determine_risk_level(security_score, scan_result.critical_count, scan_result.high_count, total_open_ports)
    
    # Detect suspicious results
    suspicious_flags = detect_suspicious_results(target, scan_result)
    
    # Parse scan results
    try:
        result_data = json.loads(scan_result.result)
    except:
        result_data = {}
    
    # Check if scan failed
    if 'error' in result_data:
        prompt = f"""
*NMAP SCAN FAILURE ANALYSIS FOR {target.upper()}*

The {scan_type} NMAP scan failed with error: {result_data['error']}

*TECHNICAL FAILURE ANALYSIS:*
1. *Root Cause Assessment:*
   - Network connectivity issues or DNS resolution failure
   - Target firewall/IPS blocking reconnaissance attempts  
   - Rate limiting or connection throttling active
   - Invalid target specification or unreachable host

2. *Systematic Troubleshooting Approach:*
   - Verify basic connectivity: ping and traceroute to target
   - Confirm DNS resolution: nslookup/dig for hostname
   - Test alternative scan methods: stealth scans (-sS), slower timing (-T1)
   - Reduce scan scope: specific ports only (-p 80,443,22)

3. *Network Security Implications:*
   - Scan failure may indicate robust perimeter defense
   - Intrusion Prevention System (IPS) likely detecting/blocking scans
   - Network segmentation and access controls appear effective
   - Target demonstrates good security posture through scan resistance

4. *Alternative Reconnaissance Strategies:*
   - Passive information gathering through search engines and databases
   - Public intelligence sources (Shodan, Censys) for baseline information
   - Social engineering and OSINT techniques for infrastructure mapping
   - Application-layer testing for web-accessible services

Provide practical next steps for security assessment while respecting defensive measures and maintaining ethical reconnaissance practices.
"""
    else:
        # Successful scan - generate comprehensive analysis
        vuln_summary = f"""
*COMPREHENSIVE NMAP SECURITY ASSESSMENT REPORT*

*TARGET INFORMATION:*
- Domain: {target}
- IP Address: {result_data.get('host', 'Unknown')}
- Scan Type: {scan_type.upper()} 
- Assessment Date: Current

*SECURITY SCORING & RISK ASSESSMENT:*
- Security Score: {security_score}/100
- Risk Level: {risk_level}
- Total Open Ports: {total_open_ports}

*VULNERABILITY BREAKDOWN:*
- 🔴 Critical Vulnerabilities: {scan_result.critical_count}
- 🟠 High Risk Issues: {scan_result.high_count}  
- 🟡 Medium Risk Issues: {scan_result.medium_count}
- 🟢 Low Risk Items: {scan_result.low_count}
- 🔵 Informational Findings: {scan_result.info_count}
- *Total Security Concerns: {scan_result.get_total_vulnerabilities()}*

*SCAN METADATA:*
- Ports Analyzed: {result_data.get('total_ports_scanned', 'Unknown')}
- Services Identified: {len(result_data.get('services', []))}
- Hosts Discovered: {len(result_data.get('hosts', []))}
"""
        
        # Add suspicious analysis if detected
        if suspicious_flags:
            vuln_summary += f"""

*⚠ CRITICAL SECURITY ALERTS:*
{chr(10).join(f"   • {flag}" for flag in suspicious_flags)}

*IMMEDIATE INVESTIGATION REQUIRED:*
   • Manual verification of flagged services essential
   • Cross-validation with alternative scanning tools recommended  
   • Assessment of whether results match expected security posture
   • Investigation for potential honeypots, misconfigurations, or compromises
"""
        
        # Add service overview
        if total_open_ports > 0:
            vuln_summary += f"""

*NETWORK EXPOSURE ANALYSIS:*
- Open Ports Detected: {total_open_ports}
- Attack Surface Assessment: {'CRITICAL - Excessive exposure' if total_open_ports > 100 else 'Standard' if total_open_ports < 10 else 'Elevated'}
- Service Security Review: Required for all exposed services
"""
        
        # Generate context-appropriate recommendations
        if total_open_ports > 500 or scan_result.critical_count > 0:
            # Critical emergency scenario
            prompt = f"""
{vuln_summary}

*🚨 CRITICAL SECURITY EMERGENCY - IMMEDIATE ACTION REQUIRED*

This NMAP assessment has revealed an extremely serious security situation requiring immediate emergency response and investigation.

*PROVIDE COMPREHENSIVE EMERGENCY ANALYSIS:*

1. *IMMEDIATE THREAT ASSESSMENT (Next 1-4 Hours):*
   - Critical system isolation and containment procedures
   - Emergency incident response team activation
   - Immediate threat hunting and compromise assessment
   - Critical service shutdown and protection protocols
   - Emergency communication plan for stakeholders and management

2. *EMERGENCY TECHNICAL RESPONSE (Next 4-24 Hours):*
   - Comprehensive network traffic analysis and monitoring
   - System integrity verification and forensic preparation
   - Emergency patch deployment for critical vulnerabilities
   - Network segmentation and access control lockdown
   - Backup verification and disaster recovery preparation

3. *INVESTIGATION AND REMEDIATION (Next 1-7 Days):*
   - Full security audit and compromise assessment
   - Root cause analysis and attack vector identification
   - Complete system hardening and configuration review
   - Security architecture redesign and implementation
   - Advanced threat detection and monitoring deployment

4. *STRATEGIC SECURITY TRANSFORMATION (Next 1-3 Months):*
   - Comprehensive security program overhaul
   - Advanced security tool deployment and integration
   - Security team training and capability enhancement
   - Regular security assessment and continuous monitoring
   - Compliance framework alignment and governance improvement

5. *REGULATORY AND BUSINESS CONTINUITY:*
   - Regulatory notification and compliance requirements
   - Business continuity and disaster recovery activation
   - Customer communication and reputation management
   - Legal consultation for breach notification requirements
   - Insurance claim preparation and documentation

Focus on immediate actionable steps that can prevent further compromise and begin recovery operations while maintaining business continuity.
"""
        
        elif scan_result.get_total_vulnerabilities() > 5 or scan_result.high_count > 1:
            # Significant security issues requiring attention
            prompt = f"""
{vuln_summary}

*⚠ SIGNIFICANT SECURITY ISSUES DETECTED - COMPREHENSIVE REMEDIATION REQUIRED*

This NMAP assessment has identified multiple security vulnerabilities and configuration issues requiring systematic remediation.

*PROVIDE DETAILED SECURITY IMPROVEMENT PLAN:*

1. *PRIORITY-BASED VULNERABILITY REMEDIATION (Next 2-4 Weeks):*
   - Critical and high-severity vulnerability patching schedule
   - Service hardening and configuration security improvements  
   - Access control strengthening and authentication enhancement
   - Network segmentation and firewall rule optimization
   - Security monitoring and logging implementation

2. *SYSTEMATIC SECURITY ENHANCEMENT (Next 1-3 Months):*
   - Comprehensive security architecture review and improvement
   - Advanced threat detection and response capability deployment
   - Security automation and orchestration implementation
   - Regular vulnerability assessment and penetration testing schedule
   - Security awareness training and team capability development

3. *OPERATIONAL SECURITY IMPROVEMENTS:*
   - Incident response plan development and testing
   - Security metrics and KPI establishment
   - Vendor and third-party security assessment
   - Data protection and privacy control implementation
   - Business continuity and disaster recovery enhancement

4. *COMPLIANCE AND GOVERNANCE FRAMEWORK:*
   - Industry standard compliance alignment (ISO, NIST, SOC)
   - Security policy development and enforcement
   - Risk management framework integration
   - Regular security audit and assessment scheduling
   - Executive reporting and governance structure

5. *CONTINUOUS IMPROVEMENT STRATEGY:*
   - Security maturity model advancement
   - Emerging threat intelligence integration
   - Technology stack modernization and security optimization
   - Industry best practice adoption and innovation
   - Security community engagement and knowledge sharing

Provide practical, implementable recommendations that address immediate security concerns while building long-term security resilience.
"""
        
        else:
            # Good security posture with minor improvements needed
            prompt = f"""
{vuln_summary}

*✅ STRONG SECURITY FOUNDATION - STRATEGIC OPTIMIZATION OPPORTUNITIES*

This NMAP assessment reveals a solid security foundation with opportunities for strategic enhancement and advanced security capabilities.

*PROVIDE STRATEGIC SECURITY ADVANCEMENT PLAN:*

1. *SECURITY EXCELLENCE MAINTENANCE (Ongoing):*
   - Continue current effective security practices and configurations
   - Regular security assessment and monitoring to maintain standards
   - Proactive threat hunting and advanced persistent threat detection
   - Security team skill development and advanced training programs
   - Industry best practice research and selective adoption

2. *ADVANCED SECURITY CAPABILITIES (Next 3-6 Months):*
   - Zero-trust architecture implementation and maturity
   - Advanced analytics and machine learning for threat detection
   - Security automation and orchestration platform deployment
   - Cloud security and hybrid infrastructure protection
   - Advanced incident response and forensic capabilities

3. *INNOVATION AND FUTURE-PROOFING (Next 6-12 Months):*
   - Emerging security technology evaluation and pilot programs
   - Next-generation security tool integration and optimization
   - Threat intelligence platform deployment and utilization
   - Security research and development initiative support
   - Industry leadership and security community contribution

4. *STRATEGIC SECURITY GOVERNANCE:*
   - Security maturity model advancement and measurement
   - Executive security dashboard and metrics optimization
   - Risk management framework sophistication and integration
   - Compliance framework excellence and continuous improvement
   - Security investment optimization and ROI measurement

5. *ORGANIZATIONAL SECURITY CULTURE:*
   - Security awareness program advancement and innovation
   - Security champion program development and expansion
   - Cross-functional security integration and collaboration
   - Security by design methodology implementation
   - Continuous learning and improvement culture development

Focus on strategic recommendations that leverage the strong security foundation to achieve security leadership and excellence while preparing for future challenges and opportunities.
"""
    
    return prompt

@login_required
def nmap_scan_view(request):
    """FIXED: NMAP scan view with complete bug resolution"""
    if request.method == 'POST':
        target = request.POST.get('target')
        scan_type = request.POST.get('scan_type')

        try:
            # Validate and clean target
            cleaned_target = validate_and_clean_target(target)
            
            print(f"DEBUG: Starting FIXED NMAP scan - Target: {target} -> {cleaned_target}, Type: {scan_type}")

            # Run NMAP scan with FIXED counting
            scan_result = run_nmap_scan(target, scan_type, request.user)
            
            print(f"DEBUG: FIXED NMAP scan completed - ID: {scan_result.id}")
            print(f"DEBUG: FIXED Vulnerabilities - C:{scan_result.critical_count}, H:{scan_result.high_count}, M:{scan_result.medium_count}, L:{scan_result.low_count}, I:{scan_result.info_count}")

            # Calculate FIXED security score
            security_score = calculate_realistic_security_score(
                scan_result.critical_count,
                scan_result.high_count,
                scan_result.medium_count, 
                scan_result.low_count,
                scan_result.info_count
            )
            
            # Get total open ports for risk assessment
            try:
                result_data = json.loads(scan_result.result)
                total_open_ports = len(result_data.get('open_ports', {}).get('tcp', [])) + len(result_data.get('open_ports', {}).get('udp', []))
            except:
                total_open_ports = 0
            
            risk_level = determine_risk_level(security_score, scan_result.critical_count, scan_result.high_count, total_open_ports)
            
            print(f"DEBUG: FINAL FIXED SCORING - Score: {security_score}, Risk: {risk_level}, Open Ports: {total_open_ports}")

            # Generate enhanced prompt for Cohere AI
            enhanced_prompt = generate_enhanced_cohere_recommendation_nmap(scan_result, target, scan_type)
            
            print(f"DEBUG: Generated enhanced prompt (length: {len(enhanced_prompt)})")

            # FIXED: Cohere API call without problematic parameters
            try:
                print("DEBUG: Initializing Cohere client...")
                co = cohere.Client(COHERE_API_KEY)
                
                print("DEBUG: Making Cohere API request...")
                # FIXED: Removed 'model' parameter and other potentially problematic parameters
                response = co.generate(
                    prompt=enhanced_prompt,
                    max_tokens=1500,
                    temperature=0.2
                    # Removed 'truncate' parameter as well in case it's causing issues
                )

                # Save AI recommendation
                ai_recommendation = response.generations[0].text
                scan_result.recommendation = ai_recommendation
                scan_result.save()
                
                print(f"DEBUG: ✅ FIXED Cohere API SUCCESS - Recommendation saved")
                
            except Exception as cohere_error:
                print(f"DEBUG: ❌ Cohere API error (will use fallback): {cohere_error}")
                print(f"DEBUG: Error type: {type(cohere_error)}")
                print(f"DEBUG: Error details: {str(cohere_error)}")
                
                # Generate enhanced fallback recommendation
                fallback_recommendation = generate_enhanced_fallback_recommendation(
                    scan_result, target, scan_type, security_score, risk_level, total_open_ports
                )
                scan_result.recommendation = fallback_recommendation
                scan_result.save()
                
                messages.warning(request, 
                    f"⚠ AI service temporarily unavailable (Error: {str(cohere_error)[:50]}...). "
                    f"Using enhanced backup analysis with full technical assessment.")

            # FIXED: Enhanced success messages with proper context
            total_vulns = scan_result.get_total_vulnerabilities()
            suspicious_flags = detect_suspicious_results(target, scan_result)
            
            if total_open_ports > 500:
                messages.error(request,
                    f"🚨 CRITICAL SECURITY EMERGENCY: {total_open_ports} open ports detected! "
                    f"Score: {security_score}/100, Risk: {risk_level}. "
                    f"IMMEDIATE INVESTIGATION REQUIRED!")
            elif suspicious_flags:
                messages.warning(request, 
                    f"⚠ SUSPICIOUS RESULTS DETECTED: {total_vulns} issues found "
                    f"(Score: {security_score}/100, Risk: {risk_level}). "
                    f"Manual verification essential - check detailed analysis.")
            elif scan_result.critical_count > 0:
                messages.error(request,
                    f"🚨 CRITICAL VULNERABILITIES: {scan_result.critical_count} critical issues! "
                    f"Security Score: {security_score}/100, Risk: {risk_level}. "
                    f"IMMEDIATE ACTION REQUIRED!")
            elif total_vulns > 5:
                messages.warning(request, 
                    f"⚠ MULTIPLE SECURITY ISSUES: {total_vulns} vulnerabilities detected. "
                    f"Security Score: {security_score}/100, Risk: {risk_level}. "
                    f"Systematic remediation required.")
            elif security_score >= 85:
                messages.success(request, 
                    f"✅ EXCELLENT SECURITY: Score {security_score}/100, Risk: {risk_level}. "
                    f"Strong security posture maintained. Continue current practices.")
            else:
                messages.info(request, 
                    f"📊 ASSESSMENT COMPLETE: Score {security_score}/100, Risk: {risk_level}. "
                    f"Review recommendations for optimization opportunities.")

            return redirect('scan_result', scan_id=scan_result.id)

        except ValueError as ve:
            messages.error(request, f"❌ Invalid target specified: {str(ve)}")
            print(f"ERROR: Target validation failed: {str(ve)}")
        except Exception as e:
            messages.error(request, f"❌ Scan execution failed: {str(e)}")
            print(f"ERROR: NMAP scan exception: {str(e)}")
            import traceback
            print(f"ERROR: Full traceback: {traceback.format_exc()}")

    # Enhanced form context with fixed features
    context = {
        'scan_types': [
            ('port', '🔍 Port Scan - Network service discovery with security analysis (3-5 minutes)'),
            ('vuln', '🛡 Vulnerability Scan - CVE detection and security assessment (8-12 minutes)'),
            ('os', '💻 OS Detection - System identification and fingerprinting (5-8 minutes)'),
            ('script', '📜 Script Scan - Advanced service enumeration and analysis (10-15 minutes)'),
            ('aggressive', '⚡ Aggressive Scan - Comprehensive security assessment (15-20 minutes)')
        ],
        'nmap_available': nmap_path is not None,
        'nmap_path': nmap_path,
        'enhancement_info': {
            'enabled': True,
            'version': '2.0 - FULLY FIXED',
            'features': [
                '✅ Professional NMAP network scanning with FIXED vulnerability counting',
                '✅ Advanced security scoring using realistic industry-standard metrics',
                '✅ FIXED Cohere AI integration for comprehensive security recommendations',
                '✅ Intelligent suspicious result detection for enterprise targets',
                '✅ Context-aware risk assessment with proper severity classification', 
                '✅ Enhanced error handling and comprehensive fallback analysis',
                '✅ Professional security reporting with actionable insights',
                '✅ Complete bug resolution for accurate vulnerability assessment'
            ],
            'fixes_applied': [
                'FIXED: Vulnerability counting logic - no longer counts closed ports as info',
                'FIXED: Cohere API integration - removed problematic model parameter',
                'FIXED: Security scoring algorithm - realistic calculations based on severity',
                'FIXED: Service risk classification - proper analysis of actual security risks',
                'ENHANCED: Suspicious result detection for abnormal port patterns',
                'ENHANCED: Comprehensive fallback recommendations with technical depth'
            ]
        }
    }
    
    return render(request, 'nmap_scanner/scan_form.html', context)

def generate_enhanced_fallback_recommendation(scan_result, target, scan_type, security_score, risk_level, total_open_ports):
    """ENHANCED: Generate comprehensive fallback recommendations"""
    
    total_vulns = scan_result.get_total_vulnerabilities()
    suspicious_flags = detect_suspicious_results(target, scan_result)
    
    # Create detailed vulnerability breakdown
    vuln_details = []
    if scan_result.critical_count > 0:
        vuln_details.append(f"🔴 Critical: {scan_result.critical_count}")
    if scan_result.high_count > 0:
        vuln_details.append(f"🟠 High: {scan_result.high_count}")
    if scan_result.medium_count > 0:
        vuln_details.append(f"🟡 Medium: {scan_result.medium_count}")
    if scan_result.low_count > 0:
        vuln_details.append(f"🟢 Low: {scan_result.low_count}")
    if scan_result.info_count > 0:
        vuln_details.append(f"🔵 Info: {scan_result.info_count}")
    
    vuln_summary = " | ".join(vuln_details) if vuln_details else "No significant vulnerabilities detected"
    
    # Add suspicious flags section
    suspicious_section = ""
    if suspicious_flags:
        suspicious_section = f"""

🚩 *CRITICAL SECURITY ALERTS - IMMEDIATE ATTENTION REQUIRED:*
{chr(10).join(f"   • {flag}" for flag in suspicious_flags)}

📋 *EMERGENCY VERIFICATION PROTOCOL:*
   • Perform immediate manual testing of all flagged services
   • Cross-validate results using multiple scanning tools and techniques
   • Verify if results align with expected organizational security posture
   • Investigate potential honeypots, misconfigurations, or security compromises
   • Document all findings with timestamps for incident response team
"""
    
    if total_open_ports > 500 or scan_result.critical_count > 0:
        # Critical emergency scenario
        return f"""
🚨 *CRITICAL SECURITY EMERGENCY - COMPREHENSIVE INCIDENT RESPONSE REQUIRED*

📊 *EMERGENCY ASSESSMENT SUMMARY:*
• Target: {target} ({scan_type.upper()} scan)
• Security Score: {security_score}/100 (CRITICAL LEVEL)
• Risk Classification: {risk_level}
• Open Ports Detected: {total_open_ports}
• Vulnerability Profile: {vuln_summary}{suspicious_section}

⚡ *IMMEDIATE EMERGENCY RESPONSE (NEXT 1-4 HOURS):*

*Phase 1: Crisis Assessment & Containment*
• IMMEDIATE: Activate incident response team and emergency communication protocols
• URGENT: Isolate affected systems from critical network infrastructure 
• PRIORITY: Implement emergency firewall rules to restrict all non-essential access
• CRITICAL: Begin comprehensive network traffic monitoring and threat hunting
• ESSENTIAL: Document all findings and actions for forensic analysis

*Phase 2: Threat Analysis & System Protection*
• Deploy additional monitoring on all detected services for signs of active exploitation
• Conduct emergency vulnerability assessment of all critical business systems
• Implement emergency authentication controls and access restrictions
• Prepare for potential system shutdown if compromise indicators are discovered
• Coordinate with security vendors and law enforcement if necessary

🔧 *EMERGENCY TECHNICAL REMEDIATION (NEXT 4-24 HOURS):*

*Critical Service Hardening:*
• Immediately disable or secure all unnecessary network services identified
• Apply emergency security patches to all systems with critical vulnerabilities
• Implement multi-factor authentication on all administrative access points
• Deploy emergency intrusion detection and prevention systems
• Conduct full system integrity verification and malware scanning

*Network Defense Enhancement:*
• Implement emergency network segmentation to protect critical assets
• Deploy additional firewall rules and access control policies
• Enhance logging and monitoring across all network infrastructure
• Establish secure communication channels for incident response coordination
• Prepare backup and recovery systems for potential data restoration needs

🛡 *STRATEGIC SECURITY RECOVERY (NEXT 1-7 DAYS):*

*Comprehensive Security Audit:*
• Conduct full forensic analysis of all systems and network infrastructure
• Perform comprehensive penetration testing to identify additional vulnerabilities
• Review all user accounts, access permissions, and authentication systems
• Analyze network logs for indicators of compromise or unauthorized access
• Develop detailed incident timeline and root cause analysis

*Security Architecture Rebuilding:*
• Redesign network architecture with defense-in-depth principles
• Implement zero-trust security model for all system access
• Deploy enterprise-grade security monitoring and incident response capabilities
• Establish regular security assessment and vulnerability management programs
• Create comprehensive security policies and incident response procedures

📊 *LONG-TERM SECURITY TRANSFORMATION (NEXT 1-6 MONTHS):*

*Advanced Security Program Development:*
• Implement comprehensive security operations center (SOC) capabilities
• Deploy advanced threat detection and response technologies
• Establish threat intelligence gathering and analysis capabilities
• Create security awareness training and incident response training programs
• Develop partnerships with cybersecurity experts and law enforcement

*Compliance and Governance Framework:*
• Align security practices with industry standards (ISO 27001, NIST, SOC 2)
• Implement regular third-party security audits and assessments
• Establish executive-level security governance and reporting structures
• Create legal and regulatory compliance monitoring and reporting systems
• Develop customer and stakeholder communication protocols for security incidents

This assessment indicates an extremely serious security situation requiring immediate, comprehensive emergency response across technical, operational, and strategic domains.
        """
    
    elif total_vulns > 3 or scan_result.high_count > 0 or total_open_ports > 50:
        # Significant security issues
        return f"""
⚠ *SIGNIFICANT SECURITY CONCERNS - COMPREHENSIVE REMEDIATION STRATEGY*

📊 *DETAILED SECURITY ASSESSMENT:*
• Target: {target} ({scan_type.upper()} scan)
• Security Score: {security_score}/100
• Risk Classification: {risk_level}  
• Open Ports: {total_open_ports}
• Security Issues: {vuln_summary}{suspicious_section}

🔧 *SYSTEMATIC SECURITY IMPROVEMENT PLAN:*

*Phase 1: Immediate Security Hardening (Next 1-2 Weeks)*
• Priority vulnerability remediation based on CVSS scoring and business impact
• Service configuration hardening and security baseline implementation
• Access control strengthening with multi-factor authentication deployment
• Network segmentation and firewall rule optimization for reduced attack surface
• Security monitoring and logging enhancement for improved threat detection

*Phase 2: Advanced Security Implementation (Next 3-6 Weeks)*
• Comprehensive security architecture review and improvement recommendations
• Advanced threat detection and response capability deployment and configuration
• Security automation and orchestration platform implementation
• Regular vulnerability assessment and penetration testing program establishment
• Security team training and capability development with industry certifications

*Phase 3: Security Maturity Enhancement (Next 2-4 Months)*
• Enterprise security operations center (SOC) development and staffing
• Threat intelligence integration and proactive threat hunting capabilities
• Incident response plan development, testing, and continuous improvement
• Security metrics and KPI establishment for continuous security posture monitoring
• Vendor and third-party security assessment and risk management program

🛡 *COMPREHENSIVE SECURITY FRAMEWORK DEVELOPMENT:*

*Technical Security Controls:*
• Multi-layered network security with intrusion detection and prevention systems
• Endpoint detection and response (EDR) deployment across all organizational assets
• Data encryption at rest and in transit with key management best practices
• Regular security patch management and configuration management programs
• Cloud security and hybrid infrastructure protection with zero-trust principles

*Administrative Security Controls:*
• Security policy development and enforcement with regular review and updates
• Security awareness training programs with phishing simulation and testing
• Incident response and business continuity planning with regular tabletop exercises
• Risk management framework integration with business process and decision making
• Compliance monitoring and reporting for relevant industry and regulatory standards

*Physical and Environmental Security:*
• Facility access control and monitoring with visitor management systems
• Environmental monitoring and protection for critical infrastructure components
• Secure asset disposal and data destruction procedures and documentation
• Emergency response and evacuation procedures with coordination protocols
• Physical security awareness and training for all personnel and contractors

📈 *CONTINUOUS IMPROVEMENT AND OPTIMIZATION:*

*Security Maturity Advancement:*
• Regular security maturity assessments using industry-standard frameworks
• Emerging threat research and defense strategy development
• Technology innovation evaluation and strategic security tool deployment
• Industry best practice adoption and organizational security culture development
• Security community engagement and knowledge sharing for continuous learning

This assessment provides a structured approach to addressing identified security concerns while building comprehensive security resilience and organizational security maturity.
        """
    
    else:
        # Good security posture with optimization opportunities
        return f"""
✅ *STRONG SECURITY FOUNDATION - STRATEGIC OPTIMIZATION PLAN*

📊 *SECURITY EXCELLENCE ASSESSMENT:*
• Target: {target} ({scan_type.upper()} scan)
• Security Score: {security_score}/100 (STRONG PERFORMANCE)
• Risk Classification: {risk_level}
• Network Exposure: {total_open_ports} open ports
• Security Profile: {vuln_summary}{suspicious_section}

🏆 *SECURITY LEADERSHIP RECOGNITION:*

Your network infrastructure demonstrates exceptional security practices with minimal vulnerabilities and strong defensive posture. This indicates mature security operations, effective policy implementation, and commitment to cybersecurity excellence.

📋 *STRATEGIC SECURITY OPTIMIZATION OPPORTUNITIES:*

*Advanced Security Capabilities Development (Next 3-6 Months):*
• Zero-trust architecture implementation and maturity assessment
• Advanced behavioral analytics and machine learning threat detection deployment
• Security automation and orchestration platform optimization and expansion
• Cloud security posture management and hybrid infrastructure protection enhancement
• Advanced incident response and digital forensics capability development

*Security Innovation and Excellence (Next 6-12 Months):*
• Emerging security technology evaluation, pilot programs, and strategic adoption
• Next-generation security tool integration and comprehensive platform optimization
• Threat intelligence platform deployment with proactive threat hunting capabilities
• Security research and development initiative support and industry collaboration
• Cybersecurity center of excellence establishment and knowledge leadership

*Operational Security Excellence (Ongoing):*
• Continuous security monitoring and threat landscape adaptation
• Security team advanced training and professional certification programs
• Industry security leadership and thought leadership development
• Security community contribution and knowledge sharing initiatives
• Customer and partner security collaboration and best practice sharing

🎯 *STRATEGIC SECURITY GOVERNANCE AND LEADERSHIP:*

*Security Maturity and Measurement:*
• Advanced security maturity model implementation and continuous improvement
• Executive security dashboard development with strategic KPIs and metrics
• Security investment optimization and return on investment measurement
• Risk management framework sophistication and business integration
• Security performance benchmarking against industry leaders and standards

*Organizational Security Culture Excellence:*
• Security awareness program innovation and advanced engagement strategies
• Security champion program expansion and cross-functional integration
• Security by design methodology implementation across all business processes
• Continuous learning and improvement culture development and sustainability
• Security leadership development and succession planning programs

*Industry Leadership and Innovation:*
• Cybersecurity thought leadership and industry conference participation
• Security research publication and academic collaboration initiatives
• Industry standard development and cybersecurity policy influence
• Mentorship and knowledge transfer programs for the broader security community
• Innovation in cybersecurity practices and technology advancement

🌟 *SECURITY EXCELLENCE SUSTAINABILITY:*

*Future-Proofing and Resilience:*
• Adaptive security architecture that evolves with emerging threats and technologies
• Quantum-resistant cryptography research and implementation planning
• Artificial intelligence and machine learning security applications and ethics
• Supply chain security and third-party risk management advancement
• Global security threat landscape monitoring and response capability development

Your organization represents cybersecurity excellence and leadership. Continue these outstanding practices while pioneering advanced security capabilities and contributing to the broader security community's knowledge and advancement.
        """