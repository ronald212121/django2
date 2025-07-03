# COMPLETE FIXED: nmap_scanner/utils.py - Copy Paste Keseluruhan
# 🚨 GANTI SELURUH ISI FILE utils.py DENGAN KODE INI!

import nmap
import json
import re
from urllib.parse import urlparse
from core.models import ScanResult

def clean_target_for_nmap(target):
    """
    Membersihkan target URL untuk NMAP
    Menghilangkan protokol, path, dan query parameters
    """
    if re.match(r'^[\d\.]+$', target) or not ('://' in target):
        return target.strip()
    
    try:
        parsed = urlparse(target)
        hostname = parsed.hostname or parsed.netloc
        return hostname.strip() if hostname else target.strip()
    except:
        cleaned = re.sub(r'^https?://', '', target)
        cleaned = re.sub(r'/.*$', '', cleaned)
        return cleaned.strip()

def classify_vulnerability_severity(script_name, output):
    """Enhanced vulnerability severity classification"""
    script_lower = script_name.lower()
    output_lower = output.lower()
    
    # Critical vulnerabilities
    critical_indicators = [
        'ms17-010', 'eternal', 'wannacry', 'shellshock', 'heartbleed',
        'remote code execution', 'buffer overflow', 'backdoor',
        'cve-2017', 'cve-2019', 'cve-2020', 'cve-2021', 'cve-2022', 'cve-2023', 'cve-2024'
    ]
    
    if any(indicator in script_lower or indicator in output_lower for indicator in critical_indicators):
        return 'critical'
    
    # High vulnerabilities
    high_indicators = [
        'vuln', 'exploit', 'weakness', 'security', 'dangerous',
        'authentication bypass', 'privilege escalation', 'injection',
        'cross-site scripting', 'sql injection', 'directory traversal'
    ]
    
    if any(indicator in script_lower or indicator in output_lower for indicator in high_indicators):
        if 'vulnerable' in output_lower or 'exploit' in output_lower:
            return 'high'
    
    # Medium vulnerabilities
    medium_indicators = [
        'information disclosure', 'enumeration', 'fingerprint',
        'banner grabbing', 'service detection', 'brute force',
        'weak', 'insecure', 'misconfiguration'
    ]
    
    if any(indicator in script_lower or indicator in output_lower for indicator in medium_indicators):
        return 'medium'
    
    # Low vulnerabilities
    low_indicators = [
        'trace', 'options', 'methods', 'headers', 'cookie',
        'redirect', 'robots', 'sitemap'
    ]
    
    if any(indicator in script_lower or indicator in output_lower for indicator in low_indicators):
        return 'low'
    
    # Check for general vulnerability indicators
    if ('vulnerable' in output_lower or 'cve-' in output_lower or 'exploit' in output_lower):
        return 'info'
    
    return 'none'

def analyze_service_risk(service_name, port_num):
    """
    FIXED: Analyze service security risk properly
    Returns (risk_level, should_count_as_vuln) AND collects detailed vulnerability info
    """
    service_lower = service_name.lower().strip()
    
    # Skip empty service names
    if not service_lower or service_lower in ['', 'unknown']:
        return 'info', False
    
    # Critical risk services - Always security concerns
    critical_services = {
        'telnet': 'Unencrypted admin protocol - critical security risk',
        'rsh': 'Remote shell without encryption - critical risk', 
        'rlogin': 'Remote login without encryption - critical risk',
    }
    
    if service_lower in critical_services:
        return 'critical', True
    
    # High risk services - Significant security concerns
    high_risk_services = {
        'ftp': 'Unencrypted file transfer - high security risk',
        'snmp': 'Network management protocol - should not be public',
        'tftp': 'Trivial FTP - no authentication',
        'finger': 'User information service - information disclosure',
        'rpc': 'Remote procedure call - attack vector',
        'portmap': 'Port mapper service - information disclosure'
    }
    
    if service_lower in high_risk_services:
        return 'high', True
    
    # Medium risk services - Need proper security
    medium_risk_services = {
        'ssh': 'Secure admin access - needs hardening' if port_num == 22 else 'SSH service',
        'http': 'Web service - needs security headers and HTTPS',
        'pop3': 'Email service - should use encryption (POP3S)',
        'imap': 'Email service - should use encryption (IMAPS)', 
        'smtp': 'Mail transfer - needs proper authentication',
        'nntp': 'News service - information disclosure risk'
    }
    
    if service_lower in medium_risk_services:
        return 'medium', True
    
    # Low risk services - Generally acceptable but monitor
    low_risk_services = {
        'https': 'Secure web service',
        'dns': 'Domain name service',
        'domain': 'Domain name service',
        'ntp': 'Network time protocol',
        'ldaps': 'Secure directory service'
    }
    
    if service_lower in low_risk_services:
        return 'low', False  # Don't count as vulnerability
    
    # Info level - Unknown or uncommon services
    return 'info', False

def create_vulnerability_from_service(service_name, port_num, risk_level):
    """
    Create detailed vulnerability info from service analysis
    """
    service_descriptions = {
        'ftp': 'Unencrypted FTP service detected - allows plaintext authentication and data transfer',
        'telnet': 'Unencrypted Telnet service detected - transmits passwords and data in plaintext',
        'snmp': 'SNMP service exposed to public - can reveal network infrastructure information',
        'tftp': 'TFTP service detected - no authentication and transfers files in plaintext',
        'finger': 'Finger service detected - can reveal user information and system details',
        'ssh': 'SSH service detected - ensure strong authentication and latest version',
        'http': 'HTTP service detected - unencrypted web traffic, consider HTTPS',
        'pop3': 'POP3 service detected - email service without encryption',
        'imap': 'IMAP service detected - email service, should use encryption (IMAPS)',
        'smtp': 'SMTP service detected - mail transfer, ensure proper authentication',
        'nntp': 'NNTP news service detected - may expose sensitive information'
    }
    
    description = service_descriptions.get(service_name, f'{service_name.upper()} service detected')
    
    return {
        'service': service_name,
        'port': port_num,
        'severity': risk_level,
        'description': description,
        'is_vulnerability': True
    }

def store_port_vulnerabilities_to_result(result, port_vulnerabilities):
    """
    FIXED: Store port-based vulnerabilities dalam format yang bisa dibaca template
    """
    print(f"🔍 STORING {len(port_vulnerabilities)} port vulnerabilities to result")
    
    if 'vulnerabilities' not in result:
        result['vulnerabilities'] = []
    if 'network_vulnerabilities' not in result:
        result['network_vulnerabilities'] = []
    
    # Store each vulnerability
    for vuln in port_vulnerabilities:
        vuln_data = {
            'type': f"{vuln['service'].upper()} Service",
            'severity': vuln['severity'],
            'description': vuln['description'],
            'location': f"Port {vuln['port']}",
            'path': f"Port {vuln['port']}",
            'status': 'Detected',
            'category': 'network'
        }
        
        result['vulnerabilities'].append(vuln_data)
        result['network_vulnerabilities'].append(vuln_data)
        
        print(f"✅ STORED: {vuln['service']} on port {vuln['port']} - {vuln['severity']}")
    
    print(f"✅ TOTAL vulnerabilities in result: {len(result['vulnerabilities'])}")
    return result

def run_nmap_scan(target, scan_type, user):
    """
    FIXED: Complete bug resolution for NMAP scanning
    """
    # Clean target for NMAP
    cleaned_target = clean_target_for_nmap(target)
    
    print(f"DEBUG: Original target: {target}")
    print(f"DEBUG: Cleaned target for NMAP: {cleaned_target}")
    
    nm = nmap.PortScanner()
    print(f"Starting {scan_type} scan for {cleaned_target}...")
    
    try:
        # Execute NMAP scan based on type
        if scan_type == 'os':
            try:
                print("Attempting OS fingerprinting...")
                nm.scan(hosts=cleaned_target, arguments='-sV --version-intensity 5 -T4 --host-timeout 60s --max-retries 2 -p 21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3389,5900')
            except Exception as os_error:
                print(f"OS scan failed: {os_error}")
                try:
                    print("Fallback: Service detection only...")
                    nm.scan(hosts=cleaned_target, arguments='-sV --version-intensity 3 -T4 --host-timeout 30s -p 80,443,22,21,25')
                except Exception as fallback_error:
                    print(f"Service detection failed: {fallback_error}")
                    print("Last resort: Simple port scan...")
                    nm.scan(hosts=cleaned_target, arguments='-sT -T4 --host-timeout 20s -p 80,443,22')
            
        elif scan_type == 'port':
            print(f"Running port scan with timeout...")
            nm.scan(hosts=cleaned_target, arguments='-sT -T4 --host-timeout 90s -p 1-1000')
            
        elif scan_type == 'vuln':
            print(f"Running vulnerability scan...")
            try:
                args = '-sT --script http-vuln-cve* --script-timeout=30s --host-timeout=60s -T4 -p 80,443,8080'
                nm.scan(hosts=cleaned_target, arguments=args)
            except Exception as vuln_error:
                print(f"Vuln scan failed: {vuln_error}")
                try:
                    args = '-sT --script http-title,http-headers --script-timeout=15s --host-timeout=30s -T4 -p 80,443'
                    nm.scan(hosts=cleaned_target, arguments=args)
                except Exception as fallback_error:
                    print(f"Fallback failed: {fallback_error}")
                    nm.scan(hosts=cleaned_target, arguments='-sT -sV --version-intensity=3 -T4 --host-timeout=20s -p 80,443')
        
        elif scan_type == 'script':
            print(f"Running script scan...")
            nm.scan(hosts=cleaned_target, arguments='-sT -sC --script=default --script-timeout=45s --host-timeout=60s -T4 -p 80,443,22,21,25')
            
        elif scan_type == 'aggressive':
            print(f"Running aggressive scan...")
            nm.scan(hosts=cleaned_target, arguments='-sT -sV -sC --version-intensity 6 --script-timeout=60s --host-timeout=120s -T4 -p 1-1000')
            
        else:  # comprehensive
            print(f"Running comprehensive scan...")
            nm.scan(hosts=cleaned_target, arguments='-sT -sV -sC --script=default --script-timeout=60s --host-timeout=90s -T4 -p 1-1000')
        
        print(f"Scan execution completed, processing results...")
        
        # Check if any hosts were found
        all_hosts = nm.all_hosts()
        print(f"Hosts found: {all_hosts}")
        
        if not all_hosts:
            result = {
                'error': 'No hosts found in scan results',
                'scan_info': nm.scaninfo(),
                'target_attempted': target,
                'target_cleaned': cleaned_target,
                'scan_type': scan_type,
                'suggestion': 'Target may be unreachable, behind firewall, or blocking scans',
                'vulnerabilities': [],
                'application_vulnerabilities': [],
                'network_vulnerabilities': [],
                'hosts': [],
                'ports': [],
                'services': [],
                'summary': {
                    'total_hosts': 0,
                    'total_ports': 0,
                    'open_ports': 0,
                    'total_vulnerabilities': 0,
                    'status': 'no_hosts_found'
                }
            }
        else:
            # Process results for the target host
            target_host = all_hosts[0]
            print(f"Processing results for host: {target_host}")
            
            # Create host data structure
            host_data = {
                'host': target_host,
                'status': nm[target_host].get('status', {}),
                'addresses': nm[target_host].get('addresses', {}),
                'hostnames': nm[target_host].get('hostnames', []),
                'ports': []
            }
            
            # Process based on scan type
            if scan_type == 'port':
                tcp_ports = nm[target_host].get('tcp', {})
                udp_ports = nm[target_host].get('udp', {})
                
                # Convert ports to list format for template
                ports_list = []
                services_list = []
                
                # Process TCP ports
                for port_num, port_data in tcp_ports.items():
                    port_info = {
                        'port': port_num,
                        'protocol': 'tcp',
                        'state': port_data.get('state', 'unknown'),
                        'service': port_data.get('name', 'unknown'),
                        'version': port_data.get('version', ''),
                        'product': port_data.get('product', '')
                    }
                    ports_list.append(port_info)
                    if port_data.get('state') == 'open':
                        services_list.append(port_info)
                        host_data['ports'].append(port_info)
                
                # Process UDP ports
                for port_num, port_data in udp_ports.items():
                    port_info = {
                        'port': port_num,
                        'protocol': 'udp',
                        'state': port_data.get('state', 'unknown'),
                        'service': port_data.get('name', 'unknown'),
                        'version': port_data.get('version', ''),
                        'product': port_data.get('product', '')
                    }
                    ports_list.append(port_info)
                    if port_data.get('state') == 'open':
                        services_list.append(port_info)
                        host_data['ports'].append(port_info)
                
                result = {
                    'scan_successful': True,
                    'host': target_host,
                    'tcp': tcp_ports,
                    'udp': udp_ports,
                    'status': nm[target_host].get('status', {}),
                    'addresses': nm[target_host].get('addresses', {}),
                    'hostnames': nm[target_host].get('hostnames', []),
                    'open_ports': {
                        'tcp': [port for port, info in tcp_ports.items() if info.get('state') == 'open'],
                        'udp': [port for port, info in udp_ports.items() if info.get('state') == 'open']
                    },
                    'total_ports_scanned': len(tcp_ports) + len(udp_ports),
                    'target_attempted': target,
                    'target_cleaned': cleaned_target,
                    'vulnerabilities': [],
                    'application_vulnerabilities': [],
                    'network_vulnerabilities': [],
                    'hosts': [host_data],
                    'ports': ports_list,
                    'services': services_list,
                    'summary': {
                        'total_hosts': 1,
                        'total_ports': len(ports_list),
                        'open_ports': len([p for p in ports_list if p['state'] == 'open']),
                        'total_vulnerabilities': 0,
                        'status': 'completed'
                    }
                }
            
            # Handle other scan types
            elif scan_type == 'os':
                result = {
                    'scan_successful': True,
                    'host': target_host,
                    'osmatch': nm[target_host].get('osmatch', []),
                    'portused': nm[target_host].get('portused', []),
                    'status': nm[target_host].get('status', {}),
                    'addresses': nm[target_host].get('addresses', {}),
                    'hostnames': nm[target_host].get('hostnames', []),
                    'vendor': nm[target_host].get('vendor', {}),
                    'scan_method': 'os_detection',
                    'target_attempted': target,
                    'target_cleaned': cleaned_target,
                    'vulnerabilities': [],
                    'application_vulnerabilities': [],
                    'network_vulnerabilities': [],
                    'hosts': [host_data],
                    'ports': [],
                    'services': [],
                    'summary': {
                        'total_hosts': 1,
                        'total_ports': 0,
                        'open_ports': 0,
                        'total_vulnerabilities': 0,
                        'status': 'completed'
                    }
                }
                
                # Add service info if available
                tcp_ports = nm[target_host].get('tcp', {})
                for port_num, port_data in tcp_ports.items():
                    if port_data.get('state') == 'open':
                        port_info = {
                            'port': port_num,
                            'protocol': 'tcp',
                            'state': port_data.get('state', 'unknown'),
                            'service': port_data.get('name', 'unknown'),
                            'version': port_data.get('version', ''),
                            'product': port_data.get('product', '')
                        }
                        result['ports'].append(port_info)
                        result['services'].append(port_info)
                        host_data['ports'].append(port_info)
                
                result['summary']['total_ports'] = len(result['ports'])
                result['summary']['open_ports'] = len([p for p in result['ports'] if p['state'] == 'open'])
            
            elif scan_type == 'vuln':
                result = {
                    'scan_successful': True,
                    'host': target_host,
                    'tcp': nm[target_host].get('tcp', {}),
                    'udp': nm[target_host].get('udp', {}),
                    'hostscript': nm[target_host].get('hostscript', []),
                    'status': nm[target_host].get('status', {}),
                    'addresses': nm[target_host].get('addresses', {}),
                    'hostnames': nm[target_host].get('hostnames', []),
                    'vulnerability_scan_completed': True,
                    'scan_method': 'vulnerability_scripts',
                    'target_attempted': target,
                    'target_cleaned': cleaned_target,
                    'vulnerabilities': [],
                    'application_vulnerabilities': [],
                    'network_vulnerabilities': [],
                    'hosts': [host_data],
                    'ports': [],
                    'services': [],
                    'summary': {
                        'total_hosts': 1,
                        'total_ports': 0,
                        'open_ports': 0,
                        'total_vulnerabilities': 0,
                        'status': 'completed'
                    }
                }
            
            else:  # comprehensive, script, aggressive
                result = {
                    'scan_successful': True,
                    'host': target_host,
                    'scan_method': f'{scan_type}_scan',
                    'target_attempted': target,
                    'target_cleaned': cleaned_target,
                    'vulnerabilities': [],
                    'application_vulnerabilities': [],
                    'network_vulnerabilities': [],
                    'hosts': [host_data],
                    'ports': [],
                    'services': [],
                    'summary': {
                        'total_hosts': 1,
                        'total_ports': 0,
                        'open_ports': 0,
                        'total_vulnerabilities': 0,
                        'status': 'completed'
                    },
                    **nm[target_host]
                }
                
    except Exception as e:
        print(f"NMAP scan exception: {e}")
        result = {
            'error': f'Scan failed: {str(e)}',
            'scan_type': scan_type,
            'target': target,
            'target_attempted': target,
            'target_cleaned': cleaned_target,
            'error_details': 'Scan failed - timeout, network error, or target unreachable',
            'suggestion': 'Target may be blocking scans or unreachable. Try a different scan type or check connectivity.',
            'vulnerabilities': [],
            'application_vulnerabilities': [],
            'network_vulnerabilities': [],
            'hosts': [],
            'ports': [],
            'services': [],
            'summary': {
                'total_hosts': 0,
                'total_ports': 0,
                'open_ports': 0,
                'total_vulnerabilities': 0,
                'status': 'error'
            }
        }
    
    print(f"Starting FIXED vulnerability parsing...")
    
    # FIXED: Proper vulnerability counting + detailed port vulnerability collection
    low, medium, high, critical, info = 0, 0, 0, 0, 0
    port_vulnerabilities = []  # FIXED: Collect detailed vulnerability info
    
    if 'error' not in result and 'scan_successful' in result:
        print(f"Parsing {scan_type} scan results with FIXED counting logic...")
        
        # Check TCP ports with FIXED logic
        if 'tcp' in result:
            tcp_ports = result['tcp']
            print(f"Checking {len(tcp_ports)} TCP ports with FIXED analysis...")
            
            open_ports_analyzed = 0
            for port_num, port_data in tcp_ports.items():
                if isinstance(port_data, dict) and port_data.get('state') == 'open':
                    open_ports_analyzed += 1
                    service_name = port_data.get('name', '').lower()
                    
                    # FIXED: Use proper service risk analysis
                    risk_level, is_vulnerability = analyze_service_risk(service_name, port_num)
                    
                    if is_vulnerability:
                        # FIXED: Create detailed vulnerability info for storage
                        vuln_info = create_vulnerability_from_service(service_name, port_num, risk_level)
                        port_vulnerabilities.append(vuln_info)
                        print(f"✅ ADDED to port_vulnerabilities: {service_name} on port {port_num}")
                        
                        if risk_level == 'critical':
                            critical += 1
                            print(f"CRITICAL service: {service_name} on port {port_num}")
                        elif risk_level == 'high':
                            high += 1
                            print(f"HIGH-risk service: {service_name} on port {port_num}")
                        elif risk_level == 'medium':
                            medium += 1
                            print(f"MEDIUM-risk service: {service_name} on port {port_num}")
                        elif risk_level == 'low':
                            low += 1
                            print(f"LOW-risk service: {service_name} on port {port_num}")
                    else:
                        # Only log monitoring for known services
                        if service_name and service_name not in ['', 'unknown']:
                            print(f"Service monitored: {service_name} on port {port_num}")
                    
                    # Check for script vulnerabilities
                    if 'script' in port_data:
                        scripts = port_data['script']
                        print(f"Port {port_num} has {len(scripts)} scripts to analyze")
                        
                        for script_name, output in scripts.items():
                            if isinstance(output, str):
                                severity = classify_vulnerability_severity(script_name, output)
                                if severity != 'none':
                                    print(f"Script vulnerability: {script_name} - Severity: {severity}")
                                    
                                    if severity == 'critical':
                                        critical += 1
                                    elif severity == 'high':
                                        high += 1
                                    elif severity == 'medium':
                                        medium += 1
                                    elif severity == 'low':
                                        low += 1
                                    else:
                                        info += 1
            
            print(f"FIXED: Analyzed {open_ports_analyzed} open ports (not all {len(tcp_ports)} scanned ports)")
        
        # Check UDP ports with FIXED logic
        if 'udp' in result:
            udp_ports = result['udp']
            print(f"Checking {len(udp_ports)} UDP ports with FIXED analysis...")
            
            for port_num, port_data in udp_ports.items():
                if isinstance(port_data, dict) and port_data.get('state') == 'open':
                    service_name = port_data.get('name', '').lower()
                    risk_level, is_vulnerability = analyze_service_risk(service_name, port_num)
                    
                    if is_vulnerability:
                        # FIXED: Create detailed vulnerability info for UDP services
                        vuln_info = create_vulnerability_from_service(service_name, port_num, risk_level)
                        port_vulnerabilities.append(vuln_info)
                        
                        if risk_level == 'high':
                            high += 1
                            print(f"HIGH-risk UDP service: {service_name} on port {port_num}")
                        elif risk_level == 'medium':
                            medium += 1
                            print(f"MEDIUM-risk UDP service: {service_name} on port {port_num}")
                        elif risk_level == 'low':
                            low += 1
                            print(f"LOW-risk UDP service: {service_name} on port {port_num}")
        
        # Check hostscript results
        if 'hostscript' in result:
            hostscripts = result['hostscript']
            print(f"Checking {len(hostscripts)} host scripts...")
            
            for script in hostscripts:
                if isinstance(script, dict) and 'output' in script:
                    script_name = script.get('id', '')
                    output = script['output']
                    severity = classify_vulnerability_severity(script_name, output)
                    
                    if severity != 'none':
                        print(f"Host vulnerability: {script_name} - Severity: {severity}")
                        
                        if severity == 'critical':
                            critical += 1
                        elif severity == 'high':
                            high += 1
                        elif severity == 'medium':
                            medium += 1
                        elif severity == 'low':
                            low += 1
                        else:
                            info += 1
        
        # FIXED: Add suspicious pattern detection for abnormal port counts
        total_open_ports = len(result.get('open_ports', {}).get('tcp', [])) + len(result.get('open_ports', {}).get('udp', []))
        if total_open_ports > 100:
            info += 1  # Add one info item about suspicious port count
            print(f"SUSPICIOUS: {total_open_ports} open ports detected - may indicate misconfiguration or honeypot")
        
        # FIXED: Store port vulnerabilities to result JSON BEFORE saving
        print(f"🔍 Before storage - port_vulnerabilities length: {len(port_vulnerabilities)}")
        print(f"🔍 port_vulnerabilities content: {[v['service'] + ':' + str(v['port']) for v in port_vulnerabilities]}")
        
        result = store_port_vulnerabilities_to_result(result, port_vulnerabilities)
        
        # Verify storage
        stored_vulns = len(result.get('vulnerabilities', []))
        print(f"🔍 After storage - result['vulnerabilities'] length: {stored_vulns}")
        
        # Update summary with FIXED vulnerability count
        if 'summary' in result:
            result['summary']['total_vulnerabilities'] = critical + high + medium + low
        
        print(f"FINAL FIXED count - Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}, Info: {info}")
        print(f"STORED {len(port_vulnerabilities)} port vulnerabilities to result JSON")
    
    # Store the scan result with FIXED counts
    print(f"Saving FIXED scan result to database...")
    scan_result = ScanResult(
        user=user,
        target=target,
        tool='nmap',
        scan_type=scan_type,
        result=json.dumps(result, default=str, indent=2),
        low_count=low,
        medium_count=medium,
        high_count=high,
        critical_count=critical,
        info_count=info
    )
    scan_result.save()
    
    print(f"FIXED scan result saved for {target} - Type: {scan_type}, ID: {scan_result.id}")
    print(f"FINAL COUNTS: C={critical}, H={high}, M={medium}, L={low}, I={info}")
    return scan_result