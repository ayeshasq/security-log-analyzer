from collections import defaultdict
from typing import List, Dict

class EventCorrelator:
    """Advanced event correlation for enterprise attacks"""
    
    def __init__(self):
        self.brute_force_threshold = 3
        self.time_window = 300  # 5 minutes
    
    def correlate_events(self, parsed_logs: List[Dict]) -> List[Dict]:
        """Correlate events to detect sophisticated attacks"""
        
        incidents = []
        
        # Group by source IP
        ip_events = defaultdict(list)
        for log in parsed_logs:
            for ip in log.get('ips', []):
                ip_events[ip].append(log)
            
            # Also track by user if in KV data
            user = log.get('kv_data', {}).get('user')
            if user:
                ip_events[f"user:{user}"].append(log)
        
        # Detect Brute Force Attacks
        for key, events in ip_events.items():
            failed_logins = [e for e in events if e['event_type'] == 'FAILED_LOGIN']
            
            if len(failed_logins) >= self.brute_force_threshold:
                incidents.append({
                    'type': 'BRUTE_FORCE',
                    'severity': 'HIGH',
                    'source_ip': key,
                    'event_count': len(failed_logins),
                    'events': failed_logins,
                    'description': f'Brute force attack detected from {key}',
                    'mitre': 'T1110 - Brute Force',
                    'recommendations': [
                        f'Block IP/user: {key}',
                        'Enable account lockout policies',
                        'Implement MFA',
                        'Review authentication logs for past 24 hours'
                    ]
                })
        
        # Detect Port Scans
        for ip, events in ip_events.items():
            if ip.startswith('user:'):
                continue
            
            port_scans = [e for e in events if e['event_type'] == 'PORT_SCAN']
            firewall_blocks = [e for e in events if e['event_type'] == 'FIREWALL_BLOCK']
            
            if port_scans or len(firewall_blocks) >= 3:
                incidents.append({
                    'type': 'PORT_SCAN_DETECTED',
                    'severity': 'MEDIUM',
                    'source_ip': ip,
                    'event_count': len(port_scans) + len(firewall_blocks),
                    'events': port_scans + firewall_blocks,
                    'description': f'Network reconnaissance from {ip}',
                    'mitre': 'T1046 - Network Service Scanning',
                    'recommendations': [
                        f'Block IP: {ip}',
                        'Review firewall rules',
                        'Check for successful connections',
                        'Enable IDS/IPS'
                    ]
                })
        
        # Detect Ransomware/Malware
        ransomware_events = [e for e in parsed_logs if e['event_type'] == 'RANSOMWARE']
        malware_events = [e for e in parsed_logs if e['event_type'] == 'MALWARE']
        
        if ransomware_events:
            incidents.append({
                'type': 'RANSOMWARE_DETECTED',
                'severity': 'CRITICAL',
                'source_ip': ransomware_events[0].get('ips', ['unknown'])[0] if ransomware_events[0].get('ips') else 'unknown',
                'event_count': len(ransomware_events),
                'events': ransomware_events,
                'description': 'CRITICAL: Ransomware activity detected',
                'mitre': 'T1486 - Data Encrypted for Impact',
                'recommendations': [
                    '🚨 IMMEDIATE: Isolate infected systems',
                    'Disable network shares',
                    'Check backups',
                    'Contact incident response team',
                    'Do NOT pay ransom',
                    'Preserve forensic evidence'
                ]
            })
        
        if malware_events:
            incidents.append({
                'type': 'MALWARE_DETECTED',
                'severity': 'HIGH',
                'source_ip': malware_events[0].get('ips', ['unknown'])[0] if malware_events[0].get('ips') else 'unknown',
                'event_count': len(malware_events),
                'events': malware_events,
                'description': 'Malware detected on endpoint',
                'mitre': 'T1204 - User Execution',
                'recommendations': [
                    'Quarantine affected systems',
                    'Run full system scan',
                    'Check for lateral movement',
                    'Review recent file modifications'
                ]
            })
        
        # Detect MFA Bypass
        mfa_bypass = [e for e in parsed_logs if e['event_type'] == 'MFA_BYPASS']
        if mfa_bypass:
            incidents.append({
                'type': 'MFA_BYPASS_ATTEMPT',
                'severity': 'HIGH',
                'source_ip': mfa_bypass[0].get('ips', ['unknown'])[0] if mfa_bypass[0].get('ips') else 'unknown',
                'event_count': len(mfa_bypass),
                'events': mfa_bypass,
                'description': 'MFA bypass attempt detected',
                'mitre': 'T1556 - Modify Authentication Process',
                'recommendations': [
                    'Review MFA configuration',
                    'Check for compromised credentials',
                    'Enable conditional access',
                    'Investigate user account'
                ]
            })
        
        # Detect Privilege Escalation
        priv_esc = [e for e in parsed_logs if e['event_type'] == 'PRIVILEGE_ESCALATION']
        if priv_esc:
            incidents.append({
                'type': 'PRIVILEGE_ESCALATION',
                'severity': 'HIGH',
                'source_ip': priv_esc[0].get('ips', ['unknown'])[0] if priv_esc[0].get('ips') else 'unknown',
                'event_count': len(priv_esc),
                'events': priv_esc,
                'description': 'Privilege escalation attempt detected',
                'mitre': 'T1068 - Exploitation for Privilege Escalation',
                'recommendations': [
                    'Review user permissions',
                    'Check for vulnerabilities',
                    'Audit privileged accounts',
                    'Implement least privilege'
                ]
            })
        
        # Detect Cloud Credential Abuse
        cloud_failures = [e for e in parsed_logs if e['event_type'] == 'CLOUD_LOGIN_FAILURE']
        cred_creation = [e for e in parsed_logs if e['event_type'] == 'CREDENTIAL_CREATION']
        
        if cloud_failures and cred_creation:
            # Check if from same IP
            failure_ips = set()
            for event in cloud_failures:
                failure_ips.update(event.get('ips', []))
            
            creation_ips = set()
            for event in cred_creation:
                creation_ips.update(event.get('ips', []))
            
            common_ips = failure_ips & creation_ips
            
            if common_ips:
                incidents.append({
                    'type': 'CLOUD_CREDENTIAL_ABUSE',
                    'severity': 'CRITICAL',
                    'source_ip': list(common_ips)[0],
                    'event_count': len(cloud_failures) + len(cred_creation),
                    'events': cloud_failures + cred_creation,
                    'description': 'Cloud credential compromise pattern detected',
                    'mitre': 'T1078 - Valid Accounts',
                    'recommendations': [
                        '🚨 CRITICAL: Rotate all access keys immediately',
                        'Review CloudTrail/Azure AD logs',
                        'Check for unauthorized resources',
                        'Enable MFA on all accounts',
                        'Review IAM policies'
                    ]
                })
        
        return incidents
