import re
from datetime import datetime
from typing import Dict, List
from collections import defaultdict

class AdvancedLogParser:
    """Enterprise-grade log parser for Splunk, CloudTrail, Azure AD, and more"""
    
    def __init__(self):
        # Enhanced patterns for enterprise logs
        self.patterns = {
            # Basic patterns
            'timestamp': r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',
            'ip': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            
            # Key-value patterns (Splunk style)
            'kv_pair': r'(\w+)=([^\s]+)',
            
            # Attack patterns
            'failed_login': r'(failed|failure|unsuccessful|denied).*(login|authentication|auth|signin)',
            'brute_force': r'(brute.?force|multiple.?attempts|repeated.?failures)',
            'privilege_escalation': r'(privilege.?escalation|sudo|admin.?access|elevate)',
            'ransomware': r'(ransomware|crypto|encrypted|ransom|locker)',
            'malware': r'(malware|virus|trojan|backdoor|rootkit)',
            'port_scan': r'(port.?scan|scanning|probe|reconnaissance)',
            'mfa_bypass': r'(mfa.?bypass|2fa.?bypass|multi.?factor.?bypass)',
            'data_exfil': r'(exfiltration|data.?transfer|large.?upload|suspicious.?download)',
            'lateral_movement': r'(lateral.?movement|pass.?the.?hash|smb|rdp.?connection)',
            'command_injection': r'(command.?injection|code.?injection|arbitrary.?code)',
            
            # Cloud-specific
            'aws_event': r'(CloudTrail|IAM|S3|EC2|Lambda)',
            'azure_event': r'(AzureAD|Azure Active Directory|SignIn)',
            'gcp_event': r'(GCP|Cloud Audit|Stackdriver)',
        }
        
        # MITRE ATT&CK mapping
        self.mitre_mapping = {
            'BRUTE_FORCE': 'T1110 - Brute Force',
            'PRIVILEGE_ESCALATION': 'T1068 - Privilege Escalation',
            'RANSOMWARE': 'T1486 - Data Encrypted for Impact',
            'CREDENTIAL_ACCESS': 'T1078 - Valid Accounts',
            'MFA_BYPASS': 'T1556 - Modify Authentication Process',
            'LATERAL_MOVEMENT': 'T1021 - Remote Services',
            'DATA_EXFILTRATION': 'T1041 - Exfiltration Over C2 Channel',
            'MALWARE': 'T1204 - User Execution',
            'PORT_SCAN': 'T1046 - Network Service Scanning',
        }
    
    def parse_line(self, line: str) -> Dict:
        """Parse a single log line - supports multiple formats"""
        
        # Extract key-value pairs (Splunk/Elastic style)
        kv_data = {}
        for match in re.finditer(self.patterns['kv_pair'], line):
            key, value = match.groups()
            kv_data[key.lower()] = value
        
        # Basic extraction
        parsed = {
            'raw': line,
            'timestamp': self._extract_timestamp(line),
            'ips': self._extract_ips(line),
            'kv_data': kv_data,
            'severity': self._determine_severity(line, kv_data),
            'event_type': self._classify_event(line, kv_data),
            'platform': self._detect_platform(line),
            'mitre_technique': None
        }
        
        # Add MITRE mapping
        if parsed['event_type'] and parsed['event_type'] in self.mitre_mapping:
            parsed['mitre_technique'] = self.mitre_mapping[parsed['event_type']]
        
        return parsed
    
    def _extract_timestamp(self, line: str):
        match = re.search(self.patterns['timestamp'], line)
        return match.group() if match else None
    
    def _extract_ips(self, line: str):
        ips = re.findall(self.patterns['ip'], line)
        return ips if ips else []
    
    def _detect_platform(self, line: str) -> str:
        """Detect log source platform"""
        line_lower = line.lower()
        
        if re.search(self.patterns['aws_event'], line):
            return 'AWS'
        elif re.search(self.patterns['azure_event'], line):
            return 'Azure'
        elif re.search(self.patterns['gcp_event'], line):
            return 'GCP'
        elif 'splunk' in line_lower or 'index=' in line_lower:
            return 'Splunk'
        elif 'syslog' in line_lower:
            return 'Syslog'
        
        return 'Generic'
    
    def _determine_severity(self, line: str, kv_data: Dict) -> str:
        """Determine severity with enhanced logic"""
        line_lower = line.lower()
        
        # Check explicit severity in KV data
        if 'severity' in kv_data:
            sev = kv_data['severity'].upper()
            if sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                return sev
        
        # Critical keywords
        if any(word in line_lower for word in ['critical', 'emergency', 'ransomware', 'breach', 'compromise']):
            return 'CRITICAL'
        
        # High severity keywords
        if any(word in line_lower for word in ['alert', 'attack', 'exploit', 'failed', 'denied', 'blocked', 'malware', 'escalation']):
            return 'HIGH'
        
        # Medium severity
        if any(word in line_lower for word in ['warning', 'suspicious', 'unusual', 'attempt']):
            return 'MEDIUM'
        
        return 'LOW'
    
    def _classify_event(self, line: str, kv_data: Dict) -> str:
        """Enhanced event classification"""
        line_lower = line.lower()
        
        # Check KV data first
        action = kv_data.get('action', '').lower()
        threat = kv_data.get('threat', '').lower()
        event_type = kv_data.get('eventname', '').lower()
        
        # Ransomware/Malware (HIGHEST PRIORITY)
        if re.search(self.patterns['ransomware'], line_lower) or 'ransomware' in threat:
            return 'RANSOMWARE'
        
        if re.search(self.patterns['malware'], line_lower) or any(m in threat for m in ['malware', 'virus', 'trojan']):
            return 'MALWARE'
        
        # MFA Bypass
        if re.search(self.patterns['mfa_bypass'], line_lower):
            return 'MFA_BYPASS'
        
        # Privilege Escalation
        if re.search(self.patterns['privilege_escalation'], line_lower) or 'privilegeescalation' in event_type:
            return 'PRIVILEGE_ESCALATION'
        
        # Failed Login / Auth
        if re.search(self.patterns['failed_login'], line_lower) or action in ['failed_login', 'failure', 'denied']:
            return 'FAILED_LOGIN'
        
        # Brute Force
        if re.search(self.patterns['brute_force'], line_lower):
            return 'BRUTE_FORCE'
        
        # Cloud-specific events
        if 'consolelogin' in event_type and 'failure' in line_lower:
            return 'CLOUD_LOGIN_FAILURE'
        
        if 'createaccesskey' in event_type or 'createsecret' in event_type:
            return 'CREDENTIAL_CREATION'
        
        # Port Scan
        if re.search(self.patterns['port_scan'], line_lower):
            return 'PORT_SCAN'
        
        # Firewall blocks
        if 'firewall' in line_lower and any(w in action for w in ['block', 'denied', 'drop']):
            return 'FIREWALL_BLOCK'
        
        # Data exfiltration
        if re.search(self.patterns['data_exfil'], line_lower):
            return 'DATA_EXFILTRATION'
        
        return 'GENERAL'
    
    def parse_file(self, filepath: str) -> List[Dict]:
        """Parse entire log file"""
        parsed_logs = []
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.strip():
                    parsed_logs.append(self.parse_line(line))
        
        return parsed_logs


# Keep old LogParser class for backward compatibility
class LogParser(AdvancedLogParser):
    """Alias for backward compatibility"""
    pass
