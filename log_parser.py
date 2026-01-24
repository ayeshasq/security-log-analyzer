import re
from datetime import datetime
from typing import Dict, List

class LogParser:
    """Parse various security log formats"""
    
    def __init__(self):
        # Common log patterns
        self.patterns = {
            'timestamp': r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',
            'ip': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'failed_login': r'(failed|unsuccessful|denied).*(login|authentication|auth)',
            'port_scan': r'(port.?scan|scanning|probe)',
            'malware': r'(malware|virus|trojan|ransomware)',
        }
    
    def parse_line(self, line: str) -> Dict:
        """Parse a single log line"""
        parsed = {
            'raw': line,
            'timestamp': self._extract_timestamp(line),
            'ips': self._extract_ips(line),
            'severity': self._determine_severity(line),
            'event_type': self._classify_event(line)
        }
        return parsed
    
    def _extract_timestamp(self, line: str):
        match = re.search(self.patterns['timestamp'], line)
        return match.group() if match else None
    
    def _extract_ips(self, line: str):
        return re.findall(self.patterns['ip'], line)
    
    def _determine_severity(self, line: str) -> str:
        line_lower = line.lower()
        if any(word in line_lower for word in ['critical', 'emergency', 'alert']):
            return 'HIGH'
        elif any(word in line_lower for word in ['error', 'warning', 'failed']):
            return 'MEDIUM'
        return 'LOW'
    
    def _classify_event(self, line: str) -> str:
        line_lower = line.lower()
        
        if re.search(self.patterns['failed_login'], line_lower):
            return 'FAILED_LOGIN'
        elif re.search(self.patterns['port_scan'], line_lower):
            return 'PORT_SCAN'
        elif re.search(self.patterns['malware'], line_lower):
            return 'MALWARE'
        elif 'firewall' in line_lower and 'block' in line_lower:
            return 'FIREWALL_BLOCK'
        
        return 'GENERAL'
    
    def parse_file(self, filepath: str) -> List[Dict]:
        """Parse entire log file"""
        parsed_logs = []
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.strip():
                    parsed_logs.append(self.parse_line(line))
        
        return parsed_logs
