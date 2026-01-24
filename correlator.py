from collections import defaultdict
from typing import List, Dict

class EventCorrelator:
    """Correlate related security events"""
    
    def __init__(self):
        self.correlation_window = 300  # 5 minutes in seconds
    
    def correlate_events(self, parsed_logs: List[Dict]) -> List[Dict]:
        """Group related events together"""
        
        # Group by IP address
        ip_events = defaultdict(list)
        for log in parsed_logs:
            for ip in log.get('ips', []):
                ip_events[ip].append(log)
        
        # Find suspicious patterns
        incidents = []
        
        for ip, events in ip_events.items():
            # Multiple failed logins
            failed_logins = [e for e in events if e['event_type'] == 'FAILED_LOGIN']
            if len(failed_logins) >= 3:
                incidents.append({
                    'type': 'BRUTE_FORCE_ATTEMPT',
                    'severity': 'HIGH',
                    'source_ip': ip,
                    'event_count': len(failed_logins),
                    'events': failed_logins,
                    'description': f'Multiple failed login attempts from {ip}'
                })
            
            # Port scanning
            port_scans = [e for e in events if e['event_type'] == 'PORT_SCAN']
            if port_scans:
                incidents.append({
                    'type': 'PORT_SCAN_DETECTED',
                    'severity': 'MEDIUM',
                    'source_ip': ip,
                    'event_count': len(port_scans),
                    'events': port_scans,
                    'description': f'Port scanning activity from {ip}'
                })
        
        return incidents
