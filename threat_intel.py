import os
import requests
from typing import Dict
from dotenv import load_dotenv

load_dotenv()

class ThreatIntelligence:
    """Check IPs against threat intelligence databases"""
    
    def __init__(self):
        self.api_key = os.getenv('ABUSEIPDB_API_KEY')
        self.use_mock = True  # Always use mock for free tier
        
    def check_ip(self, ip_address: str) -> Dict:
        """Check IP reputation"""
        
        # Use mock data (no API calls needed)
        return self._mock_ip_check(ip_address)
    
    def _mock_ip_check(self, ip_address: str) -> Dict:
        """Mock data for testing without API"""
        
        mock_data = {
            '198.51.100.23': {
                'abuse_score': 95,
                'country': 'RU',
                'isp': 'Unknown Hosting Provider',
                'is_tor': False,
                'is_vpn': True,
                'total_reports': 234,
                'threat_level': 'CRITICAL',
                'is_malicious': True
            },
            '203.0.113.50': {
                'abuse_score': 72,
                'country': 'CN',
                'isp': 'China Telecom',
                'is_tor': False,
                'is_vpn': False,
                'total_reports': 89,
                'threat_level': 'HIGH',
                'is_malicious': True
            },
            '45.33.32.156': {
                'abuse_score': 88,
                'country': 'Unknown',
                'isp': 'Bulletproof Hosting',
                'is_tor': True,
                'is_vpn': False,
                'total_reports': 456,
                'threat_level': 'CRITICAL',
                'is_malicious': True
            },
            '192.168.1.100': {
                'abuse_score': 82,
                'country': 'RU',
                'isp': 'Suspicious Hosting',
                'is_tor': False,
                'is_vpn': True,
                'total_reports': 156,
                'threat_level': 'HIGH',
                'is_malicious': True
            }
        }
        
        if ip_address in mock_data:
            result = mock_data[ip_address].copy()
            result['ip'] = ip_address
            return result
        
        return {
            'ip': ip_address,
            'abuse_score': 15,
            'country': 'US',
            'isp': 'Generic ISP',
            'is_tor': False,
            'is_vpn': False,
            'total_reports': 2,
            'threat_level': 'LOW',
            'is_malicious': False
        }
    
    def enrich_incident(self, incident: Dict) -> Dict:
        """Add threat intelligence to incident"""
        
        source_ip = incident.get('source_ip', 'unknown')
        
        if source_ip != 'unknown' and not source_ip.startswith('user:'):
            threat_data = self.check_ip(source_ip)
            incident['threat_intel'] = threat_data
            
            if threat_data['is_malicious'] and incident['severity'] != 'CRITICAL':
                incident['original_severity'] = incident['severity']
                incident['severity'] = 'HIGH'
                incident['severity_upgraded'] = True
        
        return incident
