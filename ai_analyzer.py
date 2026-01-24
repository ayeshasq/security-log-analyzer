import os
from anthropic import Anthropic
from dotenv import load_dotenv
from typing import Dict, List

load_dotenv()

class AIAnalyzer:
    """Use Claude to analyze and summarize security incidents"""
    
    def __init__(self):
        # SET THIS TO False WHEN YOU HAVE API CREDITS
        self.use_mock = True
        
        if not self.use_mock:
            self.client = Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
    
    def analyze_incident(self, incident: Dict) -> str:
        """Generate human-readable analysis of security incident"""
        
        # MOCK RESPONSE (doesn't use API credits)
        if self.use_mock:
            return self._generate_mock_analysis(incident)
        
        # REAL API CALL (requires credits)
        prompt = f"""You are a security analyst. Analyze this security incident and provide:

1. **Incident Summary**: Brief overview
2. **Threat Level**: Assessment of severity
3. **Recommended Actions**: What should be done
4. **Technical Details**: Key technical information

Incident Data:
- Type: {incident['type']}
- Severity: {incident['severity']}
- Source IP: {incident.get('source_ip', 'N/A')}
- Event Count: {incident['event_count']}
- Description: {incident['description']}

Sample Events:
{self._format_events(incident['events'][:3])}

Provide a clear, actionable security report."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return response.content[0].text
    
    def _generate_mock_analysis(self, incident: Dict) -> str:
        """Generate realistic mock analysis without using API"""
        
        severity = incident['severity']
        incident_type = incident['type']
        source_ip = incident.get('source_ip', 'unknown')
        event_count = incident['event_count']
        
        # Customize response based on incident type
        if incident_type == 'BRUTE_FORCE_ATTEMPT':
            return f"""**Incident Summary**: 
A brute force authentication attack was detected originating from IP address {source_ip}. The attacker made {event_count} failed login attempts targeting multiple user accounts including admin, root, and administrator. This pattern indicates an automated attack attempting to gain unauthorized system access through credential guessing.

**Threat Level**: {severity} - Immediate Action Required
This represents a serious security threat. Brute force attacks are often precursors to more sophisticated intrusions. The use of common administrative usernames suggests the attacker is targeting privileged accounts, which if compromised, could lead to complete system takeover.

**Recommended Actions**:
1. **Immediately block IP address {source_ip}** at the firewall and network perimeter
2. **Review all authentication logs** from the past 24 hours for this IP and related patterns
3. **Implement account lockout policies** - lock accounts after 3-5 failed attempts for 15-30 minutes
4. **Enable multi-factor authentication (MFA)** for all administrative accounts
5. **Notify the security operations team** and incident response personnel
6. **Monitor for lateral movement** - check if any accounts were successfully compromised
7. **Consider implementing rate limiting** on authentication endpoints

**Technical Details**:
- Attack Vector: Network-based brute force authentication attack
- Target: SSH/Remote login services
- Source IP: {source_ip}
- Targeted Accounts: admin, root, administrator (high-privilege accounts)
- Attack Duration: Concentrated within minutes, indicating automated tooling
- Pattern Indicators: Sequential failed attempts, common username enumeration
- Risk Assessment: High probability of continued attacks; attacker may attempt from different IPs"""

        elif incident_type == 'PORT_SCAN_DETECTED':
            return f"""**Incident Summary**: 
Port scanning activity was detected from {source_ip}, probing ports in the range 22-1024. This reconnaissance activity suggests an attacker is mapping your network infrastructure to identify potential entry points and vulnerable services. Port 22 (SSH) and 445 (SMB) were specifically targeted, which are common attack vectors.

**Threat Level**: {severity} - Prompt Investigation Required
While port scanning itself doesn't compromise systems, it's typically the first phase of a targeted attack. The attacker is gathering intelligence about your network topology and exposed services to plan subsequent exploitation attempts.

**Recommended Actions**:
1. **Block source IP {source_ip}** to prevent further reconnaissance
2. **Review firewall rules** to ensure unnecessary ports are closed
3. **Analyze scan patterns** to determine if attacker found any open ports
4. **Check IDS/IPS logs** for any subsequent exploitation attempts
5. **Verify that critical services** (SSH, SMB, RDP) are properly secured and not exposed to untrusted networks
6. **Implement network segmentation** to limit lateral movement if penetration occurs
7. **Enable verbose logging** on border devices to track attacker behavior

**Technical Details**:
- Scan Type: Sequential port scan (indicates methodical reconnaissance)
- Ports Targeted: 22-1024 (well-known service ports)
- Key Services Probed: SSH (22), SMB (445)
- Firewall Response: Successfully blocked connection attempts
- Origin: {source_ip}
- Scan Velocity: {event_count} events detected
- Threat Intelligence: Check if this IP is associated with known threat actor groups or botnets"""

        elif incident_type == 'MALWARE':
            return f"""**Incident Summary**: 
Malware activity was detected on the network with {event_count} related events. A malicious file download was identified from {source_ip}, and ransomware signatures were subsequently detected on WORKSTATION-05. This indicates an active infection that poses immediate risk to data integrity and business operations.

**Threat Level**: CRITICAL - Emergency Response Required
Ransomware attacks can encrypt critical business data within minutes and spread laterally across the network. Immediate containment is essential to prevent catastrophic data loss and operational disruption.

**Recommended Actions**:
1. **IMMEDIATE**: Isolate infected host WORKSTATION-05 from the network
2. **IMMEDIATE**: Block all traffic to/from {source_ip} at perimeter firewalls
3. **Identify patient zero** - determine initial infection vector
4. **Scan all systems** for indicators of compromise (IOCs)
5. **Disable file sharing and administrative shares** temporarily
6. **Restore from clean backups** if available (verify backup integrity first)
7. **Do NOT pay ransom** - contact law enforcement and cyber insurance provider
8. **Preserve forensic evidence** - create disk images before remediation
9. **Activate incident response plan** and notify executive leadership
10. **Monitor for data exfiltration** - ransomware often steals data before encrypting

**Technical Details**:
- Malware Family: Ransomware (file encryption threat)
- Initial Vector: Malicious file download from {source_ip}
- Affected Systems: WORKSTATION-05 (confirmed), potential lateral spread
- Severity Classification: Critical/Emergency
- Data at Risk: All files accessible to infected user account
- Network Containment: Requires immediate isolation
- Recovery Strategy: Restore from verified clean backups; rebuild compromised systems
- Post-Incident: Full security audit, user awareness training, endpoint detection improvement"""

        else:
            # Generic response for other incident types
            return f"""**Incident Summary**: 
A {incident_type} security incident was detected from {source_ip} with {event_count} related events. {incident['description']}

**Threat Level**: {severity}
This incident requires {"immediate" if severity == "HIGH" else "prompt"} attention from the security team.

**Recommended Actions**:
1. Investigate the source IP address {source_ip}
2. Review related logs and correlate with other security events
3. Implement appropriate blocking or filtering rules
4. Monitor for similar patterns or escalation
5. Document findings in the incident management system

**Technical Details**:
- Incident Type: {incident_type}
- Source: {source_ip}
- Event Count: {event_count}
- Detection Pattern: {incident['description']}"""
    
    def _format_events(self, events: List[Dict]) -> str:
        """Format events for the prompt"""
        formatted = []
        for i, event in enumerate(events, 1):
            formatted.append(f"{i}. {event['raw'][:200]}")
        return "\n".join(formatted)
    
    def generate_executive_summary(self, incidents: List[Dict]) -> str:
        """Generate overall security summary"""
        
        # MOCK RESPONSE
        if self.use_mock:
            return self._generate_mock_summary(incidents)
        
        # REAL API CALL
        prompt = f"""You are a CISO preparing a security report. Given these incidents, create an executive summary:

Total Incidents: {len(incidents)}

Incident Breakdown:
{self._format_incident_summary(incidents)}

Provide:
1. **Executive Summary**: High-level overview for leadership
2. **Key Findings**: Most critical issues
3. **Risk Assessment**: Overall security posture
4. **Priority Recommendations**: Top 3 actions to take

Keep it concise and business-focused."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return response.content[0].text
    
    def _generate_mock_summary(self, incidents: List[Dict]) -> str:
        """Generate realistic executive summary without using API"""
        
        high_count = sum(1 for i in incidents if i['severity'] == 'HIGH')
        medium_count = sum(1 for i in incidents if i['severity'] == 'MEDIUM')
        
        incident_types = [i['type'] for i in incidents]
        
        return f"""**EXECUTIVE SUMMARY**

Analysis of security logs has identified {len(incidents)} significant security incidents requiring immediate attention. The current threat landscape indicates active reconnaissance and attack attempts targeting our infrastructure.

**SECURITY POSTURE**: {"CRITICAL" if high_count > 0 else "ELEVATED"}

**KEY FINDINGS**:

1. **Active Attack Attempts**: {high_count} high-severity and {medium_count} medium-severity incidents detected
2. **Attack Types Identified**: {', '.join(set(incident_types))}
3. **Threat Actors**: Multiple source IPs indicate either coordinated attack or opportunistic scanning
4. **Current Defenses**: Firewall and detection systems are functioning but require policy updates

**RISK ASSESSMENT**:

The combination of brute force authentication attempts and network reconnaissance suggests we are being actively targeted. The detection of these incidents demonstrates our monitoring capabilities are working, but the volume and sophistication indicate we should elevate our security posture.

Critical concerns:
- Exposed services are being actively probed
- Administrative accounts are being targeted
- Attack patterns suggest automated tooling or coordinated efforts

**PRIORITY RECOMMENDATIONS**:

1. **Immediate (Next 24 Hours)**:
   - Block all identified malicious IP addresses
   - Implement account lockout policies on authentication systems
   - Verify multi-factor authentication is enabled on all privileged accounts

2. **Short-term (This Week)**:
   - Conduct comprehensive review of firewall rules and close unnecessary ports
   - Deploy additional endpoint detection and response (EDR) tools
   - Initiate security awareness training focused on authentication security

3. **Strategic (This Month)**:
   - Implement network segmentation to limit lateral movement
   - Deploy deception technology (honeypots) to detect reconnaissance
   - Engage external penetration testing to validate defenses

**BUSINESS IMPACT**:
Without prompt remediation, these attack patterns could escalate to system compromise, data breach, or operational disruption. Estimated risk exposure is HIGH based on the targeting of administrative accounts and critical services.

**NEXT STEPS**:
The Security Operations Center (SOC) should convene an incident response meeting to coordinate immediate mitigation efforts. All findings have been documented and are available for detailed technical review."""
    
    def _format_incident_summary(self, incidents: List[Dict]) -> str:
        summary = []
        for inc in incidents:
            summary.append(f"- {inc['type']}: {inc['severity']} severity, {inc['event_count']} events")
        return "\n".join(summary)
