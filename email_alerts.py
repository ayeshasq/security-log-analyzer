import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from typing import List, Dict
from datetime import datetime
import os

class EmailAlerter:
    """Send email alerts for critical security incidents to fkmade email"""
    
    def __init__(self):
        self.use_mock = True  # Set to False when you have real SMTP credentials
        self.smtp_server = "smtp.gmail.com"  # Change for other providers
        self.smtp_port = 587
        self.sender_email = os.getenv('ALERT_EMAIL', 'security-alerts@company.com')
        self.sender_password = os.getenv('ALERT_EMAIL_PASSWORD', '')
        self.recipient_emails = [
            'soc-team@company.com',
            'security-lead@company.com'
        ]
    
    def send_critical_alert(self, incident: Dict, pdf_report_path: str = None) -> bool:
        """Send email alert for critical incident"""
        
        if self.use_mock:
            return self._mock_send_alert(incident)
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = ', '.join(self.recipient_emails)
            msg['Subject'] = f"🚨 CRITICAL SECURITY ALERT: {incident['type']}"
            
            # Email body
            body = self._create_email_body(incident)
            msg.attach(MIMEText(body, 'html'))
            
            # Attach PDF if available
            if pdf_report_path and os.path.exists(pdf_report_path):
                with open(pdf_report_path, 'rb') as f:
                    pdf_attachment = MIMEApplication(f.read(), _subtype='pdf')
                    pdf_attachment.add_header('Content-Disposition', 'attachment', 
                                             filename=os.path.basename(pdf_report_path))
                    msg.attach(pdf_attachment)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"Email send error: {e}")
            return False
    
    def _create_email_body(self, incident: Dict) -> str:
        """Create HTML email body"""
        
        severity_color = {
            'CRITICAL': '#d32f2f',
            'HIGH': '#f57c00',
            'MEDIUM': '#fbc02d',
            'LOW': '#388e3c'
        }.get(incident.get('severity', 'MEDIUM'), '#757575')
        
        # Get threat intel if available
        threat_intel_html = ""
        if 'threat_intel' in incident:
            ti = incident['threat_intel']
            threat_intel_html = f"""
            <tr>
                <td style="padding: 10px; background-color: #f5f5f5; font-weight: bold;">Threat Intelligence</td>
                <td style="padding: 10px;">
                    Abuse Score: {ti['abuse_score']}% | 
                    Country: {ti['country']} | 
                    ISP: {ti['isp']}<br>
                    {'<span style="color: #d32f2f;">⚠️ Known Malicious IP</span>' if ti['is_malicious'] else ''}
                </td>
            </tr>
            """
        
        # Get risk score if available
        risk_score_html = ""
        if 'risk_score' in incident:
            risk_score_html = f"""
            <tr>
                <td style="padding: 10px; background-color: #f5f5f5; font-weight: bold;">Risk Score</td>
                <td style="padding: 10px; font-size: 18px; font-weight: bold; color: {severity_color};">
                    {incident['risk_score']}/100
                </td>
            </tr>
            """
        
        # Format recommendations
        recommendations_html = ""
        if 'recommendations' in incident:
            recs = ''.join([f"<li>{rec}</li>" for rec in incident['recommendations'][:5]])
            recommendations_html = f"""
            <h3 style="color: #d32f2f;">⚡ IMMEDIATE ACTIONS REQUIRED:</h3>
            <ul style="font-size: 14px; line-height: 1.8;">
                {recs}
            </ul>
            """
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .header {{ background-color: {severity_color}; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                td {{ border: 1px solid #ddd; }}
                .footer {{ background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 CRITICAL SECURITY INCIDENT DETECTED</h1>
                <p style="font-size: 18px; margin: 10px 0 0 0;">
                    {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}
                </p>
            </div>
            
            <div class="content">
                <h2 style="color: {severity_color};">Incident Details</h2>
                
                <table>
                    <tr>
                        <td style="padding: 10px; background-color: #f5f5f5; font-weight: bold; width: 30%;">
                            Incident Type
                        </td>
                        <td style="padding: 10px; font-size: 16px; font-weight: bold;">
                            {incident['type'].replace('_', ' ').title()}
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; background-color: #f5f5f5; font-weight: bold;">Severity</td>
                        <td style="padding: 10px; font-size: 18px; font-weight: bold; color: {severity_color};">
                            {incident['severity']}
                        </td>
                    </tr>
                    {risk_score_html}
                    <tr>
                        <td style="padding: 10px; background-color: #f5f5f5; font-weight: bold;">Source IP</td>
                        <td style="padding: 10px; font-family: monospace;">
                            {incident.get('source_ip', 'N/A')}
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; background-color: #f5f5f5; font-weight: bold;">Event Count</td>
                        <td style="padding: 10px;">{incident.get('event_count', 0)}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; background-color: #f5f5f5; font-weight: bold;">MITRE ATT&CK</td>
                        <td style="padding: 10px;">{incident.get('mitre', 'N/A')}</td>
                    </tr>
                    {threat_intel_html}
                </table>
                
                <h3>📋 Description</h3>
                <p style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107;">
                    {incident.get('description', 'No description available')}
                </p>
                
                {recommendations_html}
                
                <p style="margin-top: 30px; padding: 15px; background-color: #e3f2fd; border-left: 4px solid #2196f3;">
                    <strong>📎 Note:</strong> Full analysis report is attached to this email.
                    Review immediately and coordinate response with the security team.
                </p>
            </div>
            
            <div class="footer">
                <p>This is an automated security alert from the AI-Powered Security Log Analyzer</p>
                <p>Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
                <p style="color: #999; font-size: 11px;">
                    Do not reply to this email. For urgent issues, contact the SOC directly.
                </p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _mock_send_alert(self, incident: Dict) -> bool:
        """Mock email sending for testing"""
        
        print(f"\n{'='*80}")
        print(f"📧 EMAIL ALERT (MOCK MODE)")
        print(f"{'='*80}")
        print(f"To: {', '.join(self.recipient_emails)}")
        print(f"Subject: 🚨 CRITICAL SECURITY ALERT: {incident['type']}")
        print(f"Severity: {incident['severity']}")
        print(f"Source IP: {incident.get('source_ip', 'N/A')}")
        
        if 'risk_score' in incident:
            print(f"Risk Score: {incident['risk_score']}/100")
        
        if 'threat_intel' in incident:
            ti = incident['threat_intel']
            print(f"Threat Intel: Abuse Score {ti['abuse_score']}% | Country: {ti['country']}")
        
        print(f"\n✅ Email would be sent to security team")
        print(f"{'='*80}\n")
        
        return True
    
    def send_summary_report(self, incidents: List[Dict], pdf_report_path: str) -> bool:
        """Send daily/weekly summary report"""
        
        if self.use_mock:
            print(f"\n📊 SUMMARY REPORT EMAIL (MOCK)")
            print(f"Incidents: {len(incidents)}")
            print(f"PDF attached: {pdf_report_path}")
            print(f"✅ Summary email would be sent\n")
            return True
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = ', '.join(self.recipient_emails)
            msg['Subject'] = f"📊 Security Summary Report - {datetime.now().strftime('%Y-%m-%d')}"
            
            # Simple summary body
            high_count = sum(1 for i in incidents if i['severity'] in ['HIGH', 'CRITICAL'])
            
            body = f"""
            <html>
            <body>
                <h2>Security Incident Summary</h2>
                <p>Total Incidents: {len(incidents)}</p>
                <p>High/Critical: {high_count}</p>
                <p>Full report attached.</p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # Attach PDF
            if pdf_report_path and os.path.exists(pdf_report_path):
                with open(pdf_report_path, 'rb') as f:
                    pdf_attachment = MIMEApplication(f.read(), _subtype='pdf')
                    pdf_attachment.add_header('Content-Disposition', 'attachment', 
                                             filename=os.path.basename(pdf_report_path))
                    msg.attach(pdf_attachment)
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"Email send error: {e}")
            return False
