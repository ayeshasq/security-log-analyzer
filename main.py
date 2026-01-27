from log_parser import LogParser
from correlator import EventCorrelator
from ai_analyzer import AIAnalyzer
from colorama import init, Fore, Style
import json
from datetime import datetime
from visualizations import SecurityVisualizer
from pdf_generator import PDFReportGenerator
from email_alerts import EmailAlerter

init()

class SecurityLogAnalyzer:
    """Main application orchestrator here"""
    
    def __init__(self):
        self.parser = LogParser()
        self.correlator = EventCorrelator()
        self.ai_analyzer = AIAnalyzer()
        self.visualizer = SecurityVisualizer()
        self.pdf_generator = PDFReportGenerator()     
        self.email_alerter = EmailAlerter()   

    def analyze_logs(self, log_file: str):
        """Complete analysis pipeline"""
        
        print(f"{Fore.CYAN}[*] Starting Security Log Analysis...{Style.RESET_ALL}\n")
        
        # Step 1: Parse logs
        print(f"{Fore.YELLOW}[1/7] Parsing log file...{Style.RESET_ALL}")
        parsed_logs = self.parser.parse_file(log_file)
        print(f"      Parsed {len(parsed_logs)} log entries\n")
        
        # Step 2: Correlate events
        print(f"{Fore.YELLOW}[2/7] Correlating security events...{Style.RESET_ALL}")
        incidents = self.correlator.correlate_events(parsed_logs)
        print(f"      Found {len(incidents)} potential incidents\n")
        
        if not incidents:
            print(f"{Fore.GREEN}[✓] No security incidents detected!{Style.RESET_ALL}")
            return
        
        # Step 3: AI Analysis of each incident
        print(f"{Fore.YELLOW}[3/7] Analyzing incidents with AI...{Style.RESET_ALL}")
        for i, incident in enumerate(incidents, 1):
            print(f"      Analyzing incident {i}/{len(incidents)}...")
            incident['ai_analysis'] = self.ai_analyzer.analyze_incident(incident)
        print()
        
        # Step 4: Generate executive summary
        print(f"{Fore.YELLOW}[4/7] Generating executive summary...{Style.RESET_ALL}\n")
        executive_summary = self.ai_analyzer.generate_executive_summary(incidents)
        
        # Display results
        self._display_results(incidents, executive_summary)
        
        # Generate visualizations
        print(f"{Fore.YELLOW}[5/7] Generating visualizations...{Style.RESET_ALL}")
        timeline_path = self.visualizer.create_timeline(incidents)
        summary_path = self.visualizer.create_summary_chart(incidents)
        
        if timeline_path:
            print(f"{Fore.GREEN}[✓] Timeline saved: {timeline_path}{Style.RESET_ALL}")
        if summary_path:
            print(f"{Fore.GREEN}[✓] Summary chart saved: {summary_path}{Style.RESET_ALL}")
        print()

        # Generate PDF report
        print(f"{Fore.YELLOW}[6/6] Generating PDF report...{Style.RESET_ALL}")
        pdf_path = self.pdf_generator.generate_report(incidents, executive_summary, 
                                                       timeline_path, summary_path)
        print(f"{Fore.GREEN}[✓] PDF report saved: {pdf_path}{Style.RESET_ALL}\n")

        # Send email alerts for critical incidents
        print(f"{Fore.YELLOW}[7/7] Checking for critical alerts...{Style.RESET_ALL}")
        critical_incidents = [i for i in incidents if i['severity'] == 'CRITICAL']
        
        if critical_incidents:
            for incident in critical_incidents:
                self.email_alerter.send_critical_alert(incident, pdf_path)
        else:
            print(f"{Fore.GREEN}[✓] No critical incidents requiring immediate alerts{Style.RESET_ALL}\n")

        # Save report
        self._save_report(incidents, executive_summary)
    
    def _display_results(self, incidents, summary):
        """Display analysis results below"""
        
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}EXECUTIVE SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
        print(summary)
        
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}DETAILED INCIDENT REPORTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
        
        for i, incident in enumerate(incidents, 1):
            severity_color = Fore.RED if incident['severity'] in ['HIGH', 'CRITICAL'] else Fore.YELLOW
            
            print(f"{severity_color}[Incident #{i}] {incident['type']}{Style.RESET_ALL}")
            print(f"Severity: {severity_color}{incident['severity']}{Style.RESET_ALL}")
            
            # Display risk score
            if 'risk_score' in incident:
                risk_score = incident['risk_score']
                if risk_score >= 80:
                    risk_color = Fore.RED
                    risk_emoji = "🔴"
                elif risk_score >= 60:
                    risk_color = Fore.YELLOW
                    risk_emoji = "🟡"
                else:
                    risk_color = Fore.GREEN
                    risk_emoji = "🟢"
                print(f"Risk Score: {risk_color}{risk_score}/100 {risk_emoji}{Style.RESET_ALL}")

            # Show threat intelligence
            if 'threat_intel' in incident:
                ti = incident['threat_intel']
                threat_color = Fore.RED if ti['is_malicious'] else Fore.GREEN
                print(f"Threat Intel: {threat_color}Abuse Score: {ti['abuse_score']}% | Country: {ti['country']} | {ti['isp']}{Style.RESET_ALL}")
                if ti['is_malicious']:
                    print(f"{Fore.RED}⚠️  Known malicious IP - {ti['total_reports']} previous reports{Style.RESET_ALL}")
                if ti['is_tor']:
                    print(f"{Fore.YELLOW}🕵️  TOR exit node detected{Style.RESET_ALL}")
                if ti['is_vpn']:
                    print(f"{Fore.YELLOW}🔒 VPN/Proxy detected{Style.RESET_ALL}")
            
            print(f"\n{incident['ai_analysis']}\n")
            print(f"{Fore.CYAN}{'-'*80}{Style.RESET_ALL}\n")
    
    def _save_report(self, incidents, summary):
        """Save report to file"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"outputs/security_report_{timestamp}.txt"
        json_file = f"outputs/incidents_{timestamp}.json"
        
        # Save text report
        with open(report_file, 'w') as f:
            f.write("SECURITY ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 80 + "\n")
            f.write(summary + "\n\n")
            
            f.write("DETAILED INCIDENTS\n")
            f.write("=" * 80 + "\n\n")
            
            for i, incident in enumerate(incidents, 1):
                f.write(f"Incident #{i}: {incident['type']}\n")
                f.write(f"Severity: {incident['severity']}\n")
                
                # Add threat intel to report
                if 'threat_intel' in incident:
                    ti = incident['threat_intel']
                    f.write(f"Threat Intel: Abuse Score {ti['abuse_score']}% | Country: {ti['country']} | ISP: {ti['isp']}\n")
                    if ti['is_malicious']:
                        f.write(f"WARNING: Known malicious IP - {ti['total_reports']} reports\n")
                
                f.write(f"\n{incident['ai_analysis']}\n\n")
                f.write("-" * 80 + "\n\n")
        
        # Save JSON data
        with open(json_file, 'w') as f:
            json.dump(incidents, f, indent=2, default=str)
        
        print(f"{Fore.GREEN}[✓] Reports saved:{Style.RESET_ALL}")
        print(f"    - {report_file}")
        print(f"    - {json_file}\n")

if __name__ == "__main__":
    analyzer = SecurityLogAnalyzer()
    analyzer.analyze_logs("logs/enterprise_attacks.log")
