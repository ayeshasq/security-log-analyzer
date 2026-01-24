from log_parser import LogParser
from correlator import EventCorrelator
from ai_analyzer import AIAnalyzer
from colorama import init, Fore, Style
import json
from datetime import datetime

init()  # Initialize colorama

class SecurityLogAnalyzer:
    """Main application orchestrator"""
    
    def __init__(self):
        self.parser = LogParser()
        self.correlator = EventCorrelator()
        self.ai_analyzer = AIAnalyzer()
    
    def analyze_logs(self, log_file: str):
        """Complete analysis pipeline"""
        
        print(f"{Fore.CYAN}[*] Starting Security Log Analysis...{Style.RESET_ALL}\n")
        
        # Step 1: Parse logs
        print(f"{Fore.YELLOW}[1/4] Parsing log file...{Style.RESET_ALL}")
        parsed_logs = self.parser.parse_file(log_file)
        print(f"      Parsed {len(parsed_logs)} log entries\n")
        
        # Step 2: Correlate events
        print(f"{Fore.YELLOW}[2/4] Correlating security events...{Style.RESET_ALL}")
        incidents = self.correlator.correlate_events(parsed_logs)
        print(f"      Found {len(incidents)} potential incidents\n")
        
        if not incidents:
            print(f"{Fore.GREEN}[✓] No security incidents detected!{Style.RESET_ALL}")
            return
        
        # Step 3: AI Analysis of each incident
        print(f"{Fore.YELLOW}[3/4] Analyzing incidents with AI...{Style.RESET_ALL}")
        for i, incident in enumerate(incidents, 1):
            print(f"      Analyzing incident {i}/{len(incidents)}...")
            incident['ai_analysis'] = self.ai_analyzer.analyze_incident(incident)
        print()
        
        # Step 4: Generate executive summary
        print(f"{Fore.YELLOW}[4/4] Generating executive summary...{Style.RESET_ALL}\n")
        executive_summary = self.ai_analyzer.generate_executive_summary(incidents)
        
        # Display results
        self._display_results(incidents, executive_summary)
        
        # Save report
        self._save_report(incidents, executive_summary)
    
    def _display_results(self, incidents, summary):
        """Display analysis results"""
        
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}EXECUTIVE SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
        print(summary)
        
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}DETAILED INCIDENT REPORTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
        
        for i, incident in enumerate(incidents, 1):
            severity_color = Fore.RED if incident['severity'] == 'HIGH' else Fore.YELLOW
            
            print(f"{severity_color}[Incident #{i}] {incident['type']}{Style.RESET_ALL}")
            print(f"Severity: {severity_color}{incident['severity']}{Style.RESET_ALL}")
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
                f.write(f"Severity: {incident['severity']}\n\n")
                f.write(incident['ai_analysis'] + "\n\n")
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
