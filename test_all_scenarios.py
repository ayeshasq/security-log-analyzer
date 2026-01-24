from main import SecurityLogAnalyzer

scenarios = [
    ("logs/sample_security.log", "Comprehensive Security Analysis"),
    ("logs/brute_force_attack.log", "Brute Force Attack Scenario"),
    ("logs/reconnaissance.log", "Network Reconnaissance Scenario"),
    ("logs/malware_incident.log", "Malware Outbreak Scenario"),
]

analyzer = SecurityLogAnalyzer()

for log_file, description in scenarios:
    print(f"\n{'='*80}")
    print(f"TESTING: {description}")
    print(f"{'='*80}\n")
    
    try:
        analyzer.analyze_logs(log_file)
    except FileNotFoundError:
        print(f"⚠️  File not found: {log_file} - skipping...")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print("\n" + "="*80 + "\n")
