# 🛡️ AI Security Log Analyzer

**AI Security Log Analyzer** is a smart cybersecurity tool that uses artificial intelligence to automatically detect threats in security logs and generate clear, actionable incident reports.

If you're tired of manually analyzing thousands of log entries — this tool does it for you in seconds.

---

## 🎯 Who Is This For?

- Cybersecurity students learning log analysis
- SOC analysts looking to automate first-level triage
- Security enthusiasts building portfolio projects
- Anyone interested in practical AI applications in security

No advanced security experience required to use it.

---

## 🚀 What This Tool Does

This analyzer helps security teams:

- **Detect threats automatically** - Finds brute force attacks, port scans, malware, and more
- **Correlate related events** - Groups suspicious activities from the same attacker
- **Generate professional reports** - Creates incident summaries that anyone can understand
- **Save investigation time** - Analyzes 1000+ logs in seconds instead of hours

---

Instead of staring at raw log files, you get:

- Clear threat assessments
- Recommended actions
- Executive summaries
- Both technical and business-friendly reports

---

## 🔍 What It Detects

- **Brute Force Attacks** - Multiple failed login attempts
- **Port Scanning** - Network reconnaissance activity
- **Malware & Ransomware** - Malicious software signatures
- **SQL Injection** - Database attack attempts
- **Suspicious Patterns** - Unusual behavior detection

Each detection includes:

- What happened
- How serious it is
- What to do about it
- Technical details for investigation

---

## ⚡ Quick Start
```bash
# Clone and setup
git clone https://github.com/ayeshasq/security-log-analyzer.git
cd security-log-analyzer
python3 -m venv venv && source venv/bin/activate

# Install and run
pip3 install -r requirements.txt
echo "ANTHROPIC_API_KEY=your_key" > .env
python3 main.py
```

**Done!** Your security reports are in the `outputs/` folder.

---

## 🤖 How It Works

The analyzer uses a simple 4-step process:

1. **Parse** - Reads security logs and extracts key information
2. **Correlate** - Groups related events to find attack patterns
3. **Analyze** - Uses AI to understand what each incident means
4. **Report** - Generates clear summaries with recommendations

All automatically. No manual work needed.

---

## 📊 Example Output
```
[*] Starting Security Log Analysis...

Found 4 security incidents:

[Incident #1] BRUTE_FORCE_ATTACK - Severity: HIGH
Source: 192.168.1.100
Details: 4 failed login attempts on admin accounts

Recommended Actions:
✓ Block this IP immediately
✓ Enable multi-factor authentication
✓ Review other attempts from this IP

[✓] Full reports saved to outputs/
```

---

## 🛠️ Technology

Built with:

- **Python** - Core programming
- **Claude AI** - Intelligent analysis
- **Pattern Recognition** - Threat detection
- **Natural Language Processing** - Report generation

**Skills demonstrated:** Cybersecurity • AI Integration • Log Analysis • SIEM Concepts • Automation

---

## 🎯 Goal of This Project

The goal is simple:

> Show how AI can automate security tasks that would take analysts hours to do manually.

This project demonstrates:

- Practical AI application in cybersecurity
- Understanding of SIEM concepts
- Threat detection methodologies
- Professional software engineering

Perfect for portfolios, learning, and job interviews.

---

## 🗺️ What's Next

Current features:

- [x] Multi-threat detection
- [x] AI-powered analysis
- [x] Professional reporting
- [x] Event correlation

Coming soon:

- [ ] Web dashboard interface
- [ ] Real-time log monitoring
- [ ] Integration with Splunk/ELK
- [ ] Machine learning anomaly detection

---

## 📌 Disclaimer

This tool is for **educational and professional use**.

Always use security tools ethically and with proper authorization.

---

## ⭐ If This Helps You

Star ⭐ the repository if you find it useful or use it in your portfolio.

Share it with other cybersecurity students and professionals.

---

## 📚 Learn More

- **[Full Documentation](DOCUMENTATION.md)** - Complete setup and API reference
- **[Demo Examples](DEMO.md)** - See it in action with sample scenarios

---

## 👤 Created By

**Ayesha Siddiqui** - Cybersecurity Graduate

Building tools that make security work easier and more accessible.

---

**License:** MIT - Free to use for learning and portfolio projects
