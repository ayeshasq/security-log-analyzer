import streamlit as st
import json
from datetime import datetime
from log_parser import LogParser
from correlator import EventCorrelator
from ai_analyzer import AIAnalyzer

# Page configuration
st.set_page_config(
    page_title="AI Security Log Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 1rem;
    }
    .stAlert {
        background-color: #f0f2f6;
        border-left: 5px solid #667eea;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<h1 class="main-header">🛡️ AI-Powered Security Log Analyzer</h1>', unsafe_allow_html=True)
st.markdown("### Automate threat detection with artificial intelligence")

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/security-checked.png", width=100)
    st.title("About")
    st.info("""
    **AI Security Log Analyzer**
    
    This tool automatically:
    - 🔍 Detects security threats
    - 🔗 Correlates related events
    - 🤖 Generates AI-powered reports
    - 📊 Provides actionable insights
    """)
    
    st.markdown("---")
    st.markdown("**Detection Capabilities:**")
    st.markdown("""
    - Brute Force Attacks
    - Port Scanning
    - Malware Detection
    - SQL Injection
    - Suspicious Patterns
    """)
    
    st.markdown("---")
    st.markdown("**Tech Stack:**")
    st.markdown("""
    - Python
    - Claude AI
    - Pattern Recognition
    - NLP
    """)
    
    st.markdown("---")
    st.markdown("**Created by:** Ayesha Siddiqui")
    st.markdown("[GitHub](https://github.com/ayeshasq/security-log-analyzer) | [LinkedIn](https://linkedin.com/in/yourprofile)")

# Main content
tab1, tab2, tab3 = st.tabs(["📝 Analyze Logs", "📚 Sample Data", "ℹ️ How It Works"])

with tab1:
    st.header("Upload or Paste Security Logs")
    
    # Input method selection
    input_method = st.radio("Choose input method:", ["Paste Logs", "Upload File", "Use Sample Data"])
    
    log_content = ""
    
    if input_method == "Paste Logs":
        log_content = st.text_area(
            "Paste your security logs here:",
            height=300,
            placeholder="Example:\n2024-01-15 10:23:45 Failed login attempt from 192.168.1.100 for user admin\n2024-01-15 10:23:50 Failed login attempt from 192.168.1.100 for user root"
        )
    
    elif input_method == "Upload File":
        uploaded_file = st.file_uploader("Upload a log file (.log or .txt)", type=["log", "txt"])
        if uploaded_file:
            log_content = uploaded_file.read().decode("utf-8")
            st.success(f"✅ File uploaded: {uploaded_file.name}")
    
    else:  # Use Sample Data
        with open("logs/sample_security.log", "r") as f:
            log_content = f.read()
        st.info("📄 Using built-in sample security logs")
        with st.expander("Preview Sample Logs"):
            st.code(log_content, language="log")
    
    # Analysis button
    if st.button("🔍 Analyze Logs", type="primary", use_container_width=True):
        if not log_content:
            st.error("⚠️ Please provide log data to analyze")
        else:
            with st.spinner("🔄 Analyzing security logs..."):
                # Progress bar
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Step 1: Parse logs
                status_text.text("📋 [1/4] Parsing log entries...")
                progress_bar.progress(25)
                
                parser = LogParser()
                parsed_logs = []
                for line in log_content.strip().split('\n'):
                    if line.strip():
                        parsed_logs.append(parser.parse_line(line))
                
                st.success(f"✅ Parsed {len(parsed_logs)} log entries")
                
                # Step 2: Correlate events
                status_text.text("🔗 [2/4] Correlating security events...")
                progress_bar.progress(50)
                
                correlator = EventCorrelator()
                incidents = correlator.correlate_events(parsed_logs)
                
                st.success(f"✅ Found {len(incidents)} potential incidents")
                
                # Step 3: AI Analysis
                status_text.text("🤖 [3/4] Analyzing with AI...")
                progress_bar.progress(75)
                
                analyzer = AIAnalyzer()
                for incident in incidents:
                    incident['ai_analysis'] = analyzer.analyze_incident(incident)
                
                # Step 4: Generate summary
                status_text.text("📊 [4/4] Generating executive summary...")
                progress_bar.progress(100)
                
                executive_summary = analyzer.generate_executive_summary(incidents)
                
                status_text.text("✅ Analysis complete!")
                progress_bar.empty()
                
                # Display results
                st.markdown("---")
                st.header("📊 Analysis Results")
                
                # Metrics
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total Logs", len(parsed_logs))
                with col2:
                    st.metric("Incidents Found", len(incidents))
                with col3:
                    high_severity = sum(1 for i in incidents if i['severity'] == 'HIGH')
                    st.metric("High Severity", high_severity)
                with col4:
                    st.metric("Analysis Time", "< 5 seconds")
                
                st.markdown("---")
                
                # Executive Summary
                st.subheader("📋 Executive Summary")
                st.markdown(executive_summary)
                
                st.markdown("---")
                
                # Detailed Incidents
                st.subheader("🚨 Detailed Incident Reports")
                
                for i, incident in enumerate(incidents, 1):
                    severity_color = "🔴" if incident['severity'] == 'HIGH' else "🟡"
                    
                    with st.expander(f"{severity_color} Incident #{i}: {incident['type']} - Severity: {incident['severity']}", expanded=True):
                        st.markdown(f"**Source IP:** {incident.get('source_ip', 'N/A')}")
                        st.markdown(f"**Event Count:** {incident['event_count']}")
                        st.markdown(f"**Description:** {incident['description']}")
                        
                        st.markdown("---")
                        st.markdown("**AI Analysis:**")
                        st.markdown(incident['ai_analysis'])
                        
                        st.markdown("---")
                        st.markdown("**Sample Events:**")
                        for j, event in enumerate(incident['events'][:3], 1):
                            st.code(f"{j}. {event['raw']}", language="log")
                
                # Download reports
                st.markdown("---")
                st.subheader("💾 Download Reports")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    # Text report
                    text_report = f"""SECURITY ANALYSIS REPORT
{'='*80}

EXECUTIVE SUMMARY
{'-'*80}
{executive_summary}

DETAILED INCIDENTS
{'='*80}

"""
                    for i, incident in enumerate(incidents, 1):
                        text_report += f"""
Incident #{i}: {incident['type']}
Severity: {incident['severity']}

{incident['ai_analysis']}

{'-'*80}
"""
                    
                    st.download_button(
                        label="📄 Download Text Report",
                        data=text_report,
                        file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        mime="text/plain"
                    )
                
                with col2:
                    # JSON report
                    json_report = json.dumps(incidents, indent=2, default=str)
                    st.download_button(
                        label="📋 Download JSON Data",
                        data=json_report,
                        file_name=f"incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )

with tab2:
    st.header("📚 Sample Log Formats")
    
    st.markdown("### Copy these examples to test the analyzer:")
    
    st.subheader("1️⃣ Brute Force Attack")
    brute_force = """2024-01-15 10:23:45 Failed login attempt from 192.168.1.100 for user admin
2024-01-15 10:23:50 Failed login attempt from 192.168.1.100 for user root
2024-01-15 10:23:55 Failed login attempt from 192.168.1.100 for user administrator
2024-01-15 10:24:00 Failed login attempt from 192.168.1.100 for user admin"""
    st.code(brute_force, language="log")
    
    st.subheader("2️⃣ Port Scanning")
    port_scan = """2024-01-15 11:15:22 Port scan detected from 203.0.113.50 scanning ports 22-1024
2024-01-15 11:15:30 Firewall blocked connection from 203.0.113.50 to port 445
2024-01-15 11:15:35 Firewall blocked connection from 203.0.113.50 to port 3389"""
    st.code(port_scan, language="log")
    
    st.subheader("3️⃣ Malware Detection")
    malware = """2024-01-15 14:30:12 Malware signature detected in file download from 198.51.100.25
2024-01-15 14:30:15 Critical: Ransomware activity detected on host WORKSTATION-05
2024-01-15 14:30:20 File encryption activity detected on multiple hosts"""
    st.code(malware, language="log")
    
    st.subheader("4️⃣ Mixed Attack Scenario")
    mixed = """2024-01-15 10:23:45 Failed login attempt from 192.168.1.100 for user admin
2024-01-15 10:23:50 Failed login attempt from 192.168.1.100 for user root
2024-01-15 10:23:55 Failed login attempt from 192.168.1.100 for user administrator
2024-01-15 11:15:22 Port scan detected from 203.0.113.50 scanning ports 22-1024
2024-01-15 11:15:30 Firewall blocked connection from 203.0.113.50 to port 445
2024-01-15 14:30:12 Malware signature detected in file download from 198.51.100.25
2024-01-15 14:30:15 Critical: Ransomware activity detected on host WORKSTATION-05"""
    st.code(mixed, language="log")

with tab3:
    st.header("ℹ️ How It Works")
    
    st.markdown("""
    ### 🔄 Analysis Pipeline
    
    This tool uses a 4-stage intelligent pipeline to analyze security logs:
    """)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **1. 📋 Log Parsing**
        - Extracts timestamps, IP addresses, usernames
        - Identifies event types
        - Determines severity levels
        - Handles various log formats
        
        **2. 🔗 Event Correlation**
        - Groups related security events
        - Identifies attack patterns
        - Detects coordinated attacks
        - Reduces false positives
        """)
    
    with col2:
        st.markdown("""
        **3. 🤖 AI Analysis**
        - Uses Claude AI for intelligent analysis
        - Generates human-readable reports
        - Provides risk assessments
        - Recommends remediation actions
        
        **4. 📊 Report Generation**
        - Creates executive summaries
        - Produces technical incident reports
        - Exports in text and JSON formats
        - Includes actionable recommendations
        """)
    
    st.markdown("---")
    
    st.markdown("""
    ### 🎯 Detection Capabilities
    
    | Attack Type | Detection Method | Severity |
    |------------|------------------|----------|
    | 🔐 Brute Force | 3+ failed logins from same IP | HIGH |
    | 🌐 Port Scanning | Sequential port probe patterns | MEDIUM |
    | 🦠 Malware | Signature matching | CRITICAL |
    | 💉 SQL Injection | Pattern recognition | HIGH |
    | 🌊 DDoS | Volume analysis | HIGH |
    """)
    
    st.markdown("---")
    
    st.success("""
    **💡 Pro Tip:** This tool uses mock AI responses for demo purposes. 
    In production, it connects to Claude API for real-time intelligent analysis.
    """)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666;'>
    <p>🛡️ AI-Powered Security Log Analyzer | Built by Ayesha Siddiqui</p>
    <p>
        <a href='https://github.com/ayeshasq/security-log-analyzer' target='_blank'>GitHub</a> | 
        <a href='https://linkedin.com/in/yourprofile' target='_blank'>LinkedIn</a>
    </p>
</div>
""", unsafe_allow_html=True)
