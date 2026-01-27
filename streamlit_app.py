import streamlit as st
from datetime import datetime
from log_parser import AdvancedLogParser
from correlator import EventCorrelator
from threat_intel import ThreatIntelligence

# Page config
st.set_page_config(
    page_title="AI Security Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Title
st.markdown('<h1 style="text-align: center; color: #667eea;">🛡️ AI Security Log Analyzer</h1>', unsafe_allow_html=True)
st.markdown("### Enterprise-Grade Threat Detection with MITRE ATT&CK Mapping")

# Sample logs
SAMPLE_LOGS = """user=root action=failed_login src_ip=198.51.100.23 method=ssh timestamp=2024-01-15T10:00:01
user=root action=failed_login src_ip=198.51.100.23 method=ssh timestamp=2024-01-15T10:00:05
user=root action=failed_login src_ip=198.51.100.23 method=ssh timestamp=2024-01-15T10:00:10
user=root action=failed_login src_ip=198.51.100.23 method=ssh timestamp=2024-01-15T10:00:15
src_ip=198.51.100.23 dst_port=22 action=blocked timestamp=2024-01-15T10:00:20
threat=Ransomware.Agent action=isolated host=DESKTOP-WIN10 timestamp=2024-01-15T14:30:00
EventName=ConsoleLogin Failure user=unknown src_ip=45.33.32.156 timestamp=2024-01-15T16:00:00
EventName=CreateAccessKey user=admin src_ip=45.33.32.156 timestamp=2024-01-15T16:00:30
AzureAD MFA Bypass Attempt user=admin@company.com src_ip=203.0.113.45 timestamp=2024-01-15T18:00:00
PrivilegeEscalation status=Denied user=guest action=sudo timestamp=2024-01-15T20:00:00"""

# Sidebar
with st.sidebar:
    st.markdown("### 🎯 Features")
    st.info("""
    ✅ Splunk/SIEM Log Support  
    ✅ AWS CloudTrail Events  
    ✅ Azure AD Logs  
    ✅ MITRE ATT&CK Mapping  
    ✅ Enterprise Correlation  
    """)
    
    st.markdown("### 🔍 Detection Types")
    st.markdown("""
    - 🔐 Brute Force Attacks
    - 🌐 Port Scanning
    - 🦠 Ransomware/Malware
    - ☁️ Cloud Credential Abuse
    - 🔑 MFA Bypass
    - ⬆️ Privilege Escalation
    """)
    
    st.markdown("---")
    st.markdown("**Created by:** Ayesha Siddiqui")
    st.markdown("[GitHub](https://github.com/ayeshasq/security-log-analyzer)")

# Main content
tab1, tab2, tab3 = st.tabs(["📝 Analyze Logs", "📚 Sample Formats", "ℹ️ About"])

with tab1:
    st.header("Security Log Analysis")
    
    input_method = st.radio("Input Method:", ["Use Sample Data", "Paste Custom Logs", "Upload File"])
    
    log_input = ""
    
    if input_method == "Use Sample Data":
        st.success("Using built-in enterprise attack scenarios (Splunk/CloudTrail/Azure)")
        with st.expander("Preview Sample Logs"):
            st.code(SAMPLE_LOGS, language="log")
        log_input = SAMPLE_LOGS
        
    elif input_method == "Paste Custom Logs":
        log_input = st.text_area(
            "Paste your security logs:",
            height=300,
            placeholder="user=admin action=failed_login src_ip=192.168.1.100..."
        )
        
    else:  # Upload File
        uploaded_file = st.file_uploader("Upload log file", type=["log", "txt"])
        if uploaded_file:
            log_input = uploaded_file.read().decode("utf-8")
            st.success(f"✅ Uploaded: {uploaded_file.name}")
    
    if st.button("🔍 Analyze Logs", type="primary", use_container_width=True):
        if not log_input:
            st.error("⚠️ Please provide log data")
        else:
            with st.spinner("Analyzing security logs..."):
                # Parse logs
                lines = [l.strip() for l in log_input.split('\n') if l.strip()]
                
                parser = AdvancedLogParser()
                parsed = [parser.parse_line(l) for l in lines]
                
                # Correlate events
                correlator = EventCorrelator()
                incidents = correlator.correlate_events(parsed)
                
                # Display results
                st.success(f"✅ Analyzed {len(parsed)} log entries")
                st.success(f"✅ Found {len(incidents)} security incidents")
                
                # Metrics
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Total Logs", len(parsed))
                col2.metric("Incidents", len(incidents))
                
                high_sev = sum(1 for i in incidents if i['severity'] in ['HIGH', 'CRITICAL'])
                col3.metric("High/Critical", high_sev)
                
                platforms = set(p['platform'] for p in parsed if p['platform'] != 'Generic')
                col4.metric("Platforms", len(platforms) if platforms else 1)
                
                if incidents:
                    st.markdown("---")
                    st.subheader("🚨 Detected Security Incidents")
                    
                    for i, inc in enumerate(incidents, 1):
                        # Color based on severity
                        if inc['severity'] == 'CRITICAL':
                            emoji = "🔴"
                            color = "red"
                        elif inc['severity'] == 'HIGH':
                            emoji = "🟠"
                            color = "orange"
                        else:
                            emoji = "🟡"
                            color = "yellow"
                        
                        with st.expander(f"{emoji} Incident #{i}: {inc['type']} - {inc['severity']}", expanded=True):
                            col_a, col_b = st.columns(2)
                            
                            with col_a:
                                st.markdown(f"**Type:** {inc['type']}")
                                st.markdown(f"**Severity:** {inc['severity']}")
                                st.markdown(f"**Source:** {inc.get('source_ip', 'N/A')}")
                                
                            with col_b:
                                st.markdown(f"**Event Count:** {inc['event_count']}")
                                if inc.get('mitre'):
                                    st.markdown(f"**MITRE ATT&CK:** {inc['mitre']}")
                            
                            st.markdown("---")
                            st.markdown("**Description:**")
                            st.info(inc['description'])
                            
                            if inc.get('recommendations'):
                                st.markdown("**Recommended Actions:**")
                                for rec in inc['recommendations']:
                                    st.markdown(f"- {rec}")
                            
                            st.markdown("**Sample Events:**")
                            for j, event in enumerate(inc['events'][:3], 1):
                                st.code(f"{j}. {event['raw']}", language="log")
                else:
                    st.info("No security incidents detected in the provided logs.")

with tab2:
    st.header("📚 Supported Log Formats")
    
    st.subheader("1️⃣ Splunk/Key-Value Format")
    st.code("""user=admin action=failed_login src_ip=192.168.1.100 method=ssh
user=admin action=failed_login src_ip=192.168.1.100 method=ssh
user=admin action=failed_login src_ip=192.168.1.100 method=ssh""", language="log")
    
    st.subheader("2️⃣ AWS CloudTrail Events")
    st.code("""EventName=ConsoleLogin Failure user=unknown src_ip=45.33.32.156
EventName=CreateAccessKey user=admin src_ip=45.33.32.156
EventName=AssumeRole user=attacker src_ip=45.33.32.156""", language="log")
    
    st.subheader("3️⃣ Azure AD Security Logs")
    st.code("""AzureAD MFA Bypass Attempt user=admin@company.com src_ip=203.0.113.45
AzureAD SignIn Failure user=admin@company.com src_ip=203.0.113.45""", language="log")
    
    st.subheader("4️⃣ Endpoint Security")
    st.code("""threat=Ransomware.Agent action=isolated host=DESKTOP-WIN10
threat=Malware.Trojan action=quarantined host=LAPTOP-USER5
PrivilegeEscalation status=Denied user=guest action=sudo""", language="log")
    
    st.subheader("5️⃣ Firewall Logs")
    st.code("""src_ip=198.51.100.23 dst_port=22 action=blocked
src_ip=198.51.100.23 dst_port=445 action=blocked
src_ip=198.51.100.23 dst_port=3389 action=blocked""", language="log")

with tab3:
    st.header("ℹ️ About This Tool")
    
    st.markdown("""
    ### 🛡️ Enterprise Security Log Analyzer
    
    An advanced security tool that uses pattern recognition and correlation 
    to detect sophisticated attacks across multiple platforms.
    
    ### 🎯 Key Features:
    
    - **Multi-Platform Support**: Splunk, AWS CloudTrail, Azure AD, Syslog
    - **Advanced Correlation**: Groups related events to detect attack chains
    - **MITRE ATT&CK**: Maps incidents to MITRE framework
    - **Real-Time Analysis**: Processes logs in seconds
    - **Actionable Reports**: Provides specific remediation steps
    
    ### 🔍 Detection Capabilities:
    
    | Attack Type | MITRE Technique |
    |------------|-----------------|
    | Brute Force | T1110 |
    | Privilege Escalation | T1068 |
    | Ransomware | T1486 |
    | Credential Abuse | T1078 |
    | MFA Bypass | T1556 |
    | Port Scanning | T1046 |
    
    ### 💻 Technology Stack:
    
    - Python 3.10+
    - Advanced Pattern Recognition
    - Event Correlation Engine
    - Streamlit Web Framework
    
    ### 📊 Why This Matters:
    
    Traditional SIEM tools often miss sophisticated attacks that span 
    multiple events. This analyzer uses intelligent correlation to 
    detect attack patterns that would otherwise go unnoticed.
    """)
    
    st.markdown("---")
    st.success("🎓 Built for portfolio demonstration and educational purposes")

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666;'>
    <p>🛡️ Enterprise Security Log Analyzer | Built by Ayesha Siddiqui</p>
    <p><a href='https://github.com/ayeshasq/security-log-analyzer'>GitHub</a> | 
    <a href='https://linkedin.com/in/yourprofile'>LinkedIn</a></p>
</div>
""", unsafe_allow_html=True)
