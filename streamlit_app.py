import streamlit as st
import re
from datetime import datetime
from collections import defaultdict

st.set_page_config(page_title="AI Security Log Analyzer", page_icon="🛡️", layout="wide")

st.markdown('<h1 style="text-align: center; color: #667eea;">🛡️ AI Security Log Analyzer</h1>', unsafe_allow_html=True)
st.markdown("### Automate threat detection with artificial intelligence")

# Sample data
SAMPLE_LOGS = """2024-01-15 10:23:45 Failed login attempt from 192.168.1.100 for user admin
2024-01-15 10:23:50 Failed login attempt from 192.168.1.100 for user root
2024-01-15 10:23:55 Failed login attempt from 192.168.1.100 for user administrator
2024-01-15 10:24:00 Failed login attempt from 192.168.1.100 for user admin
2024-01-15 11:15:22 Port scan detected from 203.0.113.50 scanning ports 22-1024
2024-01-15 11:15:30 Firewall blocked connection from 203.0.113.50 to port 445
2024-01-15 14:30:12 Malware signature detected in file download from 198.51.100.25
2024-01-15 14:30:15 Critical: Ransomware activity detected on host WORKSTATION-05"""

def parse_log(line):
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ips = re.findall(ip_pattern, line)
    
    severity = 'HIGH' if any(w in line.lower() for w in ['critical', 'failed', 'ransomware']) else 'MEDIUM'
    
    event_type = 'GENERAL'
    if 'failed' in line.lower() and 'login' in line.lower():
        event_type = 'FAILED_LOGIN'
    elif 'port scan' in line.lower():
        event_type = 'PORT_SCAN'
    elif any(w in line.lower() for w in ['malware', 'ransomware']):
        event_type = 'MALWARE'
    
    return {'raw': line, 'ips': ips, 'severity': severity, 'type': event_type}

def analyze_logs(log_text):
    lines = [l.strip() for l in log_text.split('\n') if l.strip()]
    parsed = [parse_log(l) for l in lines]
    
    # Group by IP
    ip_events = defaultdict(list)
    for log in parsed:
        for ip in log['ips']:
            ip_events[ip].append(log)
    
    incidents = []
    for ip, events in ip_events.items():
        failed = [e for e in events if e['type'] == 'FAILED_LOGIN']
        if len(failed) >= 3:
            incidents.append({
                'type': 'BRUTE_FORCE_ATTACK',
                'severity': 'HIGH',
                'ip': ip,
                'count': len(failed),
                'events': failed
            })
        
        scans = [e for e in events if e['type'] == 'PORT_SCAN']
        if scans:
            incidents.append({
                'type': 'PORT_SCAN_DETECTED',
                'severity': 'MEDIUM',
                'ip': ip,
                'count': len(scans),
                'events': scans
            })
        
        malware = [e for e in events if e['type'] == 'MALWARE']
        if malware:
            incidents.append({
                'type': 'MALWARE_DETECTED',
                'severity': 'CRITICAL',
                'ip': ip,
                'count': len(malware),
                'events': malware
            })
    
    return parsed, incidents

# Main UI
tab1, tab2 = st.tabs(["📝 Analyze Logs", "📚 Sample Data"])

with tab1:
    st.header("Upload or Paste Security Logs")
    
    use_sample = st.checkbox("Use sample data", value=True)
    
    if use_sample:
        log_input = st.text_area("Security Logs:", value=SAMPLE_LOGS, height=200)
    else:
        log_input = st.text_area("Paste your logs here:", height=200, placeholder="2024-01-15 10:23:45 Failed login...")
    
    if st.button("🔍 Analyze Logs", type="primary"):
        if log_input:
            with st.spinner("Analyzing..."):
                parsed, incidents = analyze_logs(log_input)
                
                st.success(f"✅ Analyzed {len(parsed)} log entries")
                st.success(f"✅ Found {len(incidents)} security incidents")
                
                col1, col2, col3 = st.columns(3)
                col1.metric("Total Logs", len(parsed))
                col2.metric("Incidents", len(incidents))
                col3.metric("High Severity", sum(1 for i in incidents if i['severity'] == 'HIGH'))
                
                st.markdown("---")
                st.subheader("🚨 Detected Incidents")
                
                for i, inc in enumerate(incidents, 1):
                    with st.expander(f"{'🔴' if inc['severity']=='HIGH' else '🟡'} Incident #{i}: {inc['type']}", expanded=True):
                        st.write(f"**Severity:** {inc['severity']}")
                        st.write(f"**Source IP:** {inc['ip']}")
                        st.write(f"**Event Count:** {inc['count']}")
                        
                        if inc['type'] == 'BRUTE_FORCE_ATTACK':
                            st.warning("⚠️ Multiple failed login attempts detected. Recommend: Block IP, enable MFA, review logs.")
                        elif inc['type'] == 'PORT_SCAN_DETECTED':
                            st.info("ℹ️ Network reconnaissance detected. Recommend: Block IP, review firewall rules.")
                        elif inc['type'] == 'MALWARE_DETECTED':
                            st.error("🚨 Malware activity detected! Recommend: Isolate host, scan all systems, check for data exfiltration.")
                        
                        st.code('\n'.join(e['raw'] for e in inc['events'][:3]))

with tab2:
    st.header("📚 Sample Log Examples")
    st.code(SAMPLE_LOGS, language="log")
    st.info("Copy these examples to test the analyzer!")

st.markdown("---")
st.markdown("<p style='text-align: center;'>🛡️ Built by Ayesha Siddiqui | <a href='https://github.com/ayeshasq/security-log-analyzer'>GitHub</a></p>", unsafe_allow_html=True)
