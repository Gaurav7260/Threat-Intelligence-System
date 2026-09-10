import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import sys
import requests
from dotenv import load_dotenv
from fpdf import FPDF
import psutil
from streamlit_autorefresh import st_autorefresh

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from auth import login
from backend.database import fetch_alerts, create_tables

load_dotenv(os.path.join(PROJECT_ROOT, ".env"))
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

st.set_page_config(
    page_title="Enterprise SOC Platform & Threat Intelligence",
    layout="wide",
    initial_sidebar_state="expanded"
)

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    login()
    st.stop()

# Auto-refresh every 5 seconds for live telemetry
st_autorefresh(interval=5000, key="soc_dashboard_refresh")

st.markdown("""
<style>
.stApp {
    background:
        radial-gradient(circle at 20% 20%, rgba(56,189,248,0.18), transparent 25%),
        radial-gradient(circle at 80% 10%, rgba(239,68,68,0.16), transparent 25%),
        radial-gradient(circle at 50% 85%, rgba(34,197,94,0.12), transparent 25%),
        linear-gradient(135deg, #020617 0%, #0f172a 45%, #111827 100%);
    background-size: 250% 250%;
    animation: cyberBackground 14s ease infinite;
}

@keyframes cyberBackground {
    0% { background-position: 0% 50%; }
    50% { background-position: 100% 50%; }
    100% { background-position: 0% 50%; }
}

.block-container {
    padding-top: 1.5rem;
}

h1 {
    text-align: center;
    color: #38bdf8 !important;
    font-size: 48px !important;
    font-weight: 900 !important;
    text-shadow: 0 0 20px rgba(56,189,248,0.9);
}

h2, h3 {
    color: #f8fafc !important;
}

.command-center {
    background: linear-gradient(90deg, rgba(15,23,42,0.95), rgba(30,41,59,0.9), rgba(15,23,42,0.95));
    border: 1px solid #38bdf8;
    border-radius: 24px;
    padding: 24px;
    margin-bottom: 28px;
    box-shadow: 0 0 35px rgba(56,189,248,0.35);
    animation: glowPulse 3s ease-in-out infinite;
}

@keyframes glowPulse {
    0% { box-shadow: 0 0 22px rgba(56,189,248,0.25); }
    50% { box-shadow: 0 0 40px rgba(56,189,248,0.65); }
    100% { box-shadow: 0 0 22px rgba(56,189,248,0.25); }
}

.command-title {
    color: white;
    font-size: 28px;
    font-weight: 900;
}

.command-subtitle {
    color: #bfdbfe;
    font-size: 16px;
}

.status-active {
    color: #22c55e;
    font-weight: 900;
}

[data-testid="stMetric"] {
    background: rgba(15,23,42,0.92);
    border: 1px solid #38bdf8;
    padding: 22px;
    border-radius: 20px;
    box-shadow: 0 0 25px rgba(56,189,248,0.25);
}

[data-testid="stMetric"]:hover {
    transform: translateY(-4px);
    transition: 0.3s ease;
    box-shadow: 0 0 35px rgba(56,189,248,0.55);
}

section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #020617, #0f172a);
    border-right: 1px solid #334155;
}

div[data-testid="stButton"] > button,
div[data-testid="stDownloadButton"] > button {
    background: linear-gradient(90deg, #2563eb, #06b6d4);
    color: white;
    border-radius: 14px;
    border: none;
    font-weight: 800;
    box-shadow: 0 0 18px rgba(6,182,212,0.45);
}
            .stApp::before {
    content: "";
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;

    background-image:
        linear-gradient(rgba(56,189,248,0.08) 1px, transparent 1px),
        linear-gradient(90deg, rgba(56,189,248,0.08) 1px, transparent 1px);

    background-size: 45px 45px;
    animation: gridMove 18s linear infinite;
    pointer-events: none;
    z-index: 0;
}

@keyframes gridMove {
    from {
        background-position: 0 0;
    }
    to {
        background-position: 90px 90px;
    }
}
            section.main > div {
    position: relative;
    z-index: 1;
}

[data-testid="stVerticalBlock"] {
    animation: fadeInUp 0.7s ease;
}

@keyframes fadeInUp {
    from {
        opacity: 0;
        transform: translateY(18px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}
            .stApp::after {
    content: "";
    position: fixed;
    inset: 0;
    background:
        radial-gradient(circle at 15% 25%, rgba(0,255,255,0.18), transparent 20%),
        radial-gradient(circle at 85% 20%, rgba(255,0,80,0.15), transparent 22%),
        radial-gradient(circle at 50% 90%, rgba(0,255,120,0.10), transparent 25%);
    animation: pulseGlow 6s ease-in-out infinite alternate;
    pointer-events: none;
    z-index: 0;
}

@keyframes pulseGlow {
    from {
        opacity: 0.45;
        filter: blur(0px);
    }
    to {
        opacity: 0.9;
        filter: blur(2px);
    }
}

.block-container {
    position: relative;
    z-index: 2;
}

[data-testid="stHeader"] {
    background: rgba(2, 6, 23, 0.75);
    backdrop-filter: blur(12px);
}

.cyber-card {
    background: linear-gradient(135deg, rgba(15,23,42,0.95), rgba(30,41,59,0.85));
    border: 1px solid rgba(56,189,248,0.65);
    border-radius: 22px;
    padding: 22px;
    box-shadow:
        0 0 25px rgba(56,189,248,0.25),
        inset 0 0 20px rgba(56,189,248,0.06);
    margin-bottom: 22px;
}
            [data-testid="stMetric"]{
    background: rgba(15,23,42,0.92);
    border: 1px solid rgba(56,189,248,0.5);
    border-radius: 18px;
    padding: 15px;
    box-shadow: 0 0 20px rgba(56,189,248,0.15);
    transition: all 0.3s ease;
}

[data-testid="stMetric"]:hover{
    transform: translateY(-6px);
    box-shadow: 0 0 35px rgba(56,189,248,0.55);
    border: 1px solid #38bdf8;
}

[data-testid="stMetricValue"]{
    color:#38bdf8;
    font-size:32px;
    font-weight:bold;
}

[data-testid="stMetricLabel"]{
    color:#e2e8f0;
    font-weight:600;
}
</style>
""", unsafe_allow_html=True)
st.title("Threat Intelligence Aggregator & Risk Scoring System")
from datetime import datetime

current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
st.markdown("""
<div class="soc-banner">
    <h2>🚨 SOC Monitoring Status: ACTIVE</h2>
    <p>Real-time Mac process monitoring, AbuseIPDB enrichment, VirusTotal lookup, risk scoring, MITRE mapping, alert rules, and incident reporting are enabled.</p>
</div>
""", unsafe_allow_html=True)
st.markdown("""
<div style="
    width:100%;
    overflow:hidden;
    background:rgba(15,23,42,0.95);
    border:1px solid #38bdf8;
    border-radius:14px;
    padding:12px;
    box-shadow:0 0 20px rgba(56,189,248,0.35);
    margin-bottom:25px;
">
<marquee behavior="scroll" direction="left" scrollamount="7" style="
    color:#67e8f9;
    font-weight:800;
    font-size:16px;
">
🚨 LIVE SOC FEED ACTIVE &nbsp;&nbsp; | &nbsp;&nbsp;
Real-time Mac Agent Monitoring Enabled &nbsp;&nbsp; | &nbsp;&nbsp;
AbuseIPDB Reputation Checks Active &nbsp;&nbsp; | &nbsp;&nbsp;
VirusTotal Lookup Enabled &nbsp;&nbsp; | &nbsp;&nbsp;
MITRE ATT&CK Mapping Enabled &nbsp;&nbsp; | &nbsp;&nbsp;
Incident Reports & CSV Export Ready
</marquee>
</div>
""", unsafe_allow_html=True)
st.markdown("""
<div class="cyber-card">
<h3>⚙️ Backend Processing Architecture</h3>

<pre>
Real-Time Agent
   ├── Monitors Mac Processes
   ├── Detects Suspicious Activity
   └── Generates Alerts

Threat Intelligence
   ├── AbuseIPDB
   └── VirusTotal

Risk Engine
   ├── Risk Score
   ├── Risk Level
   └── Recommended Action

Reporting
   ├── Dashboard
   ├── CSV Export
   └── PDF Reports
</pre>

</div>
""", unsafe_allow_html=True)
st.markdown(f"""
<div class="command-center">
    <div class="command-title">🛡️ SOC Command Center</div>
    <div class="command-subtitle">
        Status: <span class="status-active">ACTIVE</span> |
        Real-Time Monitoring Enabled |
        AbuseIPDB + VirusTotal Integrated |
        Current Time: {current_time}
    </div>
</div>
""", unsafe_allow_html=True)
st.markdown("""
<div style="
    background: rgba(15,23,42,0.9);
    border: 1px solid #38bdf8;
    border-radius: 14px;
    padding: 10px;
    overflow: hidden;
    margin-bottom: 20px;
">
<marquee behavior="scroll" direction="left" scrollamount="6" style="color:#67e8f9; font-weight:700;">
🚨 LIVE SOC FEED ACTIVE &nbsp;&nbsp; | &nbsp;&nbsp;
Real-time Mac agent monitoring processes &nbsp;&nbsp; | &nbsp;&nbsp;
AbuseIPDB enrichment enabled &nbsp;&nbsp; | &nbsp;&nbsp;
VirusTotal lookup enabled &nbsp;&nbsp; | &nbsp;&nbsp;
MITRE ATT&CK mapping active &nbsp;&nbsp; | &nbsp;&nbsp;
Incident reports available
</marquee>
</div>
""", unsafe_allow_html=True)
# ====================================
# SYSTEM HEALTH CARDS
# ====================================
st.markdown("""
<hr style="
border: none;
height: 2px;
background: linear-gradient(90deg, transparent, #38bdf8, #ef4444, transparent);
box-shadow: 0 0 14px #38bdf8;
margin: 30px 0;
">
""", unsafe_allow_html=True)

st.subheader("🖥️ System Health Monitor")

cpu_usage = psutil.cpu_percent(interval=1)
ram_usage = psutil.virtual_memory().percent
disk_usage = psutil.disk_usage("/").percent
active_processes = len(psutil.pids())

col1, col2, col3, col4 = st.columns(4)

col1.metric("CPU Usage", f"{cpu_usage}%")
col2.metric("RAM Usage", f"{ram_usage}%")
col3.metric("Disk Usage", f"{disk_usage}%")
col4.metric("Active Processes", active_processes)
# ====================================


st.info(f"Current System Time: {current_time}")
st.markdown("""
<style>
.main {
    background-color: #0e1117;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}

.metric-card {
    background-color: #161b22;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #30363d;
}

.alert-box {
    background-color: #2d1117;
    padding: 15px;
    border-left: 5px solid #ff4b4b;
    border-radius: 8px;
    color: white;
}

.success-box {
    background-color: #10291b;
    padding: 15px;
    border-left: 5px solid #2ecc71;
    border-radius: 8px;
    color: white;
}

h1, h2, h3 {
    color: #f0f6fc;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="alert-box">
<h3> SOC Monitoring Status: ACTIVE</h3>
<p>Real-time Mac agent, AbuseIPDB, VirusTotal, risk scoring, and alert engine are running.</p>
</div>
""", unsafe_allow_html=True)
st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #050505 0%, #0b1220 50%, #111827 100%);
    color: #f8fafc;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}

h1 {
    color: #38bdf8;
    font-size: 42px !important;
    font-weight: 800 !important;
}

h2, h3 {
    color: #e5e7eb;
}

[data-testid="stMetric"] {
    background: linear-gradient(135deg, #111827, #1e293b);
    border: 1px solid #334155;
    padding: 20px;
    border-radius: 18px;
    box-shadow: 0 0 18px rgba(56, 189, 248, 0.15);
}

[data-testid="stMetricLabel"] {
    color: #93c5fd;
}

[data-testid="stMetricValue"] {
    color: #f8fafc;
    font-size: 32px;
}

.soc-banner {
    background: linear-gradient(90deg, #7f1d1d, #991b1b, #1e3a8a);
    padding: 22px;
    border-radius: 18px;
    border: 1px solid #ef4444;
    box-shadow: 0 0 25px rgba(239, 68, 68, 0.35);
    margin-bottom: 25px;
}

.soc-banner h2 {
    color: #ffffff;
    margin-bottom: 5px;
}

.soc-banner p {
    color: #fee2e2;
    font-size: 16px;
}

.info-card {
    background: rgba(15, 23, 42, 0.95);
    padding: 20px;
    border-radius: 16px;
    border: 1px solid #334155;
    box-shadow: 0 0 14px rgba(14, 165, 233, 0.12);
    margin-bottom: 20px;
}

.ale
rt-card {
    background: rgba(127, 29, 29, 0.9);
    padding: 18px;
    border-radius: 16px;
    border-left: 6px solid #f87171;
    box-shadow: 0 0 18px rgba(248, 113, 113, 0.25);
    margin-bottom: 20px;
}

.success-card {
    background: rgba(20, 83, 45, 0.9);
    padding: 18px;
    border-radius: 16px;
    border-left: 6px solid #22c55e;
    box-shadow: 0 0 18px rgba(34, 197, 94, 0.25);
    margin-bottom: 20px;
}

section[data-testid="stSidebar"] {
    background: #020617;
    border-right: 1px solid #1e293b;
}

.stDataFrame {
    border-radius: 14px;
    overflow: hidden;
}

div[data-testid="stButton"] > button {
    background: linear-gradient(90deg, #2563eb, #06b6d4);
    color: white;
    border-radius: 12px;
    border: none;
    padding: 0.6rem 1rem;
    font-weight: 700;
}

div[data-testid="stDownloadButton"] > button {
    background: linear-gradient(90deg, #16a34a, #22c55e);
    color: white;
    border-radius: 12px;
    border: none;
    padding: 0.6rem 1rem;
    font-weight: 700;
}
</style>
""", unsafe_allow_html=True)

# ====================================
# ====================================
# PROJECT ARCHITECTURE
# ====================================
st.markdown("""
<hr style="
border: none;
height: 2px;
background: linear-gradient(90deg, transparent, #38bdf8, #ef4444, transparent);
box-shadow: 0 0 14px #38bdf8;
margin: 30px 0;
">
""", unsafe_allow_html=True)

st.markdown("""
<div class="info-card">
<h3>🧩 Threat Intelligence Aggregator & Risk Scoring System</h3>
</div>
""", unsafe_allow_html=True)

 
# SOC KILL CHAIN / ATTACK FLOW
# ====================================

st.subheader("🧬 SOC Detection & Intelligence Flow")

st.markdown("""
<div class="info-card" style="padding: 22px; border-radius: 18px; background: rgba(15,23,42,0.85); border: 1px solid #1e293b; margin-bottom: 25px; box-shadow: 0 4px 20px rgba(0,0,0,0.3);">
<h3 style="color: #38bdf8; margin-top: 0; margin-bottom: 20px; font-size: 20px; font-weight: 700;">⚡ Automated Threat Intelligence Pipeline</h3>
<div style="display:flex; justify-content:space-between; align-items:center; gap:12px; text-align:center; flex-wrap: wrap;">
<div style="flex:1; min-width: 140px; padding:16px 12px; border-radius:14px; background:#0f172a; border:1px solid #38bdf8; box-shadow: 0 0 15px rgba(56,189,248,0.15);">
<div style="font-size: 26px; margin-bottom: 6px;">📥</div>
<div style="color: #38bdf8; font-weight: 700; font-size: 15px;">Log Sources</div>
<div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Endpoint / DDoS / Mac Agent</div>
</div>
<div style="font-size:22px; color:#38bdf8; font-weight: 900;">➜</div>
<div style="flex:1; min-width: 140px; padding:16px 12px; border-radius:14px; background:#0f172a; border:1px solid #f97316; box-shadow: 0 0 15px rgba(249,115,22,0.15);">
<div style="font-size: 26px; margin-bottom: 6px;">🔍</div>
<div style="color: #f97316; font-weight: 700; font-size: 15px;">Detection</div>
<div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Rules + Process Monitor</div>
</div>
<div style="font-size:22px; color:#f97316; font-weight: 900;">➜</div>
<div style="flex:1; min-width: 140px; padding:16px 12px; border-radius:14px; background:#0f172a; border:1px solid #eab308; box-shadow: 0 0 15px rgba(234,179,8,0.15);">
<div style="font-size: 26px; margin-bottom: 6px;">🎯</div>
<div style="color: #eab308; font-weight: 700; font-size: 15px;">Risk Score</div>
<div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Low / Medium / High</div>
</div>
<div style="font-size:22px; color:#eab308; font-weight: 900;">➜</div>
<div style="flex:1; min-width: 140px; padding:16px 12px; border-radius:14px; background:#0f172a; border:1px solid #22c55e; box-shadow: 0 0 15px rgba(34,197,94,0.15);">
<div style="font-size: 26px; margin-bottom: 6px;">🌐</div>
<div style="color: #22c55e; font-weight: 700; font-size: 15px;">Threat Intel</div>
<div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">AbuseIPDB + VirusTotal</div>
</div>
<div style="font-size:22px; color:#22c55e; font-weight: 900;">➜</div>
<div style="flex:1; min-width: 140px; padding:16px 12px; border-radius:14px; background:#0f172a; border:1px solid #ef4444; box-shadow: 0 0 15px rgba(239,68,68,0.15);">
<div style="font-size: 26px; margin-bottom: 6px;">🚨</div>
<div style="color: #ef4444; font-weight: 700; font-size: 15px;">Alert & Report</div>
<div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">SOC Panel + PDF Export</div>
</div>
</div>
</div>
""", unsafe_allow_html=True)
# LOAD DATASETS
# ====================================
st.markdown("""
<hr style="
border: none;
height: 2px;
background: linear-gradient(90deg, transparent, #38bdf8, #ef4444, transparent);
box-shadow: 0 0 14px #38bdf8;
margin: 30px 0;
">
""", unsafe_allow_html=True)

import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# For enriched_endpoint_logs.csv
endpoint_df = pd.read_csv(os.path.join(BASE_DIR, "..", "datasets", "enriched_endpoint_logs.csv"))

# For ddos_risk_logs.csv
ddos_df = pd.read_csv(os.path.join(BASE_DIR, "..", "datasets", "ddos_risk_logs.csv"))


st.markdown("""
<hr style="
border: none;
height: 2px;
background: linear-gradient(90deg, transparent, #38bdf8, #ef4444, transparent);
box-shadow: 0 0 14px #38bdf8;
margin: 30px 0;
">
""", unsafe_allow_html=True)
# ====================================

realtime_path = os.path.join(BASE_DIR, "..", "datasets", "realtime_alerts.csv")

if os.path.exists(realtime_path):

    realtime_df = pd.read_csv(
        realtime_path,
        on_bad_lines="skip"
    )

else:

    realtime_df = pd.DataFrame(columns=[
        "time",
        "attack_type",
        "process_name",
        "pid",
        "risk_score",
        "risk_level",
        "source",
        "details"
    ])

# ====================================
# VIRUSTOTAL DATA
# ====================================

vt_path = os.path.join(BASE_DIR, "..", "datasets", "virustotal_results.csv")

if os.path.exists(vt_path):

    vt_df = pd.read_csv(
        vt_path,
        on_bad_lines="skip"
    )

else:

    vt_df = pd.DataFrame(columns=[
        "indicator",
        "malicious",
        "suspicious",
        "harmless",
        "undetected"
    ])

# ====================================
# MAC FAILED LOGINS & UNIFIED LOG DATA
# ====================================

mac_logins_path = os.path.join(BASE_DIR, "..", "datasets", "mac_failed_logins.csv")

if os.path.exists(mac_logins_path):
    mac_logins_df = pd.read_csv(
        mac_logins_path,
        on_bad_lines="skip"
    )
    if "event" in mac_logins_df.columns and "details" not in mac_logins_df.columns:
        mac_logins_df = mac_logins_df.rename(columns={"event": "details"})
else:
    mac_logins_df = pd.DataFrame(columns=[
        "time",
        "attack_type",
        "risk_score",
        "risk_level",
        "source",
        "details"
    ])

# ====================================
# SOURCE LABELS
# ====================================

endpoint_df["source"] = "Endpoint Logs"

# ====================================
# COMBINE DATASETS & FILTERS
# ====================================

combined_df = pd.concat(
    [
        endpoint_df,
        realtime_df,
        mac_logins_df
    ],
    ignore_index=True
)

combined_df["risk_level"] = combined_df["risk_level"].fillna("Unknown")
combined_df["attack_type"] = combined_df["attack_type"].fillna("Unknown")
combined_df["risk_score"] = pd.to_numeric(combined_df["risk_score"], errors="coerce").fillna(0)

# Sidebar Filters
st.sidebar.header("🎯 SOC Filter Controls")

risk_options = [r for r in combined_df["risk_level"].unique() if pd.notna(r)]
risk_filter = st.sidebar.multiselect(
    "Select Risk Level",
    options=risk_options,
    default=risk_options
)

source_options = [s for s in combined_df["source"].unique() if pd.notna(s)]
source_filter = st.sidebar.multiselect(
    "Select Log Source",
    options=source_options,
    default=source_options
)

filtered_df = combined_df[
    (combined_df["risk_level"].isin(risk_filter)) &
    (combined_df["source"].isin(source_filter))
].copy()

def recommend_action(row):
    attack = str(row.get("attack_type", "")).lower()
    source = str(row.get("source", "")).lower()
    score = float(row.get("risk_score", 0))

    if "ddos" in attack:
        return "Check traffic spike, rate-limit source, review firewall logs"
    elif "suspicious" in attack or "process" in attack:
        return "Investigate process, verify command, terminate if malicious"
    elif score >= 80:
        return "Immediate investigation required"
    elif score >= 50:
        return "Monitor and review related logs"
    else:
        return "Low priority, keep for baseline"

filtered_df["recommended_action"] = filtered_df.apply(recommend_action, axis=1)
combined_df["recommended_action"] = combined_df.apply(recommend_action, axis=1)

# ====================================
# MAIN DASHBOARD TABS
# ====================================

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🏠 Overview",
    "🚨 Alerts",
    "🌐 Threat Intel",
    "📊 Analytics",
    "📄 Reports"
])

# ==============================================================================
# TAB 1: 🏠 OVERVIEW
# ==============================================================================
with tab1:
    st.subheader("📊 SOC Threat Command Overview")

    total_threats = len(filtered_df)
    high_risk_alerts = len(filtered_df[filtered_df["risk_level"] == "High"])
    medium_risk_alerts = len(filtered_df[filtered_df["risk_level"] == "Medium"])
    live_count = len(realtime_df)
    avg_risk_score = float(filtered_df["risk_score"].mean()) if not filtered_df.empty else 0.0

    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("🚨 Total Threats", total_threats)
    k2.metric("🔴 High Risk", high_risk_alerts)
    k3.metric("🟡 Medium Risk", medium_risk_alerts)
    k4.metric("⚡ Live Mac Events", live_count)
    k5.metric("🎯 Avg Severity", f"{round(avg_risk_score, 1)}/100")

    st.markdown("---")

    # Threat Correlation Engine
    st.subheader("⚡ Threat Correlation Engine")
    correlation_alerts = []
    if "abuse_score" in filtered_df.columns:
        high_abuse_count = len(filtered_df[pd.to_numeric(filtered_df["abuse_score"], errors="coerce").fillna(0) >= 50])
        if high_abuse_count > 0:
            correlation_alerts.append(f"⚠️ High AbuseIPDB Reputation Indicators: {high_abuse_count} suspicious IPs detected.")
    if "malicious" in vt_df.columns and not vt_df.empty:
        vt_malicious_count = len(vt_df[pd.to_numeric(vt_df["malicious"], errors="coerce").fillna(0) > 0])
        if vt_malicious_count > 0:
            correlation_alerts.append(f"🚨 VirusTotal Malicious Indicators: {vt_malicious_count} confirmed malicious IOCs.")
    if high_risk_alerts > 0:
        correlation_alerts.append(f"🔴 Active High Risk Threat Incidents: {high_risk_alerts} events require triage.")
    if len(realtime_df) > 0:
        correlation_alerts.append(f"📡 Real-time Host Ingestion Active: {len(realtime_df)} live host events logged.")

    for alert in correlation_alerts:
        st.warning(alert)
    if not correlation_alerts:
        st.success("✅ System Clean: No critical threat correlations active.")

    st.markdown("---")

    # Risk Gauges
    c_gauge1, c_gauge2 = st.columns(2)
    with c_gauge1:
        st.subheader("🎯 Overall Threat Severity Index")
        fig_gauge = go.Figure(
            go.Indicator(
                mode="gauge+number+delta",
                value=avg_risk_score,
                title={"text": "SOC Threat Index", "font": {"size": 22, "color": "#38bdf8"}},
                number={"suffix": "/100", "font": {"size": 38, "color": "white"}},
                gauge={
                    "axis": {"range": [0, 100], "tickwidth": 2, "tickcolor": "#94a3b8"},
                    "bar": {"color": "#00ffff", "thickness": 0.3},
                    "steps": [
                        {"range": [0, 30], "color": "#16a34a"},
                        {"range": [30, 60], "color": "#ca8a04"},
                        {"range": [60, 80], "color": "#ea580c"},
                        {"range": [80, 100], "color": "#dc2626"}
                    ],
                    "threshold": {
                        "line": {"color": "white", "width": 4},
                        "thickness": 0.75,
                        "value": avg_risk_score
                    }
                }
            )
        )
        fig_gauge.update_layout(height=320, margin=dict(l=20, r=20, t=40, b=20), paper_bgcolor="rgba(0,0,0,0)", font={"color": "white"})
        st.plotly_chart(fig_gauge, use_container_width=True)

    with c_gauge2:
        st.subheader("🛡️ Risk vs Nominal Capacity")
        risk_pie_gauge = px.pie(
            names=["Threat Load", "Nominal Capacity"],
            values=[max(avg_risk_score, 1), max(100 - avg_risk_score, 0)],
            hole=0.65,
            color=["Threat Load", "Nominal Capacity"],
            color_discrete_map={"Threat Load": "#ef4444", "Nominal Capacity": "#22c55e"}
        )
        risk_pie_gauge.update_layout(height=320, margin=dict(l=20, r=20, t=40, b=20), paper_bgcolor="rgba(0,0,0,0)", font={"color": "white"})
        st.plotly_chart(risk_pie_gauge, use_container_width=True)

    st.markdown("---")

    # Recommendations & MITRE Mapping
    col_rec, col_mitre = st.columns([1, 1])
    with col_rec:
        st.subheader("💡 SOC Analyst Recommendations")
        recommendations = []
        if high_risk_alerts > 0:
            recommendations.append("🚨 Priority 1: Investigate and triage all High-Risk alerts immediately.")
        if medium_risk_alerts > 0:
            recommendations.append("⚠️ Priority 2: Review Medium-Risk events for lateral movement or persistence.")
        if "abuse_score" in endpoint_df.columns:
            risky_ips = len(endpoint_df[endpoint_df["abuse_score"].fillna(0) >= 50])
            if risky_ips > 0:
                recommendations.append(f"🌐 Found {risky_ips} high-risk external IPs. Validate and enforce perimeter firewall blocking.")
        if len(realtime_df) > 0:
            recommendations.append("💻 Review live Mac process activity and audit failed sudo attempts.")
        if not recommendations:
            recommendations.append("✅ Baseline normal: No immediate SOC remediation required.")
        for item in recommendations:
            st.info(item)

    with col_mitre:
        st.subheader("🎯 MITRE ATT&CK Matrix Mapping")
        mitre_mapping = pd.DataFrame({
            "Attack Type": ["DDoS Attack", "Suspicious Process", "Failed Password", "Brute Force", "SQL Injection"],
            "MITRE ID": ["T1498", "T1059", "T1110", "T1110.001", "T1190"],
            "Tactic": ["Impact", "Execution", "Credential Access", "Credential Access", "Initial Access"],
            "Technique Name": ["Network Denial of Service", "Command & Scripting", "Brute Force Auth", "Password Guessing", "Exploit Public Application"]
        })
        st.dataframe(mitre_mapping, use_container_width=True)

# ==============================================================================
# TAB 2: 🚨 ALERTS
# ==============================================================================
with tab2:
    st.subheader("⚡ Live Mac & Real-Time Alert Stream")
    st.caption("Live streaming endpoint telemetry and macOS unified audit logs")

    if not realtime_df.empty:
        rt_display = realtime_df.copy()
        if "time" in rt_display.columns:
            rt_display = rt_display.sort_values(by="time", ascending=False)
        st.dataframe(rt_display, use_container_width=True)
    else:
        st.info("No live alerts recorded yet. Start `python3 dashboard/agent/real_time_agent.py` or `python3 dashboard/agent/mac_failed_password_monitor.py`.")

    st.markdown("---")

    # Real-Time Mac Process & System Alerts
    st.subheader("🚨 Real-Time Mac Process & System Alerts")
    if not realtime_df.empty:
        st.error(f"🚨 Live threat activity detected on Mac ({len(realtime_df)} events captured).")
        rt_recent = realtime_df.copy()
        if "time" in rt_recent.columns:
            rt_recent = rt_recent.sort_values(by="time", ascending=False)
        st.dataframe(rt_recent.head(15), use_container_width=True)
    else:
        st.info("No live Mac process alerts currently detected.")

    st.markdown("---")

    # High Risk SOC Action Panel
    st.subheader("🔴 High Risk Threats - SOC Action Panel")
    high_df = filtered_df[filtered_df["risk_level"] == "High"]
    display_cols = ["time", "attack_type", "risk_score", "risk_level", "source", "recommended_action", "details"]
    available_display_cols = [c for c in display_cols if c in high_df.columns]

    if not high_df.empty:
        st.dataframe(high_df[available_display_cols].head(50), use_container_width=True)
        csv_data = high_df.to_csv(index=False)
        st.download_button(
            label="📥 Download High Risk Threat Report (CSV)",
            data=csv_data,
            file_name="high_risk_threat_report.csv",
            mime="text/csv"
        )
    else:
        st.success("No High-Risk alerts matching current filters.")

    st.markdown("---")

    # Alert Rules Engine
    st.subheader("⚙️ SOC Alert Rules Engine")
    active_rule_alerts = []
    if len(high_df) >= 5:
        active_rule_alerts.append(f"🔴 Rule 1 Triggered: High Volume of High-Risk Alerts ({len(high_df)}).")
    if "malicious" in vt_df.columns:
        malicious_iocs = len(vt_df[vt_df["malicious"] > 0])
        if malicious_iocs > 0:
            active_rule_alerts.append(f"⚠️ Rule 2 Triggered: {malicious_iocs} malicious indicators identified in VirusTotal.")
    if len(realtime_df) >= 10:
        active_rule_alerts.append(f"📡 Rule 3 Triggered: High volume of live host detections ({len(realtime_df)}).")

    if active_rule_alerts:
        for a in active_rule_alerts:
            st.error(a)
    else:
        st.success("All alert rules passing within nominal thresholds.")

    st.markdown("---")

    # Backend API Alerts
    st.subheader("🗄️ Backend API Alerts (FastAPI Live Endpoint)")
    try:
        response = requests.get("http://127.0.0.1:8000/alerts", timeout=2)
        if response.status_code == 200:
            api_data = response.json()["alerts"]
            api_df = pd.DataFrame(
                api_data,
                columns=["time", "attack_type", "risk_level", "risk_score", "source", "details"]
            )
            st.dataframe(api_df, use_container_width=True)
        else:
            st.error(f"API returned status code: {response.status_code}")
    except Exception:
        st.info("Backend API is currently offline. Run `uvicorn backend.api:app --reload --port 8000` to enable.")

# ==============================================================================
# TAB 3: 🌐 THREAT INTEL
# ==============================================================================
with tab3:
    st.subheader("🔍 Live VirusTotal IP & IOC Lookup")
    c_vt1, c_vt2 = st.columns([3, 1])
    with c_vt1:
        vt_input = st.text_input("Enter IP address or indicator to scan against VirusTotal:", value="8.8.8.8")
    with c_vt2:
        st.write("")
        st.write("")
        scan_btn = st.button("🚀 Scan Indicator", use_container_width=True)

    if scan_btn:
        if not VT_API_KEY:
            st.error("VirusTotal API key not found in .env file.")
        elif not vt_input:
            st.warning("Please enter an IP address.")
        else:
            try:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{vt_input.strip()}"
                headers = {"x-apikey": VT_API_KEY}
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    stats = data["data"]["attributes"]["last_analysis_stats"]
                    st.success(f"VirusTotal lookup completed for {vt_input}")
                    col1, col2, col3, col4 = st.columns(4)
                    col1.metric("🔴 Malicious", stats.get("malicious", 0))
                    col2.metric("🟡 Suspicious", stats.get("suspicious", 0))
                    col3.metric("🟢 Harmless", stats.get("harmless", 0))
                    col4.metric("⚪ Undetected", stats.get("undetected", 0))

                    new_vt_result = pd.DataFrame([{
                        "indicator": vt_input.strip(),
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0)
                    }])
                    if os.path.exists(vt_path):
                        old_vt = pd.read_csv(vt_path, on_bad_lines="skip")
                        up_vt = pd.concat([old_vt, new_vt_result], ignore_index=True)
                    else:
                        up_vt = new_vt_result
                    up_vt.to_csv(vt_path, index=False)
                    st.success("Scan result persisted to virustotal_results.csv")
                else:
                    st.error(f"VirusTotal API error: {response.status_code}")
            except Exception as e:
                st.error(f"Error querying VirusTotal: {e}")

    st.markdown("---")

    # AbuseIPDB Threat Intelligence
    st.subheader("🌐 AbuseIPDB Threat Intelligence Enrichment")
    if "abuse_score" in endpoint_df.columns:
        avg_abuse = endpoint_df["abuse_score"].fillna(0).mean()
        high_abuse_count = len(endpoint_df[endpoint_df["abuse_score"].fillna(0) >= 50])
        tor_count = len(endpoint_df[endpoint_df["is_tor"] == True]) if "is_tor" in endpoint_df.columns else 0

        m1, m2, m3 = st.columns(3)
        m1.metric("Average AbuseIPDB Score", f"{round(avg_abuse, 1)}/100")
        m2.metric("High Reputation Risk IPs", high_abuse_count)
        m3.metric("Tor Exit Nodes Detected", tor_count)

        intel_cols = ["IpAddress", "abuse_score", "country", "isp", "domain", "is_tor", "total_reports", "risk_score", "risk_level"]
        available_cols = [c for c in intel_cols if c in endpoint_df.columns]
        st.dataframe(endpoint_df[available_cols].head(50), use_container_width=True)

        high_abuse = endpoint_df[endpoint_df["abuse_score"].fillna(0) >= 50]
        if not high_abuse.empty:
            st.subheader("⚠️ High Reputation-Risk Watchlist")
            st.dataframe(high_abuse[available_cols], use_container_width=True)
    else:
        st.info("AbuseIPDB enrichment data not available. Run `python3 api/enrich_logs.py` to generate.")

    st.markdown("---")

    # VirusTotal Panel
    st.subheader("🛡️ VirusTotal Dataset Reputation History")
    if not vt_df.empty:
        vt_display = vt_df.copy()
        vt_display["threat_status"] = vt_display.apply(
            lambda r: "Malicious" if r.get("malicious", 0) > 0 or r.get("suspicious", 0) > 0 else "Clean",
            axis=1
        )
        st.dataframe(vt_display, use_container_width=True)
    else:
        st.info("No VirusTotal historical records found. Run `python3 api/virustotal_lookup.py`.")

    st.markdown("---")

    # Globe Map & Geo-IP
    st.subheader("🌍 Global Threat Intelligence Map")
    if "country" in endpoint_df.columns:
        globe_df = endpoint_df["country"].fillna("Unknown").value_counts().reset_index()
        globe_df.columns = ["country", "threat_count"]
        globe_df = globe_df[globe_df["country"] != "Unknown"]

        if not globe_df.empty:
            c_map, c_bar = st.columns([3, 2])
            with c_map:
                globe_map = px.choropleth(
                    globe_df,
                    locations="country",
                    locationmode="ISO-3",
                    color="threat_count",
                    hover_name="country",
                    title="Threat Distribution by Country Code",
                    color_continuous_scale="Reds"
                )
                globe_map.update_layout(paper_bgcolor="rgba(0,0,0,0)", geo_bgcolor="rgba(0,0,0,0)", font_color="white", height=380)
                st.plotly_chart(globe_map, use_container_width=True)
            with c_bar:
                country_chart = px.bar(
                    globe_df.head(8),
                    x="country",
                    y="threat_count",
                    title="Top Threat Origin Countries",
                    color="threat_count",
                    color_continuous_scale="Reds"
                )
                country_chart.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white", height=380)
                st.plotly_chart(country_chart, use_container_width=True)

# ==============================================================================
# TAB 4: 📊 ANALYTICS
# ==============================================================================
with tab4:
    st.subheader("📈 SOC Threat Analytics & Temporal Trends")

    col_chart1, col_chart2 = st.columns(2)
    with col_chart1:
        top_attacks = filtered_df["attack_type"].value_counts().reset_index()
        top_attacks.columns = ["attack_type", "count"]
        top_attack_chart = px.bar(
            top_attacks.head(10),
            x="attack_type",
            y="count",
            color="count",
            title="Top 10 Detected Attack Types",
            color_continuous_scale="Blues"
        )
        top_attack_chart.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(top_attack_chart, use_container_width=True)

    with col_chart2:
        top_sources = filtered_df["source"].value_counts().reset_index()
        top_sources.columns = ["source", "count"]
        source_chart = px.bar(
            top_sources,
            x="source",
            y="count",
            color="count",
            title="Threat Events by Log Source",
            color_continuous_scale="Teal"
        )
        source_chart.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(source_chart, use_container_width=True)

    st.markdown("---")

    col_chart3, col_chart4 = st.columns(2)
    with col_chart3:
        risk_pie = px.pie(
            filtered_df,
            names="risk_level",
            title="Threat Events by Risk Level",
            color="risk_level",
            color_discrete_map={"High": "#ef4444", "Medium": "#eab308", "Low": "#22c55e", "Unknown": "#94a3b8"}
        )
        risk_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(risk_pie, use_container_width=True)

    with col_chart4:
        attack_chart = px.histogram(
            filtered_df,
            x="attack_type",
            color="risk_level",
            title="Attack Types Breakdown by Severity",
            color_discrete_map={"High": "#ef4444", "Medium": "#eab308", "Low": "#22c55e", "Unknown": "#94a3b8"}
        )
        attack_chart.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(attack_chart, use_container_width=True)

    st.markdown("---")

    # Threat Timeline
    st.subheader("📅 Threat Event Timeline")
    if "time" in filtered_df.columns:
        t_df = filtered_df.copy()
        t_df["time"] = pd.to_datetime(t_df["time"], errors="coerce")
        t_df = t_df.dropna(subset=["time"])
        if not t_df.empty:
            timeline_chart = px.histogram(
                t_df,
                x="time",
                color="risk_level",
                title="Event Frequency Over Time",
                color_discrete_map={"High": "#ef4444", "Medium": "#eab308", "Low": "#22c55e"}
            )
            timeline_chart.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(timeline_chart, use_container_width=True)
        else:
            st.info("No timeline data with valid timestamps available.")

# ==============================================================================
# TAB 5: 📄 REPORTS
# ==============================================================================
with tab5:
    st.subheader("📄 Incident Briefing & Report Export")

    latest_high = filtered_df[filtered_df["risk_level"] == "High"]
    if not latest_high.empty:
        latest_event = latest_high.iloc[-1]
        st.warning(f"""
        **🚨 Latest Critical Incident Alert:**
        - **Attack Type:** {latest_event.get('attack_type', 'Unknown')}
        - **Source:** {latest_event.get('source', 'Unknown')}
        - **Risk Score:** {latest_event.get('risk_score', 'N/A')}
        - **Recommended Action:** {latest_event.get('recommended_action', 'Immediate investigation required.')}
        """)
    else:
        st.success("✅ No critical incidents currently active.")

    st.markdown("---")

    col_rep1, col_rep2 = st.columns(2)
    with col_rep1:
        st.subheader("📝 Automated Incident Report (Text)")
        high_alerts_list = filtered_df[filtered_df["risk_level"] == "High"].tail(10)
        report_text = f"""==================================================
THREAT INTELLIGENCE INCIDENT REPORT
Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
==================================================

EXECUTIVE SUMMARY:
- Total Events Analyzed: {len(filtered_df)}
- High Risk Threats: {len(filtered_df[filtered_df["risk_level"] == "High"])}
- Medium Risk Events: {len(filtered_df[filtered_df["risk_level"] == "Medium"])}
- Live Telemetry Alerts: {len(realtime_df)}

TOP RECENT HIGH-RISK DETECTIONS:
{high_alerts_list[["attack_type", "source", "risk_score"]].to_string() if not high_alerts_list.empty else "None"}

RECOMMENDED REMEDIATION ACTIONS:
1. Isolate compromised endpoints identified in live detections.
2. Block malicious external IP addresses flagged by AbuseIPDB and VirusTotal.
3. Review sudo audit logs and verify unauthorized access attempts.
4. Enforce strict rate-limiting for DDoS and Brute-Force indicators.
=================================================="""

        st.text_area("Incident Briefing Preview", report_text, height=260)
        st.download_button(
            label="📥 Download Incident Briefing (.txt)",
            data=report_text,
            file_name="soc_incident_report.txt",
            mime="text/plain"
        )

    with col_rep2:
        st.subheader("📑 PDF Incident Report Generator")
        st.write("Generate a professionally formatted PDF incident report summarizing active threats and recommended remediation steps.")

        if st.button("📄 Generate & Build PDF Report", use_container_width=True):
            try:
                pdf = FPDF()
                pdf.add_page()
                pdf.set_font("Arial", 'B', 16)
                pdf.cell(190, 10, txt="Threat Intelligence Incident Report", ln=True, align="C")
                pdf.ln(5)

                pdf.set_font("Arial", size=10)
                pdf.cell(190, 8, txt=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | SOC Analyst Report", ln=True, align="C")
                pdf.ln(8)

                pdf.set_font("Arial", 'B', 12)
                pdf.cell(190, 8, txt="1. Executive Summary", ln=True)
                pdf.set_font("Arial", size=10)
                pdf.cell(190, 6, txt=f"- Total Threat Events Analyzed: {len(filtered_df)}", ln=True)
                pdf.cell(190, 6, txt=f"- High Risk Incidents: {len(filtered_df[filtered_df['risk_level'] == 'High'])}", ln=True)
                pdf.cell(190, 6, txt=f"- Medium Risk Incidents: {len(filtered_df[filtered_df['risk_level'] == 'Medium'])}", ln=True)
                pdf.cell(190, 6, txt=f"- Real-time Host Ingestion Alerts: {len(realtime_df)}", ln=True)
                pdf.ln(6)

                pdf.set_font("Arial", 'B', 12)
                pdf.cell(190, 8, txt="2. Recent High-Risk Incidents", ln=True)
                pdf.set_font("Arial", size=9)
                top_pdf_alerts = filtered_df[filtered_df["risk_level"] == "High"].tail(8)
                for _, r in top_pdf_alerts.iterrows():
                    pdf.multi_cell(190, 6, txt=f"• Attack: {r.get('attack_type', 'N/A')} | Source: {r.get('source', 'N/A')} | Score: {r.get('risk_score', 'N/A')} | Time: {str(r.get('time', 'N/A'))[:19]}")
                pdf.ln(6)

                pdf.set_font("Arial", 'B', 12)
                pdf.cell(190, 8, txt="3. Remediation Recommendations", ln=True)
                pdf.set_font("Arial", size=9)
                pdf.multi_cell(190, 6, txt="• Immediately triage and terminate unauthorized suspicious processes.\n• Add malicious IPs from AbuseIPDB to edge firewall blacklists.\n• Verify system logs for repeated authentication failures.")

                pdf_dir = os.path.join(BASE_DIR, "..", "reports")
                os.makedirs(pdf_dir, exist_ok=True)
                pdf_path = os.path.join(pdf_dir, "incident_report.pdf")
                pdf.output(pdf_path)

                with open(pdf_path, "rb") as file:
                    st.download_button(
                        label="📥 Download PDF Incident Report",
                        data=file,
                        file_name="incident_report.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
                st.success("PDF generated successfully!")
            except Exception as e:
                st.error(f"Error generating PDF: {e}")

    st.markdown("---")

    # IOC Search Panel
    st.subheader("🔎 Universal IOC Search Panel")
    search_term = st.text_input("Search IP, process name, attack type, source, or domain keyword:")
    if search_term:
        searchable_df = filtered_df.astype(str)
        search_results = filtered_df[searchable_df.apply(lambda row: row.str.lower().str.contains(search_term.lower()).any(), axis=1)]
        st.write(f"Results Found: **{len(search_results)}**")
        st.dataframe(search_results.tail(100), use_container_width=True)
    else:
        st.info("Enter any IP, hash, process name, or keyword above to search.")

    st.markdown("---")

    # Unified Threat Intelligence Dataset
    st.subheader("🗂️ Unified Threat Intelligence Dataset (Live Ingestion)")
    st.dataframe(filtered_df.tail(200), use_container_width=True)
    st.download_button(
        label="📥 Export Full Dataset (CSV)",
        data=filtered_df.to_csv(index=False),
        file_name="unified_threat_dataset.csv",
        mime="text/csv"
    )