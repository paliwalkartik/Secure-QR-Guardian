"""
Main Streamlit entry point. Initializes session state and renders homepage.
 All analysis logic is in core/. This file is view-only.
"""

import os
import streamlit as st

# Configure Streamlit page layout and title
st.set_page_config(page_title="Secure QR Guardian", page_icon="🛡️", layout="wide")

from dashboard.stats_aggregator import get_dashboard_stats
from core.blacklist.firebase_client import delete_expired
from utils.logger import get_logger

logger = get_logger(__name__)

# Initialize session state keys if not present
SESSION_KEYS = [
    "last_scan_result",
    "last_osint",
    "last_risk",
    "last_verdict",
    "last_payload",
    "last_report_bytes"
]

for key in SESSION_KEYS:
    if key not in st.session_state:
        st.session_state[key] = None

# Call blacklist/firebase_client.delete_expired() on startup (once per session)
if "app_initialized" not in st.session_state:
    try:
        deleted_count = delete_expired()
        logger.info(f"Startup task: Deleted {deleted_count} expired blacklist entries.")
    except Exception as e:
        logger.error(f"Startup task failed (delete_expired): {e}")
    finally:
        st.session_state["app_initialized"] = True

# Show sidebar with navigation links to all 5 pages
st.sidebar.title("Navigation")
st.sidebar.markdown("Use the links below to navigate through the security pipeline:")

pages = [
    ("pages/01_scanner.py", "1. QR Scanner", "📷"),
    ("pages/02_osint.py", "2. OSINT Traceback", "🔍"),
    ("pages/03_reasoning.py", "3. Reasoning Engine", "🧠"),
    ("pages/04_dashboard.py", "4. Threat Dashboard", "📊"),
    ("pages/05_report.py", "5. Forensic Report", "📄")
]

# Provide fallback for links if the files are not yet created by the user
for file_path, label, icon in pages:
    if os.path.exists(file_path):
        st.sidebar.page_link(file_path, label=label, icon=icon)
    else:
        st.sidebar.markdown(f"{icon} **{label}** *(Coming Soon)*")

# Show homepage with project title and one-line description
st.title("🛡️ Secure QR Guardian")
st.markdown("##### AI-powered QR code fraud detection, OSINT traceback, and forensic reporting for India's UPI ecosystem.")
st.divider()

# Pull metrics from dashboard/stats_aggregator.py
try:
    stats = get_dashboard_stats()
except Exception as e:
    logger.error(f"Failed to fetch stats for homepage: {e}")
    stats = {}

total_scans = stats.get("total_scans", 0)
threats_today = stats.get("threats_today", 0)
safe_scans = stats.get("safe_count", 0)

# Calculate unique archetypes detected
archetype_dist = stats.get("archetype_distribution", {})
archetypes_detected = len([k for k in archetype_dist.keys() if k != "NONE"])

# Render four metric cards
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(label="Total Scans", value=total_scans)
with col2:
    st.metric(label="Threats Today", value=threats_today)
with col3:
    st.metric(label="Archetypes Detected", value=archetypes_detected)
with col4:
    st.metric(label="Safe Scans", value=safe_scans)

st.markdown("---")
st.info("👈 Please select a module from the sidebar to begin.")
