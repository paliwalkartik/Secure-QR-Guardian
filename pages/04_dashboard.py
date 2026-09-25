"""
Dashboard page. Displays aggregate threat intelligence. View only.
"""

import streamlit as st
from dashboard.stats_aggregator import get_dashboard_stats
from dashboard.visualizations import threat_timeline_chart, archetype_pie_chart, asn_bar_chart

st.set_page_config(page_title="Threat Dashboard", page_icon="📊", layout="wide")

st.title("📊 Live Threat Dashboard")
st.caption("Stats refresh every 60 seconds")

# Fetch aggregate stats
stats = get_dashboard_stats()

total_scans = stats.get("total_scans", 0)
threats_today = stats.get("threats_today", 0)
safe_count = stats.get("safe_count", 0)

archetype_dist = stats.get("archetype_distribution", {})
threat_dist = {k: v for k, v in archetype_dist.items() if k != "NONE"}
if threat_dist:
    most_common_archetype = max(threat_dist.items(), key=lambda x: x[1])[0].replace("_", " ").title()
else:
    most_common_archetype = "N/A"

# Row 1: Four metric cards
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(label="Total Scans", value=f"{total_scans:,}")
with col2:
    st.metric(label="Threats Today", value=f"{threats_today:,}")
with col3:
    st.metric(label="Safe Scans", value=f"{safe_count:,}")
with col4:
    st.metric(label="Most Common Archetype", value=most_common_archetype)

st.markdown("---")

# Row 2: Two columns
col_left, col_right = st.columns(2)

with col_left:
    fig_timeline = threat_timeline_chart(stats)
    st.plotly_chart(fig_timeline, use_container_width=True)

with col_right:
    fig_pie = archetype_pie_chart(stats)
    st.plotly_chart(fig_pie, use_container_width=True)

st.markdown("---")

# Row 3: Full width
fig_asn = asn_bar_chart(stats)
st.plotly_chart(fig_asn, use_container_width=True)

st.markdown("---")
st.info("Data sourced from community reports. Individual scans are anonymized.")
