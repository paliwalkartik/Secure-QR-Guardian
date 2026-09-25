"""
Simulator page. Red-team testing with pre-defined scenarios. No live network calls.
"""

import json
import streamlit as st
from simulator.scenario_loader import list_scenarios, load_scenario, run_scenario

st.set_page_config(page_title="Threat Simulator", page_icon="🧪", layout="centered")

st.title("🧪 Threat Simulator — Red Team Mode")
st.warning("This sandbox uses pre-defined scenarios. No live URLs are called.")

scenarios = list_scenarios()
if not scenarios:
    st.error("No scenarios found in simulator/scenarios/")
    st.stop()

selected_info = st.selectbox(
    "Select Test Scenario",
    options=scenarios,
    format_func=lambda x: f"{x['id'].replace('_', ' ').title()} — {x['name']}"
)

if selected_info:
    st.info(f"**Description:** {selected_info['description']}")
    
    scenario = load_scenario(selected_info['id'])
    
    if st.button("Run Scenario", type="primary", use_container_width=True):
        with st.spinner("Executing isolated simulation pipeline..."):
            result = run_scenario(scenario)
            
            st.markdown("---")
            
            passed = result.get("passed", False)
            if passed:
                st.markdown(
                    "<h1 style='text-align: center; color: white; background-color: #28a745; padding: 15px; border-radius: 8px;'>✅ PASS</h1>", 
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    "<h1 style='text-align: center; color: white; background-color: #dc3545; padding: 15px; border-radius: 8px;'>❌ FAIL</h1>", 
                    unsafe_allow_html=True
                )
                
            st.markdown("<br>", unsafe_allow_html=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Expected Verdict")
                st.write(f"**Threat Level:** `{scenario.expected_verdict.threat_level}`")
                st.write(f"**Archetype:** `{scenario.expected_verdict.matched_archetype}`")
                
            with col2:
                st.subheader("Actual Verdict")
                st.write(f"**Threat Level:** `{result.get('actual_verdict', 'UNKNOWN')}`")
                st.write(f"**Archetype:** `{result.get('actual_archetype', 'UNKNOWN')}`")
                st.write(f"**Risk Score:** `{result.get('actual_risk_score', 0)}/100`")
                
            st.markdown("---")
            
            with st.expander("View full mock OSINT data"):
                # Represent mock data safely as formatted JSON
                st.json(scenario.mock_osint)
