"""
Forensics page. Reads from session_state only. View layer only.
"""

import streamlit as st
import pandas as pd
from core.forensics.payload_analyzer import analyze_payload
from core.forensics.network_mapper import build_network_graph
from core.forensics.screenshot_capture import capture_page
from core.reasoning.archetype_classifier import get_archetype_detail

st.set_page_config(page_title="Forensics Report", page_icon="📄", layout="wide")

st.title("📄 Forensic Analysis Report")
st.markdown("Detailed breakdown of OSINT, reasoning, and visual forensics.")

# Enforce prerequisite scan
if st.session_state.get("last_payload") is None or st.session_state.get("last_scan_result") is None and st.session_state.get("last_verdict") is None:
    st.warning("Run a scan first from the Scanner page.")
    st.stop()

# Retrieve stored state
payload = st.session_state.get("last_payload")
osint = st.session_state.get("last_osint", {})
risk = st.session_state.get("last_risk", {})
verdict = st.session_state.get("last_verdict", {})

# Extract specific bundles
url_trail = osint.get("url_trail", {})
domain_forensics = osint.get("domain_forensics", {})
ip_analysis = osint.get("ip_analysis", {})
typosquat = osint.get("typosquat", {})

# Use payload object or dict
if hasattr(payload, "raw_data"):
    raw_data = payload.raw_data
else:
    raw_data = payload.get("raw_data", "") if isinstance(payload, dict) else ""

# Setup Tabs
tab1, tab2, tab3, tab4 = st.tabs(["OSINT Trail", "Payload Analysis", "AI Chain of Thought", "Network Map"])

with tab1:
    st.header("Open Source Intelligence (OSINT)")
    
    col_os1, col_os2 = st.columns(2)
    
    with col_os1:
        st.subheader("URL Trail")
        hops = url_trail.get("hops", [])
        if hops:
            for i, hop in enumerate(hops, 1):
                st.markdown(f"**{i}.** `{hop}`")
            st.info(f"Final IP: {url_trail.get('final_ip', 'Unknown')}")
        else:
            st.write("No URL redirects detected.")
            
        st.subheader("IP Analysis")
        if ip_analysis:
            asn = ip_analysis.get("asn", "Unknown")
            bulletproof = ip_analysis.get("is_known_bulletproof", False)
            st.write(f"**ASN:** {asn}")
            if bulletproof:
                st.error("🚨 Hosted on known Bulletproof/High-Risk infrastructure")
            else:
                st.success("Infrastructure not flagged as bulletproof.")
        else:
            st.write("No IP analysis available.")

    with col_os2:
        st.subheader("Domain Forensics")
        if domain_forensics:
            df = pd.DataFrame([
                {"Metric": k, "Value": str(v)} for k, v in domain_forensics.items()
            ])
            st.dataframe(df, hide_index=True, use_container_width=True)
        else:
            st.write("No domain forensics available.")
            
        st.subheader("Typosquatting")
        if typosquat:
            is_ts = typosquat.get("is_typosquat", False)
            distance = typosquat.get("distance", 0)
            closest = typosquat.get("closest_legit", "")
            match = typosquat.get("match", "")
            
            if is_ts:
                st.error(f"⚠️ Typosquat Detected! Distance: {distance}")
                st.write(f"Expected: `{closest}`")
                st.write(f"Actual: `{match}`")
            else:
                st.success("No typosquatting detected.")
        else:
            st.write("No typosquat analysis available.")


with tab2:
    st.header("Payload Forensic Dump")
    
    # Do not display raw_data directly. Pass it to the analyzer.
    analysis = analyze_payload(raw_data)
    
    st.write(f"**SHA-256 Hash:** `{analysis.get('sha256_hash', '')}`")
    st.write(f"**Byte Length:** `{analysis.get('byte_length', 0)} bytes`")
    
    if analysis.get("contains_suspicious_patterns"):
        st.error("🚩 Suspicious text patterns detected in payload.")
    else:
        st.success("No standard suspicious keywords found.")
        
    st.subheader("Hex Dump")
    st.code(analysis.get("hex_dump", ""), language="text")
    
    st.subheader("Base64 Dump")
    st.code(analysis.get("base64_dump", ""), language="text")


with tab3:
    st.header("AI Reasoning Engine")
    
    st.markdown("### Final Reasoning Summary")
    st.info(verdict.get("reasoning_summary", "No reasoning available."))
    
    col_ai1, col_ai2 = st.columns(2)
    
    with col_ai1:
        st.markdown("### Detected Archetype")
        arch_id = verdict.get("matched_archetype", "NONE")
        arch_detail = get_archetype_detail(arch_id)
        
        st.write(f"**{arch_detail.get('name', arch_id)}**")
        st.write(f"_{arch_detail.get('description', '')}_")
        
        indicators = arch_detail.get("indicators", [])
        if indicators:
            st.write("**Typical Indicators:**")
            for ind in indicators:
                st.markdown(f"- [x] {ind}")
                
    with col_ai2:
        st.markdown("### Confidence Calculation")
        ml_score = risk.get("risk_score", 0)
        llm_score = verdict.get("risk_score", 0)
        critique_score = verdict.get("revised_confidence", 0)
        final_score = verdict.get("final_score", 0)
        
        st.write(f"1. **ML Classifier Score:** {ml_score}")
        st.write(f"2. **LLM Initial Risk:** {llm_score}")
        st.write(f"3. **Self-Critique Revision:** {critique_score}")
        st.markdown("---")
        st.write(f"**Final Averaged Score:** {final_score}")
        st.write(f"**Confidence Interval:** ±{verdict.get('confidence_interval', 0)}")
        
    with st.expander("⚖️ Devil's Advocate (Self-Critique)"):
        st.write(verdict.get("critique_summary", "No critique available."))


with tab4:
    st.header("Visual Forensics")
    
    if st.button("Render Network Map"):
        with st.spinner("Building node graph..."):
            fig = build_network_graph(url_trail)
            st.pyplot(fig)
            
    st.markdown("---")
    
    threat_level = verdict.get("final_threat_level", verdict.get("threat_level", "UNKNOWN"))
    
    if threat_level in ["HIGH", "CRITICAL"]:
        st.warning("⚠️ High Threat Level detected. Capture screenshot with caution.")
        
        if "confirm_capture" not in st.session_state:
            st.session_state.confirm_capture = False
            
        if st.button("Capture Screenshot"):
            st.session_state.confirm_capture = True
            
        if st.session_state.confirm_capture:
            st.error("This will render the suspicious URL in a headless browser sandbox. Continue?")
            
            col_btn1, col_btn2 = st.columns([1, 4])
            with col_btn1:
                if st.button("Confirm Capture"):
                    target_url = url_trail.get("final_url", "")
                    if target_url:
                        with st.spinner("Capturing page in sandbox..."):
                            screenshot_bytes = capture_page(target_url, sandbox=True)
                            if screenshot_bytes:
                                st.image(screenshot_bytes, caption=f"Sandboxed Screenshot of {target_url}")
                            else:
                                st.error("Failed to capture screenshot.")
                    else:
                        st.error("No valid URL found to capture.")
                    st.session_state.confirm_capture = False
            with col_btn2:
                if st.button("Cancel"):
                    st.session_state.confirm_capture = False
