"""
Scanner page. View only. Calls pipeline and stores results in session_state.
 Does not import directly from core/ — calls go through orchestrator pattern.
"""

import streamlit as st
from core.orchestrator import run_pipeline

st.set_page_config(page_title="QR Scanner", page_icon="🔍", layout="centered")

st.title("🔍 QR Code Scanner")
st.markdown("Scan a QR code from your camera or upload an image to detect potential threats.")

# Tabs for input methods
tab1, tab2 = st.tabs(["📷 Camera", "📁 Upload File"])

image_bytes = None
source_type = None

with tab1:
    camera_img = st.camera_input("Take a picture of a QR code")
    if camera_img is not None:
        image_bytes = camera_img.getvalue()
        source_type = "camera"

with tab2:
    uploaded_file = st.file_uploader("Upload QR Code Image", type=["png", "jpg", "jpeg"])
    if uploaded_file is not None:
        image_bytes = uploaded_file.getvalue()
        source_type = "file"

if image_bytes is not None:
    with st.spinner("Analyzing QR code..."):
        # Run full pipeline via orchestrator
        results = run_pipeline(image_bytes, source=source_type)
        
        if not results:
            st.error("Failed to analyze QR code or no valid QR code detected.")
        else:
            # Store ALL results in st.session_state
            payload = results.get("payload")
            osint = results.get("osint", {})
            risk = results.get("risk", {})
            verdict = results.get("verdict", {})
            
            st.session_state["last_payload"] = payload
            st.session_state["last_osint"] = osint
            st.session_state["last_risk"] = risk
            st.session_state["last_verdict"] = verdict
            
            # Extract data for the result card
            # Using dict access if Pydantic model is dumped, or dot notation if it's an object
            # Safe handling for Pydantic models
            if hasattr(payload, "data_type"):
                data_type = payload.data_type.name if hasattr(payload.data_type, "name") else str(payload.data_type)
            else:
                data_type = payload.get("data_type", "UNKNOWN") if isinstance(payload, dict) else "UNKNOWN"
            
            threat_level = verdict.get("final_threat_level", verdict.get("threat_level", "UNKNOWN"))
            risk_score = verdict.get("final_score", risk.get("risk_score", 0))
            conf_interval = verdict.get("confidence_interval", risk.get("confidence_interval", 0))
            archetype = verdict.get("matched_archetype", "NONE")
            reasoning = verdict.get("reasoning_summary", "No reasoning provided.")
            
            st.markdown("---")
            st.subheader("Analysis Results")
            
            # CRITICAL: Never display raw_data in the UI. Show data_type only.
            st.info(f"**Detected Data Type:** {data_type}")
            
            # Large colored badge
            color_map = {
                "SAFE": "green",
                "LOW": "yellow",
                "MEDIUM": "orange",
                "HIGH": "red",
                "CRITICAL": "darkred"
            }
            badge_color = color_map.get(threat_level, "gray")
            
            st.markdown(
                f"<h2 style='text-align: center; color: white; background-color: {badge_color}; padding: 10px; border-radius: 5px;'>"
                f"{threat_level} THREAT</h2>", 
                unsafe_allow_html=True
            )
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric(label="Risk Score", value=f"{risk_score}/100", delta=f"±{conf_interval} CI", delta_color="off")
            with col2:
                st.metric(label="Matched Archetype", value=archetype.replace("_", " "))
                
            st.markdown(f"**Reasoning Summary:**\n> {reasoning}")
            
            st.markdown("<br>", unsafe_allow_html=True)
            
            if st.button("View Full Forensics →", use_container_width=True):
                st.switch_page("pages/02_forensics.py")
