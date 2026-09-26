"""
Report page. Generates and downloads forensic PDF. Handles community reporting.
"""

import uuid
import streamlit as st
import pandas as pd
from urllib.parse import urlparse

from compliance.nist_mapper import get_nist_summary
from core.forensics.report_generator import generate_report
from core.forensics.payload_analyzer import analyze_payload
from core.reasoning.archetype_classifier import get_archetype_detail
from core.blacklist.consensus_engine import report_domain
from core.blacklist.firebase_client import get_report_count

st.set_page_config(page_title="Forensic Report", page_icon="📄", layout="wide")

# Generate a stable per-session reporter ID for community reports.
# This is an anonymous session UUID — never displayed or logged.
# Without this, all reports are keyed to the same Firestore document and
# report_count can never exceed 1, making BLACKLIST_MIN_REPORTS unreachable.
if "anon_reporter_id" not in st.session_state:
    st.session_state["anon_reporter_id"] = str(uuid.uuid4())

st.title("📄 Forensic Report")

if st.session_state.get("last_payload") is None and st.session_state.get("last_scan_result") is None and st.session_state.get("last_verdict") is None:
    st.warning("Run a scan first from the Scanner page.")
    st.stop()

# Load state
payload = st.session_state.get("last_payload")
osint = st.session_state.get("last_osint", {})
risk = st.session_state.get("last_risk", {})
verdict = st.session_state.get("last_verdict", {})

# Extract specific details
nist_tags = verdict.get("nist_tags", [])
url_trail = osint.get("url_trail", {})
final_url = url_trail.get("final_url", "")

domain = ""
if final_url:
    domain = urlparse(final_url).hostname or ""

st.header("NIST Cybersecurity Framework")
if nist_tags:
    st.markdown("### Applied Tags")
    badges = [f"<span style='background-color: #0d6efd; color: white; padding: 5px 10px; border-radius: 15px; font-size: 14px; margin-right: 5px;'>{tag}</span>" for tag in nist_tags]
    st.markdown("".join(badges), unsafe_allow_html=True)
else:
    st.write("No NIST tags applied to this scan.")

st.markdown("<br>", unsafe_allow_html=True)

with st.expander("NIST CSF Explanation Table", expanded=False):
    nist_summary = get_nist_summary()
    if nist_summary:
        df_nist = pd.DataFrame([
            {"Module": module_name, "NIST CSF Functions": ", ".join(tags)} 
            for module_name, tags in nist_summary.items()
        ])
        st.table(df_nist)
    else:
        st.write("NIST map configuration unavailable.")

st.markdown("---")
st.header("Generate Official Report")

if st.button("Generate Forensic PDF", type="primary"):
    with st.spinner("Compiling evidence..."):
        
        # Standardize payload dict
        if hasattr(payload, "model_dump"):
            payload_dict = payload.model_dump()
        elif hasattr(payload, "__dict__"):
            payload_dict = vars(payload)
        else:
            payload_dict = payload if isinstance(payload, dict) else {}
            
        raw_data = payload_dict.get("raw_data", "")
        
        # Build all_results object required by report_generator
        all_results = {
            "payload": payload_dict,
            "osint_bundle": osint,
            "risk_result": risk,
            "llm_verdict": verdict,
            "critique_result": verdict,
            "final_confidence": verdict.get("final_score", 0),
            "archetype_detail": get_archetype_detail(verdict.get("matched_archetype", "NONE")),
            "payload_analysis": analyze_payload(raw_data),
            "nist_tags": nist_tags
        }
        
        report_bytes = generate_report(all_results)
        if report_bytes:
            st.session_state.last_report_bytes = report_bytes
            # Generate a consistent ID just for display reference
            if "report_case_id" not in st.session_state:
                st.session_state.report_case_id = str(uuid.uuid4())[:8].upper()
        else:
            st.error("Failed to generate PDF report.")

# Render Download Button if available
report_bytes = st.session_state.get("last_report_bytes")
if report_bytes:
    case_id = st.session_state.get("report_case_id", "UNKNOWN")
    st.success(f"Report generated. Case ID: {case_id}. Pages: 1")
    
    st.download_button(
        label="⬇️ Download PDF Report",
        data=report_bytes,
        file_name=f"Forensic_Report_{case_id}.pdf",
        mime="application/pdf"
    )

st.markdown("---")
st.header("Community Defense")

with st.expander("Report Domain to Community", expanded=True):
    if domain:
        st.write(f"**Identified Domain:** `{domain}`")
        st.write("Submit this domain to the global community blacklist to protect other users.")
        
        if st.button("Submit Report"):
            with st.spinner("Submitting securely to Firebase..."):
                result = report_domain(domain, reporter_id=st.session_state["anon_reporter_id"])
                count = result.get("report_count", get_report_count(domain))
                if result.get("reported"):
                    st.success(f"✅ Domain successfully reported! Total community reports for this domain: **{count}**")
                elif result.get("reason") == "Rate limited":
                    remaining = result.get("cooldown_seconds", 60)
                    st.warning(f"⏳ You already reported this domain. Please wait {remaining}s before reporting again.")
                else:
                    st.error("Failed to submit report. Please try again later.")
    else:
        st.info("No network domain was extracted from this scan. Only URLs can be reported to the community blacklist.")
