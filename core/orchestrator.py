"""
Main orchestrator for the QR analysis pipeline.
Coordinates the execution of scanning, OSINT, risk classification, and reasoning.
"""

from urllib.parse import urlparse

from core.scanner.qr_scanner import QRScanner
from core.osint.url_tracer import get_url_trail
from core.osint.domain_forensics import get_whois, get_ssl_info
from core.osint.ip_analyzer import analyze_ip
from core.osint.typosquat_detector import check_typosquat
from core.osint.vpa_verifier import verify_vpa
from core.blacklist.firebase_client import check_blacklist
from core.risk.feature_extractor import extract_features
from core.risk.classifier import risk_classifier
from core.reasoning.prompt_builder import build_system_prompt, build_user_prompt
from core.reasoning.llm_engine import call_llm
from core.reasoning.self_critique import run_self_critique
from core.reasoning.confidence import calculate_final_confidence
from compliance.nist_mapper import annotate_result
from utils.validators import is_valid_url
from utils.logger import get_logger

logger = get_logger(__name__)

def run_pipeline(image_bytes: bytes, source: str = "camera") -> dict:
    """
    Executes the full analysis pipeline end-to-end.
    Returns a dictionary with all intermediate and final results.
    """
    try:
        # a. sanitize payload
        scanner = QRScanner()
        payload = scanner.from_image_bytes(image_bytes, source=source)
        
        # Determine the domain/IP to analyze based on the payload string
        raw_data = payload.raw_data or ""
        # Very basic parsing to drive the OSINT
        domain = ""
        ip = ""
        vpa_id = ""
        
        if "://" in raw_data:
            parsed = urlparse(raw_data)
            domain = parsed.hostname or ""
        elif "@" in raw_data and not raw_data.startswith("mailto:"):
            # Roughly handling UPI VPA
            vpa_id = raw_data
        
        # b. OSINT
        url_trail = get_url_trail(raw_data) if is_valid_url(raw_data) else {}
        
        # If url_tracer found a final domain/IP, we should analyze that
        if url_trail.get("final_url"):
            domain = urlparse(url_trail["final_url"]).hostname or domain
        if url_trail.get("final_ip"):
            ip = url_trail["final_ip"]

        domain_forensics = {}
        if domain:
            whois_info = get_whois(domain)
            ssl_info = get_ssl_info(domain)
            domain_forensics = {**whois_info, **ssl_info}
            
        ip_analysis = analyze_ip(ip) if ip else {}
        typosquat = check_typosquat(domain) if domain else {}
        vpa = verify_vpa(vpa_id) if vpa_id else {}
        
        # c. blacklist check
        is_blacklisted = check_blacklist(domain) if domain else False

        osint_bundle = {
            "url_trail": url_trail,
            "domain_forensics": domain_forensics,
            "ip_analysis": ip_analysis,
            "typosquat": typosquat,
            "vpa": vpa,
            "is_blacklisted": is_blacklisted
        }

        # d. risk_classifier.predict
        features = extract_features(osint_bundle)
        risk_result = risk_classifier.predict(features)
        
        # e. call_llm + self_critique + calculate_final_confidence
        sys_prompt = build_system_prompt()
        user_prompt = build_user_prompt(osint_bundle, risk_result)
        llm_verdict = call_llm(sys_prompt, user_prompt)
        
        critique = run_self_critique(llm_verdict, osint_bundle)
        final_verdict = calculate_final_confidence(risk_result, llm_verdict, critique)
        
        # Merge critique and final verdict fields into a unified verdict object
        verdict = {**llm_verdict, **critique, **final_verdict}

        # f. nist_mapper.annotate_result
        active_modules = ["qr_scanner", "osint", "risk_classifier", "llm_engine"]
        verdict = annotate_result(verdict, active_modules)

        return {
            "payload": payload,
            "osint": osint_bundle,
            "risk": risk_result,
            "verdict": verdict
        }

    except Exception as e:
        logger.error(f"Error executing orchestrator pipeline: {e}")
        return {}
