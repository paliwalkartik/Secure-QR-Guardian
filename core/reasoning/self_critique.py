"""
Adversarial self-critique loop. Forces LLM to challenge its own verdict.
Increases transparency and reduces false positives in edge cases.
"""

import json
from core.reasoning.llm_engine import call_llm
from core.reasoning.prompt_builder import build_system_prompt
from core.reasoning.injection_guard import sanitize_osint_bundle
from utils.logger import get_logger

logger = get_logger(__name__)

def run_self_critique(first_verdict: dict, osint_bundle: dict) -> dict:
    risk_score = first_verdict.get("risk_score", 50)
    threat_level = first_verdict.get("threat_level", "UNKNOWN")
    
    # Sanitize OSINT bundle via SEC-1/SEC-3 guard BEFORE building clean_osint.
    # This prevents injected WHOIS/registrar strings from reaching the second LLM call.
    sanitized_bundle = sanitize_osint_bundle(osint_bundle)
    clean_osint = {
        "domain_forensics": sanitized_bundle.get("domain_forensics", {}),
        "ip_analysis": sanitized_bundle.get("ip_analysis", {}),
        "typosquat_result": sanitized_bundle.get("typosquat", {}),
        "vpa_result": sanitized_bundle.get("vpa", {})
    }
    
    user_prompt = f"""EVIDENCE:
{json.dumps(clean_osint, indent=2)}

You previously assessed this case as {threat_level} with score {risk_score}.
Now act as a defense attorney. List 2-3 specific reasons this could be a false positive.
Then provide a revised_confidence score (0-100) reflecting how certain you are.
Respond ONLY with JSON: {{"critique_summary": "string", "revised_confidence": int}}"""

    # Requirements explicitly state to use the exact same system prompt
    sys_prompt = build_system_prompt()
    
    logger.debug("Initiating adversarial self-critique.")
    
    # Call the updated LLM engine with response_type="critique" so the correct
    # CritiqueResponseSchema validates the response (not LLMResponseSchema).
    response = call_llm(
        system_prompt=sys_prompt,
        user_prompt=user_prompt,
        expected_keys={"critique_summary", "revised_confidence"},
        response_type="critique"
    )
    
    # If the LLM engine falls back or fails validation, it returns the standard fallback
    if "critique_summary" not in response or "revised_confidence" not in response:
        logger.warning("Self-critique LLM output missed expected schema.")
        return {
            "critique_summary": "Critique unavailable",
            "revised_confidence": risk_score
        }
        
    return {
        "critique_summary": response["critique_summary"],
        "revised_confidence": int(response["revised_confidence"])
    }


# Backward-compatibility alias
self_critique = run_self_critique

