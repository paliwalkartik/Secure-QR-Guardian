"""
Adversarial self-critique loop. Forces LLM to challenge its own verdict.
Increases transparency and reduces false positives in edge cases.
"""

import json
from core.reasoning.llm_engine import call_llm
from core.reasoning.prompt_builder import build_system_prompt
from utils.logger import get_logger

logger = get_logger(__name__)

def run_self_critique(first_verdict: dict, osint_bundle: dict) -> dict:
    risk_score = first_verdict.get("risk_score", 50)
    threat_level = first_verdict.get("threat_level", "UNKNOWN")
    
    # Securely format evidence without raw payloads or URLs
    clean_osint = {
        "domain_forensics": osint_bundle.get("domain_forensics", {}),
        "ip_analysis": osint_bundle.get("ip_analysis", {}),
        "typosquat_result": osint_bundle.get("typosquat", {}),
        "vpa_result": osint_bundle.get("vpa", {})
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
    
    # Call the updated LLM engine that accepts custom expected keys
    response = call_llm(
        system_prompt=sys_prompt, 
        user_prompt=user_prompt, 
        expected_keys={"critique_summary", "revised_confidence"}
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
