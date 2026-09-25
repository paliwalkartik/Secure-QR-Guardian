"""
LLM engine. Calls DeepSeek-R1 via Groq API.
Returns parsed dict. Never raises. Falls back to neutral verdict on any failure.
"""

import json
from groq import Groq
from config.settings import settings
from utils.logger import get_logger
from core.reasoning.response_validator import validate_llm_response, safe_fallback_verdict

logger = get_logger(__name__)

def _extract_json_from_text(text: str) -> str:
    """
    Robust JSON extraction. DeepSeek-R1 outputs its internal thoughts in
    <think> tags before the final response, and sometimes wraps JSON in backticks.
    This extracts exactly the first '{' to the last '}'.
    """
    start_idx = text.find('{')
    end_idx = text.rfind('}')
    
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        return text[start_idx:end_idx+1]
        
    return text

def call_llm(system_prompt: str, user_prompt: str, expected_keys: set = None) -> dict:
    if expected_keys is None:
        expected_keys = {"risk_score", "threat_level", "reasoning_summary", "matched_archetype"}
        
    fallback = {
        "risk_score": 50,
        "threat_level": "MEDIUM",
        "reasoning_summary": "LLM parse error",
        "matched_archetype": "NONE"
    }
    
    if not settings.GROQ_API_KEY:
        logger.error("GROQ_API_KEY is not configured. Failing over to neutral verdict.")
        return fallback
        
    try:
        client = Groq(api_key=settings.GROQ_API_KEY)
        
        response = client.chat.completions.create(
            model=settings.GROQ_MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,
            max_tokens=settings.LLM_MAX_TOKENS
        )
        
        content = response.choices[0].message.content
        
        if response.usage:
            logger.debug(
                "LLM API Call Completed", 
                extra={
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens
                }
            )
            
        json_str = _extract_json_from_text(content)
        parsed = json.loads(json_str)

        # --- Structural key presence check (fast, before full validation) ---
        if not expected_keys.issubset(parsed.keys()):
            logger.warning(
                "LLM response missing required keys.",
                extra={"keys_found": list(parsed.keys()), "expected": list(expected_keys)},
            )
            return safe_fallback_verdict()

        # --- Full hallucination / schema validation -------------------------
        valid, reason = validate_llm_response(parsed)
        if not valid:
            logger.warning(
                "Hallucinated LLM response detected; using safe fallback verdict.",
                extra={
                    "hallucination_detected": True,
                    "reason": reason,
                    "raw_response": str(parsed)[:200],
                },
            )
            return safe_fallback_verdict()

        return parsed
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse LLM JSON: {e}")
        return fallback
        
    except Exception as e:
        logger.error(f"LLM Groq API request failed: {e}")
        return fallback
