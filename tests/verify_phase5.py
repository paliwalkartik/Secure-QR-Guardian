import os
import sys
import json

# Ensure we can import modules from the project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config.settings import settings
from core.reasoning.prompt_builder import build_system_prompt, build_user_prompt
from core.reasoning.llm_engine import call_llm
from core.reasoning.self_critique import run_self_critique
from core.reasoning.confidence import calculate_final_confidence
from core.reasoning.archetype_classifier import get_archetype_detail

def main():
    print("--- 1. Testing build_system_prompt ---")
    sys_prompt = build_system_prompt()
    assert "Cyber-Fraud Investigator" in sys_prompt, "Missing role in system prompt"
    assert len(sys_prompt) > 500, "System prompt seems suspiciously short"
    print("build_system_prompt OK.")
    
    print("\n--- 2. Testing build_user_prompt ---")
    mock_osint = {
        "domain_forensics": {"creation_date": "2024-01-01", "ssl_issued_on": "2024-01-01"},
        "url_trail": {"hops": ["http://evil.com"]},
        "typosquat": {"is_typosquat": True, "distance": 1, "match": "evll.com"},
        "ip_analysis": {"is_known_bulletproof": True, "asn": "AS9009"},
        "vpa": {"mismatch": False},
        "is_blacklisted": False
    }
    mock_risk = {"risk_score": 85, "threat_level": "HIGH"}
    
    user_prompt = build_user_prompt(mock_osint, mock_risk)
    assert user_prompt and len(user_prompt) > 0, "User prompt is empty"
    print("build_user_prompt OK.")
    
    print("\n--- 3. Testing LLM API Connectivity ---")
    # Basic check to see if an API key is provided and looks vaguely like a Groq key
    if settings.GROQ_API_KEY and len(settings.GROQ_API_KEY) > 10:
        print("Valid GROQ_API_KEY detected. Running live inference tests...")
        
        # Test basic LLM call
        llm_verdict = call_llm(sys_prompt, user_prompt)
        required_keys = {"risk_score", "threat_level", "reasoning_summary", "matched_archetype"}
        assert required_keys.issubset(llm_verdict.keys()), "Missing keys in LLM output"
        print("call_llm OK.")
        
        # Test self-critique loop
        critique = run_self_critique(llm_verdict, mock_osint)
        assert critique["critique_summary"], "Critique summary is empty"
        assert "revised_confidence" in critique, "Missing revised_confidence in critique"
        print("run_self_critique OK.")
    else:
        print("Skipping live LLM tests (GROQ_API_KEY not configured or invalid in .env)")
        
        # Create mock objects to satisfy down-stream test calculations
        llm_verdict = {"risk_score": 80, "threat_level": "HIGH", "reasoning_summary": "Mocked", "matched_archetype": "TYPOSQUATTER"}
        critique = {"critique_summary": "Mock critique", "revised_confidence": 75}
        
    print("\n--- 4. Testing calculate_final_confidence ---")
    final_conf = calculate_final_confidence(mock_risk, llm_verdict, critique)
    assert 0 <= final_conf["final_score"] <= 100, f"Score {final_conf['final_score']} out of bounds"
    assert "confidence_interval" in final_conf, "Missing confidence_interval"
    assert "final_threat_level" in final_conf, "Missing final_threat_level"
    print("calculate_final_confidence OK.")
    
    print("\n--- 5. Testing get_archetype_detail (Valid) ---")
    arch1 = get_archetype_detail("FRESH_PHISH")
    assert arch1["name"] and arch1["name"] != "Unknown", "Failed to retrieve valid archetype"
    print("get_archetype_detail (Valid) OK.")
    
    print("\n--- 6. Testing get_archetype_detail (NONE/Unknown) ---")
    arch2 = get_archetype_detail("NONE")
    assert arch2["id"] == "NONE", f"Expected ID NONE, got {arch2['id']}"
    
    arch3 = get_archetype_detail("INVALID_ID_TEST")
    assert arch3["id"] == "NONE", f"Expected ID NONE, got {arch3['id']}"
    print("get_archetype_detail (Unknown) OK.")
    
    print("\nPHASE 5 VERIFIED")

if __name__ == "__main__":
    main()
