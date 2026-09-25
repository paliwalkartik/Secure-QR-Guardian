"""
Tests for LLM prompts, Groq API calling, and confidence aggregation.
"""
import pytest
from unittest.mock import patch, MagicMock
from core.reasoning.prompt_builder import build_system_prompt, build_user_prompt
from core.reasoning.llm_engine import call_llm
from core.reasoning.confidence import calculate_final_confidence

def test_build_system_prompt():
    """Test system prompt creates a robust string with JSON enforcement."""
    prompt = build_system_prompt()
    assert "Cyber-Fraud Investigator" in prompt  # actual phrasing from source
    assert "JSON" in prompt

def test_build_user_prompt():
    """Test user prompt properly serializes input bundles."""
    osint = {"ip_analysis": {"is_known_bulletproof": True}, "domain_forensics": {"registrar": "BadReg"}}
    risk = {"risk_score": 90}
    # build_user_prompt signature is (osint_bundle, risk_result) — 2 args
    # It serialises nested keys: domain_forensics, ip_analysis, typosquat_result, etc.
    prompt = build_user_prompt(osint, risk)
    assert "is_known_bulletproof" in prompt  # from ip_analysis
    assert "90" in prompt                    # from risk_score

@patch("core.reasoning.llm_engine.Groq")
def test_call_llm_success(mock_groq_class):
    """Test LLM engine calls Groq SDK and parses JSON response."""
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.choices[0].message.content = '{"risk_score": 88, "threat_level": "HIGH", "reasoning_summary": "Test", "matched_archetype": "FRESH_PHISH"}'
    mock_client.chat.completions.create.return_value = mock_response
    mock_groq_class.return_value = mock_client
    
    res = call_llm("sys", "user")
    assert res["risk_score"] == 88
    assert res["matched_archetype"] == "FRESH_PHISH"

@patch("core.reasoning.llm_engine.Groq")
def test_call_llm_fallback(mock_groq_class):
    """Test LLM engine handles API failure gracefully."""
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = Exception("API Down")
    mock_groq_class.return_value = mock_client
    
    res = call_llm("sys", "user")
    # The neutral fallback in llm_engine.py returns threat_level="MEDIUM"
    assert res["threat_level"] == "MEDIUM"
    assert res["matched_archetype"] == "NONE"

def test_calculate_final_confidence():
    """Test confidence aggregator averages ML, LLM, and critique correctly."""
    risk = {"risk_score": 50}
    llm = {"risk_score": 70}
    critique = {"revised_confidence": 60}
    
    res = calculate_final_confidence(risk, llm, critique)
    # 50*0.4 + 70*0.4 + 60*0.2 = 20 + 28 + 12 = 60
    assert res["final_score"] == 60
    assert res["confidence_interval"] == 10  # (70 - 50) / 2
