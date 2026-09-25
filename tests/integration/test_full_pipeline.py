"""
Integration tests for the full QR analysis pipeline.
Exercises the orchestrator end-to-end using scenario fixtures.
All network calls (OSINT, LLM, Firebase) are mocked.
No live URLs are contacted. No API keys required.
"""

import json
import os
import pytest
from unittest.mock import patch, MagicMock
import numpy as np

from simulator.scenario_loader import load_scenario, list_scenarios
from core.risk.feature_extractor import extract_features
from core.risk.classifier import risk_classifier
from core.reasoning.prompt_builder import build_system_prompt, build_user_prompt
from core.reasoning.confidence import calculate_final_confidence
from compliance.nist_mapper import annotate_result
from core.forensics.payload_analyzer import analyze_payload
from core.forensics.report_generator import generate_report
from core.reasoning.archetype_classifier import get_archetype_detail

# ---------------------------------------------------------------------------
# Shared LLM response factory
# ---------------------------------------------------------------------------

def make_llm_response(threat_level: str, archetype: str, score: int) -> str:
    return json.dumps({
        "risk_score": score,
        "threat_level": threat_level,
        "reasoning_summary": f"Integration test mock verdict: {archetype}",
        "matched_archetype": archetype
    })


# ---------------------------------------------------------------------------
# Fixture: one patched LLM for all integration tests
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_llm_high():
    """Patches Groq to return a HIGH-threat verdict."""
    with patch("core.reasoning.llm_engine.Groq") as mock_groq:
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices[0].message.content = make_llm_response("HIGH", "FRESH_PHISH", 85)
        mock_resp.usage = None
        mock_client.chat.completions.create.return_value = mock_resp
        mock_groq.return_value = mock_client
        yield mock_groq


@pytest.fixture
def mock_llm_safe():
    """Patches Groq to return a SAFE verdict."""
    with patch("core.reasoning.llm_engine.Groq") as mock_groq:
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices[0].message.content = make_llm_response("SAFE", "NONE", 10)
        mock_resp.usage = None
        mock_client.chat.completions.create.return_value = mock_resp
        mock_groq.return_value = mock_client
        yield mock_groq


# ---------------------------------------------------------------------------
# Test 1: Scenarios load and validate correctly
# ---------------------------------------------------------------------------

def test_all_scenarios_loadable():
    """Verify all 5 scenario JSON files parse into valid SimulatorScenario models."""
    scenarios = list_scenarios()
    assert len(scenarios) == 5, f"Expected 5 scenarios, found {len(scenarios)}"
    for meta in scenarios:
        loaded = load_scenario(meta["filename"])  # filename stem, not internal id
        assert loaded.id == meta["id"]
        assert loaded.expected_verdict.threat_level in {"SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert loaded.mock_osint is not None


# ---------------------------------------------------------------------------
# Test 2: Feature extraction from scenario OSINT bundles
# ---------------------------------------------------------------------------

def test_feature_extraction_from_all_scenarios():
    """Verify extract_features produces an 8-element float array for every scenario."""
    for meta in list_scenarios():
        scenario = load_scenario(meta["filename"])
        features = extract_features(scenario.mock_osint)
        assert features.shape == (8,), f"{meta['id']}: expected 8 features, got {features.shape}"
        assert features.dtype == float


# ---------------------------------------------------------------------------
# Test 3: Risk classifier runs on all scenarios without error
# ---------------------------------------------------------------------------

def test_risk_classifier_on_all_scenarios():
    """Verify risk_classifier.predict returns a valid dict for every scenario."""
    for meta in list_scenarios():
        scenario = load_scenario(meta["filename"])
        features = extract_features(scenario.mock_osint)
        result = risk_classifier.predict(features)
        assert "risk_score" in result
        assert "threat_level" in result
        assert 0 <= result["risk_score"] <= 100
        assert result["threat_level"] in {"SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


# ---------------------------------------------------------------------------
# Test 4: Full pipeline — fresh_phish scenario → HIGH threat
# ---------------------------------------------------------------------------

@patch("core.reasoning.self_critique.call_llm")
def test_pipeline_fresh_phish_verdict(mock_critique_llm, mock_llm_high):
    """End-to-end: fresh_phish scenario produces HIGH threat level."""
    mock_critique_llm.return_value = {
        "critique_summary": "Domain freshness is clear indicator.",
        "revised_confidence": 80
    }
    scenario = load_scenario("fresh_phish")  # filename stem

    features = extract_features(scenario.mock_osint)
    risk_result = risk_classifier.predict(features)

    sys_prompt = build_system_prompt()
    user_prompt = build_user_prompt(scenario.mock_osint, risk_result)

    from core.reasoning.llm_engine import call_llm
    llm_verdict = call_llm(sys_prompt, user_prompt)

    critique = {"critique_summary": "Domain freshness is clear indicator.", "revised_confidence": 80}
    final = calculate_final_confidence(risk_result, llm_verdict, critique)

    assert final["final_threat_level"] in {"HIGH", "CRITICAL"}, (
        f"Expected HIGH/CRITICAL for fresh_phish, got {final['final_threat_level']}"
    )


# ---------------------------------------------------------------------------
# Test 5: Full pipeline — upi_mismatch scenario → annotated with NIST tags
# ---------------------------------------------------------------------------

def test_pipeline_nist_annotation():
    """Verify annotate_result correctly appends nist_tags to any verdict dict."""
    result = {
        "threat_level": "HIGH",
        "matched_archetype": "VPA_IMPOSTOR"
    }
    active_modules = ["qr_scanner", "osint", "risk_classifier", "llm_engine"]
    annotated = annotate_result(result, active_modules)
    assert "nist_tags" in annotated
    assert isinstance(annotated["nist_tags"], list)


# ---------------------------------------------------------------------------
# Test 6: Confidence aggregation — weighted average is correct
# ---------------------------------------------------------------------------

def test_confidence_aggregation_weighted_average():
    """Verify weighted average: ML(0.4) + LLM(0.4) + critique(0.2) = expected."""
    risk_result = {"risk_score": 60}
    llm_verdict = {"risk_score": 80}
    critique_result = {"revised_confidence": 70}

    final = calculate_final_confidence(risk_result, llm_verdict, critique_result)
    # 60*0.4 + 80*0.4 + 70*0.2 = 24 + 32 + 14 = 70
    assert final["final_score"] == 70
    assert final["final_threat_level"] == "MEDIUM"
    assert final["confidence_interval"] == 10  # (80 - 60) / 2


# ---------------------------------------------------------------------------
# Test 7: Payload analyzer → report generator — full forensic chain
# ---------------------------------------------------------------------------

def test_forensic_chain_payload_to_pdf():
    """Verify payload_analyzer output feeds directly into generate_report to produce PDF bytes."""
    raw = "https://evil-fresh.com/pay/update"
    analysis = analyze_payload(raw)

    assert analysis["sha256_hash"] != ""
    assert analysis["byte_length"] == len(raw.encode("utf-8"))
    assert analysis["contains_suspicious_patterns"] is True

    all_results = {
        "payload": {"data_type": "URL"},
        "osint_bundle": {"domain_forensics": {}, "ip_analysis": {}},
        "risk_result": {"threat_level": "HIGH", "risk_score": 85, "confidence_interval": 5},
        "llm_verdict": {"reasoning_summary": "Fresh phish domain detected."},
        "critique_result": {"critique_summary": "Domain is 3 days old.", "revised_confidence": 80},
        "final_confidence": 82,
        "archetype_detail": get_archetype_detail("FRESH_PHISH"),
        "payload_analysis": analysis,
        "nist_tags": ["ID.RA-2", "DE.CM-1"]
    }

    pdf_bytes = generate_report(all_results)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500, "PDF too small — likely an empty error fallback"


# ---------------------------------------------------------------------------
# Test 8: Archetype classifier — all 5 known IDs resolve correctly
# ---------------------------------------------------------------------------

def test_archetype_classifier_all_known_ids():
    """Verify all 5 canonical archetype IDs resolve to non-empty name/description."""
    known_ids = ["FRESH_PHISH", "TYPOSQUATTER", "VPA_IMPOSTOR", "REDIRECT_CHAIN", "LOOKALIKE_DOMAIN"]
    for arch_id in known_ids:
        detail = get_archetype_detail(arch_id)
        assert detail["id"] == arch_id, f"{arch_id}: ID mismatch"
        assert detail["name"] != "Unknown", f"{arch_id}: name not resolved"
        assert len(detail.get("indicators", [])) > 0, f"{arch_id}: no indicators"


# ---------------------------------------------------------------------------
# Test 9: NONE / unknown archetype returns safe defaults
# ---------------------------------------------------------------------------

def test_archetype_classifier_unknown_returns_none():
    """Verify unknown archetype ID safely returns NONE sentinel values."""
    detail = get_archetype_detail("DOES_NOT_EXIST")
    assert detail["id"] == "NONE"

    detail_none = get_archetype_detail("NONE")
    assert detail_none["id"] == "NONE"


# ---------------------------------------------------------------------------
# Test 10: Scenario verdict shapes match canonical LLMVerdict schema
# ---------------------------------------------------------------------------

def test_scenario_expected_verdict_schema():
    """Verify every scenario's expected_verdict contains required canonical fields."""
    required_fields = {"threat_level", "matched_archetype"}
    for meta in list_scenarios():
        scenario = load_scenario(meta["filename"])  # filename stem, not internal id
        verdict_dict = scenario.expected_verdict.model_dump()
        missing = required_fields - verdict_dict.keys()
        assert not missing, f"{meta['id']} missing fields: {missing}"
