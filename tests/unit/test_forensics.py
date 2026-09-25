"""
Tests for visual mapping, payload analysis, and PDF generation.
"""
import pytest
from unittest.mock import patch, MagicMock
from core.forensics.payload_analyzer import analyze_payload, dump_hex, dump_base64
from core.forensics.network_mapper import build_network_graph
from core.forensics.report_generator import generate_report

def test_dump_hex():
    """Test payload analyzer hex dump generator."""
    res = dump_hex("A")
    assert "41" in res
    assert "A" in res

def test_dump_base64():
    """Test payload analyzer base64 dump generator."""
    res = dump_base64("Test")
    assert res == "VGVzdA=="

def test_analyze_payload():
    """Test payload analyzer aggregates hashes and suspicious keywords."""
    res = analyze_payload("http://evil.com/login")
    assert res["byte_length"] == 21
    assert res["contains_suspicious_patterns"] is True
    assert len(res["sha256_hash"]) == 64

@patch("core.forensics.network_mapper.nx.draw_networkx")
def test_build_network_graph(mock_draw):
    """Test network mapper builds a matplotlib figure."""
    url_trail = {"hops": ["hop1", "hop2"], "final_ip": "1.2.3.4"}
    fig = build_network_graph(url_trail)
    assert fig is not None
    mock_draw.assert_called_once()

@patch("core.forensics.network_mapper.nx.draw_networkx")
def test_build_network_graph_empty(mock_draw):
    """Test network mapper safely handles empty trails."""
    fig = build_network_graph({})
    assert fig is not None
    mock_draw.assert_not_called()

def test_generate_report():
    """Test PDF report generator compiles all data into a bytearray."""
    dummy_results = {
        "payload": {"data_type": "URL"},
        "osint_bundle": {},
        "risk_result": {"threat_level": "HIGH", "risk_score": 85},
        "llm_verdict": {"reasoning_summary": "Test summary"},
        "critique_result": {},
        "final_confidence": 85,
        "archetype_detail": {"name": "Test Archetype"},
        "payload_analysis": {"hex_dump": "00: 00"},
        "nist_tags": ["ID.AM-1"]
    }
    
    pdf_bytes = generate_report(dummy_results)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 100  # Should have some PDF content
