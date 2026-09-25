"""
Tests for OSINT gathering modules. All network calls are mocked.
"""
import pytest
from unittest.mock import patch, MagicMock

from core.osint.url_tracer import get_url_trail
from core.osint.domain_forensics import get_whois, get_ssl_info
from core.osint.ip_analyzer import analyze_ip
from core.osint.typosquat_detector import check_typosquat
from core.osint.vpa_verifier import verify_vpa


# ---------------------------------------------------------------------------
# Fixtures: suppress cache for all tests so we always hit mock functions
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_url_cache():
    """Bypass the session cache so each test exercises the real logic."""
    with patch("core.osint.url_tracer.cache.get", return_value=None), \
         patch("core.osint.url_tracer.cache.set"):
        yield


@patch("core.osint.url_tracer.requests.get")
@patch("core.osint.url_tracer.socket.gethostbyname")
def test_url_tracer(mock_socket, mock_get):
    """Test URL tracer correctly follows a 301 redirect and resolves final IP."""
    mock_resp1 = MagicMock()
    mock_resp1.status_code = 301
    mock_resp1.headers = {"Location": "http://final.com"}

    mock_resp2 = MagicMock()
    mock_resp2.status_code = 200
    mock_resp2.headers = {}

    mock_get.side_effect = [mock_resp1, mock_resp2]
    mock_socket.return_value = "1.2.3.4"

    res = get_url_trail("http://start.com")
    assert len(res["hops"]) == 2
    assert res["final_url"] == "http://final.com"
    assert res["final_ip"] == "1.2.3.4"


@patch("core.osint.domain_forensics.cache.get", return_value=None)
@patch("core.osint.domain_forensics.cache.set")
@patch("core.osint.domain_forensics.whois.whois")
def test_domain_forensics_whois(mock_whois, _cache_set, _cache_get):
    """Test domain forensics retrieves and formats whois creation_date and registrar."""
    from datetime import datetime
    mock_res = MagicMock()
    mock_res.creation_date = datetime(2020, 1, 1)
    mock_res.registrar = "TestRegistrar"
    mock_res.country = "US"
    mock_whois.return_value = mock_res

    res = get_whois("test.com")
    assert "TestRegistrar" in res.get("registrar", "")
    assert "creation_date" in res


@patch("core.osint.ip_analyzer.cache.get", return_value=None)
@patch("core.osint.ip_analyzer.cache.set")
@patch("core.osint.ip_analyzer.requests.get")
def test_ip_analyzer(mock_get, _cache_set, _cache_get):
    """Test IP analyzer parses country and ASN from ip-api response."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success",
        "country": "RU",
        "as": "AS12345 Bulletproof"
    }
    mock_get.return_value = mock_resp

    res = analyze_ip("1.2.3.4")
    assert res["country"] == "RU"
    assert "AS12345" in res.get("asn", "")


def test_typosquat_detector_clean_domain():
    """Test typosquatting logic returns False for a legitimate trusted domain."""
    res = check_typosquat("phonepe.com")
    assert res["is_typosquat"] is False


def test_typosquat_detector_spoofed_domain():
    """Test typosquatting logic detects a 1-char substitution against trusted domain."""
    res = check_typosquat("phonep3.com")
    assert res["is_typosquat"] is True
    assert res["closest_legit"] == "phonepe.com"


def test_vpa_verifier_known_mismatch():
    """Test VPA verifier correctly flags mismatch for a known bad VPA in mock registry."""
    # "sbi.official@sbi" is in MOCK_VPA_REGISTRY with mismatch=True
    res = verify_vpa("sbi.official@sbi")
    assert res["mismatch"] is True
    assert res["registered_name"] == "Ravi Kumar"


def test_vpa_verifier_unknown_vpa():
    """Test VPA verifier returns safe defaults for an unknown VPA."""
    res = verify_vpa("unknown.user@upi")
    assert res["mismatch"] is False
    assert res["registered_name"] == "Unknown"
