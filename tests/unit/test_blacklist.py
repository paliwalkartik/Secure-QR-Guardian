"""
Tests for community blacklist consensus engine. Uses dict-based in-memory fake.
"""
import pytest
from unittest.mock import patch
from core.blacklist.consensus_engine import should_blacklist, check_and_update, report_domain

# Dict-based in-memory fake
FAKE_DB = {
    "blacklist": set(),
    "reports": {} # domain -> count
}

def fake_check_blacklist(domain: str) -> bool:
    return domain in FAKE_DB["blacklist"]

def fake_get_report_count(domain: str) -> int:
    return FAKE_DB["reports"].get(domain, 0)

def fake_add_to_blacklist(domain: str) -> None:
    FAKE_DB["blacklist"].add(domain)

def fake_submit_report(domain: str, reporter_id="test") -> None:
    FAKE_DB["reports"][domain] = FAKE_DB["reports"].get(domain, 0) + 1

@pytest.fixture(autouse=True)
def mock_firebase():
    # Reset fake db before each test
    FAKE_DB["blacklist"].clear()
    FAKE_DB["reports"].clear()
    
    with patch("core.blacklist.consensus_engine.check_blacklist", side_effect=fake_check_blacklist), \
         patch("core.blacklist.consensus_engine.get_report_count", side_effect=fake_get_report_count), \
         patch("core.blacklist.consensus_engine.add_to_blacklist", side_effect=fake_add_to_blacklist), \
         patch("core.blacklist.consensus_engine.submit_report", side_effect=fake_submit_report):
        yield

def test_should_blacklist_below_threshold():
    """Test consensus engine ignores domains below threshold."""
    FAKE_DB["reports"]["test.com"] = 1
    assert should_blacklist("test.com") is False

def test_should_blacklist_above_threshold():
    """Test consensus engine blacklists domain when reports exceed threshold."""
    FAKE_DB["reports"]["evil.com"] = 100  # assuming threshold is <= 100
    assert should_blacklist("evil.com") is True
    assert "evil.com" in FAKE_DB["blacklist"]

def test_check_and_update_already_blacklisted():
    """Test check_and_update hits fast path if already blacklisted."""
    FAKE_DB["blacklist"].add("bad.com")
    assert check_and_update("bad.com") is True

def test_check_and_update_new_threat():
    """Test check_and_update evaluates threshold if not yet blacklisted."""
    FAKE_DB["reports"]["new.com"] = 50
    with patch("core.blacklist.consensus_engine.settings") as mock_settings:
        mock_settings.BLACKLIST_MIN_REPORTS = 10
        assert check_and_update("new.com") is True
        assert "new.com" in FAKE_DB["blacklist"]

def test_report_domain():
    """Test report_domain aggregates the report and triggers consensus."""
    with patch("core.blacklist.consensus_engine.settings") as mock_settings:
        mock_settings.BLACKLIST_MIN_REPORTS = 2
        
        # Report 1
        res1 = report_domain("test.com")
        assert res1["report_count"] == 1
        assert res1["now_blacklisted"] is False
        
        # Report 2 (triggers consensus)
        res2 = report_domain("test.com")
        assert res2["report_count"] == 2
        assert res2["now_blacklisted"] is True
