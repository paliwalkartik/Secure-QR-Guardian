import os
import sys
import json
import time

# Ensure we can import modules from the project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config.settings import settings
from utils.validators import is_valid_url, is_valid_upi_vpa, is_valid_ip, is_valid_domain
from utils.cache import cache

def main():
    print("--- 1. Testing Settings ---")
    print(repr(settings))
    assert "***" in repr(settings), "API Key not properly masked in repr"
    print("Settings OK.")

    print("\n--- 2. Testing Trusted Domains ---")
    trusted_domains_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'trusted_domains.json')
    with open(trusted_domains_path, "r", encoding="utf-8") as f:
        domains = json.load(f)
    assert len(domains) >= 40, f"Expected at least 40 trusted domains, got {len(domains)}"
    print(f"Loaded {len(domains)} trusted domains. OK.")

    print("\n--- 3. Testing Archetypes ---")
    archetypes_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'archetypes.json')
    with open(archetypes_path, "r", encoding="utf-8") as f:
        archetypes = json.load(f)
    assert len(archetypes) == 5, f"Expected exactly 5 archetypes, got {len(archetypes)}"
    for arch in archetypes:
        assert "id" in arch
        assert "name" in arch
        assert "description" in arch
        assert "indicators" in arch
        assert "example" in arch
        
        example = arch["example"]
        assert "vpa_name" in example
        assert "domain" in example
        assert "domain_age_days" in example
        assert "redirect_count" in example
        assert "ssl_issuer" in example
    print("Loaded and validated 5 archetypes. OK.")

    print("\n--- 4. Testing Validators ---")
    
    # URL
    assert is_valid_url("https://example.com"), "Failed valid https URL"
    assert is_valid_url("http://test.co.uk/path?q=1"), "Failed valid http URL"
    assert not is_valid_url("javascript:alert(1)"), "Failed javascript scheme"
    assert not is_valid_url("ftp://example.com"), "Failed ftp scheme"
    assert not is_valid_url("https://192.168.1.1"), "Failed IP in URL check"

    # UPI VPA
    assert is_valid_upi_vpa("user@okicici"), "Failed valid VPA"
    assert is_valid_upi_vpa("my.name-123@sbi"), "Failed valid VPA"
    assert not is_valid_upi_vpa("user@"), "Failed missing provider"
    assert not is_valid_upi_vpa("a@sbi"), "Failed too short localpart"
    assert not is_valid_upi_vpa("user@a"), "Failed too short provider"

    # IP
    assert is_valid_ip("8.8.8.8"), "Failed valid IPv4"
    assert is_valid_ip("2001:4860:4860::8888"), "Failed valid IPv6"
    assert not is_valid_ip("192.168.1.1"), "Failed private IPv4"
    assert not is_valid_ip("10.0.0.1"), "Failed private IPv4"
    assert not is_valid_ip("127.0.0.1"), "Failed loopback IPv4"
    assert not is_valid_ip("not_an_ip"), "Failed invalid IP string"

    # Domain
    assert is_valid_domain("example.com"), "Failed valid domain"
    assert is_valid_domain("sub.example.co.in"), "Failed valid subdomain"
    assert not is_valid_domain("https://example.com"), "Failed domain with scheme"
    assert not is_valid_domain("example"), "Failed domain without TLD"

    print("Validators OK.")

    print("\n--- 5. Testing Cache ---")
    cache.set("test_key", "test_value", ttl_seconds=1)
    val = cache.get("test_key")
    assert val == "test_value", "Cache failed to store/retrieve value"
    print("Waiting 1.5 seconds for cache expiry...")
    time.sleep(1.5)
    val_expired = cache.get("test_key")
    assert val_expired is None, "Cache failed to expire value"
    print("Cache OK.")

    print("\nPHASE 1 VERIFIED")

if __name__ == "__main__":
    main()
