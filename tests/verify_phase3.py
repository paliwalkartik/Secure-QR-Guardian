import os
import sys
import time

# Ensure we can import modules from the project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.osint.url_tracer import get_url_trail
from core.osint.domain_forensics import get_whois, get_ssl_info
from core.osint.ip_analyzer import analyze_ip
from core.osint.typosquat_detector import check_typosquat
from core.osint.vpa_verifier import verify_vpa
from utils.cache import cache

def main():
    print("--- 1. Testing get_url_trail ---")
    start1 = time.time()
    trail1 = get_url_trail("https://httpbin.org/redirect/3")
    duration1 = time.time() - start1
    
    assert len(trail1["hops"]) >= 1, "Failed to capture redirect hops"
    assert trail1["final_ip"] != "", "Failed to resolve final IP"
    print("get_url_trail OK.")
    
    print("\n--- 2. Testing get_whois ---")
    whois_info = get_whois("google.com")
    assert whois_info["creation_date"] != "", "Failed to extract WHOIS creation date"
    print("get_whois OK.")
    
    print("\n--- 3. Testing get_ssl_info ---")
    ssl_info = get_ssl_info("google.com")
    assert ssl_info["ssl_issuer"] != "", "Failed to extract SSL issuer"
    print("get_ssl_info OK.")
    
    print("\n--- 4. Testing analyze_ip ---")
    ip_info = analyze_ip("8.8.8.8")
    assert ip_info["country"] == "United States", f"Expected United States, got {ip_info['country']}"
    assert ip_info["is_known_bulletproof"] is False, "Google DNS flagged as bulletproof"
    print("analyze_ip OK.")
    
    print("\n--- 5. Testing check_typosquat (Malicious) ---")
    typo_info = check_typosquat("phonep3.com")
    assert typo_info["is_typosquat"] is True, "Failed to detect typosquat"
    assert typo_info["closest_legit"] == "phonepe.com", f"Expected phonepe.com, got {typo_info['closest_legit']}"
    print("check_typosquat (Malicious) OK.")
    
    print("\n--- 6. Testing check_typosquat (Legitimate) ---")
    legit_info = check_typosquat("phonepe.com")
    assert legit_info["is_typosquat"] is False, "Legitimate domain flagged as typosquat"
    assert legit_info["distance"] == 0, "Distance for exact match should be 0"
    print("check_typosquat (Legitimate) OK.")
    
    print("\n--- 7. Testing verify_vpa ---")
    vpa_info = verify_vpa("sbi.official@sbi")
    assert vpa_info["mismatch"] is True, "Failed to detect VPA ownership mismatch"
    print("verify_vpa OK.")
    
    print("\n--- 8. Testing OSINT Caching ---")
    # Measure the second call to ensure it's significantly faster via the TTL dictionary
    start2 = time.time()
    trail2 = get_url_trail("https://httpbin.org/redirect/3")
    duration2 = time.time() - start2
    
    assert duration2 < duration1, f"Cache didn't speed up call: {duration2:.4f}s >= {duration1:.4f}s"
    
    # Explicitly verify the cache key exists
    cache_key = "url_trail:https://httpbin.org/redirect/3"
    assert cache.get(cache_key) is not None, "Data not found in cache dictionary"
    print("Caching OK.")

    print("\nPHASE 3 VERIFIED")

if __name__ == "__main__":
    main()
