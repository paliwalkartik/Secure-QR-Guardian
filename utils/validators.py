"""
Input validators. Standard library only, no network calls, no side effects.
"""

import re
import ipaddress

def is_valid_url(s: str) -> bool:
    if not isinstance(s, str):
        return False
    # Must start with http or https, explicitly denying javascript:, data:, ftp:
    if not s.startswith(("http://", "https://")):
        return False
    
    # Must have a valid domain with TLD.
    # Matches subdomains and requires a letter-only TLD of at least 2 characters.
    pattern = r'^https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::\d{1,5})?(?:[/?#].*)?$'
    return bool(re.match(pattern, s))

def is_valid_upi_vpa(s: str) -> bool:
    if not isinstance(s, str):
        return False
    # localpart: alphanumeric, dots, hyphens, underscores, min 3 chars
    # provider: alphanumeric only, 2-20 chars
    pattern = r'^[a-zA-Z0-9._-]{3,}@[a-zA-Z0-9]{2,20}$'
    return bool(re.match(pattern, s))

def is_valid_ip(s: str) -> bool:
    if not isinstance(s, str):
        return False
    try:
        ip = ipaddress.ip_address(s)
        # Return False for private/reserved/loopback ranges
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_unspecified or ip.is_multicast:
            return False
        return True
    except ValueError:
        return False

def is_valid_domain(s: str) -> bool:
    if not isinstance(s, str):
        return False
    # No scheme prefix allowed
    if "://" in s or s.startswith("http"):
        return False
    # Valid domain with TLD
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, s))
