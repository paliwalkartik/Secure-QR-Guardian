"""
Domain forensics: WHOIS and SSL certificate analysis.
Does not follow redirects. Input should be the final domain from url_tracer.
All string outputs are sanitized against prompt injection.
"""

import ssl
import socket
import whois
from datetime import datetime
from urllib.parse import urlparse

from utils.cache import cache
from utils.logger import get_logger
from core.reasoning.injection_guard import sanitize_osint_field

logger = get_logger(__name__)

def _extract_domain(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        return ""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""

def get_whois(domain: str) -> dict:
    domain_str = _extract_domain(domain)
    cache_key = f"whois:{domain_str}"
    
    cached = cache.get(cache_key)
    if cached is not None:
        return cached
        
    result = {
        "creation_date": "",
        "registrar": "",
        "country": ""
    }
    
    if not domain_str:
        return result
        
    try:
        w = whois.whois(domain_str)
        
        cdate = w.creation_date
        if isinstance(cdate, list):
            cdate = cdate[0]
        if isinstance(cdate, datetime):
            result["creation_date"] = sanitize_osint_field(cdate.isoformat(), "creation_date")
        elif isinstance(cdate, str):
            result["creation_date"] = sanitize_osint_field(cdate, "creation_date")

        reg = w.registrar
        if isinstance(reg, list):
            reg = reg[0]
        if isinstance(reg, str):
            result["registrar"] = sanitize_osint_field(reg, "registrar")

        country = w.country
        if isinstance(country, list):
            country = country[0]
        if isinstance(country, str):
            result["country"] = sanitize_osint_field(country, "country")
            
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain_str}: {e}")
        
    cache.set(cache_key, result)
    return result

def get_ssl_info(domain: str) -> dict:
    domain_str = _extract_domain(domain)
    cache_key = f"ssl:{domain_str}"
    
    cached = cache.get(cache_key)
    if cached is not None:
        return cached
        
    result = {
        "ssl_issued_on": "",
        "ssl_issuer": "",
        "ssl_days_valid": 0
    }
    
    if not domain_str:
        return result
        
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain_str, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain_str) as ssock:
                cert = ssock.getpeercert()
                
        issuer_name = ""
        for field in cert.get("issuer", ()):
            for key, value in field:
                if key == "organizationName":
                    issuer_name = value
                elif key == "commonName" and not issuer_name:
                    issuer_name = value
                    
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        
        if not_before:
            dt_before = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
            result["ssl_issued_on"] = sanitize_osint_field(dt_before.isoformat(), "ssl_issued_on")

            if not_after:
                dt_after = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                result["ssl_days_valid"] = (dt_after - dt_before).days  # numeric — not sanitized

        if issuer_name:
            result["ssl_issuer"] = sanitize_osint_field(issuer_name, "ssl_issuer")
            
    except Exception as e:
        logger.warning(f"SSL info fetch failed for {domain_str}: {e}")
        
    cache.set(cache_key, result)
    return result
