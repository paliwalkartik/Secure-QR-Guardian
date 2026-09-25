"""
IP geolocation and ASN analysis. Uses ip-api.com free tier.
Call analyze_ip() only. Never call the sub-functions directly from outside.
All string outputs are sanitized against prompt injection.
"""

import requests
from config.settings import settings
from utils.cache import cache
from utils.logger import get_logger
from core.reasoning.injection_guard import sanitize_osint_field

logger = get_logger(__name__)

def _get_ip_api_data(ip: str) -> dict:
    """Helper to fetch and cache raw ip-api.com response to avoid double-calling."""
    if not ip:
        return {}
        
    cache_key = f"ip_geo:{ip}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached
        
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,city,org,isp,as"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        # Cache the complete raw response payload
        cache.set(cache_key, data)
        return data
        
    except Exception as e:
        logger.warning(f"Failed to fetch IP details for {ip}: {e}")
        return {}

def get_ip_geo(ip: str) -> dict:
    data = _get_ip_api_data(ip)
    return {
        "country": sanitize_osint_field(data.get("country", ""), "ip_geo.country"),
        "city":    sanitize_osint_field(data.get("city",    ""), "ip_geo.city"),
        "org":     sanitize_osint_field(data.get("org",     ""), "ip_geo.org"),
        "isp":     sanitize_osint_field(data.get("isp",     ""), "ip_geo.isp"),
    }

def get_asn(ip: str) -> dict:
    data = _get_ip_api_data(ip)
    as_field = data.get("as", "")
    
    asn = ""
    asn_name = ""
    
    if as_field and as_field.startswith("AS"):
        # Format is usually "AS12345 Provider Name"
        parts = as_field.split(" ", 1)
        asn = parts[0]  # numeric token — not sanitized
        if len(parts) > 1:
            asn_name = parts[1]

    is_bulletproof = asn in getattr(settings, "BULLETPROOF_ASNS", [])

    return {
        "asn": asn,
        "asn_name": sanitize_osint_field(asn_name, "asn.asn_name"),
        "is_known_bulletproof": is_bulletproof,  # boolean — not sanitized
    }

def analyze_ip(ip: str) -> dict:
    """
    Calls both get_ip_geo and get_asn.
    Merges results into one dict.
    This is the only function other modules should call.
    """
    if not ip:
        # Provide safe default empty structure if no IP is given
        geo = get_ip_geo("")
        asn = get_asn("")
        return {**geo, **asn}
        
    geo = get_ip_geo(ip)
    asn = get_asn(ip)
    
    return {**geo, **asn}
