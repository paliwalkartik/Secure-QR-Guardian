"""
Typosquatting detector using Levenshtein distance against trusted Indian payment domains.
Loads domain list once at import. No network calls.
Also detects homograph/Punycode attacks: any xn-- label in a payment QR is treated as
suspicious regardless of Levenshtein distance, because legitimate UPI services never use
Internationalized Domain Names (IDN) in QR codes.
Does NOT resolve DNS or make any network calls.
"""

import os
import json
import unicodedata
import Levenshtein
from config.settings import settings
from utils.logger import get_logger

logger = get_logger(__name__)

# Load trusted domains once at module level
TRUSTED_DOMAINS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    'config',
    'trusted_domains.json'
)

try:
    with open(TRUSTED_DOMAINS_PATH, 'r', encoding='utf-8') as f:
        TRUSTED_DOMAINS = json.load(f)
        TRUSTED_DOMAINS_SET = set(TRUSTED_DOMAINS)
except Exception as e:
    logger.error(f"Failed to load trusted domains: {e}")
    TRUSTED_DOMAINS = []
    TRUSTED_DOMAINS_SET = set()


def _get_base_domain(domain: str) -> str:
    """Strips subdomains to extract the root domain. Uses a heuristic for .co.in type TLDs."""
    if not domain:
        return ""

    domain = domain.lower().strip()
    parts = domain.split('.')

    if len(parts) <= 2:
        return domain

    # Handle two-part TLDs commonly used in India (e.g., .co.in, .org.in)
    two_part_tlds = ('co', 'org', 'ac', 'gov', 'net', 'edu', 'com')
    if parts[-2] in two_part_tlds and len(parts[-1]) == 2:
        if len(parts) >= 3:
            return '.'.join(parts[-3:])

    # Default: keep last two parts
    return '.'.join(parts[-2:])


def _normalize_domain(domain: str) -> tuple:
    """
    Decode Punycode labels and apply NFKC normalization to expose homograph attacks.

    Returns (normalized_domain: str, punycode_detected: bool).

    Step 1 — Punycode: if any label starts with 'xn--', attempt IDNA decode on every
    label. On UnicodeError the label is treated as suspicious: WARNING is logged and
    the original label is kept so downstream Levenshtein still runs on something sensible.

    Step 2 — NFKC: collapses Unicode lookalike characters (e.g. Cyrillic 'a' U+0430)
    to their ASCII canonical form where the Unicode standard defines equivalence.

    Never raises. Always returns a 2-tuple.
    """
    punycode_detected = "xn--" in domain.lower()

    normalized_labels = []
    for label in domain.split('.'):
        if label.lower().startswith('xn--'):
            try:
                # IDNA decode: b'xn--...' -> unicode string
                decoded = label.encode('ascii').decode('idna')
                normalized_labels.append(decoded)
            except (UnicodeError, UnicodeDecodeError) as exc:
                logger.warning(
                    "IDNA decode failed for Punycode label — treating domain as suspicious",
                    extra={"label": label, "raw_domain": domain[:120], "error": str(exc)},
                )
                # Keep original label; punycode_detected already True
                normalized_labels.append(label)
        else:
            normalized_labels.append(label)

    joined = '.'.join(normalized_labels)

    # NFKC normalization maps lookalike Unicode chars to ASCII equivalents
    normalized = unicodedata.normalize("NFKC", joined)

    return normalized, punycode_detected


def check_typosquat(domain: str) -> dict:
    """
    Check whether a domain is a typosquatted version of a known legitimate payment domain.

    Returns a dict with keys: is_typosquat, closest_legit, distance, match,
    punycode_detected, normalized_domain.
    Any Punycode label unconditionally sets is_typosquat=True.
    Levenshtein runs on the NFKC-normalized domain, not the raw input.
    Never raises.
    """
    _SAFE_DEFAULTS = {
        "is_typosquat": False,
        "closest_legit": "",
        "distance": 0,
        "match": "",
        "punycode_detected": False,
        "normalized_domain": domain or "",
    }

    if not domain:
        return _SAFE_DEFAULTS

    # Step 1: Decode Punycode / normalize homoglyphs before any comparison
    normalized_domain, punycode_detected = _normalize_domain(domain)

    base_domain = _get_base_domain(normalized_domain)

    # Step 2: Exact match against trusted set (on normalized form)
    if base_domain in TRUSTED_DOMAINS_SET and not punycode_detected:
        return {
            "is_typosquat": False,
            "closest_legit": base_domain,
            "distance": 0,
            "match": base_domain,
            "punycode_detected": False,
            "normalized_domain": normalized_domain,
        }

    # Step 3: Levenshtein sweep over trusted domains
    min_dist = float('inf')
    closest_legit = ""

    for trusted in TRUSTED_DOMAINS:
        dist = Levenshtein.distance(base_domain, trusted)
        if dist < min_dist:
            min_dist = dist
            closest_legit = trusted

    max_distance = getattr(settings, "TYPOSQUAT_MAX_DISTANCE", 2)

    # Punycode unconditionally flags as typosquat; otherwise use distance threshold
    if punycode_detected:
        is_typosquat = True
    else:
        is_typosquat = (min_dist <= max_distance and base_domain not in TRUSTED_DOMAINS_SET)

    return {
        "is_typosquat": is_typosquat,
        "closest_legit": closest_legit,
        "distance": int(min_dist) if min_dist != float('inf') else 0,
        "match": base_domain,
        "punycode_detected": punycode_detected,
        "normalized_domain": normalized_domain,
    }
