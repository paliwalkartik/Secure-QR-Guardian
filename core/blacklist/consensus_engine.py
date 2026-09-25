"""
Consensus engine. A domain is only blacklisted after BLACKLIST_MIN_REPORTS unique reports.
Prevents single-user poisoning of the community blacklist.
Rate limiting: the same domain cannot be reported more than once per 60 seconds
from the same in-process session, blocking rapid-fire false-report flooding.
Does NOT make direct network calls — delegates to firebase_client exclusively.
"""

from core.blacklist.firebase_client import (
    check_blacklist,
    get_report_count,
    add_to_blacklist,
    submit_report
)
from config.settings import settings
from utils.logger import get_logger
import time

logger = get_logger(__name__)

# Per-session cooldown registry: domain_hash -> last_report_timestamp (float).
# In-memory only — resets on app restart. Not a substitute for server-side
# deduplication, but prevents trivial rapid-fire abuse within one session.
_REPORT_COOLDOWN_SECONDS: int = 60
_REPORT_COOLDOWN: dict = {}


def should_blacklist(domain: str) -> bool:
    """
    Return True if a domain has enough community reports to be blacklisted.
    Triggers add_to_blacklist automatically when the threshold is crossed.
    Never raises.
    """
    try:
        count = get_report_count(domain)
        is_above_threshold = count >= settings.BLACKLIST_MIN_REPORTS

        if is_above_threshold:
            if not check_blacklist(domain):
                add_to_blacklist(domain)

        return is_above_threshold
    except Exception as e:
        logger.error(f"Error in should_blacklist for {domain}: {e}")
        return False


def check_and_update(domain: str) -> bool:
    """
    Check blacklist status and auto-promote to blacklisted if report threshold is met.
    Never raises.
    """
    try:
        # Fast path from local cache / Firebase
        if check_blacklist(domain):
            return True

        # Check report threshold and promote if needed
        return should_blacklist(domain)
    except Exception as e:
        logger.error(f"Error in check_and_update for {domain}: {e}")
        return False


def report_domain(domain: str) -> dict:
    """
    Record a community fraud report for a domain and update blacklist status.

    Rate limited: if the same domain is reported again within
    _REPORT_COOLDOWN_SECONDS (60 s) from the same session, returns early with
    reported=False to prevent rapid-fire false-report flooding.
    Never raises.
    """
    import hashlib
    domain_hash = hashlib.sha256(domain.lower().strip().encode()).hexdigest()

    # ── Rate limiting (per-session, in-memory) ────────────────────────────
    now = time.time()
    last_reported = _REPORT_COOLDOWN.get(domain_hash, 0.0)
    elapsed = now - last_reported

    if elapsed < _REPORT_COOLDOWN_SECONDS:
        remaining = int(_REPORT_COOLDOWN_SECONDS - elapsed)
        logger.warning(
            "report_domain rate-limited",
            extra={"domain_hash": domain_hash[:12], "cooldown_remaining_s": remaining},
        )
        return {
            "reported":         False,
            "reason":           "Rate limited",
            "cooldown_seconds": _REPORT_COOLDOWN_SECONDS,
        }

    # ── Record and update ─────────────────────────────────────────────────
    try:
        submit_report(domain)
        _REPORT_COOLDOWN[domain_hash] = now       # stamp after successful submission
        is_blacklisted = check_and_update(domain)
        count = get_report_count(domain)

        return {
            "reported":         True,
            "now_blacklisted":  is_blacklisted,
            "report_count":     count,
        }
    except Exception as e:
        logger.error(f"Error in report_domain for {domain}: {e}")
        return {
            "reported":         False,
            "now_blacklisted":  False,
            "report_count":     0,
        }
