"""
Consensus engine. A domain is only blacklisted after BLACKLIST_MIN_REPORTS unique reports.
Prevents single-user poisoning of the community blacklist.
"""

from core.blacklist.firebase_client import (
    check_blacklist,
    get_report_count,
    add_to_blacklist,
    submit_report
)
from config.settings import settings
from utils.logger import get_logger

logger = get_logger(__name__)


def should_blacklist(domain: str) -> bool:
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
    try:
        # Fast path from Firebase
        if check_blacklist(domain):
            return True
            
        # Check report threshold
        return should_blacklist(domain)
    except Exception as e:
        logger.error(f"Error in check_and_update for {domain}: {e}")
        return False


def report_domain(domain: str) -> dict:
    try:
        submit_report(domain)
        is_blacklisted = check_and_update(domain)
        count = get_report_count(domain)
        
        return {
            "reported": True,
            "now_blacklisted": is_blacklisted,
            "report_count": count
        }
    except Exception as e:
        logger.error(f"Error in report_domain for {domain}: {e}")
        return {
            "reported": False,
            "now_blacklisted": False,
            "report_count": 0
        }
