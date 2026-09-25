"""
Firebase client for community blacklist. All domain keys are SHA-256 hashed.
No PII is stored. If Firebase unavailable, all functions return safe defaults.
"""

import hashlib
from datetime import datetime, timedelta, timezone

import firebase_admin
from firebase_admin import credentials, firestore

from config.settings import settings
from utils.logger import get_logger

logger = get_logger(__name__)

db = None

try:
    if settings.FIREBASE_CREDENTIALS_PATH and settings.FIREBASE_CREDENTIALS_PATH != "your_key_here":
        cred = credentials.Certificate(settings.FIREBASE_CREDENTIALS_PATH)
        # Check if already initialized to avoid errors during hot reloads
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred)
        db = firestore.client()
    else:
        logger.warning("FIREBASE_CREDENTIALS_PATH not valid. Firebase functionality disabled.")
except Exception as e:
    logger.warning(f"Failed to initialize Firebase Admin SDK: {e}")
    db = None


def _hash_domain(domain: str) -> str:
    """Helper to hash domains using SHA-256 for privacy-preserving keys."""
    return hashlib.sha256(domain.lower().strip().encode("utf-8")).hexdigest()


def check_blacklist(domain: str) -> bool:
    """
    Check if a domain is currently on the active blacklist.
    """
    if db is None:
        return False

    try:
        domain_hash = _hash_domain(domain)
        doc_ref = db.collection("blacklist").document(domain_hash)
        doc = doc_ref.get()

        if doc.exists:
            data = doc.to_dict()
            expires_at_str = data.get("expires_at")
            if expires_at_str:
                now_iso = datetime.now(timezone.utc).isoformat()
                # Lexicographical comparison works for standard ISO 8601 UTC strings
                if now_iso < expires_at_str:
                    return True
        return False
    except Exception as e:
        logger.error(f"Error checking blacklist for {domain}: {e}")
        return False


def submit_report(domain: str, reporter_id: str = "anonymous") -> None:
    """
    Submit a community report for a malicious domain.
    """
    if db is None:
        return

    try:
        domain_hash = _hash_domain(domain)
        now_iso = datetime.now(timezone.utc).isoformat()

        doc_ref = (
            db.collection("reports")
            .document(domain_hash)
            .collection("reporters")
            .document(reporter_id)
        )

        doc_ref.set({
            "timestamp": now_iso,
            "domain": domain.lower().strip()
        })
    except Exception as e:
        logger.error(f"Error submitting report for {domain}: {e}")


def get_report_count(domain: str) -> int:
    """
    Get the total number of unique community reports for a domain.
    """
    if db is None:
        return 0

    try:
        domain_hash = _hash_domain(domain)
        reporters_ref = (
            db.collection("reports")
            .document(domain_hash)
            .collection("reporters")
        )

        docs = reporters_ref.get()
        return len(docs)
    except Exception as e:
        logger.error(f"Error getting report count for {domain}: {e}")
        return 0


def add_to_blacklist(domain: str) -> None:
    """
    Add a domain to the global blacklist with a standard TTL.
    """
    if db is None:
        return

    try:
        domain_hash = _hash_domain(domain)
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=settings.BLACKLIST_TTL_DAYS)

        data = {
            "domain": domain.lower().strip(),
            "added_at": now.isoformat(),
            "expires_at": expires.isoformat()
        }

        db.collection("blacklist").document(domain_hash).set(data)
    except Exception as e:
        logger.error(f"Error adding {domain} to blacklist: {e}")


def delete_expired() -> int:
    """
    Prune expired domains from the active blacklist.
    """
    if db is None:
        return 0

    try:
        now_iso = datetime.now(timezone.utc).isoformat()

        blacklist_ref = db.collection("blacklist")
        query = blacklist_ref.where("expires_at", "<", now_iso)
        docs = query.get()

        count = 0
        for doc in docs:
            doc.reference.delete()
            count += 1

        return count
    except Exception as e:
        logger.error(f"Error deleting expired blacklist entries: {e}")
        return 0
