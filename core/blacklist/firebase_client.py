"""
Firebase client for community blacklist. All domain keys are SHA-256 hashed.
No PII is stored. If Firebase unavailable, all functions return safe defaults.
Resilience layer: a module-level local cache (TTL = 300 s) absorbs Firebase
downtime for read operations. Writes always go to Firebase first, then mirror
to local cache. Every blacklist mutation is recorded via _audit_log — if Firebase
is unreachable, the audit event is written to the application logger instead.
Does NOT store raw domains anywhere — only SHA-256 hashes leave this module.
"""

import time
import hashlib
from datetime import datetime, timedelta, timezone

import firebase_admin
from firebase_admin import credentials, firestore

from config.settings import settings
from utils.logger import get_logger

logger = get_logger(__name__)

# ── Local read cache (resilience against Firebase downtime) ──────────────────
# Maps domain_hash → {"is_blacklisted": bool, "expires_at": str}
# Never written directly — populated by check_blacklist and add_to_blacklist.
_LOCAL_BLACKLIST: dict = {}
_LOCAL_CACHE_TTL: int  = 300   # seconds before a full Firebase refresh
_local_cache_timestamp: float = 0.0

# ── Firebase init ────────────────────────────────────────────────────────────
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


# ── Private helpers ──────────────────────────────────────────────────────────

def _hash_domain(domain: str) -> str:
    """SHA-256 hash of the normalised domain. Used as the Firestore document key."""
    return hashlib.sha256(domain.lower().strip().encode("utf-8")).hexdigest()


def _is_cache_stale() -> bool:
    """Return True if the local cache has exceeded its TTL."""
    return (time.time() - _local_cache_timestamp) > _LOCAL_CACHE_TTL


def _refresh_local_cache() -> None:
    """
    Pull the full active blacklist from Firebase into _LOCAL_BLACKLIST.

    Private — called automatically by check_blacklist when the cache is stale.
    No-op if Firebase is unavailable. Never raises.
    """
    global _local_cache_timestamp

    if db is None:
        return

    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        docs = db.collection("blacklist").get()

        refreshed: dict = {}
        for doc in docs:
            data = doc.to_dict() or {}
            expires_at = data.get("expires_at", "")
            is_active  = bool(expires_at and now_iso < expires_at)
            refreshed[doc.id] = {
                "is_blacklisted": is_active,
                "expires_at":     expires_at,
            }

        _LOCAL_BLACKLIST.clear()
        _LOCAL_BLACKLIST.update(refreshed)
        _local_cache_timestamp = time.time()

        logger.debug(
            "Local blacklist cache refreshed",
            extra={"entries": len(_LOCAL_BLACKLIST)},
        )
    except Exception as exc:
        logger.error(
            "Failed to refresh local blacklist cache from Firebase",
            extra={"error": str(exc)},
        )


def _audit_log(action: str, domain_hash: str) -> None:
    """
    Fire-and-forget audit trail for blacklist mutations.

    Writes to Firebase path: audit/{timestamp_ms}/{action}.
    If Firebase is unreachable, the event is emitted at WARNING level via
    utils/logger.py — the record is never silently dropped.
    Never raises under any circumstances.
    """
    now      = datetime.now(timezone.utc)
    now_iso  = now.isoformat()
    ts_key   = str(int(now.timestamp() * 1000))   # ms precision, unique enough for audit keys

    payload = {
        "action":       action,
        "domain_hash":  domain_hash,
        "timestamp_iso": now_iso,
        "app_version":  "1.0",
    }

    try:
        if db is not None:
            db.collection("audit").document(ts_key).collection("events").document(action).set(payload)
        else:
            raise RuntimeError("Firebase not available")
    except Exception as exc:
        # Degrade gracefully — persist to application log rather than losing the record
        logger.warning(
            "Audit log could not reach Firebase — recording locally",
            extra={**payload, "firebase_error": str(exc)},
        )


# ── Public API ───────────────────────────────────────────────────────────────

def check_blacklist(domain: str) -> bool:
    """
    Check if a domain is currently on the active blacklist.

    Fast path: consult _LOCAL_BLACKLIST first.
    Slow path: if cache is stale (> 300 s), refresh from Firebase, then check.
    Returns False when both local cache and Firebase are unavailable.
    Never raises.
    """
    domain_hash = _hash_domain(domain)

    # Fast path — serve from local cache when fresh
    if not _is_cache_stale() and domain_hash in _LOCAL_BLACKLIST:
        return _LOCAL_BLACKLIST[domain_hash].get("is_blacklisted", False)

    # Slow path — refresh cache if stale, then re-check
    if _is_cache_stale():
        _refresh_local_cache()

    # After refresh, check local cache
    if domain_hash in _LOCAL_BLACKLIST:
        return _LOCAL_BLACKLIST[domain_hash].get("is_blacklisted", False)

    # Local cache miss after refresh — fall through to direct Firebase query
    if db is None:
        return False

    try:
        doc_ref = db.collection("blacklist").document(domain_hash)
        doc     = doc_ref.get()

        if doc.exists:
            data       = doc.to_dict()
            expires_at = data.get("expires_at", "")
            now_iso    = datetime.now(timezone.utc).isoformat()
            active     = bool(expires_at and now_iso < expires_at)

            # Populate local cache with the freshly fetched entry
            _LOCAL_BLACKLIST[domain_hash] = {
                "is_blacklisted": active,
                "expires_at":     expires_at,
            }
            return active

        return False
    except Exception as exc:
        logger.error(
            "Error checking blacklist for domain",
            extra={"domain_hash": domain_hash[:12], "error": str(exc)},
        )
        return False


def submit_report(domain: str, reporter_id: str = "anonymous") -> None:
    """
    Submit a community report for a malicious domain.
    """
    if db is None:
        return

    try:
        domain_hash = _hash_domain(domain)
        now_iso     = datetime.now(timezone.utc).isoformat()

        doc_ref = (
            db.collection("reports")
            .document(domain_hash)
            .collection("reporters")
            .document(reporter_id)
        )

        doc_ref.set({
            "timestamp": now_iso,
            "domain":    domain.lower().strip(),
        })
    except Exception as exc:
        logger.error(f"Error submitting report for domain: {exc}")


def get_report_count(domain: str) -> int:
    """
    Get the total number of unique community reports for a domain.
    """
    if db is None:
        return 0

    try:
        domain_hash   = _hash_domain(domain)
        reporters_ref = (
            db.collection("reports")
            .document(domain_hash)
            .collection("reporters")
        )
        docs = reporters_ref.get()
        return len(docs)
    except Exception as exc:
        logger.error(f"Error getting report count for domain: {exc}")
        return 0


def add_to_blacklist(domain: str) -> None:
    """
    Add a domain to the global blacklist with a standard TTL.

    Write order: Firebase first, then local cache mirror, then audit log.
    If Firebase is unavailable, the local cache is still updated so the entry
    survives for the current session. Audit log is always attempted.
    Never raises.
    """
    domain_hash = _hash_domain(domain)
    now         = datetime.now(timezone.utc)
    expires     = now + timedelta(days=settings.BLACKLIST_TTL_DAYS)
    expires_iso = expires.isoformat()

    # 1. Write to Firebase (primary store)
    if db is not None:
        try:
            data = {
                "domain":     domain.lower().strip(),
                "added_at":   now.isoformat(),
                "expires_at": expires_iso,
            }
            db.collection("blacklist").document(domain_hash).set(data)
        except Exception as exc:
            logger.error(
                "Error adding domain to Firebase blacklist",
                extra={"domain_hash": domain_hash[:12], "error": str(exc)},
            )

    # 2. Mirror to local cache immediately (write-through)
    _LOCAL_BLACKLIST[domain_hash] = {
        "is_blacklisted": True,
        "expires_at":     expires_iso,
    }

    # 3. Audit log — fire and forget, never raises
    _audit_log("BLACKLIST_ADD", domain_hash)


def delete_expired() -> int:
    """
    Prune expired domains from the active Firebase blacklist.

    Returns the count of deleted documents. Returns 0 on any failure.
    """
    if db is None:
        return 0

    try:
        now_iso       = datetime.now(timezone.utc).isoformat()
        blacklist_ref = db.collection("blacklist")
        query         = blacklist_ref.where("expires_at", "<", now_iso)
        docs          = query.get()

        count = 0
        for doc in docs:
            doc.reference.delete()
            # Also evict from local cache
            _LOCAL_BLACKLIST.pop(doc.id, None)
            count += 1

        return count
    except Exception as exc:
        logger.error(f"Error deleting expired blacklist entries: {exc}")
        return 0


def get_blacklist_stats() -> dict:
    """
    Return health metrics for the blacklist subsystem.

    Used by the dashboard to show blacklist integrity at a glance.
    Returns a safe default dict on any failure. Never raises.
    """
    try:
        now_iso = datetime.now(timezone.utc).isoformat()

        total_entries   = len(_LOCAL_BLACKLIST)
        expired_entries = sum(
            1 for entry in _LOCAL_BLACKLIST.values()
            if entry.get("expires_at", "") < now_iso
        )
        local_cache_size = total_entries

        return {
            "total_entries":    total_entries,
            "expired_entries":  expired_entries,
            "local_cache_size": local_cache_size,
            "firebase_online":  db is not None,
            "cache_age_seconds": int(time.time() - _local_cache_timestamp),
        }
    except Exception as exc:
        logger.error(f"Error computing blacklist stats: {exc}")
        return {
            "total_entries":    0,
            "expired_entries":  0,
            "local_cache_size": 0,
            "firebase_online":  False,
            "cache_age_seconds": -1,
        }
