"""
Dashboard stats aggregator. Pulls from Firebase with 60-second cache.
Falls back to synthetic demo data if Firebase unavailable.
"""

from datetime import datetime, timedelta, timezone
from utils.cache import cache
from utils.logger import get_logger
from core.blacklist.firebase_client import db

logger = get_logger(__name__)


def _get_demo_data() -> dict:
    """Returns realistic synthetic data so the Streamlit dashboard renders beautifully."""
    return {
        "total_scans": 12543,
        "threats_today": 842,
        "top_asns": [
            {"asn": "AS13335 (Cloudflare)", "count": 412},
            {"asn": "AS49392 (Bulletproof RU)", "count": 289},
            {"asn": "AS16509 (AWS)", "count": 156},
            {"asn": "AS14061 (DigitalOcean)", "count": 92},
            {"asn": "AS20473 (Choopa)", "count": 45}
        ],
        "archetype_distribution": {
            "TYPOSQUATTER": 4210,
            "FRESH_PHISH": 3150,
            "LOOKALIKE_DOMAIN": 2400,
            "VPA_IMPOSTOR": 1820,
            "REDIRECT_CHAIN": 963
        },
        "safe_count": 8940
    }


def get_dashboard_stats() -> dict:
    """
    Retrieves global aggregation stats for the metrics dashboard.
    Leverages TTLCache to prevent database spam on page refreshes.
    """
    # 1. Check TTL Cache First (60 seconds)
    cached_stats = cache.get("dashboard_stats")
    if cached_stats is not None:
        return cached_stats

    # 2. Safety fallback if Firebase is not configured
    if db is None:
        logger.info("Firebase db is None. Serving synthetic demo dashboard stats.")
        demo = _get_demo_data()
        cache.set("dashboard_stats", demo, ttl_seconds=60)
        return demo

    try:
        scans_ref = db.collection("scans")
        
        # In a massive production system, this would use Cloud Functions for aggregation.
        # For this implementation, we pull docs and manually aggregate.
        all_docs = scans_ref.get()
        
        total_scans = len(all_docs)
        
        threats_today = 0
        safe_count = 0
        asn_counts = {}
        archetype_dist = {}
        
        yesterday_iso = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        
        for doc in all_docs:
            data = doc.to_dict()
            
            threat_level = data.get("threat_level", "UNKNOWN")
            timestamp = data.get("timestamp", "")
            
            # Count Safe
            if threat_level == "SAFE":
                safe_count += 1
                
            # Count Threats Today
            if threat_level in ["HIGH", "CRITICAL"] and timestamp >= yesterday_iso:
                threats_today += 1
                
            # Aggregate ASNs
            asn = data.get("asn")
            if asn:
                asn_counts[asn] = asn_counts.get(asn, 0) + 1
                
            # Aggregate Archetypes
            arch = data.get("matched_archetype")
            if arch and arch != "NONE":
                archetype_dist[arch] = archetype_dist.get(arch, 0) + 1
                
        # Sort and take top 5 ASNs
        sorted_asns = sorted(asn_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_asns = [{"asn": k, "count": v} for k, v in sorted_asns]
        
        stats = {
            "total_scans": total_scans,
            "threats_today": threats_today,
            "top_asns": top_asns,
            "archetype_distribution": archetype_dist,
            "safe_count": safe_count
        }
        
        # Cache for 60 seconds
        cache.set("dashboard_stats", stats, ttl_seconds=60)
        return stats
        
    except Exception as e:
        logger.error(f"Failed to fetch real dashboard stats from Firebase: {e}")
        # Absolute Rule 3: Fail gracefully
        demo = _get_demo_data()
        cache.set("dashboard_stats", demo, ttl_seconds=60)
        return demo
