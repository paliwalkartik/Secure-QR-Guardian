"""
Privacy layer for community reporting. Strips PII and adds timestamp noise before Firebase writes.
All data submitted to Firebase passes through this module first.
"""

import random
from datetime import datetime, timedelta
from utils.logger import get_logger

logger = get_logger(__name__)


def add_timestamp_noise(iso_timestamp: str) -> str:
    """
    Parse an ISO timestamp, add ±0-3600 seconds of random noise, and return a new ISO string.
    This prevents timing correlation attacks when submitting community reports.
    """
    try:
        # Handle string parsing
        dt = datetime.fromisoformat(iso_timestamp)
        
        # Add random noise (± random integer between 0 and 3600 seconds)
        noise_seconds = random.randint(-3600, 3600)
        noised_dt = dt + timedelta(seconds=noise_seconds)
        
        return noised_dt.isoformat()
    except Exception as e:
        logger.error(f"Error adding timestamp noise to '{iso_timestamp}': {e}")
        # Safe default: return the original string if parsing/noising fails
        return iso_timestamp


def anonymize_report(scan_data: dict) -> dict:
    """
    Strips raw data and PII identifiers from a scan result, returning only core
    analytical metrics alongside a noised timestamp.
    """
    try:
        cleaned = {}
        
        # Whitelist the only acceptable keys to completely eliminate PII 
        # (like raw_data, input_source, or keys containing 'ip', 'user', 'device')
        if "data_type" in scan_data:
            cleaned["data_type"] = scan_data["data_type"]
            
        if "timestamp" in scan_data:
            cleaned["timestamp"] = add_timestamp_noise(scan_data["timestamp"])
            
        if "threat_level" in scan_data:
            cleaned["threat_level"] = scan_data["threat_level"]
            
        if "matched_archetype" in scan_data:
            cleaned["matched_archetype"] = scan_data["matched_archetype"]
            
        return cleaned
    except Exception as e:
        logger.error(f"Error anonymizing report data: {e}")
        # Safe default: return empty dict to prevent leaking anything on failure
        return {}
