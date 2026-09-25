"""
NIST Cybersecurity Framework mapper. Annotates scan results with NIST function tags.
Tags reflect which framework functions each module implements.
"""

import os
import json
from typing import List
from utils.logger import get_logger

logger = get_logger(__name__)

# Load NIST map at module level to avoid repeated disk reads
_nist_map = {}
try:
    map_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), 
        'config', 
        'nist_map.json'
    )
    
    if os.path.exists(map_path):
        with open(map_path, 'r', encoding='utf-8') as f:
            _nist_map = json.load(f)
    else:
        logger.warning(f"NIST map file not found at {map_path}")
        
except Exception as e:
    logger.error(f"Error loading NIST map at module level: {e}")


def get_nist_summary() -> dict:
    """
    Return the full nist_map.json contents for reporting/display purposes.
    """
    try:
        # Return a copy to prevent accidental mutation of the module-level dictionary
        return dict(_nist_map)
    except Exception as e:
        logger.error(f"Error retrieving NIST summary: {e}")
        return {}


def annotate_result(result: dict, active_modules: List[str]) -> dict:
    """
    Collects all unique NIST CSF functions from the activated modules
    and adds them as a list under the 'nist_tags' key in the result dictionary.
    """
    try:
        tags = set()
        
        for module in active_modules:
            if module in _nist_map:
                for tag in _nist_map[module]:
                    tags.add(tag)
                    
        # Add the collected tags to the result dictionary in deterministic order
        result["nist_tags"] = sorted(list(tags))
        return result
        
    except Exception as e:
        logger.error(f"Error annotating result with NIST tags: {e}")
        
        # Absolute Rule 3: Safe default fallback
        if "nist_tags" not in result:
            result["nist_tags"] = []
            
        return result
