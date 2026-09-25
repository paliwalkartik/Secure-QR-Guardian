"""
Archetype detail lookup. Maps LLM archetype ID to full archetype definition from archetypes.json.
"""

import os
import json
from utils.logger import get_logger

logger = get_logger(__name__)

ARCHETYPES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
    'config', 
    'archetypes.json'
)

try:
    with open(ARCHETYPES_PATH, 'r', encoding='utf-8') as f:
        _archetypes_list = json.load(f)
        ARCHETYPES_REGISTRY = {item["id"]: item for item in _archetypes_list}
except Exception as e:
    logger.error(f"Failed to load archetypes.json: {e}")
    ARCHETYPES_REGISTRY = {}


def get_archetype_detail(archetype_id: str) -> dict:
    if not archetype_id or str(archetype_id).strip().upper() == "NONE":
        return {
            "id": "NONE",
            "name": "Unknown",
            "description": "No archetype matched",
            "indicators": []
        }
        
    archetype_id_upper = str(archetype_id).strip().upper()
    
    if archetype_id_upper in ARCHETYPES_REGISTRY:
        archetype = ARCHETYPES_REGISTRY[archetype_id_upper]
        return {
            "id": archetype.get("id", "NONE"),
            "name": archetype.get("name", "Unknown"),
            "description": archetype.get("description", "No description"),
            "indicators": archetype.get("indicators", [])
        }
        
    logger.debug(f"LLM returned an unrecognized archetype ID: {archetype_id}")
    
    return {
        "id": "NONE",
        "name": "Unknown",
        "description": "No archetype matched",
        "indicators": []
    }
