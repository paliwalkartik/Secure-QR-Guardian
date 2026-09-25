"""
In-memory TTL cache. All OSINT modules must check cache before making network calls.
Call cache.get(key) first. If None, fetch, then cache.set(key, result).
"""

import time
import threading
from typing import Any, Optional

from config.settings import settings

class TTLCache:
    def __init__(self):
        self._cache = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._cache:
                return None
            
            value, expiry = self._cache[key]
            if time.time() > expiry:
                # Expired, clean it up and return None
                del self._cache[key]
                return None
            
            return value

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        if ttl_seconds is None:
            ttl_seconds = settings.CACHE_TTL_SECONDS
            
        expiry = time.time() + ttl_seconds
        
        with self._lock:
            self._cache[key] = (value, expiry)

    def invalidate(self, key: str) -> None:
        with self._lock:
            if key in self._cache:
                del self._cache[key]

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

# Export a single module-level instance
cache = TTLCache()
