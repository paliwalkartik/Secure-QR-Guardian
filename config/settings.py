"""
Central configuration. All constants come from here.
Never hardcode thresholds or secrets in any other file.
"""

import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

# Load environment variables from .env at import time
load_dotenv()

@dataclass
class Settings:
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    FIREBASE_CREDENTIALS_PATH: str = os.getenv("FIREBASE_CREDENTIALS_PATH", "")
    IP_API_KEY: str = os.getenv("IP_API_KEY", "")
    GROQ_MODEL_NAME: str = os.getenv("GROQ_MODEL_NAME", "llama-3.3-70b-versatile")
    BLACKLIST_MIN_REPORTS: int = int(os.getenv("BLACKLIST_MIN_REPORTS", "3"))
    BLACKLIST_TTL_DAYS: int = int(os.getenv("BLACKLIST_TTL_DAYS", "90"))
    TYPOSQUAT_MAX_DISTANCE: int = int(os.getenv("TYPOSQUAT_MAX_DISTANCE", "2"))
    DOMAIN_SAFE_AGE_DAYS: int = int(os.getenv("DOMAIN_SAFE_AGE_DAYS", "730"))
    DOMAIN_DANGER_AGE_DAYS: int = int(os.getenv("DOMAIN_DANGER_AGE_DAYS", "7"))
    LLM_MAX_TOKENS: int = int(os.getenv("LLM_MAX_TOKENS", "1000"))
    CACHE_TTL_SECONDS: int = int(os.getenv("CACHE_TTL_SECONDS", "3600"))
    BULLETPROOF_ASNS: list = field(default_factory=lambda: ["AS200019", "AS9009", "AS60068", "AS48666", "AS206728"])

    def __repr__(self) -> str:
        masked_key = f"***{self.GROQ_API_KEY[-4:]}" if self.GROQ_API_KEY and len(self.GROQ_API_KEY) >= 4 else "***"
        return (
            f"Settings("
            f"GROQ_API_KEY='{masked_key}', "
            f"FIREBASE_CREDENTIALS_PATH='{self.FIREBASE_CREDENTIALS_PATH}', "
            f"IP_API_KEY='{self.IP_API_KEY}', "
            f"GROQ_MODEL_NAME='{self.GROQ_MODEL_NAME}', "
            f"BLACKLIST_MIN_REPORTS={self.BLACKLIST_MIN_REPORTS}, "
            f"BLACKLIST_TTL_DAYS={self.BLACKLIST_TTL_DAYS}, "
            f"TYPOSQUAT_MAX_DISTANCE={self.TYPOSQUAT_MAX_DISTANCE}, "
            f"DOMAIN_SAFE_AGE_DAYS={self.DOMAIN_SAFE_AGE_DAYS}, "
            f"DOMAIN_DANGER_AGE_DAYS={self.DOMAIN_DANGER_AGE_DAYS}, "
            f"LLM_MAX_TOKENS={self.LLM_MAX_TOKENS}, "
            f"CACHE_TTL_SECONDS={self.CACHE_TTL_SECONDS}, "
            f"BULLETPROOF_ASNS={self.BULLETPROOF_ASNS}"
            f")"
        )

# Export a single instance
settings = Settings()
