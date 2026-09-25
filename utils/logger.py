"""
Structured JSON logger. Import get_logger() and call it once per module at the top level.
Never use print() anywhere in this project.
"""

import json
import logging
import datetime
import re
from typing import Any, Dict

from config.settings import settings

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter with payload and secret sanitization."""
    
    STANDARD_ATTRS = {
        'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename', 
        'funcName', 'levelname', 'levelno', 'lineno', 'module', 'msecs', 
        'message', 'msg', 'name', 'pathname', 'process', 'processName', 
        'relativeCreated', 'stack_info', 'thread', 'threadName', 'taskName', 'color_message'
    }

    def format(self, record: logging.LogRecord) -> str:
        # Extract any extra attributes added via logger.info("...", extra={"key": "value"})
        extra_dict = {k: v for k, v in record.__dict__.items() if k not in self.STANDARD_ATTRS}
        
        # Construct the structured JSON dictionary
        log_record = {
            "timestamp": datetime.datetime.fromtimestamp(record.created, tz=datetime.timezone.utc).isoformat() + "Z",
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
            "extra": extra_dict
        }

        # Apply sanitization to ensure no secrets or raw payloads are logged
        sanitized_record = self._sanitize(log_record)
        return json.dumps(sanitized_record)

    def _sanitize(self, data: Any) -> Any:
        if isinstance(data, dict):
            return {k: self._sanitize_value(k, v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._sanitize(v) for v in data]
        elif isinstance(data, str):
            return self._mask_string(data)
        return data

    def _sanitize_value(self, key: str, value: Any) -> Any:
        key_lower = key.lower()
        # Mask keys that look like secrets
        if any(secret in key_lower for secret in ["api_key", "token", "secret", "password", "credentials"]):
            return "***"
        return self._sanitize(value)

    def _mask_string(self, text: str) -> str:
        # Mask raw QR payloads (e.g., UPI URIs)
        text = re.sub(r'upi://\S+', 'upi://[MASKED_PAYLOAD]', text, flags=re.IGNORECASE)
        
        # Mask specific API keys from settings if they happen to appear in strings
        for attr in ["GROQ_API_KEY", "IP_API_KEY"]:
            secret = getattr(settings, attr, "")
            if secret and len(secret) >= 8 and secret in text:
                text = text.replace(secret, f"***{secret[-4:]}")
            elif secret and secret in text:
                text = text.replace(secret, "***")
                
        return text

def get_logger(module_name: str) -> logging.Logger:
    """
    Returns a configured JSON logger for the specified module.
    """
    logger = logging.getLogger(module_name)
    
    # Prevent duplicate handlers if get_logger is called multiple times for the same module
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        
        # Determine log level from settings, defaulting to INFO
        is_debug = getattr(settings, "DEBUG", False)
        logger.setLevel(logging.DEBUG if is_debug else logging.INFO)
        
        # Do not propagate up to the root logger to avoid duplicate logs
        logger.propagate = False
        
    return logger
