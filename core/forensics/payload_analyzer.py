"""
Raw payload forensic analysis. No network calls. Input is the raw QR string.
Produces hex dump, base64, and hash for evidentiary records.
"""

import base64
import hashlib
from utils.logger import get_logger

logger = get_logger(__name__)


def dump_hex(raw: str) -> str:
    """
    Encode string to UTF-8 and return an xxd-style hex dump.
    Groups of 2 hex chars per byte, 16 bytes per line, with an ASCII sidebar.
    """
    try:
        data = raw.encode("utf-8")
        lines = []
        
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            
            # 2 hex characters per byte separated by space
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            # Pad the hex part so the ASCII sidebar always aligns
            # 16 bytes * 2 chars + 15 spaces = 47 characters total length
            hex_part = f"{hex_part:<47}"
            
            # Printable ASCII representation (replace non-printable with '.')
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            
            lines.append(f"{i:08x}: {hex_part}  {ascii_part}")
            
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error generating hex dump: {e}")
        return ""


def dump_base64(raw: str) -> str:
    """
    Encode string to UTF-8 and return a standard base64 string, 
    line-wrapped at 76 characters.
    """
    try:
        data = raw.encode("utf-8")
        b64 = base64.standard_b64encode(data).decode("ascii")
        
        # Line wrap at 76 characters
        lines = [b64[i:i + 76] for i in range(0, len(b64), 76)]
        
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error generating base64 dump: {e}")
        return ""


def analyze_payload(raw: str) -> dict:
    """
    Aggregate the forensic dumps and compute additional indicators like byte length,
    SHA-256 hash, and basic string pattern matching.
    """
    fallback = {
        "hex_dump": "",
        "base64_dump": "",
        "byte_length": 0,
        "sha256_hash": "",
        "contains_suspicious_patterns": False
    }
    
    try:
        data = raw.encode("utf-8")
        
        hex_dump = dump_hex(raw)
        b64_dump = dump_base64(raw)
        length = len(data)
        h = hashlib.sha256(data).hexdigest()
        
        suspicious_patterns = ["login", "verify", "secure", "update", "bank", "upi", "pay"]
        raw_lower = raw.lower()
        
        # Check if any suspicious pattern exists in the payload
        contains_suspicious = any(pattern in raw_lower for pattern in suspicious_patterns)
        
        return {
            "hex_dump": hex_dump,
            "base64_dump": b64_dump,
            "byte_length": length,
            "sha256_hash": h,
            "contains_suspicious_patterns": contains_suspicious
        }
    except Exception as e:
        logger.error(f"Error analyzing payload: {e}")
        return fallback
