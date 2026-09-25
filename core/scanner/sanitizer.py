"""
Sanitizer converts raw QR string into a typed SanitizedPayload.
No network calls. No side effects. Input is treated as untrusted.
"""

from core.scanner.payload_models import SanitizedPayload, DataType
from utils.validators import is_valid_url, is_valid_upi_vpa
from utils.logger import get_logger

logger = get_logger(__name__)

def sanitize(raw: str, source: str = "unknown") -> SanitizedPayload:
    if not isinstance(raw, str):
        raw = ""
        
    # 1. Strip whitespace from raw
    clean_raw = raw.strip()
    
    # 2. If matches UPI VPA regex -> DataType.UPI
    # We also check for the upi:// URI scheme which is standard for UPI QR payloads
    if is_valid_upi_vpa(clean_raw) or clean_raw.lower().startswith("upi://"):
        data_type = DataType.UPI
    # 3. Elif matches URL regex -> DataType.URL
    elif is_valid_url(clean_raw):
        data_type = DataType.URL
    # 4. Elif raw is non-empty plain text -> DataType.TEXT
    elif len(clean_raw) > 0:
        data_type = DataType.TEXT
    # 5. Else -> DataType.UNKNOWN
    else:
        data_type = DataType.UNKNOWN
        
    payload = SanitizedPayload(
        raw_data=clean_raw,
        data_type=data_type,
        input_source=source
    )
    
    # CRITICAL: Do NOT log the raw_data value (it may contain malicious strings)
    # Log only: scan_id, data_type, source (safe fields only)
    logger.info(
        "Payload sanitized",
        extra={
            "scan_id": payload.scan_id,
            "data_type": payload.data_type.value,
            "source": payload.input_source
        }
    )
    
    return payload
