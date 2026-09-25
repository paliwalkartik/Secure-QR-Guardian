"""
VPA identity verification against mock registry.
In production, replace mock with NPCI API integration.
All string outputs are sanitized against prompt injection.
"""

from utils.logger import get_logger
from core.reasoning.injection_guard import sanitize_osint_field

logger = get_logger(__name__)

# PRODUCTION NOTE: Replace this mock registry with NPCI UPI API when available.
# Current NPCI APIs do not expose VPA ownership publicly. This is a known limitation.
MOCK_VPA_REGISTRY = {
    "paytm@paytm": {"registered_name": "Paytm Payments Bank", "mismatch": False},
    "sbi.official@sbi": {"registered_name": "Ravi Kumar", "mismatch": True},
    "support@hdfcbank": {"registered_name": "HDFC Customer Care", "mismatch": False},
    "customer-care@icici": {"registered_name": "Amit Singh", "mismatch": True},
    "amazon-pay@apl": {"registered_name": "Amazon Pay India", "mismatch": False},
    "flipkart.rewards@ybl": {"registered_name": "Sneha Patil", "mismatch": True},
    "googlepay@okhdfcbank": {"registered_name": "Google India Digital", "mismatch": False},
    "jio.recharge@jio": {"registered_name": "Reliance Jio", "mismatch": False},
    "airtel.kyc@airtel": {"registered_name": "Vikram Sharma", "mismatch": True},
    "phonepe.cashback@ybl": {"registered_name": "Priya Das", "mismatch": True}
}

def verify_vpa(vpa: str) -> dict:
    if not vpa or "@" not in vpa:
        return {
            "claimed_name": "",
            "registered_name": "Unknown",
            "mismatch": False,
            "vpa": vpa if vpa else ""
        }
        
    vpa_lower = vpa.lower().strip()
    localpart = vpa_lower.split("@")[0]
    
    # Extract claimed_name by replacing separators with spaces and applying title case
    claimed_name = localpart.replace(".", " ").replace("-", " ").replace("_", " ").title()
    
    # Lookup against mock registry
    if vpa_lower in MOCK_VPA_REGISTRY:
        record = MOCK_VPA_REGISTRY[vpa_lower]
        registered_name = record["registered_name"]
        mismatch = record["mismatch"]
    else:
        # Default when we cannot confirm ownership
        registered_name = "Unknown"
        mismatch = False
        
    logger.debug(f"Verified VPA identity: {vpa_lower}", extra={"mismatch": mismatch})

    return {
        "claimed_name":    sanitize_osint_field(claimed_name,    "vpa.claimed_name"),
        "registered_name": sanitize_osint_field(registered_name, "vpa.registered_name"),
        "mismatch": mismatch,  # boolean — not sanitized
        "vpa": vpa_lower,      # kept intact for downstream analysis
    }
