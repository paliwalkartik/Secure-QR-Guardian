"""
VPA identity verification against mock registry.
In production, replace mock with NPCI API integration.
All string outputs are sanitized against prompt injection.
Aggregator-routed VPAs (Razorpay, Cashfree, etc.) are NOT flagged as mismatches —
payment aggregators legitimately register under their own corporate name.
Personal UPI handles (ybl, ibl, okhdfcbank, etc.) are also not flagged because
small merchants routinely use personal VPAs for business payments.
Does NOT make network calls.
"""

from utils.logger import get_logger
from core.reasoning.injection_guard import sanitize_osint_field

logger = get_logger(__name__)

# Payment aggregators whose registered_name will legitimately differ from the
# merchant's claimed identity. Any VPA provider matching one of these strings
# is routed via an aggregator and must NOT be flagged as a mismatch.
KNOWN_AGGREGATORS = [
    "razorpay", "cashfree", "payu", "instamojo", "ccavenue",
    "easebuzz", "zaakpay", "billdesk", "stripe", "juspay",
    "airpay", "payumoney", "direcpay", "sabpaisa", "atom",
]

# UPI handle suffixes used by individual/personal VPA accounts issued by banks.
# Small and micro-merchants commonly use these for business; name mismatch is
# not a reliable fraud signal on personal providers.
INDIVIDUAL_PROVIDER_PATTERNS = [
    "okaxis", "okhdfcbank", "okicici", "oksbi",
    "ybl", "ibl", "axl", "upi",
]

# PRODUCTION NOTE: Replace this mock registry with NPCI UPI API when available.
# Current NPCI APIs do not expose VPA ownership publicly. This is a known limitation.
MOCK_VPA_REGISTRY = {
    # ── Existing entries (unchanged) ─────────────────────────────────────────
    "paytm@paytm":              {"registered_name": "Paytm Payments Bank",  "mismatch": False},
    "sbi.official@sbi":         {"registered_name": "Ravi Kumar",            "mismatch": True},
    "support@hdfcbank":         {"registered_name": "HDFC Customer Care",    "mismatch": False},
    "customer-care@icici":      {"registered_name": "Amit Singh",            "mismatch": True},
    "amazon-pay@apl":           {"registered_name": "Amazon Pay India",      "mismatch": False},
    "flipkart.rewards@ybl":     {"registered_name": "Sneha Patil",           "mismatch": True},
    "googlepay@okhdfcbank":     {"registered_name": "Google India Digital",  "mismatch": False},
    "jio.recharge@jio":         {"registered_name": "Reliance Jio",          "mismatch": False},
    "airtel.kyc@airtel":        {"registered_name": "Vikram Sharma",         "mismatch": True},
    "phonepe.cashback@ybl":     {"registered_name": "Priya Das",             "mismatch": True},
    # ── Aggregator-routed entries (SEC-7) ─────────────────────────────────────
    "merchant123@razorpay":     {"registered_name": "Razorpay Software Pvt", "mismatch": False},
    "shop.krishna@cashfree":    {"registered_name": "Cashfree Payments",     "mismatch": False},
    "boutique.ananya@payu":     {"registered_name": "PayU India",            "mismatch": False},
    "kirana.store@easebuzz":    {"registered_name": "Easebuzz Pvt Ltd",      "mismatch": False},
    "travels.arjun@instamojo":  {"registered_name": "Instamojo Technologies","mismatch": False},
}


def _matches_known_provider(provider: str, known_list: list[str]) -> bool:
    """
    Exact-match or dot-suffix-match a VPA provider string against a known list.

    Never uses substring containment ('agg in provider') — that allowed strings
    like 'fakeatomcorp' to match 'atom' and 'notarazorpayclone' to match
    'razorpay'. A provider is considered a match only if it IS one of the known
    strings exactly, or ends with '.' + known (covering legitimate bank-issued
    sub-provider handles like 'sub.razorpay' without matching unrelated strings
    that merely happen to contain the substring).

    Never raises.
    """
    try:
        provider = provider.lower().strip()
        for known in known_list:
            known = known.lower().strip()
            if provider == known or provider.endswith("." + known):
                return True
        return False
    except Exception:
        return False


def verify_vpa(vpa: str) -> dict:
    """
    Verify a UPI VPA against the mock registry and classify the routing context.

    Returns a dict with keys:
      claimed_name, registered_name, mismatch, vpa,
      is_aggregator_routed, is_personal_vpa, mismatch_note.

    Aggregator routing (is_aggregator_routed=True) unconditionally sets mismatch=False.
    Personal VPAs (is_personal_vpa=True) also set mismatch=False.
    Registry-confirmed mismatches are preserved unless overridden by the above.
    Never raises.
    """
    if not vpa or "@" not in vpa:
        return {
            "claimed_name":       "",
            "registered_name":    "Unknown",
            "mismatch":           False,
            "vpa":                vpa if vpa else "",
            "is_aggregator_routed": False,
            "is_personal_vpa":    False,
            "mismatch_note":      "Not in registry — insufficient data",
        }

    vpa_lower  = vpa.lower().strip()
    localpart  = vpa_lower.split("@")[0]
    provider   = vpa_lower.split("@")[-1]

    # Derive human-readable claimed name from the local part
    claimed_name = localpart.replace(".", " ").replace("-", " ").replace("_", " ").title()

    # ── Routing classification ─────────────────────────────────────────────
    is_aggregator_routed = _matches_known_provider(provider, KNOWN_AGGREGATORS)
    is_personal_provider = _matches_known_provider(provider, INDIVIDUAL_PROVIDER_PATTERNS)

    # ── Registry lookup ───────────────────────────────────────────────────
    if vpa_lower in MOCK_VPA_REGISTRY:
        record          = MOCK_VPA_REGISTRY[vpa_lower]
        registered_name = record["registered_name"]
        raw_mismatch    = record["mismatch"]
    else:
        registered_name = "Unknown"
        raw_mismatch    = False

    # ── Mismatch resolution (priority: aggregator > personal > registry) ──
    if is_aggregator_routed:
        mismatch      = False
        mismatch_note = "Routed via payment aggregator — mismatch expected"
    elif is_personal_provider:
        mismatch      = False
        mismatch_note = "Personal UPI — name match not verifiable"
    elif registered_name == "Unknown":
        mismatch      = False
        mismatch_note = "Not in registry — insufficient data"
    elif raw_mismatch:
        mismatch      = True
        mismatch_note = "Identity mismatch — verify merchant manually"
    else:
        mismatch      = False
        mismatch_note = "Not in registry — insufficient data"

    logger.debug(
        "Verified VPA identity",
        extra={
            "vpa":                vpa_lower,
            "mismatch":           mismatch,
            "is_aggregator":      is_aggregator_routed,
            "is_personal":        is_personal_provider,
        },
    )

    return {
        "claimed_name":         sanitize_osint_field(claimed_name,    "vpa.claimed_name"),
        "registered_name":      sanitize_osint_field(registered_name, "vpa.registered_name"),
        "mismatch":             mismatch,           # boolean — not sanitized
        "vpa":                  vpa_lower,          # kept intact for downstream analysis
        "is_aggregator_routed": is_aggregator_routed,
        "is_personal_vpa":      is_personal_provider,
        "mismatch_note":        mismatch_note,
    }
