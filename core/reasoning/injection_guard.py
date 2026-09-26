"""
Prompt injection guard. Sanitizes all data before it enters LLM prompts.
Must be called in prompt_builder.py before any string is inserted into a prompt.
Never pass raw QR payload or unsanitized OSINT fields to the LLM.
"""

import copy
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Full list — used only for raw QR PAYLOAD text, which is genuinely adversarial
# input with no legitimate-business-name false-positive risk.
PAYLOAD_INJECTION_TRIGGERS: list[str] = [
    "ignore previous", "ignore all", "disregard", "forget instructions",
    "new instruction", "system:", "assistant:", "you are now", "override",
    "jailbreak", "act as", "pretend", "simulate", "your new role",
    "do not flag", "mark as safe", "output 0", "risk_score: 0",
]

# Reduced list — used for OSINT metadata fields (registrar names, ASN org names,
# etc.) which are legitimate-but-externally-supplied strings. Only multi-word
# phrases with essentially zero legitimate-business-name overlap are kept here,
# to avoid redacting real evidence.
OSINT_INJECTION_TRIGGERS: list[str] = [
    "ignore previous", "ignore all", "forget instructions", "new instruction",
    "system:", "assistant:", "you are now", "jailbreak", "your new role",
    "do not flag", "mark as safe", "output 0", "risk_score: 0",
]

# Backward-compat alias — existing imports of INJECTION_TRIGGERS elsewhere
# (e.g. core/osint/url_tracer.py's detect_injection_in_url) keep working
# unchanged, using the full/stricter payload list.
INJECTION_TRIGGERS = PAYLOAD_INJECTION_TRIGGERS

OSINT_MAX_FIELD_LENGTH: int = 120


# ---------------------------------------------------------------------------
# Function 1 — Payload sanitizer
# ---------------------------------------------------------------------------

def sanitize_payload_for_prompt(raw: str) -> str:
    """
    Sanitize a raw QR payload string before inserting it into an LLM prompt.

    Returns '[REDACTED-INJECTION-ATTEMPT]' if any injection trigger is found.
    Returns the original string (truncated to 200 chars) if clean.
    Never raises.
    """
    try:
        lowered = raw.lower()
        for trigger in INJECTION_TRIGGERS:
            if trigger in lowered:
                logger.warning(
                    "Prompt injection detected in QR payload",
                    extra={"trigger_found": trigger, "field": "payload"},
                )
                return "[REDACTED-INJECTION-ATTEMPT]"

        clean = raw[:200]
        logger.debug(
            "Payload sanitized — clean",
            extra={"field": "payload", "truncated_len": len(clean)},
        )
        return clean

    except Exception as exc:
        logger.warning(
            "sanitize_payload_for_prompt encountered an unexpected error; redacting.",
            extra={"error": str(exc), "field": "payload"},
        )
        return "[REDACTED-INJECTION-ATTEMPT]"


# ---------------------------------------------------------------------------
# Function 2 — Single OSINT field sanitizer
# ---------------------------------------------------------------------------

def sanitize_osint_field(value: str, field_name: str) -> str:
    """
    Sanitize a single OSINT string field before it enters an LLM prompt.

    Returns '[FLAGGED]' if an injection trigger is detected.
    Returns the truncated original if clean.
    Returns '' for non-string inputs.
    Never raises.
    """
    try:
        if not isinstance(value, str):
            logger.debug(
                "OSINT field is not a string; returning empty string",
                extra={"field": field_name, "type": type(value).__name__},
            )
            return ""

        truncated = value[:OSINT_MAX_FIELD_LENGTH]
        lowered = truncated.lower()

        for trigger in OSINT_INJECTION_TRIGGERS:
            if trigger in lowered:
                logger.warning(
                    "Prompt injection detected in OSINT field",
                    extra={"trigger_found": trigger, "field": field_name},
                )
                return "[FLAGGED]"

        logger.debug(
            "OSINT field sanitized — clean",
            extra={"field": field_name, "truncated_len": len(truncated)},
        )
        return truncated

    except Exception as exc:
        logger.warning(
            "sanitize_osint_field encountered an unexpected error; flagging.",
            extra={"error": str(exc), "field": field_name},
        )
        return "[FLAGGED]"


# ---------------------------------------------------------------------------
# Function 3 — Recursive OSINT bundle sanitizer
# ---------------------------------------------------------------------------

def sanitize_osint_bundle(bundle: dict) -> dict:
    """
    Recursively walk the OSINT bundle and sanitize every string value.

    Works on a deep copy — never mutates the original bundle.
    Never raises; all exceptions are caught internally.
    """
    try:
        clean_bundle = copy.deepcopy(bundle)
        return _walk_and_sanitize(clean_bundle, parent_key="root")
    except Exception as exc:
        logger.warning(
            "sanitize_osint_bundle encountered an unexpected error; returning empty bundle.",
            extra={"error": str(exc)},
        )
        return {}


def _walk_and_sanitize(node: object, parent_key: str) -> object:
    """
    Internal recursive helper. Operates in-place on a deep-copied node.
    Returns the sanitized node (dict, list, str, or passthrough).
    Never raises.
    """
    try:
        if isinstance(node, dict):
            for key, value in node.items():
                field_path = f"{parent_key}.{key}"
                if isinstance(value, str):
                    node[key] = sanitize_osint_field(value, field_path)
                elif isinstance(value, (dict, list)):
                    node[key] = _walk_and_sanitize(value, field_path)
                # Non-string scalars (int, float, bool, None) pass through unchanged
            return node

        elif isinstance(node, list):
            for idx, item in enumerate(node):
                field_path = f"{parent_key}[{idx}]"
                if isinstance(item, str):
                    node[idx] = sanitize_osint_field(item, field_path)
                elif isinstance(item, (dict, list)):
                    node[idx] = _walk_and_sanitize(item, field_path)
            return node

        # Scalar fallthrough
        return node

    except Exception as exc:
        logger.warning(
            "_walk_and_sanitize encountered an unexpected error at node.",
            extra={"error": str(exc), "parent_key": parent_key},
        )
        return node
