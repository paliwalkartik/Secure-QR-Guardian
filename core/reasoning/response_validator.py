"""
LLM response validator. Every LLM response passes through here before use.
Invalid verdict responses → safe_fallback_verdict().
Invalid critique responses → safe_fallback_critique().
A hallucination is treated identically to an API failure.
Does NOT make network calls. Does NOT modify the original response dict.
"""

import json
import os
from typing import Any

from pydantic import BaseModel, field_validator, ValidationError

from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants — loaded once, reused on every call
# ---------------------------------------------------------------------------

VALID_THREAT_LEVELS: set[str] = {"SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

# Keywords that almost certainly belong to the system prompt rather than a
# genuine reasoning summary (used for the prompt-echo check).
_SYSTEM_PROMPT_KEYWORDS: frozenset[str] = frozenset({
    "cyber-fraud investigator",
    "threat archetypes",
    "output schema",
    "respond only with valid json",
    "security rule",
    "upi",
    "archetype id",
    "no markdown",
    "no preamble",
})

def _load_valid_archetype_ids() -> set[str]:
    """Load archetype IDs from archetypes.json. Returns empty set on any failure."""
    try:
        archetypes_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "config",
            "archetypes.json",
        )
        with open(archetypes_path, "r", encoding="utf-8") as fh:
            archetypes: list[dict[str, Any]] = json.load(fh)
        ids = {entry["id"] for entry in archetypes if isinstance(entry.get("id"), str)}
        logger.debug("Archetype IDs loaded for validator", extra={"count": len(ids), "ids": list(ids)})
        return ids
    except Exception as exc:
        logger.warning(
            "response_validator: failed to load archetypes.json; archetype check will be permissive.",
            extra={"error": str(exc)},
        )
        return set()


VALID_ARCHETYPE_IDS: set[str] = _load_valid_archetype_ids()


# ---------------------------------------------------------------------------
# Pydantic schema
# ---------------------------------------------------------------------------

class LLMResponseSchema(BaseModel):
    """Strict schema for the main LLM verdict response. Never merge with CritiqueResponseSchema."""

    risk_score: int
    threat_level: str
    reasoning_summary: str
    matched_archetype: str

    @field_validator("risk_score")
    @classmethod
    def score_in_range(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError(f"risk_score {v} is outside [0, 100]")
        return v

    @field_validator("reasoning_summary")
    @classmethod
    def summary_length_ok(cls, v: str) -> str:
        if len(v) < 10:
            raise ValueError("reasoning_summary is too short (< 10 chars)")
        if len(v) > 500:
            raise ValueError("reasoning_summary is too long (> 500 chars)")
        return v


class CritiqueResponseSchema(BaseModel):
    """Schema for the adversarial self-critique response — distinct from the
    main verdict schema. Do not merge these two schemas."""

    critique_summary: str
    revised_confidence: int

    @field_validator("revised_confidence")
    @classmethod
    def confidence_in_range(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError(f"revised_confidence {v} is outside [0, 100]")
        return v

    @field_validator("critique_summary")
    @classmethod
    def summary_not_empty(cls, v: str) -> str:
        if len(v) < 5:
            raise ValueError("critique_summary is too short (< 5 chars)")
        return v


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def validate_llm_response(raw: dict, response_type: str = "verdict") -> tuple[bool, str]:
    """
    Validate a parsed LLM response dict against the schema for the given response_type.

    response_type="critique"  → validates against CritiqueResponseSchema (2 fields)
    response_type="verdict"   → validates against LLMResponseSchema (4-check path, default)

    Checks for response_type="verdict" (in order):
      1. Pydantic structural + range validation (risk_score 0-100, summary length)
      2. threat_level is a known value
      3. matched_archetype is a known archetype ID or "NONE"
      4. reasoning_summary is not an echo of the system prompt

    Returns:
      (True, "")                  — all checks passed
      (False, <reason_string>)    — first failing check, human-readable reason

    Never raises.
    """
    try:
        # --- Critique path: separate schema, separate branch ----------------
        if response_type == "critique":
            try:
                CritiqueResponseSchema(**raw)
                return True, ""
            except ValidationError as exc:
                reason = f"Critique schema validation failed: {exc.errors()[0]['msg']}"
                logger.debug("Critique response schema invalid", extra={"reason": reason})
                return False, reason
            except Exception as exc:
                return False, f"Unexpected error validating critique response: {exc}"
        # --- Verdict path continues below -----------------------------------
        # --- Check 1: Pydantic structural validation -------------------------
        try:
            validated = LLMResponseSchema(**raw)
        except ValidationError as exc:
            reason = f"Schema validation failed: {exc.errors()[0]['msg']}"
            logger.debug("LLM response schema invalid", extra={"reason": reason})
            return False, reason
        except TypeError as exc:
            reason = f"Type error constructing schema: {exc}"
            logger.debug("LLM response type error", extra={"reason": reason})
            return False, reason

        # --- Check 2: threat_level whitelist --------------------------------
        if validated.threat_level not in VALID_THREAT_LEVELS:
            reason = (
                f"Invalid threat_level '{validated.threat_level}'; "
                f"must be one of {sorted(VALID_THREAT_LEVELS)}"
            )
            logger.debug("LLM response invalid threat_level", extra={"reason": reason})
            return False, reason

        # --- Check 3: matched_archetype whitelist ---------------------------
        archetype_ok = (
            validated.matched_archetype == "NONE"
            or validated.matched_archetype in VALID_ARCHETYPE_IDS
            # If archetypes failed to load, VALID_ARCHETYPE_IDS is empty — be permissive
            or len(VALID_ARCHETYPE_IDS) == 0
        )
        if not archetype_ok:
            reason = (
                f"Unknown matched_archetype '{validated.matched_archetype}'; "
                f"valid IDs: {sorted(VALID_ARCHETYPE_IDS)} or 'NONE'"
            )
            logger.debug("LLM response invalid archetype", extra={"reason": reason})
            return False, reason

        # --- Check 4: prompt-echo / hallucination check ---------------------
        summary_lower = validated.reasoning_summary.lower()
        summary_words = set(summary_lower.split())
        keyword_hits = sum(
            1 for kw in _SYSTEM_PROMPT_KEYWORDS
            if kw in summary_lower
        )
        # Flag if more than 50% of system-prompt keywords appear in summary
        hit_ratio = keyword_hits / len(_SYSTEM_PROMPT_KEYWORDS)
        if hit_ratio > 0.50:
            reason = (
                f"reasoning_summary appears to echo the system prompt "
                f"({keyword_hits}/{len(_SYSTEM_PROMPT_KEYWORDS)} system keywords matched; "
                f"ratio={hit_ratio:.0%})"
            )
            logger.debug("LLM response prompt-echo detected", extra={"reason": reason, "hit_ratio": hit_ratio})
            return False, reason

        logger.debug(
            "LLM response passed all validation checks",
            extra={
                "risk_score": validated.risk_score,
                "threat_level": validated.threat_level,
                "matched_archetype": validated.matched_archetype,
            },
        )
        return True, ""

    except Exception as exc:
        reason = f"Unexpected error during LLM response validation: {exc}"
        logger.warning("validate_llm_response raised unexpectedly", extra={"error": str(exc)})
        return False, reason


def safe_fallback_verdict() -> dict:
    """
    Return the canonical neutral verdict used whenever the LLM response is
    invalid, hallucinated, or unavailable.

    The 'llm_fallback: True' key signals to all callers that this is a
    synthetic verdict, not a real LLM judgment.
    """
    return {
        "risk_score": 50,
        "threat_level": "MEDIUM",
        "reasoning_summary": "AI verdict unavailable. Risk based on OSINT signals only.",
        "matched_archetype": "NONE",
        "llm_fallback": True,
    }


def safe_fallback_critique() -> dict:
    """
    Neutral critique fallback used when the critique LLM response is invalid,
    hallucinated, or unavailable. Mirrors safe_fallback_verdict()'s contract
    for the critique response shape.

    The 'llm_fallback: True' key signals to all callers that this is a
    synthetic critique, not a real LLM judgment.
    """
    return {
        "critique_summary": "Critique unavailable",
        "revised_confidence": 50,
        "llm_fallback": True,
    }
