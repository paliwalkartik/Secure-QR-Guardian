"""
Confidence aggregator. Combines ML classifier, LLM verdict, and self-critique
into a final score.

When either the main verdict or the self-critique used a safe-fallback (i.e.
the LLM was unavailable or hallucinated — signaled by llm_fallback=True on
either input), the final score is NOT diluted by blending in the neutral
placeholder score. Instead the classifier/formula score is used directly, and
the confidence_interval is widened to signal reduced signal diversity. This
prevents an LLM outage from silently downgrading an accurate high-risk
classifier score toward a false-neutral result.

A wide confidence_interval in normal (non-degraded) mode means the three
signals disagree — treat result with caution either way.
Does NOT make network calls. Does NOT call the LLM.
"""


def calculate_final_confidence(
    risk_result: dict,
    llm_verdict: dict,
    critique_result: dict,
) -> dict:

    risk = float(risk_result.get("risk_score", 50))
    llm = float(llm_verdict.get("risk_score", 50))
    critique = float(critique_result.get("revised_confidence", 50))

    llm_degraded = bool(llm_verdict.get("llm_fallback", False))
    critique_degraded = bool(critique_result.get("llm_fallback", False))
    degraded_mode = llm_degraded or critique_degraded

    if degraded_mode:
        # Do not dilute an accurate classifier/formula score with the neutral
        # placeholder score from a fallback verdict or fallback critique.
        # Use the classifier's own score directly.
        final_score = int(risk)
        # No meaningful spread to measure when one or both AI signals are
        # synthetic placeholders — widen the interval instead to signal
        # reduced signal diversity, floored at 20.
        confidence_interval = max(20, int(risk_result.get("confidence_interval", 15)))
    else:
        raw_final = (risk * 0.4) + (llm * 0.4) + (critique * 0.2)
        final_score = int(raw_final)

        scores = [risk, llm, critique]
        max_score = max(scores)
        min_score = min(scores)
        confidence_interval = int(abs(max_score - min_score) // 2)

    final_score = max(0, min(100, final_score))

    if final_score <= 25:
        final_threat_level = "SAFE"
    elif final_score <= 50:
        final_threat_level = "LOW"
    elif final_score <= 70:
        final_threat_level = "MEDIUM"
    elif final_score <= 85:
        final_threat_level = "HIGH"
    else:
        final_threat_level = "CRITICAL"

    return {
        "final_score": final_score,
        "confidence_interval": confidence_interval,
        "final_threat_level": final_threat_level,
        "degraded_mode": degraded_mode,
    }
