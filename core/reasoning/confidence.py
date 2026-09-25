"""
Confidence aggregator. Combines ML classifier, LLM verdict, and self-critique into a final score.
A wide confidence_interval means the three signals disagree — treat result with caution.
"""

def calculate_final_confidence(
    risk_result: dict,
    llm_verdict: dict,
    critique_result: dict
) -> dict:
    
    risk = float(risk_result.get("risk_score", 50))
    llm = float(llm_verdict.get("risk_score", 50))
    critique = float(critique_result.get("revised_confidence", 50))
    
    # Calculate weighted average based on trust distribution
    raw_final = (risk * 0.4) + (llm * 0.4) + (critique * 0.2)
    final_score = int(raw_final)
    
    # Clamp just in case
    final_score = max(0, min(100, final_score))
    
    # The confidence interval is half of the total spread between the models
    scores = [risk, llm, critique]
    max_score = max(scores)
    min_score = min(scores)
    confidence_interval = int(abs(max_score - min_score) // 2)
    
    # Map back to threat level strings
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
        "final_threat_level": final_threat_level
    }
