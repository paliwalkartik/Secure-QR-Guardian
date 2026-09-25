"""
Simulator module. Runs pre-defined scam scenarios without any live network calls.
Used for Red-Team testing and system validation.
"""

import os
import json
from typing import List, Dict, Any
from pydantic import BaseModel

from core.scanner.payload_models import SanitizedPayload, DataType
from core.risk.feature_extractor import extract_features
from core.risk.classifier import risk_classifier
from core.reasoning.prompt_builder import build_system_prompt, build_user_prompt
from core.reasoning.llm_engine import call_llm
from core.reasoning.confidence import calculate_final_confidence

class ScenarioVerdict(BaseModel):
    threat_level: str
    matched_archetype: str

class MockPayload(BaseModel):
    raw_data: str
    data_type: str

class SimulatorScenario(BaseModel):
    id: str
    name: str
    description: str
    mock_payload: MockPayload
    mock_osint: Dict[str, Any]
    expected_verdict: ScenarioVerdict


def _get_scenarios_dir() -> str:
    return os.path.join(os.path.dirname(__file__), 'scenarios')


def load_scenario(scenario_id: str) -> SimulatorScenario:
    scenarios_dir = _get_scenarios_dir()
    file_path = os.path.join(scenarios_dir, f"{scenario_id}.json")
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Scenario file '{scenario_id}.json' not found in {scenarios_dir}")
        
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    return SimulatorScenario(**data)


def list_scenarios() -> List[Dict[str, str]]:
    scenarios_dir = _get_scenarios_dir()
    if not os.path.exists(scenarios_dir):
        return []
        
    scenarios = []
    for filename in os.listdir(scenarios_dir):
        if filename.endswith(".json"):
            scenario_id = filename[:-5]
            try:
                # Load to strictly validate and extract metadata
                scenario = load_scenario(scenario_id)
                scenarios.append({
                    "id": scenario.id,
                    "filename": filename[:-5],   # stem of the .json file
                    "name": scenario.name,
                    "description": scenario.description
                })
            except Exception:
                continue
                
    # Sort alphabetically by ID
    return sorted(scenarios, key=lambda x: x["id"])


def run_scenario(scenario: SimulatorScenario) -> dict:
    # 1. Map string to enum and build SanitizedPayload bypassing QRScanner
    payload = SanitizedPayload(
        raw_data=scenario.mock_payload.raw_data,
        data_type=DataType(scenario.mock_payload.data_type.upper()),
        input_source="simulator"
    )
    
    # 2. Extract features exactly as the production pipeline would
    features = extract_features(scenario.mock_osint)
    
    # 3. Predict via ML / formula
    risk_result = risk_classifier.predict(features)
    
    # 4. Synthesize prompts and execute LLM reasoning
    sys_prompt = build_system_prompt()
    user_prompt = build_user_prompt(payload, scenario.mock_osint, risk_result)
    llm_verdict = call_llm(sys_prompt, user_prompt)
    
    # 5. Mock self-critique (pass-through LLM risk_score as revised confidence for sim)
    # The actual self_critique module involves a second LLM loop, skipped here for speed.
    critique_result = {"revised_confidence": llm_verdict.get("risk_score", 50)}
    
    # 6. Final aggregated confidence resolution
    final_conf = calculate_final_confidence(risk_result, llm_verdict, critique_result)
    
    actual_threat_level = final_conf.get("final_threat_level", "UNKNOWN")
    expected_threat_level = scenario.expected_verdict.threat_level
    
    return {
        "scenario_id": scenario.id,
        "expected_verdict": expected_threat_level,
        "actual_verdict": actual_threat_level,
        "passed": actual_threat_level == expected_threat_level,
        "actual_archetype": llm_verdict.get("matched_archetype", "UNKNOWN"),
        "actual_risk_score": final_conf.get("final_score", 0)
    }
