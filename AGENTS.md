# AGENTS.md — Secure QR Guardian
# Paste this at the top of EVERY coding session before any phase prompt.

## Project Identity
Name: Secure QR Guardian
Purpose: AI-powered QR code fraud detection, OSINT traceback, and forensic reporting for India's UPI ecosystem.
Stack: Python 3.11, Streamlit, Groq API (DeepSeek-R1), Firebase, sklearn, FPDF, Playwright, OpenCV, pyzbar

---

## Absolute Rules (never break these)

1. One class or one group of related functions per file. Never two unrelated classes in one file.
2. Every function returns a typed dict or a Pydantic model. Never return raw strings or None silently.
3. Every function that can fail must catch its own exception and return an empty dict `{}` or a safe default. Never let exceptions bubble up to the UI layer.
4. All network calls (WHOIS, IP lookup, URL tracing) happen only inside `core/osint/`. No other module touches the network except `core/forensics/screenshot_capture.py`.
5. All OSINT calls must go through `utils/cache.py` before hitting the network. Same domain is never looked up twice in one session.
6. The LLM (DeepSeek-R1) is always the last analytical step. It receives OSINT + risk score as input. It never drives the pipeline.
7. Streamlit pages in `pages/` are views only. They read from `st.session_state`. They never import from `core/` directly except through a single orchestrator call.
8. All constants, thresholds, and API keys come from `config/settings.py`. No hardcoded numbers anywhere else.
9. `utils/logger.py` is the only logger. No `print()` statements anywhere in production code.
10. Every file starts with a module docstring describing what it does and what it does NOT do.

---

## Data Flow (read before every session)

```
QR Input (image / camera / file)
        │
        ▼
[core/scanner] → SanitizedPayload (Pydantic)
        │
        ▼
[core/osint] → osint_bundle (dict with keys below)
        │
        ▼
[core/blacklist] → adds is_blacklisted: bool to osint_bundle
        │
        ▼
[core/risk] → RiskResult (risk_score, confidence_interval, threat_level)
        │
        ▼
[core/reasoning] → LLMVerdict (reasoning_summary, matched_archetype, critique_summary, revised_confidence)
        │
        ▼
[compliance/nist_mapper] → adds nist_tags: list[str]
        │
        ▼
[core/forensics] → ForensicPackage (hex_dump, network_map_fig, screenshot_bytes, pdf_bytes)
        │
        ▼
[pages/] → Display only. Read session_state. Render results.
```

---

## Canonical Dict Shapes (use these everywhere)

### osint_bundle
```python
{
  "url_trail": {
    "hops": ["https://bit.ly/xxx", "https://evil.com/pay"],
    "final_url": "https://evil.com/pay",
    "final_ip": "192.168.1.1"
  },
  "domain_forensics": {
    "creation_date": "2024-12-01",
    "registrar": "GoDaddy",
    "country": "IN",
    "ssl_issued_on": "2025-01-15",
    "ssl_issuer": "Let's Encrypt",
    "ssl_days_valid": 90
  },
  "ip_analysis": {
    "country": "Russia",
    "city": "Moscow",
    "org": "Hosting XYZ",
    "asn": "AS12345",
    "asn_name": "BulletproofHost",
    "is_known_bulletproof": True
  },
  "typosquat": {
    "is_typosquat": True,
    "closest_legit": "phonepe.com",
    "distance": 1,
    "match": "phonep3.com"
  },
  "vpa": {
    "claimed_name": "PhonePe Support",
    "registered_name": "Ravi Kumar",
    "mismatch": True
  },
  "is_blacklisted": False
}
```

### RiskResult (Pydantic)
```python
{
  "risk_score": 78,
  "confidence_interval": 6,
  "threat_level": "HIGH",  # SAFE | LOW | MEDIUM | HIGH | CRITICAL
  "score_source": "classifier"  # "classifier" | "formula"
}
```

### LLMVerdict (Pydantic)
```python
{
  "risk_score": 82,
  "threat_level": "HIGH",
  "reasoning_summary": "Domain registered 3 days ago...",
  "matched_archetype": "FRESH_PHISH",
  "critique_summary": "Could be a new legitimate merchant...",
  "revised_confidence": 74
}
```

---

## Folder Reference
```
secure_qr_guardian/
├── app.py
├── config/           settings.py, archetypes.json, trusted_domains.json, nist_map.json
├── core/
│   ├── scanner/      qr_scanner.py, payload_models.py, sanitizer.py
│   ├── osint/        url_tracer.py, domain_forensics.py, ip_analyzer.py, vpa_verifier.py, typosquat_detector.py
│   ├── reasoning/    llm_engine.py, prompt_builder.py, archetype_classifier.py, self_critique.py, confidence.py
│   ├── risk/         feature_extractor.py, classifier.py, formula.py, models/
│   ├── forensics/    report_generator.py, network_mapper.py, payload_analyzer.py, screenshot_capture.py
│   └── blacklist/    firebase_client.py, consensus_engine.py, privacy_layer.py
├── simulator/        scenario_loader.py, scenarios/*.json
├── dashboard/        stats_aggregator.py, visualizations.py
├── compliance/       nist_mapper.py
├── pages/            01_scanner.py ... 05_report.py
├── utils/            logger.py, cache.py, validators.py
└── tests/            unit/, integration/, fixtures/
```
