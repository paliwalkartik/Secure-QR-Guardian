# AGENTS.md — Secure QR Guardian (Updated for Security Patches)
# Paste this at the top of EVERY coding session before any phase or security patch prompt.

## Project Identity
Name: Secure QR Guardian
Purpose: AI-powered QR code fraud detection, OSINT traceback, and forensic reporting for India's UPI ecosystem.
Stack: Python 3.11, Streamlit, Groq API (llama-3.3-70b-versatile), Firebase, sklearn, FPDF, Playwright, OpenCV, pyzbar
Status: Phase 11 complete (43 tests passing). Security patches in progress.

---

## Security Context (SEC Patches Applied)
After Phase 11, the following security hardening is in place or being implemented:
- All QR payloads and OSINT fields are sanitized for prompt injection before LLM processing
- LLM responses are schema-validated; hallucinations trigger safe fallback verdicts
- URL tracing uses multi-agent approach to detect conditional redirects (cloaking attacks)
- Punycode domains are decoded and normalized; homograph attacks auto-flagged
- Dynamic formula weights shift based on attack signal patterns (not static)
- VPA verification no longer false-flags payment aggregator routing
- Firebase blacklist has local cache (5-min TTL) + audit logging
- Feature vector expanded to 10 features (added cloaking + punycode signals)

---

## Absolute Rules (never break these)

1. One class or one group of related functions per file. Never two unrelated classes in one file.
2. Every function returns a typed dict or a Pydantic model. Never return raw strings or None silently.
3. Every function that can fail must catch its own exception and return an empty dict `{}` or a safe default. Never let exceptions bubble up to the UI layer.
4. All network calls (WHOIS, IP lookup, URL tracing) happen only inside `core/osint/`. No other module touches the network except `core/forensics/screenshot_capture.py`.
5. All OSINT calls must go through `utils/cache.py` before hitting the network. Same domain is never looked up twice in one session.
6. The LLM (llama-3.3-70b-versatile via Groq) is always the last analytical step. It receives sanitized OSINT + risk score as input. It never drives the pipeline.
7. Streamlit pages in `pages/` are views only. They read from `st.session_state`. They never import from `core/` directly except through a single orchestrator call.
8. All constants, thresholds, and API keys come from `config/settings.py`. No hardcoded numbers anywhere else.
9. `utils/logger.py` is the only logger. No `print()` statements anywhere in production code.
10. Every file starts with a module docstring describing what it does and what it does NOT do.
11. **NEW — All string fields extracted from OSINT sources must pass through sanitization before entering prompts.**
12. **NEW — All LLM responses must be validated against the response schema before use.**
13. **NEW — Injection-like strings in data fields are security events and must be logged at WARNING level.**

---

## Data Flow (read before every session)

```
QR Input (image / camera / file)
        │
        ▼
[core/scanner] → SanitizedPayload (Pydantic)
        │
        ▼
[core/osint] → osint_bundle (dict with sanitized string fields)
        │
        ▼
[core/blacklist] → adds is_blacklisted: bool to osint_bundle
        │
        ▼
[core/risk] → RiskResult (risk_score, confidence_interval, threat_level)
        │
        ├→ [core/risk/feature_extractor] → 10-feature numpy array
        │
        ├→ [core/risk/formula] → dynamic weights + risk calculation
        │
        └→ [core/risk/classifier] → ML model prediction
        │
        ▼
[core/reasoning] → LLMVerdict (SANITIZED prompt input → VALIDATED response output)
        │
        ├→ [core/reasoning/injection_guard] → detects injection strings
        │
        ├→ [core/reasoning/llm_engine] → calls Groq API
        │
        ├→ [core/reasoning/response_validator] → schema validation
        │
        ├→ [core/reasoning/self_critique] → adversarial second pass
        │
        └→ [core/reasoning/confidence] → weighted average of 3 scores
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

### osint_bundle (UPDATED FOR SEC PATCHES)
```python
{
  "url_trail": {
    "hops": ["https://bit.ly/xxx", "https://evil.com/pay"],
    "final_url": "https://evil.com/pay",
    "final_ip": "192.168.1.1",
    "cloaking_detected": False,                    # NEW — SEC-4 (multi-agent detection)
    "alternate_destinations": [],                  # NEW — SEC-4 (if cloaking: list of URLs seen)
    "agent_results": {                             # NEW — SEC-4 (per-agent final URLs)
      "desktop": "https://evil.com/pay",
      "mobile": "https://evil.com/pay",
      "bot": "https://evil.com/pay"
    },
    "injection_in_url": False                      # NEW — SEC-3 (injection in URL params/path)
  },
  "domain_forensics": {
    "creation_date": "2024-12-01",                # Sanitized by SEC-3
    "registrar": "GoDaddy",                        # Sanitized by SEC-3
    "country": "IN",
    "ssl_issued_on": "2025-01-15",                # Sanitized by SEC-3
    "ssl_issuer": "Let's Encrypt",                # Sanitized by SEC-3
    "ssl_days_valid": 90
  },
  "ip_analysis": {
    "country": "Russia",                           # Sanitized by SEC-3
    "city": "Moscow",                              # Sanitized by SEC-3
    "org": "Hosting XYZ",                          # Sanitized by SEC-3
    "isp": "Provider ABC",                         # Sanitized by SEC-3
    "asn": "AS12345",
    "asn_name": "BulletproofHost",                # Sanitized by SEC-3
    "is_known_bulletproof": True
  },
  "typosquat": {
    "is_typosquat": True,
    "closest_legit": "phonepe.com",
    "distance": 1,
    "match": "phonep3.com",
    "punycode_detected": False,                    # NEW — SEC-5 (homograph: xn-- domains)
    "normalized_domain": "phonep3.com"             # NEW — SEC-5 (decoded from Punycode if present)
  },
  "vpa": {
    "claimed_name": "PhonePe Support",            # Sanitized by SEC-3
    "registered_name": "Ravi Kumar",              # Sanitized by SEC-3
    "mismatch": False,
    "is_aggregator_routed": False,                # NEW — SEC-7 (Razorpay, Cashfree, PayU, etc.)
    "is_personal_vpa": False,                     # NEW — SEC-7 (ybl, ibl, individual providers)
    "mismatch_note": "Identity verified"          # NEW — SEC-7 (explanation for mismatch decision)
  },
  "is_blacklisted": False
}
```

### RiskResult (Pydantic)
```python
{
  "risk_score": 78,
  "confidence_interval": 6,
  "threat_level": "HIGH",                # SAFE | LOW | MEDIUM | HIGH | CRITICAL
  "score_source": "classifier",          # "classifier" | "formula"
  "weights_used": {                      # NEW — SEC-6 (dynamic weights)
    "mismatch": 0.6,
    "domain_age": 0.3,
    "blacklist": 0.1
  },
  "weight_reason": "default"             # NEW — SEC-6 (which condition triggered weight shift)
}
```

### LLMVerdict (Pydantic)
```python
{
  "risk_score": 82,
  "threat_level": "HIGH",
  "reasoning_summary": "Domain registered 3 days ago, shows phishing patterns...",
  "matched_archetype": "FRESH_PHISH",    # or "INJECTION_ATTEMPT" (NEW — SEC-1)
  "critique_summary": "Could be a new legitimate merchant...",
  "revised_confidence": 74,
  "llm_fallback": False                  # NEW — SEC-2 (True if LLM failed validation)
}
```

---

## Feature Vector (10 features after SEC patches)
```
Index  Name                    Source                      Type      Range
────────────────────────────────────────────────────────────────────────
0      domain_age_days         domain_forensics            float     0-3650
1      redirect_count          url_trail.hops length       int       0-10+
2      is_typosquat            typosquat.is_typosquat      int       0 or 1
3      is_known_bulletproof    ip_analysis                 int       0 or 1
4      ssl_age_days            domain_forensics            float     0-3650
5      vpa_mismatch            vpa.mismatch                int       0 or 1
6      is_blacklisted          root level                  int       0 or 1
7      typosquat_distance      typosquat.distance          int       0-10+
8      cloaking_detected       url_trail (SEC-4)           int       0 or 1 (NEW)
9      punycode_detected       typosquat (SEC-5)           int       0 or 1 (NEW)
```

Feature extraction: `np.array([f0, f1, ..., f9], dtype=float)`
Features 8-9 are binary (0.0 or 1.0).

---

## Folder Reference (Updated)
```
secure_qr_guardian/
│
├── app.py                            # Streamlit entry point
├── .env                              # Secrets (never commit)
├── requirements.txt
├── README.md
│
├── config/
│   ├── settings.py                   # All constants, API keys
│   ├── archetypes.json               # 6 archetypes (added INJECTION_ATTEMPT)
│   ├── trusted_domains.json          # 40+ Indian banking domains
│   └── nist_map.json                 # NIST CSF function mapping
│
├── core/
│   ├── scanner/
│   │   ├── qr_scanner.py
│   │   ├── payload_models.py
│   │   └── sanitizer.py
│   │
│   ├── osint/
│   │   ├── url_tracer.py             # UPDATED — multi-agent, cloaking detection
│   │   ├── domain_forensics.py       # UPDATED — string sanitization
│   │   ├── ip_analyzer.py            # UPDATED — string sanitization
│   │   ├── vpa_verifier.py           # UPDATED — aggregator whitelist
│   │   └── typosquat_detector.py     # UPDATED — Punycode normalization
│   │
│   ├── reasoning/
│   │   ├── injection_guard.py        # NEW — SEC-1 (prompt injection defense)
│   │   ├── response_validator.py     # NEW — SEC-2 (LLM hallucination detection)
│   │   ├── llm_engine.py             # UPDATED — uses validators + guards
│   │   ├── prompt_builder.py         # UPDATED — sanitizes input before prompt
│   │   ├── archetype_classifier.py
│   │   └── confidence.py
│   │
│   ├── risk/
│   │   ├── feature_extractor.py      # UPDATED — 10 features (was 8)
│   │   ├── classifier.py             # UPDATED — retrained on 10 features
│   │   ├── formula.py                # UPDATED — dynamic weights (SEC-6)
│   │   └── models/
│   │       └── risk_classifier.pkl   # Retrained after SEC-4 and SEC-5
│   │
│   ├── forensics/
│   │   ├── report_generator.py       # UPDATED — fixed Unicode em-dash
│   │   ├── network_mapper.py
│   │   ├── payload_analyzer.py
│   │   └── screenshot_capture.py
│   │
│   └── blacklist/
│       ├── firebase_client.py        # UPDATED — local cache, audit log (SEC-8)
│       ├── consensus_engine.py       # UPDATED — rate limiting
│       └── privacy_layer.py
│
├── simulator/
│   ├── scenario_loader.py
│   └── scenarios/
│       ├── fresh_phish.json
│       ├── typosquatting.json
│       ├── upi_mismatch.json
│       ├── redirect_chain.json
│       └── lookalike_domain.json
│
├── dashboard/
│   ├── stats_aggregator.py           # UPDATED — uses local blacklist cache
│   └── visualizations.py
│
├── compliance/
│   └── nist_mapper.py
│
├── pages/
│   ├── 01_scanner.py
│   ├── 02_forensics.py
│   ├── 03_simulator.py
│   ├── 04_dashboard.py
│   └── 05_report.py
│
├── utils/
│   ├── logger.py                     # Structured JSON logging
│   ├── cache.py                      # TTL-based cache for OSINT
│   └── validators.py                 # URL, UPI, IP validation
│
├── tests/
│   ├── unit/
│   │   ├── test_scanner.py
│   │   ├── test_osint.py
│   │   ├── test_risk.py
│   │   ├── test_reasoning.py
│   │   ├── test_blacklist.py
│   │   └── test_forensics.py
│   ├── integration/
│   │   └── test_full_pipeline.py
│   ├── fixtures/
│   │   ├── test_qr.png
│   │   └── mock_responses.json
│   └── verify_*.py                   # Phase verification scripts
│
└── data/
    ├── training/
    │   ├── train.py                  # Retrained after SEC-4 and SEC-5
    │   └── training_data.csv
    └── synthetic/
        └── test_scenarios.csv
```

---

## Archetypes (6 total, added INJECTION_ATTEMPT)

Archetype IDs:
- `FRESH_PHISH` — domain < 7 days old
- `TYPOSQUATTER` — domain within edit distance 2 of trusted brand
- `VPA_IMPOSTOR` — VPA name claims bank but owner is different person
- `REDIRECT_CHAIN` — 3+ redirects before final destination
- `LOOKALIKE_DOMAIN` — subdomains, hyphens mimicking legitimate domains
- `INJECTION_ATTEMPT` — QR payload or OSINT contains instruction-like language (NEW — SEC-1)

---

## Groq Model Configuration
```
GROQ_API_KEY=your_key_here
GROQ_MODEL_NAME=llama-3.3-70b-versatile
LLM_MAX_TOKENS=1000
Temperature: 0.1 (low for consistency)
```

**Note:** DeepSeek-R1 was swapped to Llama due to API key tier restrictions. Llama-3.3-70b-versatile is a strong reasoning model and runs fast on Groq.

---

## Environment Setup Checklist

Before every new session:
- [ ] `.env` file has real GROQ_API_KEY, FIREBASE_CREDENTIALS_PATH, IP_API_KEY
- [ ] `core/risk/models/risk_classifier.pkl` exists (trained model)
- [ ] `config/archetypes.json` has 6 archetypes (including INJECTION_ATTEMPT)
- [ ] `config/trusted_domains.json` has 40+ domains
- [ ] All OSINT modules are importable without network calls
- [ ] Logger is initialized at module top level: `logger = get_logger(__name__)`
- [ ] No hardcoded API keys anywhere except in `.env`

---

## Testing Commands

```bash
# Run all unit + integration tests
python -m pytest tests/unit/ tests/integration/ -v

# Run SEC patch verifications (after each patch)
python -c "from core.reasoning.injection_guard import sanitize_payload_for_prompt; print('SEC-1 OK')"
python -c "from core.reasoning.response_validator import validate_llm_response; print('SEC-2 OK')"
python -c "from core.osint.url_tracer import detect_injection_in_url; print('SEC-3 OK')"
python -c "from core.risk.feature_extractor import FEATURE_NAMES; assert len(FEATURE_NAMES)==10; print('SEC-4/5 OK')"
python -c "from core.risk.formula import calculate_risk; print('SEC-6 OK')"
python -c "from core.osint.vpa_verifier import verify_vpa; print('SEC-7 OK')"
python -c "from core.blacklist.firebase_client import get_blacklist_stats; print('SEC-8 OK')"

# Retrain classifier (after SEC-4 and SEC-5)
python data/training/train.py

# Run Streamlit app
python -m streamlit run app.py
```

---

## Key Differences from Phase 11

| Aspect | Phase 11 | Post-SEC |
|--------|----------|----------|
| Features | 8 | 10 |
| Archetypes | 5 | 6 |
| LLM Input | Raw OSINT | Sanitized OSINT |
| LLM Output | Trusted | Schema-validated |
| URL Tracing | Single agent | 3 agents (detect cloaking) |
| Domain Normalization | ASCII only | Punycode-aware |
| Formula Weights | Static (0.6, 0.3, 0.1) | Dynamic (shifts by signal) |
| VPA Mismatch | All marked as mismatch | Aggregators/personal exempt |
| Blacklist | Firebase only | Firebase + 5-min local cache |
| Audit Trail | None | All writes logged |

---

## Security Mindset

Every module is asking: "What if this input is malicious?"

- Scanner: What if the QR payload is an injection attempt?
- OSINT: What if WHOIS data contains malicious instructions?
- Risk: What if the formula can be gamed by age or by noise?
- LLM: What if the model hallucinates a safe verdict?
- Blacklist: What if an attacker poisons it or the database fails?

Test against adversarial inputs, not just happy paths.

---

*Secure QR Guardian | AGENTS.md (Updated for Security Patches) | Ready for SEC-1*
