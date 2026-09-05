import json
import os
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=True)

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
VALID_VERDICTS = {"benign", "suspicious", "phishing"}
VALID_ACTIONS = {"allow", "investigate", "quarantine", "escalate"}


def is_ollama_available() -> bool:
    try:
        response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=0.5)
        response.raise_for_status()
        installed_models = {
            str(model.get("name", "")).lower()
            for model in response.json().get("models", [])
        }
        return OLLAMA_MODEL.lower() in installed_models
    except requests.RequestException:
        return False


def _unavailable_result(note: str) -> dict:
    return {
        "enabled": False,
        "verdict": "unavailable",
        "confidence": 0,
        "summary": note,
        "recommended_action": "investigate",
        "evidence": [],
    }


def _build_case_context(parsed: dict, enrichment: dict) -> dict:
    return {
        "sender": parsed.get("from", ""),
        "subject": parsed.get("subject", ""),
        "recipients": parsed.get("to", []),
        "body_preview": parsed.get("body_preview", ""),
        "urls": parsed.get("urls", []),
        "authentication_results": (parsed.get("headers") or {}).get("Authentication-Results", ""),
        "virustotal": (enrichment.get("virustotal") or {}).get("results", []),
        "abuseipdb": (enrichment.get("abuseipdb") or {}).get("results", []),
    }


def _normalize_result(result: dict) -> dict:
    verdict = str(result.get("verdict", "suspicious")).lower()
    action = str(result.get("recommended_action", "investigate")).lower()
    confidence = result.get("confidence", 0)
    evidence = result.get("evidence", [])

    if verdict not in VALID_VERDICTS:
        verdict = "suspicious"
    if action not in VALID_ACTIONS:
        action = "investigate"
    try:
        confidence = max(0, min(100, int(confidence)))
    except (TypeError, ValueError):
        confidence = 0

    return {
        "enabled": True,
        "verdict": verdict,
        "confidence": confidence,
        "summary": str(result.get("summary", "No analyst summary returned.")),
        "recommended_action": action,
        "evidence": [str(item) for item in evidence[:5]] if isinstance(evidence, list) else [],
    }


def analyze_with_ai(parsed: dict, enrichment: dict) -> dict:
    context = _build_case_context(parsed, enrichment)
    prompt = (
        "You are an L1 SOC analyst reviewing one email. Use only the supplied case data. "
        "Do not claim evidence that is absent. Return JSON only with verdict (benign, suspicious, or phishing), "
        "confidence (0-100), summary, recommended_action (allow, investigate, quarantine, or escalate), "
        "and evidence (a list of up to five concise facts).\n\n"
        f"Case data:\n{json.dumps(context, ensure_ascii=True)}"
    )
    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "stream": False,
                "format": "json",
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=45,
        )
        response.raise_for_status()
        content = response.json().get("message", {}).get("content", "")
        return _normalize_result(json.loads(content))
    except requests.RequestException:
        return _unavailable_result("AI analyst unavailable. Start Ollama and install the configured model.")
    except (TypeError, ValueError, json.JSONDecodeError):
        return _unavailable_result("AI analyst returned an invalid response. Review the Ollama model configuration.")


def build_ai_analysis(ai_result: dict) -> dict:
    verdict = ai_result.get("verdict", "unavailable")
    score_by_verdict = {"benign": 10, "suspicious": 50, "phishing": 85}
    score = score_by_verdict.get(verdict, 0)
    level = "high" if score >= 70 else "medium" if score >= 40 else "low"
    evidence = ai_result.get("evidence", []) if ai_result.get("enabled") else []
    summary = ai_result.get("summary", "")
    reasons = []
    if summary:
        reasons.append({"rule": "ai_summary", "points": 0, "detail": summary})
    reasons.extend(
        {"rule": "ai_evidence", "points": 0, "detail": item}
        for item in evidence
    )

    return {
        "risk_score": score,
        "risk_level": level,
        "rule_count": len(reasons),
        "reasons": reasons,
        "ai": ai_result,
    }