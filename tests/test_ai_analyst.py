from app import ai_analyst


def test_ai_analyst_returns_unavailable_result_when_ollama_is_offline(monkeypatch) -> None:
    def raise_connection_error(*args, **kwargs):
        raise ai_analyst.requests.ConnectionError()

    monkeypatch.setattr(ai_analyst.requests, "post", raise_connection_error)

    result = ai_analyst.analyze_with_ai({}, {})

    assert result["enabled"] is False
    assert result["verdict"] == "unavailable"


def test_ai_analyst_normalizes_a_valid_ollama_response(monkeypatch) -> None:
    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "message": {
                    "content": '{"verdict":"phishing","confidence":91,"summary":"Credential lure.","recommended_action":"quarantine","evidence":["SPF failed"]}'
                }
            }

    monkeypatch.setattr(ai_analyst.requests, "post", lambda *args, **kwargs: FakeResponse())

    result = ai_analyst.analyze_with_ai({"subject": "Verify now"}, {})

    assert result["enabled"] is True
    assert result["verdict"] == "phishing"
    assert result["confidence"] == 91
    assert result["recommended_action"] == "quarantine"

def test_ai_analysis_maps_a_phishing_verdict_to_high_risk() -> None:
    analysis = ai_analyst.build_ai_analysis(
        {
            "enabled": True,
            "verdict": "phishing",
            "confidence": 91,
            "summary": "Credential lure.",
            "recommended_action": "quarantine",
            "evidence": ["SPF failed"],
        }
    )

    assert analysis["risk_score"] == 85
    assert analysis["risk_level"] == "high"
    assert analysis["ai"]["recommended_action"] == "quarantine"