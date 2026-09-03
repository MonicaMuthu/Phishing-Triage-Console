from app import ml_classifier


def test_classifier_returns_disabled_result_when_model_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(ml_classifier, "get_model", lambda: None)

    result = ml_classifier.predict_phishing_text("Subject", "Body")

    assert result["enabled"] is False
    assert result["prediction"] == "disabled"
    assert result["phishing_percent"] == 0


def test_classifier_classifies_using_model_probability(monkeypatch) -> None:
    class FakeModel:
        def predict_proba(self, texts: list[str]) -> list[list[float]]:
            assert texts == ["Verify your account now"]
            return [[0.18, 0.82]]

    monkeypatch.setattr(ml_classifier, "get_model", lambda: FakeModel())

    result = ml_classifier.predict_phishing_text("Verify", "your account now")

    assert result == {
        "enabled": True,
        "phishing_probability": 0.82,
        "phishing_percent": 82,
        "prediction": "phishing",
    }