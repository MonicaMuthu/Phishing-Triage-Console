from app import main


def test_health_reports_phase_7_and_ml_integration(monkeypatch) -> None:
    monkeypatch.setattr(main, "is_model_available", lambda: True)

    result = main.health()

    assert result["status"] == "ok"
    assert result["phase"] == 7
    assert isinstance(result["integrations"]["ml_model_loaded"], bool)