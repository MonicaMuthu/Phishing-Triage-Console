from app import main


def test_health_reports_ollama_integration(monkeypatch) -> None:
    monkeypatch.setattr(main, "is_ollama_available", lambda: True)

    result = main.health()

    assert result["status"] == "ok"
    assert result["phase"] == 7
    assert result["integrations"]["ollama_available"] is True