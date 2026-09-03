from app.rules import analyze_phishing_risk


def test_rules_score_multiple_phishing_indicators() -> None:
    parsed = {
        "subject": "URGENT: verify your account",
        "from": "notice@billing.xyz",
        "body_preview": "Your account suspended. Act immediately.",
        "urls": ["https://bit.ly/login"],
        "headers": {
            "Reply-To": "attacker@evil.example",
            "Authentication-Results": "spf=fail dkim=fail dmarc=fail",
        },
    }

    analysis = analyze_phishing_risk(parsed)
    rules = {reason["rule"] for reason in analysis["reasons"]}

    assert analysis["risk_score"] == 100
    assert analysis["risk_level"] == "high"
    assert {"shortened_url", "urgency_language", "suspicious_sender_tld"} <= rules
    assert {"reply_to_mismatch", "spf_fail", "dkim_fail", "dmarc_fail"} <= rules


def test_rules_add_ml_points_only_for_phishing_prediction() -> None:
    parsed = {"subject": "Monthly newsletter", "from": "news@example.com", "body_preview": "Hello", "urls": [], "headers": {}}

    phishing_analysis = analyze_phishing_risk(
        parsed,
        ml_result={"enabled": True, "phishing_percent": 72, "prediction": "phishing"},
    )
    ham_analysis = analyze_phishing_risk(
        parsed,
        ml_result={"enabled": True, "phishing_percent": 18, "prediction": "ham"},
    )

    assert phishing_analysis["risk_score"] == 25
    assert phishing_analysis["reasons"][0]["rule"] == "ml_phishing_prediction"
    assert phishing_analysis["ml"]["prediction"] == "phishing"
    assert ham_analysis["risk_score"] == 0
    assert ham_analysis["reasons"] == []