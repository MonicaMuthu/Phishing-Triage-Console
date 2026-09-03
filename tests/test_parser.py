from app.parser import parse_email


def test_parse_email_extracts_addresses_urls_and_headers() -> None:
    raw_email = b"""From: Security Team <alerts@example.com>
To: analyst@example.com, lead@example.com
Subject: Review this message
Authentication-Results: mx.example.com; spf=pass

Please review https://example.com/report and https://example.com/report.
"""

    parsed = parse_email(raw_email)

    assert parsed["subject"] == "Review this message"
    assert parsed["from"] == "alerts@example.com"
    assert parsed["to"] == ["analyst@example.com", "lead@example.com"]
    assert parsed["urls"] == ["https://example.com/report"]
    assert parsed["url_count"] == 1
    assert parsed["headers"]["Authentication-Results"].endswith("spf=pass")