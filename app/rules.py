import re
from urllib.parse import urlparse

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "is.gd",
    "cutt.ly",
}

SUSPICIOUS_TLDS = {"ru", "tk", "xyz", "top", "click", "work"}

URGENCY_PATTERNS = [
    "urgent",
    "immediately",
    "verify",
    "account suspended",
    "action required",
    "password reset",
    "security alert",
]


def _domain_from_email(address: str) -> str:
    if "@" not in address:
        return ""
    return address.split("@", 1)[1].strip().lower()


def _domain_from_url(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").split(":")[0].lower()
    except ValueError:
        return ""


def analyze_phishing_risk(parsed: dict, ml_result: dict | None = None) -> dict:
    score = 0
    reasons: list[dict] = []

    def add(points: int, rule: str, detail: str) -> None:
        nonlocal score
        score += points
        reasons.append({"rule": rule, "points": points, "detail": detail})

    subject = (parsed.get("subject") or "").lower()
    body_preview = (parsed.get("body_preview") or "").lower()
    headers = parsed.get("headers") or {}
    urls = parsed.get("urls") or []

    if len(urls) >= 3:
        add(20, "many_urls", f"Email contains {len(urls)} URLs")

    shortener_hits = []
    for url in urls:
        domain = _domain_from_url(url)
        if domain in SHORTENER_DOMAINS:
            shortener_hits.append(domain)
    if shortener_hits:
        uniq = sorted(set(shortener_hits))
        add(25, "shortened_url", f"Shortened URL domains detected: {', '.join(uniq)}")

    urgency_hits = [kw for kw in URGENCY_PATTERNS if kw in subject or kw in body_preview]
    if urgency_hits:
        add(20, "urgency_language", f"Urgency phrases detected: {', '.join(urgency_hits[:4])}")

    sender_domain = _domain_from_email(parsed.get("from") or "")
    if sender_domain and "." in sender_domain:
        tld = sender_domain.rsplit(".", 1)[1]
        if tld in SUSPICIOUS_TLDS:
            add(20, "suspicious_sender_tld", f"Sender TLD '.{tld}' is high-risk")

    reply_to = (headers.get("Reply-To") or "").strip()
    if reply_to:
        reply_domain = _domain_from_email(reply_to)
        if reply_domain and sender_domain and reply_domain != sender_domain:
            add(25, "reply_to_mismatch", "Reply-To domain differs from sender domain")

    auth_results = (headers.get("Authentication-Results") or "").lower()
    for mech in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{mech}=fail\b", auth_results):
            add(15, f"{mech}_fail", f"Authentication failure: {mech}=fail")

    if ml_result and ml_result.get("enabled"):
        pct = ml_result.get("phishing_percent", 0)
        if pct >= 50:
            add(25, "ml_phishing_prediction", f"ML Classifier predicted phishing ({pct}% probability)")

    capped = min(score, 100)
    if capped >= 70:
        level = "high"
    elif capped >= 40:
        level = "medium"
    else:
        level = "low"

    res = {
        "risk_score": capped,
        "risk_level": level,
        "rule_count": len(reasons),
        "reasons": reasons,
    }
    if ml_result:
        res["ml"] = ml_result
    return res
