import base64
import ipaddress
import os
import re
from pathlib import Path

import requests
from dotenv import load_dotenv

VT_URL_REPORT = "https://www.virustotal.com/api/v3/urls/{url_id}"
ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"

load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=True)


def _public_ipv4_from_headers(headers: dict) -> list[str]:
    candidates: list[str] = []
    for name in ("Received", "X-Originating-IP", "X-Forwarded-For"):
        value = headers.get(name) or ""
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value)
        for ip_raw in ips:
            try:
                ip_obj = ipaddress.ip_address(ip_raw)
            except ValueError:
                continue
            if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj.is_global:
                candidates.append(ip_raw)
    return sorted(set(candidates))


def _vt_url_id(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return encoded.strip("=")


def _enrich_virustotal(urls: list[str], api_key: str | None) -> dict:
    if not api_key:
        return {
            "enabled": False,
            "note": "Set VIRUSTOTAL_API_KEY to enable VirusTotal checks.",
            "results": [],
        }

    results = []
    for url in urls[:10]:
        item = {"url": url}
        try:
            response = requests.get(
                VT_URL_REPORT.format(url_id=_vt_url_id(url)),
                headers={"x-apikey": api_key},
                timeout=8,
            )

            if response.status_code != 200:
                item["error"] = f"VirusTotal HTTP {response.status_code}"
                results.append(item)
                continue

            data = response.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            item.update(
                {
                    "malicious": int(stats.get("malicious", 0)),
                    "suspicious": int(stats.get("suspicious", 0)),
                    "harmless": int(stats.get("harmless", 0)),
                    "undetected": int(stats.get("undetected", 0)),
                }
            )
        except requests.RequestException as exc:
            item["error"] = f"VirusTotal request failed: {exc}"

        results.append(item)

    return {
        "enabled": True,
        "results": results,
    }


def _enrich_abuseipdb(ips: list[str], api_key: str | None) -> dict:
    if not api_key:
        return {
            "enabled": False,
            "note": "Set ABUSEIPDB_API_KEY to enable AbuseIPDB checks.",
            "results": [],
        }

    results = []
    for ip in ips[:10]:
        item = {"ip": ip}
        try:
            response = requests.get(
                ABUSEIPDB_CHECK,
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": api_key, "Accept": "application/json"},
                timeout=8,
            )

            if response.status_code != 200:
                item["error"] = f"AbuseIPDB HTTP {response.status_code}"
                results.append(item)
                continue

            data = response.json().get("data", {})
            item.update(
                {
                    "abuse_confidence_score": int(data.get("abuseConfidenceScore", 0)),
                    "total_reports": int(data.get("totalReports", 0)),
                    "country_code": data.get("countryCode"),
                    "usage_type": data.get("usageType"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "last_reported_at": data.get("lastReportedAt"),
                }
            )
        except requests.RequestException as exc:
            item["error"] = f"AbuseIPDB request failed: {exc}"

        results.append(item)

    return {
        "enabled": True,
        "results": results,
    }


def enrich_email(parsed: dict) -> dict:
    urls = parsed.get("urls") or []
    headers = parsed.get("headers") or {}
    sender_ips = _public_ipv4_from_headers(headers)

    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")

    vt_data = _enrich_virustotal(urls, vt_key)
    abuse_data = _enrich_abuseipdb(sender_ips, abuse_key)

    vt_flagged = sum(
        1
        for r in vt_data.get("results", [])
        if int(r.get("malicious", 0)) > 0 or int(r.get("suspicious", 0)) > 0
    )
    abuse_high = sum(
        1
        for r in abuse_data.get("results", [])
        if int(r.get("abuse_confidence_score", 0)) >= 50
    )

    return {
        "virustotal": vt_data,
        "abuseipdb": abuse_data,
        "summary": {
            "checked_urls": len(urls[:10]),
            "checked_ips": len(sender_ips[:10]),
            "vt_flagged_urls": vt_flagged,
            "abuse_high_risk_ips": abuse_high,
        },
    }