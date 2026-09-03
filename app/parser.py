import re
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import getaddresses

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")


def _extract_body(msg: EmailMessage) -> str:
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", "")).lower()
            if "attachment" in disposition:
                continue
            if content_type in ("text/plain", "text/html"):
                content = part.get_content()
                if isinstance(content, str):
                    parts.append(content)
        return "\n".join(parts)

    content = msg.get_content()
    return content if isinstance(content, str) else ""


def parse_email(raw_email: bytes) -> dict:
    msg: EmailMessage = message_from_bytes(raw_email, policy=policy.default)  # type: ignore[assignment]

    headers = {key: str(value) for key, value in msg.items()}
    from_addr = getaddresses([headers.get("From", "")])
    to_addrs = getaddresses([headers.get("To", "")])

    body = _extract_body(msg)
    urls = sorted({url.rstrip(".,;:!?") for url in URL_PATTERN.findall(body)})

    return {
        "subject": headers.get("Subject", ""),
        "from": from_addr[0][1] if from_addr else "",
        "to": [addr for _, addr in to_addrs if addr],
        "date": headers.get("Date"),
        "message_id": headers.get("Message-ID"),
        "headers": headers,
        "url_count": len(urls),
        "urls": urls,
        "body_preview": body[:500],
    }
