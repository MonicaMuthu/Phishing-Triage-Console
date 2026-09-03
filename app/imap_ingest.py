import imaplib
from collections.abc import Callable


def _oauth2_string(username: str, access_token: str) -> bytes:
    return f"user={username}\x01auth=Bearer {access_token}\x01\x01".encode("utf-8")


def fetch_unseen(
    processor: Callable[[str, bytes], int],
    host: str,
    port: int,
    username: str,
    access_token: str,
    folder: str = "INBOX",
    limit: int = 10,
) -> list[dict]:
    """Fetch unread messages and mark only successfully processed messages as seen."""
    connection = imaplib.IMAP4_SSL(host, port)
    results: list[dict] = []

    try:
        connection.authenticate("XOAUTH2", lambda _: _oauth2_string(username, access_token))
        status, _ = connection.select(folder)
        if status != "OK":
            raise RuntimeError(f"Unable to select mailbox folder: {folder}")

        status, data = connection.search(None, "UNSEEN")
        if status != "OK":
            raise RuntimeError("Unable to search for unread messages")

        for message_id in data[0].split()[-limit:]:
            message_key = message_id.decode("ascii", errors="replace")
            status, message_data = connection.fetch(message_id, "(RFC822)")
            if status != "OK":
                results.append({"message_id": message_key, "status": "fetch_failed"})
                continue

            raw_email = next(
                (part[1] for part in message_data if isinstance(part, tuple)),
                None,
            )
            if not raw_email:
                results.append({"message_id": message_key, "status": "empty_message"})
                continue

            try:
                case_id = processor(f"imap-{message_key}.eml", raw_email)
                connection.store(message_id, "+FLAGS", "\\Seen")
                results.append({"message_id": message_key, "case_id": case_id, "status": "processed"})
            except Exception as exc:
                results.append({"message_id": message_key, "status": "processing_failed", "error": str(exc)})

        return results
    finally:
        try:
            connection.close()
        except (imaplib.IMAP4.error, OSError):
            pass
        try:
            connection.logout()
        except (imaplib.IMAP4.error, OSError):
            pass
