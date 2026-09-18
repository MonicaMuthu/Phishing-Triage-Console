from pathlib import Path

from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

GMAIL_SCOPE = "https://mail.google.com/"


def authorize(client_secret_path: Path, token_path: Path) -> None:
    flow = InstalledAppFlow.from_client_secrets_file(
        str(client_secret_path),
        scopes=[GMAIL_SCOPE],
    )
    credentials = flow.run_local_server(port=0)
    token_path.write_text(credentials.to_json(), encoding="utf-8")


def get_access_token(client_secret_path: Path, token_path: Path) -> str:
    if not token_path.exists():
        raise RuntimeError("Gmail OAuth is not authorized. Run: python -m app.gmail_oauth")

    credentials = Credentials.from_authorized_user_file(str(token_path), [GMAIL_SCOPE])
    if credentials.expired and credentials.refresh_token:
        try:
            credentials.refresh(Request())
        except RefreshError as exc:
            raise RuntimeError(
                "Gmail OAuth token has expired or been revoked. Run: python -m app.gmail_oauth"
            ) from exc
        token_path.write_text(credentials.to_json(), encoding="utf-8")

    if not credentials.valid or not credentials.token:
        raise RuntimeError("Gmail OAuth token is invalid. Run: python -m app.gmail_oauth")
    return credentials.token


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    client_secret_path = project_root / "gmail_client_secret.json"
    token_path = project_root / "gmail_token.json"
    if not client_secret_path.exists():
        raise SystemExit(
            "Missing gmail_client_secret.json. Download an OAuth Desktop app credential from Google Cloud."
        )

    authorize(client_secret_path, token_path)
    print("Gmail OAuth authorization completed.")


if __name__ == "__main__":
    main()