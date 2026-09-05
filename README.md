# Phishing Email Triage Bot

Phishing Triage Bot helps L1 SOC analysts review reported emails consistently. It ingests messages from an IMAP mailbox or manual upload, enriches URLs and sender IPs with VirusTotal and AbuseIPDB, and sends the collected case evidence to a local Ollama model for an AI-assisted verdict and recommendation.

## Features

- Upload `.eml` files from the dashboard or API.
- Fetch unread messages from an IMAP mailbox using Gmail OAuth2.
- Extract email headers, sender details, URLs, and message content.
- Enrich URLs through VirusTotal and sender IPs through AbuseIPDB.
- Run a local Ollama model to return a structured L1 analyst verdict, confidence, evidence, and recommended action.
- Maintain a searchable case queue with New, Investigating, and Closed statuses.
- Persist investigation history in SQLite.
- Run automated tests in GitHub Actions on pushes and pull requests.

## Requirements

- Python 3.11 or later.
- Optional: Ollama for AI recommendations.
- Optional: VirusTotal and AbuseIPDB API keys for threat-intelligence enrichment.
- Optional: an IMAP mailbox for mailbox ingestion.

## Installation

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Set only the integrations you need in `.env`. Keep `.env`, Gmail OAuth credentials, and OAuth tokens out of source control.

## Local AI Analyst

Install Ollama from [ollama.com](https://ollama.com/download), then download the default model:

```powershell
ollama pull llama3.1:8b
```

The application calls Ollama at `http://127.0.0.1:11434` by default. Configure a different endpoint or model in `.env`:

```dotenv
OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_MODEL=llama3.1:8b
```

Without Ollama, the application remains available and clearly marks the AI assessment as unavailable. VirusTotal and AbuseIPDB enrichment continue independently.

## Gmail OAuth2

1. Enable the Gmail API in Google Cloud Console.
2. Create a Desktop application OAuth client.
3. Save the downloaded client as `gmail_client_secret.json` in the project root.
4. Run the authorization flow:

   ```powershell
   python -m app.gmail_oauth
   ```

The generated `gmail_token.json` refreshes automatically. Neither OAuth file should be committed.

## Run the Application

```powershell
uvicorn app.main:app --reload --port 8010
```

Open the dashboard at `http://127.0.0.1:8010` and the interactive API documentation at `http://127.0.0.1:8010/docs`.

## API Endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Check integrations, including local Ollama availability. |
| `POST` | `/upload-eml` | Analyze an uploaded email. |
| `POST` | `/imap/fetch` | Fetch and analyze unread IMAP messages. |
| `GET` | `/history` | List, search, filter, sort, and page through cases. |
| `GET` | `/history/{case_id}` | View a stored investigation. |
| `PATCH` | `/history/{case_id}/status` | Update a case status. |

## Tests

```powershell
python -m pytest -v
```

The test suite covers parsing, local AI response validation and fallback behavior, case severity mapping, legacy rule logic, and the health endpoint contract.

## Security Notes

- Never commit `.env`, `gmail_client_secret.json`, or `gmail_token.json`.
- Treat uploaded emails, extracted URLs, mailbox data, and `triage_history.db` as sensitive.
- AI recommendations assist triage; they do not replace analyst review or enterprise email-security controls.
