# Phishing Email Triage Bot

Designed to help **L1 SOC analysts** investigate suspicious emails quickly and consistently,
Phishing Triage Bot automates the initial analysis and prioritization of potential phishing
incidents. It ingests messages from live IMAP mailboxes or manual uploads, evaluates email
authentication results, sender and brand-impersonation indicators, message content, and
threat-intelligence data from VirusTotal and AbuseIPDB. The results are presented through an
analyst dashboard with a prioritized risk verdict and supporting investigation details.

## Features

- **Multi-source ingestion**: live IMAP polling, `.eml` watch-folder, or manual upload via API/dashboard.
- **Authentication analysis**: parses `Authentication-Results` for SPF/DKIM/DMARC pass/fail.
- **Spoofing & impersonation detection**: Reply-To mismatches, display-name spoofing, brand
  lookalike domains (fuzzy matching), IP-literal and shortened URLs.
- **Content risk scoring**: urgency/pressure language detection, embedded HTML login forms,
  risky attachment extensions.
- **ML classifier**: TF-IDF + Logistic Regression trained on labeled phishing/legit email text
  (bundled starter dataset + retraining script included).
- **Threat intel enrichment**: VirusTotal URL/hash reputation and AbuseIPDB sender-IP reputation,
  with local caching to respect free-tier rate limits.
- **Weighted fusion scorer**: combines all signals into a single 0-100 score and Clean /
  Suspicious / Malicious verdict.
- **Analyst dashboard**: FastAPI + vanilla JS web UI to upload emails, trigger mailbox fetches,
  and drill into per-message findings.
- **Persistent history**: SQLite-backed triage log for auditing and metrics.
- **Tested & CI'd**: pytest suite covering parsing, heuristics, and scoring; GitHub Actions runs
  lint + tests on every push.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full diagram and scoring formula.

```
Ingestion (IMAP / watch-folder / upload)
        │
        ▼
   Email Parser  →  EmailArtifact (headers, URLs, attachments)
        │
   ┌────┼─────────────┐
   ▼    ▼             ▼
Heuristics   ML Model   Threat Intel Enrichment
   └────┬─────────────┘
        ▼
     Scorer (weighted fusion)
        │
   ┌────┴────┐
   ▼         ▼
 SQLite   REST API → Dashboard
```

## Getting started

### 1. Install dependencies

```powershell
python -m venv .venv
# Phishing Triage Bot

Phishing Triage Bot is a local security-operations tool that analyzes email messages and produces a prioritized phishing verdict. It combines deterministic email heuristics, a text-classification model, and optional threat-intelligence enrichment in a FastAPI application with a browser dashboard.

## Features

- Upload `.eml` files for analysis through the dashboard or API.
- Fetch unread messages from an IMAP mailbox.
- Parse authentication results, sender headers, URLs, and attachments.
- Detect common phishing indicators such as urgency, suspicious links, reply-to mismatches, and brand impersonation.
- Combine rule-based signals with a TF-IDF and Logistic Regression classifier.
- Optionally enrich URLs and sender IPs through VirusTotal and AbuseIPDB.
- Store investigation history and analyst status updates in SQLite.
- Expose interactive API documentation through FastAPI.

## Requirements

- Python 3.11 or later
- Optional: VirusTotal and AbuseIPDB API keys for threat-intelligence enrichment.
- Optional: Gmail or another IMAP mailbox for mailbox ingestion.

## Installation

From the project directory, create and activate a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

On systems where PowerShell script execution is restricted, activate the environment with:

```powershell
.venv\Scripts\activate.bat
```

## Configuration

Create a local environment file from the template:

```powershell
Copy-Item .env.example .env
```

Edit `.env` and set only the integrations you need:

```dotenv
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
IMAP_USER=your_mailbox@gmail.com
IMAP_FOLDER=INBOX
```

Threat-intelligence keys may be left empty to disable enrichment. IMAP ingestion requires `IMAP_HOST` and `IMAP_USER`.

### Gmail OAuth2

Gmail OAuth2 uses local files rather than client credentials in `.env`:

1. Enable the Gmail API in Google Cloud Console.
2. Configure an OAuth consent screen and add the mailbox as a test user when required.
3. Create a Desktop application OAuth client.
4. Download the client file to the project root as `gmail_client_secret.json`.
5. Run the authorization flow:

   ```powershell
   python -m app.gmail_oauth
   ```

The command creates `gmail_token.json` after authorization. Both OAuth files are ignored by Git and must never be committed.

## Run the application

Start the development server:

```powershell
uvicorn app.main:app --reload --port 8010
```

Open the dashboard at [http://127.0.0.1:8010](http://127.0.0.1:8010). FastAPI's interactive API documentation is available at [http://127.0.0.1:8010/docs](http://127.0.0.1:8010/docs).

The SQLite history database is created as `triage_history.db` when the application starts.

## API endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Check application health |
| `POST` | `/upload-eml` | Analyze an uploaded `.eml` file |
| `POST` | `/imap/fetch` | Fetch and analyze unread IMAP messages |
| `GET` | `/history` | List stored investigations |
| `GET` | `/history/{case_id}` | View one investigation |
| `PATCH` | `/history/{case_id}/status` | Update an investigation status |

## Train the classifier

The repository includes a small starter dataset and a generated model artifact. Retrain the model with:

```powershell
python ml/train.py
```

The training script reads `ml/dataset/sample_emails.csv` and writes `ml/model.joblib`. The bundled dataset is intended for development and demonstration, not production-grade detection accuracy. Validate any model with representative, organization-specific data before relying on its verdicts.

## Run tests

```powershell
pytest -v
```

The tests cover parsing, phishing rules, classifier behavior, and API functionality.

## Project layout

```text
phishing-triage-bot/
├── app/                      # FastAPI application and analysis modules
│   ├── enrichment.py         # VirusTotal and AbuseIPDB integrations
│   ├── gmail_oauth.py        # Gmail OAuth2 authorization
│   ├── history_store.py      # SQLite investigation history
│   ├── imap_ingest.py        # IMAP mailbox ingestion
│   ├── ml_classifier.py      # Model loading and prediction
│   ├── parser.py             # Email parsing
│   ├── rules.py              # Heuristic analysis
│   └── main.py               # Application entry point and API routes
├── ml/                       # Training script, dataset, and model artifact
├── sample_emails/            # Example email fixtures
├── tests/                    # Automated tests
├── .env.example              # Safe configuration template
└── requirements.txt          # Python dependencies
```

## Security notes

- Never commit `.env`, `gmail_client_secret.json`, or `gmail_token.json`.
- Treat uploaded emails, extracted URLs, mailbox credentials, and `triage_history.db` as sensitive data.
- Use API keys with the minimum permissions required and rotate any key that is exposed.
- This tool supports analyst triage; it does not replace human review or an organization's email-security controls.

## License

This project is licensed under the MIT License.










