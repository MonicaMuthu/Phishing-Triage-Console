# Phishing Email Triage Bot

A hybrid **rule-based + machine-learning** phishing detection and triage system for security
operations teams. Ingests email from a live mailbox (IMAP), a watch-folder, or manual upload,
scores each message using authentication checks, brand-impersonation heuristics, a trained text
classifier, and threat-intel enrichment (VirusTotal, AbuseIPDB), then surfaces a prioritized
verdict on an analyst dashboard.

This mirrors the triage workflow used in real SOC phishing playbooks, automating the first-pass
analysis an L1 analyst would otherwise do manually.

![status](https://img.shields.io/badge/status-active-brightgreen) ![python](https://img.shields.io/badge/python-3.11%2B-blue)

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
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure environment

```powershell
Copy-Item .env.example .env
```

Edit `.env` and fill in whichever integrations you want to enable:
- `IMAP_HOST` / `IMAP_USER` — required for Gmail mailbox ingestion.
- `IMAP_PORT` / `IMAP_FOLDER` — optional, defaulting to `993` and `INBOX`.
- `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` — free-tier keys work; leave blank to skip enrichment.

### Gmail OAuth2 authorization

1. In Google Cloud Console, enable the Gmail API and configure an OAuth consent screen.
2. Create an OAuth client with application type **Desktop app**.
3. Download the JSON file to the project root as `gmail_client_secret.json`.
4. Add the Gmail account as a test user if the consent screen is in testing mode.
5. Run the one-time authorization command:

```powershell
python -m app.gmail_oauth
```

Complete consent in the browser. The generated `gmail_token.json` is refreshed automatically.
Both OAuth files are ignored by Git and must never be committed.

### 3. Train the ML model (starter dataset included)

```powershell
python ml/train.py
```

This trains on `ml/dataset/sample_emails.csv` and writes `ml/model.joblib`. For production-grade
accuracy, retrain on a larger corpus (e.g. the Nazario phishing corpus + SpamAssassin/Enron ham,
or your own organization's reported-phishing mailbox export) — just point `--dataset` at a CSV
with `subject,body,label` columns.

### 4. Run the app

```powershell
uvicorn app.main:app --reload
```

Open **http://127.0.0.1:8000** for the dashboard, or **http://127.0.0.1:8000/docs** for the
interactive API docs.

### 5. Try it out

- Drop a `.eml` file into `./incoming/` — it's auto-triaged within ~10 seconds.
- Or upload one directly from the dashboard.
- Or `POST /api/imap/fetch` to pull unseen mail from a configured mailbox.

## Running tests

```powershell
pytest -v
ruff check .
```

## Project structure

```
phishing-triage-bot/
├── app/
│   ├── ingestion/       # IMAP client, watch-folder poller, email parser
│   ├── detection/        # Heuristic rules, ML model wrapper, fusion scorer
│   ├── enrichment/        # VirusTotal / AbuseIPDB clients + cache
│   ├── storage/           # SQLAlchemy models + session
│   ├── api/               # FastAPI routes
│   ├── models/            # Pydantic schemas
│   ├── templates/, static/ # Dashboard UI
│   └── main.py            # App entrypoint + background pollers
├── ml/                    # Training script + starter dataset
├── tests/                 # pytest suite + .eml fixtures
├── docs/architecture.md   # Diagram + scoring formula
└── .github/workflows/ci.yml
```

## Why this is more than "calling VirusTotal"

VirusTotal/AbuseIPDB are reactive reputation *lookups* — they don't understand email headers,
authentication, spoofing, or content. This project fuses those lookups with header/authentication
analysis, brand-impersonation heuristics, and a trained text classifier into a single automated
verdict — the same signal-fusion approach used in real SOC phishing triage and SOAR playbooks.



## License

MIT
