import os
import imaplib
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from dotenv import load_dotenv

from app.enrichment import enrich_email
from app.gmail_oauth import get_access_token
from app.history_store import (
    VALID_STATUSES,
    count_investigations,
    get_investigation,
    init_db,
    list_investigations,
    save_investigation,
    update_investigation_status,
)
from app.imap_ingest import fetch_unseen
from app.ml_classifier import is_model_available, predict_phishing_text
from app.parser import parse_email
from app.rules import analyze_phishing_risk

load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=True)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
GMAIL_CLIENT_SECRET_PATH = PROJECT_ROOT / "gmail_client_secret.json"
GMAIL_TOKEN_PATH = PROJECT_ROOT / "gmail_token.json"

app = FastAPI(title="Phishing Triage Console")


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def root() -> str:
    return """
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Phishing Triage Console | SOC Automation Platform</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=IBM+Plex+Mono:wght@400;600&display=swap');

            :root {
                --ink-950: #0b1a2b;
                --ink-800: #1d3552;
                --ink-600: #355171;
                --slate-200: #d4deea;
                --slate-100: #e8eff8;
                --paper: #f5f8fc;
                --card: #ffffff;
                --teal: #0ea5a4;
                --teal-soft: #d7f5f3;
                --amber: #b87900;
                --amber-soft: #fff0cd;
                --red: #b53838;
                --red-soft: #ffe0e0;
                --blue: #0f5ad8;
                --blue-soft: #dce9ff;
                --shadow: 0 14px 34px rgba(20, 49, 86, 0.12);
            }

            * {
                box-sizing: border-box;
            }

            body {
                margin: 0;
                overflow-x: hidden;
                font-family: "Space Grotesk", "Segoe UI", sans-serif;
                color: var(--ink-950);
                background:
                    radial-gradient(circle at 8% -4%, #d9f8ff 0%, transparent 36%),
                    radial-gradient(circle at 97% 3%, #d8e6ff 0%, transparent 33%),
                    linear-gradient(180deg, #f9fbff 0%, var(--paper) 48%, #edf3fb 100%);
            }

            .shell {
                max-width: 1240px;
                margin: 0 auto;
                padding: 1.25rem 1rem 2rem;
                width: 100%;
            }

            .topbar {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 1rem;
                padding: 1rem 1.1rem;
                border: 1px solid var(--slate-200);
                border-radius: 16px;
                background: rgba(255, 255, 255, 0.82);
                backdrop-filter: blur(3px);
                box-shadow: var(--shadow);
                animation: rise 420ms ease-out;
            }

            .workspace-bar {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 1rem;
                margin: 1.2rem 0 0.8rem;
            }

            .workspace-title h2 {
                margin: 0;
                font-size: 1.28rem;
                letter-spacing: -0.02em;
            }

            .workspace-title p {
                margin: 0.22rem 0 0;
                color: var(--ink-600);
                font-size: 0.84rem;
            }

            .system-status {
                display: inline-flex;
                align-items: center;
                gap: 0.45rem;
                padding: 0.45rem 0.7rem;
                border: 1px solid #b9e7dc;
                border-radius: 999px;
                color: #08745f;
                background: #e8faf5;
                font-size: 0.77rem;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.04em;
            }

            .brand {
                display: flex;
                align-items: center;
                gap: 0.85rem;
            }

            .brand-mark {
                width: 42px;
                height: 42px;
                border-radius: 11px;
                display: grid;
                place-items: center;
                color: #fff;
                background: linear-gradient(135deg, #0f5ad8 0%, #0ea5a4 100%);
                box-shadow: 0 6px 16px rgba(15, 90, 216, 0.28);
            }

            .brand-mark svg {
                width: 22px;
                height: 22px;
            }

            .brand h1 {
                margin: 0;
                font-size: 1.05rem;
                letter-spacing: 0.01em;
            }

            .sub {
                margin: 0.18rem 0 0;
                font-size: 0.83rem;
                color: var(--ink-600);
            }

            .top-links {
                display: flex;
                gap: 0.55rem;
                flex-wrap: wrap;
            }

            .top-links a {
                text-decoration: none;
                color: var(--ink-800);
                background: #fff;
                border: 1px solid var(--slate-200);
                border-radius: 999px;
                padding: 0.4rem 0.7rem;
                font-size: 0.82rem;
                font-weight: 500;
            }

            .layout {
                display: grid;
                grid-template-columns: 360px 1fr;
                gap: 1.1rem;
                margin-top: 1rem;
            }

            .layout > * {
                min-width: 0;
            }

            .panel {
                background: var(--card);
                border: 1px solid var(--slate-200);
                border-radius: 16px;
                box-shadow: var(--shadow);
                padding: 1rem;
                min-width: 0;
                animation: rise 460ms ease-out;
                transition: box-shadow 200ms ease, transform 200ms ease;
            }

            .panel:hover {
                box-shadow: 0 18px 40px rgba(20, 49, 86, 0.16);
                transform: translateY(-2px);
            }

            .tech-strip {
                display: flex;
                align-items: center;
                flex-wrap: wrap;
                gap: 0.4rem;
                margin-top: 0.85rem;
            }

            .tech-strip span {
                display: inline-flex;
                align-items: center;
                padding: 0.26rem 0.6rem;
                border-radius: 999px;
                font-size: 0.72rem;
                font-weight: 600;
                color: var(--ink-600);
                background: rgba(255, 255, 255, 0.7);
                border: 1px solid var(--slate-200);
            }


            .panel h2 {
                margin: 0 0 0.68rem;
                font-size: 1rem;
            }

            .panel p {
                margin: 0;
            }

            .hint {
                color: var(--ink-600);
                font-size: 0.86rem;
            }

            .upload {
                margin-top: 0.85rem;
                display: grid;
                gap: 0.62rem;
            }

            .dropzone {
                display: grid;
                place-items: center;
                min-height: 126px;
                padding: 1rem;
                border: 1px dashed #9db6d3;
                border-radius: 12px;
                color: var(--ink-600);
                background: linear-gradient(180deg, #fbfdff 0%, #f2f7fc 100%);
                text-align: center;
                cursor: pointer;
                transition: border-color 160ms ease, background 160ms ease;
            }

            .dropzone:hover,
            .dropzone.dragover {
                border-color: var(--blue);
                background: var(--blue-soft);
            }

            .dropzone strong {
                display: block;
                color: var(--ink-800);
                font-size: 0.92rem;
            }

            .dropzone span {
                display: block;
                margin-top: 0.32rem;
                font-size: 0.78rem;
            }

            .file-name {
                min-height: 1rem;
                color: var(--blue);
                font-family: "IBM Plex Mono", Consolas, monospace;
                font-size: 0.76rem;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }

            .eyebrow {
                margin-bottom: 0.45rem;
                color: var(--blue);
                font-size: 0.7rem;
                font-weight: 700;
                letter-spacing: 0.11em;
                text-transform: uppercase;
            }

            input[type="file"] {
                width: 100%;
                border: 1px solid var(--slate-200);
                border-radius: 10px;
                padding: 0.5rem;
                background: #fff;
            }

            button {
                width: 100%;
                border: 0;
                border-radius: 12px;
                padding: 0.67rem 0.95rem;
                background: linear-gradient(135deg, #0f5ad8 0%, #0ea5a4 100%);
                color: #fff;
                font: inherit;
                font-weight: 700;
                letter-spacing: 0.01em;
                cursor: pointer;
            }

            button:hover {
                filter: brightness(1.03);
                transform: translateY(-1px);
                box-shadow: 0 10px 22px rgba(15, 90, 216, 0.28);
            }

            button {
                transition: filter 160ms ease, transform 160ms ease, box-shadow 160ms ease;
            }

            button:disabled {
                opacity: 0.62;
                cursor: wait;
                filter: none;
            }

            .status {
                margin-top: 0.8rem;
                min-height: 1.2rem;
                color: var(--ink-800);
                font-size: 0.9rem;
                font-weight: 500;
            }

            .risk-card {
                margin-top: 1rem;
                border: 1px solid var(--slate-100);
                border-radius: 12px;
                padding: 0.75rem;
                background: #fcfeff;
            }

            .risk-tag {
                display: inline-flex;
                align-items: center;
                gap: 0.42rem;
                padding: 0.3rem 0.62rem;
                border-radius: 999px;
                font-weight: 600;
                border: 1px solid var(--slate-200);
                background: var(--blue-soft);
                color: var(--ink-800);
            }

            .gauge {
                margin-top: 0.6rem;
                width: 100%;
                height: 10px;
                border-radius: 999px;
                background: var(--slate-100);
                overflow: hidden;
            }

            .gauge > span {
                display: block;
                height: 100%;
                width: 0%;
                background: linear-gradient(90deg, #0ea5a4 0%, #0f5ad8 100%);
                transition: width 320ms ease;
            }

            .cards {
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 0.75rem;
                margin-bottom: 1rem;
            }

            .kpi {
                border: 1px solid var(--slate-200);
                border-radius: 13px;
                padding: 0.7rem;
                background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
                transition: box-shadow 180ms ease, transform 180ms ease;
            }

            .kpi:hover {
                box-shadow: 0 10px 22px rgba(20, 49, 86, 0.1);
                transform: translateY(-1px);
            }

            .k {
                font-size: 0.72rem;
                color: var(--ink-600);
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }

            .v {
                margin-top: 0.2rem;
                font-size: 0.95rem;
                font-weight: 700;
                word-break: break-word;
                overflow-wrap: anywhere;
            }

            .content-grid {
                display: grid;
                grid-template-columns: minmax(0, 1fr);
                gap: 0.9rem;
            }

            .table-wrap {
                border: 1px solid var(--slate-100);
                border-radius: 12px;
                overflow: hidden;
                background: #fff;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                table-layout: fixed;
            }

            th, td {
                border-bottom: 1px solid var(--slate-100);
                text-align: left;
                padding: 0.5rem 0.62rem;
                font-size: 0.86rem;
                overflow-wrap: anywhere;
            }

            th:first-child,
            td:first-child {
                width: 4.5rem;
            }

            .history-table th:first-child,
            .history-table td:first-child {
                width: 3.8rem;
            }

            .history-table th:nth-child(2),
            .history-table td:nth-child(2) {
                width: 58%;
            }

            .queue-table th:first-child,
            .queue-table td:first-child {
                width: 3.4rem;
            }

            .queue-table th:nth-child(2),
            .queue-table td:nth-child(2) {
                width: 46%;
            }

            .queue-table th:nth-child(3),
            .queue-table td:nth-child(3) {
                width: 4.6rem;
            }

            .queue-table th:nth-child(4),
            .queue-table td:nth-child(4) {
                width: 7.2rem;
            }

            th {
                color: var(--ink-600);
                font-weight: 600;
                background: #f7fafe;
            }

            tr:last-child td {
                border-bottom: none;
            }

            .history-row {
                cursor: pointer;
            }

            .history-row:hover td {
                background: #f1f7ff;
            }

            .history-row.active td {
                background: #e3eeff;
            }

            .queue-toolbar {
                display: flex;
                flex-wrap: wrap;
                align-items: flex-end;
                gap: 0.9rem;
                padding: 0.8rem 0.9rem;
                margin-bottom: 0.9rem;
                background: linear-gradient(180deg, #fbfdff 0%, #f3f7fc 100%);
                border: 1px solid var(--slate-200);
                border-radius: 12px;
            }

            .queue-filter {
                display: flex;
                flex-direction: column;
                gap: 0.32rem;
            }

            .queue-filter label {
                font-size: 0.65rem;
                font-weight: 700;
                letter-spacing: 0.05em;
                text-transform: uppercase;
                color: var(--ink-600);
            }

            .queue-filter.search-filter {
                flex: 1 1 200px;
                min-width: 160px;
            }

            .queue-toolbar input[type="search"],
            .queue-toolbar select {
                height: 2.15rem;
                border: 1px solid var(--slate-200);
                border-radius: 8px;
                padding: 0 0.65rem;
                font: inherit;
                font-size: 0.82rem;
                background-color: #fff;
                color: var(--ink-800);
                transition: border-color 150ms ease, box-shadow 150ms ease;
                appearance: none;
                -webkit-appearance: none;
            }

            .queue-toolbar select {
                padding-right: 1.9rem;
                min-width: 150px;
                cursor: pointer;
                background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'><path d='M1 1l4 4 4-4' stroke='%23355171' stroke-width='1.4' fill='none' stroke-linecap='round' stroke-linejoin='round'/></svg>");
                background-repeat: no-repeat;
                background-position: right 0.65rem center;
            }

            .queue-toolbar input[type="search"] {
                width: 100%;
                background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='13' height='13' viewBox='0 0 24 24'><path d='M10 4a6 6 0 104.47 10.03l4.75 4.75 1.06-1.06-4.75-4.75A6 6 0 0010 4zm0 1.5a4.5 4.5 0 110 9 4.5 4.5 0 010-9z' fill='%23355171'/></svg>");
                background-repeat: no-repeat;
                background-position: left 0.62rem center;
                padding-left: 1.95rem;
            }

            .queue-toolbar input[type="search"]:hover,
            .queue-toolbar select:hover {
                border-color: #b7c8de;
            }

            .queue-toolbar input[type="search"]:focus,
            .queue-toolbar select:focus {
                outline: none;
                border-color: var(--blue);
                box-shadow: 0 0 0 3px rgba(15, 90, 216, 0.14);
            }

            .sev-badge,
            .status-badge {
                display: inline-flex;
                align-items: center;
                gap: 0.32rem;
                padding: 0.24rem 0.6rem;
                border-radius: 999px;
                font-size: 0.7rem;
                font-weight: 700;
                letter-spacing: 0.03em;
                border: 1px solid transparent;
                white-space: nowrap;
            }

            .sev-badge::before {
                content: "";
                width: 6px;
                height: 6px;
                border-radius: 50%;
                background: currentColor;
            }

            .sev-badge.sev-high {
                background: var(--red-soft);
                color: var(--red);
                border-color: #f0b4b4;
            }

            .sev-badge.sev-medium {
                background: var(--amber-soft);
                color: var(--amber);
                border-color: #ecd39a;
            }

            .sev-badge.sev-low {
                background: var(--teal-soft);
                color: var(--teal);
                border-color: #a6e8e3;
            }

            .history-row.sev-high td:first-child {
                box-shadow: inset 3px 0 0 var(--red);
            }

            .history-row.sev-medium td:first-child {
                box-shadow: inset 3px 0 0 var(--amber);
            }

            .history-row.sev-low td:first-child {
                box-shadow: inset 3px 0 0 var(--teal);
            }

            .status-select {
                width: 100%;
                appearance: none;
                -webkit-appearance: none;
                border: 1px solid transparent;
                border-radius: 8px;
                padding: 0.32rem 1.65rem 0.32rem 0.6rem;
                font: inherit;
                font-size: 0.72rem;
                font-weight: 700;
                letter-spacing: 0.02em;
                cursor: pointer;
                background-color: #f0f4f9;
                color: var(--ink-600);
                background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='9' height='6' viewBox='0 0 10 6'><path d='M1 1l4 4 4-4' stroke='%23355171' stroke-width='1.4' fill='none' stroke-linecap='round' stroke-linejoin='round'/></svg>");
                background-repeat: no-repeat;
                background-position: right 0.5rem center;
                transition: box-shadow 150ms ease, border-color 150ms ease;
            }

            .status-select:hover {
                box-shadow: 0 0 0 2px rgba(20, 49, 86, 0.08);
            }

            .status-select:focus {
                outline: none;
                box-shadow: 0 0 0 3px rgba(15, 90, 216, 0.18);
            }

            .status-select.status-new {
                background-color: var(--blue-soft);
                color: var(--blue);
                border-color: #c3d8fb;
            }

            .status-select.status-investigating {
                background-color: var(--amber-soft);
                color: var(--amber);
                border-color: #ecd39a;
            }

            .status-select.status-closed {
                background-color: #e4e9ef;
                color: var(--ink-600);
                border-color: #cfd8e3;
            }

            .queue-pagination {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 0.6rem;
                margin-top: 0.75rem;
                padding-top: 0.65rem;
                border-top: 1px solid var(--slate-100);
                font-size: 0.78rem;
                color: var(--ink-600);
            }

            .queue-pagination-buttons {
                display: flex;
                gap: 0.4rem;
            }

            .queue-pagination button {
                width: auto;
                padding: 0.4rem 0.85rem;
                font-size: 0.78rem;
                font-weight: 600;
                letter-spacing: normal;
                border-radius: 8px;
                background: #fff;
                color: var(--ink-800);
                border: 1px solid var(--slate-200);
                box-shadow: none;
            }

            .queue-pagination button:hover:not(:disabled) {
                border-color: var(--blue);
                color: var(--blue);
                transform: none;
                box-shadow: none;
                filter: none;
            }

            .queue-pagination button:disabled {
                opacity: 0.45;
                cursor: not-allowed;
            }

            .mono {
                font-family: "IBM Plex Mono", Consolas, monospace;
            }

            .reasons {
                display: grid;
                gap: 0.46rem;
            }

            .reason {
                border: 1px solid var(--slate-100);
                border-left: 4px solid var(--blue);
                border-radius: 10px;
                padding: 0.52rem 0.6rem;
                font-size: 0.84rem;
            }

            .explain-panel {
                margin-top: 1rem;
                border-top: 1px solid var(--slate-100);
                padding-top: 1rem;
            }

            .explain-table th:first-child,
            .explain-table td:first-child {
                width: 43%;
            }

            .explain-table th:nth-child(2),
            .explain-table td:nth-child(2) {
                width: 31%;
            }

            .points {
                color: var(--blue);
                font-family: "IBM Plex Mono", Consolas, monospace;
                font-weight: 600;
                white-space: nowrap;
            }

            .decision-line {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 0.7rem;
                margin-top: 0.7rem;
                border-top: 1px solid var(--slate-200);
                padding-top: 0.65rem;
                font-size: 0.88rem;
            }

            .source-grid {
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 0.5rem;
                margin-top: 0.65rem;
            }

            .source-item {
                border: 1px solid var(--slate-100);
                border-radius: 9px;
                padding: 0.48rem;
                background: #f8fbff;
            }

            .source-item strong {
                display: block;
                margin-top: 0.18rem;
                font-size: 0.8rem;
            }

            .action-list {
                display: grid;
                gap: 0.52rem;
                margin: 0.7rem 0 0;
                padding: 0;
                list-style: none;
            }

            .action-item {
                display: flex;
                align-items: center;
                gap: 0.65rem;
                padding: 0.58rem 0.75rem;
                border-radius: 10px;
                border: 1px solid var(--slate-200);
                background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
                font-size: 0.83rem;
                color: var(--ink-950);
                box-shadow: 0 2px 6px rgba(11, 26, 43, 0.04);
                transition: transform 140ms ease, box-shadow 140ms ease;
            }

            .action-item:hover {
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(11, 26, 43, 0.08);
            }

            .action-badge {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                padding: 0.22rem 0.55rem;
                border-radius: 6px;
                font-family: "IBM Plex Mono", Consolas, monospace;
                font-size: 0.68rem;
                font-weight: 700;
                letter-spacing: 0.04em;
                text-transform: uppercase;
                white-space: nowrap;
                flex-shrink: 0;
            }

            .action-tag-critical, .action-tag-block-ioc {
                border-left: 4px solid var(--red);
            }
            .action-tag-critical .action-badge, .action-tag-block-ioc .action-badge {
                background: var(--red-soft);
                color: var(--red);
                border: 1px solid #f0b4b4;
            }

            .action-tag-verify, .action-tag-inspect, .action-tag-advise, .action-tag-user-audit, .action-tag-escalate {
                border-left: 4px solid var(--amber);
            }
            .action-tag-verify .action-badge, .action-tag-inspect .action-badge, .action-tag-advise .action-badge, .action-tag-user-audit .action-badge, .action-tag-escalate .action-badge {
                background: var(--amber-soft);
                color: var(--amber);
                border: 1px solid #ecd39a;
            }

            .action-tag-allow, .action-tag-monitor, .action-tag-init {
                border-left: 4px solid var(--teal);
            }
            .action-tag-allow .action-badge, .action-tag-monitor .action-badge, .action-tag-init .action-badge {
                background: var(--teal-soft);
                color: var(--teal);
                border: 1px solid #a6e8e3;
            }

            .action-text {
                font-weight: 500;
                line-height: 1.35;
            }

            .intel-grid {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 0.65rem;
                margin-top: 0.9rem;
            }

            .intel-box {
                border: 1px solid var(--slate-100);
                border-radius: 12px;
                padding: 0.7rem;
                background: #fbfdff;
            }

            .intel-box h3 {
                margin: 0 0 0.42rem;
                font-size: 0.88rem;
            }

            .intel-list {
                display: grid;
                gap: 0.38rem;
                color: var(--ink-600);
                font-size: 0.78rem;
            }

            .intel-item {
                padding: 0.42rem;
                border-radius: 8px;
                background: #f1f6fc;
                word-break: break-word;
            }

            pre {
                margin: 0;
                background: #0b1a2b;
                color: #d5e0ef;
                border: 1px solid #1f3652;
                padding: 0.85rem;
                border-radius: 12px;
                overflow: auto;
                max-height: 300px;
                font-size: 0.78rem;
                line-height: 1.4;
                max-width: 100%;
                white-space: pre-wrap;
                overflow-wrap: anywhere;
            }

            .section-head {
                display: flex;
                align-items: baseline;
                justify-content: space-between;
                gap: 0.6rem;
                margin-bottom: 0.55rem;
            }

            .section-head h2 {
                letter-spacing: -0.01em;
            }

            .section-head small {
                color: var(--ink-600);
                font-size: 0.78rem;
            }

            .technical-details {
                margin-top: 0.9rem;
                border-top: 1px solid var(--slate-100);
                padding-top: 0.75rem;
            }

            .technical-details summary {
                color: var(--ink-600);
                cursor: pointer;
                font-size: 0.78rem;
                font-weight: 600;
            }

            .technical-details summary:hover {
                color: var(--blue);
            }

            .technical-details pre {
                margin-top: 0.65rem;
            }

            .history-note {
                margin-top: 0.55rem;
                color: var(--ink-600);
                font-size: 0.78rem;
            }

            .pulse {
                display: inline-block;
                width: 8px;
                height: 8px;
                border-radius: 50%;
                background: #0ea5a4;
                margin-right: 0.35rem;
                box-shadow: 0 0 0 0 rgba(14, 165, 164, 0.45);
                animation: pulse 1.8s infinite;
            }

            @keyframes rise {
                from {
                    opacity: 0;
                    transform: translateY(8px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            @keyframes pulse {
                0% {
                    box-shadow: 0 0 0 0 rgba(14, 165, 164, 0.45);
                }
                70% {
                    box-shadow: 0 0 0 10px rgba(14, 165, 164, 0);
                }
                100% {
                    box-shadow: 0 0 0 0 rgba(14, 165, 164, 0);
                }
            }

            @media (max-width: 1080px) {
                .layout {
                    grid-template-columns: 1fr;
                }

                .content-grid {
                    grid-template-columns: 1fr;
                }
            }

            @media (max-width: 760px) {
                .cards {
                    grid-template-columns: repeat(2, minmax(0, 1fr));
                }

                .topbar {
                    flex-direction: column;
                    align-items: flex-start;
                }

                .workspace-bar {
                    align-items: flex-start;
                    flex-direction: column;
                }
            }

            .integrations-bar {
                display: flex;
                align-items: center;
                gap: 0.45rem;
                flex-wrap: wrap;
            }

            .integration-pill {
                display: inline-flex;
                align-items: center;
                gap: 0.35rem;
                padding: 0.28rem 0.65rem;
                border-radius: 999px;
                font-size: 0.73rem;
                font-weight: 600;
                background: #f0f4f9;
                color: var(--ink-600);
                border: 1px solid var(--slate-200);
            }

            .integration-pill.active {
                background: #e6f7f5;
                color: #0b7a79;
                border-color: #a3e6e3;
            }

            .integration-pill .dot {
                width: 6px;
                height: 6px;
                border-radius: 50%;
                background: #94a3b8;
            }

            .integration-pill.active .dot {
                background: var(--teal);
            }

            @media (max-width: 440px) {
                .shell {
                    padding: 0.75rem 0.65rem 1.5rem;
                }

                .cards {
                    gap: 0.5rem;
                }

                .kpi {
                    padding: 0.58rem;
                }

                th, td {
                    padding: 0.45rem;
                    font-size: 0.78rem;
                }
            }
        </style>
    </head>
    <body>
        <div class="shell">
            <div class="topbar">
                <div class="brand">
                    <div class="brand-mark">
                        <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M12 2L4 5v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V5l-8-3z" stroke="#ffffff" stroke-width="1.6" fill="rgba(255,255,255,0.14)" stroke-linejoin="round"/>
                            <path d="M8.8 12.2l2.2 2.2 4.2-4.6" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </div>
                    <div>
                        <h1>Phishing Triage Console</h1>
                        <p class="sub"><span class="pulse"></span>Automated email threat detection and analyst triage</p>
                    </div>
                </div>
                <div class="integrations-bar">
                    <span class="integration-pill" id="pill-vt"><span class="dot"></span>VT Intel</span>
                    <span class="integration-pill" id="pill-abuse"><span class="dot"></span>AbuseIPDB</span>
                    <span class="integration-pill" id="pill-imap"><span class="dot"></span>Mailbox Ingest</span>
                    <span class="integration-pill" id="pill-ml"><span class="dot"></span>ML Model</span>
                </div>
            </div>

            <div class="tech-strip">
                <span>FastAPI</span>
                <span>scikit-learn</span>
                <span>SQLite</span>
                <span>VirusTotal API</span>
                <span>AbuseIPDB API</span>
                <span>Gmail OAuth2 + IMAP</span>
            </div>

            <div class="workspace-bar">
                <div class="workspace-title">
                    <h2>Investigation workspace</h2>
                    <p>Review message artifacts, scoring evidence, and external reputation signals.</p>
                </div>
                <div class="system-status"><span class="pulse"></span>Console operational</div>
            </div>

            <div class="layout">
                <aside class="panel">
                    <div class="eyebrow">New investigation</div>
                    <h2>Upload Investigation</h2>
                    <p class="hint">Submit one .eml file to parse headers, extract URLs, score phishing risk, and save the case.</p>
                    <form id="upload-form">
                        <div class="upload">
                            <label class="dropzone" id="dropzone" for="eml-file">
                                <span><strong>Drop an .eml file here</strong>or click to browse from your computer</span>
                                <input id="eml-file" type="file" accept=".eml" required hidden />
                            </label>
                            <div class="file-name" id="file-name">No file selected</div>
                            <button type="submit">Analyze and Save Case</button>
                            <button class="secondary-button" id="imap-button" type="button">Fetch unread mailbox</button>
                        </div>
                    </form>
                    <div class="status" id="status"></div>

                    <div class="risk-card">
                        <div class="k">Current Case Risk</div>
                        <div class="v" id="sum-risk">Not Scored</div>
                        <div style="margin-top:0.45rem;"><span id="risk-tag" class="risk-tag">Awaiting upload</span></div>
                        <div class="gauge"><span id="risk-gauge"></span></div>
                    </div>

                    <div class="explain-panel">
                        <div class="section-head">
                            <h2>Classification Evidence</h2>
                            <small id="rule-count">Awaiting analysis</small>
                        </div>
                        <div class="table-wrap" style="margin-top:0.65rem;">
                            <table class="explain-table">
                                <thead><tr><th>Evidence</th><th>Detection rule</th><th>Points</th></tr></thead>
                                <tbody id="reasons"><tr><td colspan="3" class="hint">No active case</td></tr></tbody>
                            </table>
                        </div>
                        <div class="decision-line"><strong>Rule score</strong><strong class="mono" id="rule-score">0/100</strong></div>
                        <div class="decision-line"><strong>Final decision</strong><strong id="final-decision">Not scored</strong></div>
                        <div class="source-grid">
                            <div class="source-item"><div class="k">Rules</div><strong id="source-rules">0/100</strong></div>
                            <div class="source-item"><div class="k">ML</div><strong id="source-ml">Not enabled</strong></div>
                            <div class="source-item"><div class="k">Threat Intel</div><strong id="source-intel">Advisory</strong></div>
                        </div>
                        <div class="section-head" style="margin-top:1rem;"><h2>Automated SOC Response Directives</h2><small>Playbook Actions</small></div>
                        <ul class="action-list" id="actions"><li class="action-item action-tag-init"><span class="action-badge">INIT</span><span class="action-text">Select a case to view playbook actions</span></li></ul>
                    </div>
                </aside>

                <main class="panel">
                    <div class="cards">
                        <div class="kpi"><div class="k">Case ID</div><div class="v mono" id="sum-case">-</div></div>
                        <div class="kpi"><div class="k">Subject</div><div class="v" id="sum-subject">-</div></div>
                        <div class="kpi"><div class="k">Sender</div><div class="v" id="sum-from">-</div></div>
                        <div class="kpi"><div class="k">Recipient Count</div><div class="v" id="sum-to">0</div></div>
                        <div class="kpi"><div class="k">VT Flagged URLs</div><div class="v" id="sum-vt">0</div></div>
                        <div class="kpi"><div class="k">Abuse High-Risk IPs</div><div class="v" id="sum-abuse">0</div></div>
                    </div>

                    <div class="content-grid">
                        <section>
                            <div class="section-head">
                                <h2>Extracted URLs</h2>
                                <small id="url-count">0 found</small>
                            </div>
                            <div class="table-wrap">
                                <table class="history-table">
                                    <thead><tr><th>#</th><th>URL</th></tr></thead>
                                    <tbody id="url-body"><tr><td colspan="2" class="hint">No URL data yet.</td></tr></tbody>
                                </table>
                            </div>

                            <div class="section-head" style="margin-top:0.9rem;">
                                <h2>Threat Intel</h2>
                                <small id="intel-status">Awaiting case</small>
                            </div>
                            <div class="intel-grid">
                                <div class="intel-box">
                                    <h3>VirusTotal URLs</h3>
                                    <div id="vt-results" class="intel-list">
                                        <div class="intel-item">No VirusTotal results yet.</div>
                                    </div>
                                </div>
                                <div class="intel-box">
                                    <h3>AbuseIPDB Sender IPs</h3>
                                    <div id="abuse-results" class="intel-list">
                                        <div class="intel-item">No AbuseIPDB results yet.</div>
                                    </div>
                                </div>
                            </div>

                            <details class="technical-details">
                                <summary>View technical payload</summary>
                                <pre id="output">No file uploaded yet.</pre>
                            </details>
                        </section>

                        <section>
                            <div class="section-head">
                                <h2>Case Queue</h2>
                                <small id="queue-count">Loading...</small>
                            </div>
                            <div class="queue-toolbar">
                                <div class="queue-filter search-filter">
                                    <label for="queue-search">Search</label>
                                    <input type="search" id="queue-search" placeholder="Subject or sender..." />
                                </div>
                                <div class="queue-filter">
                                    <label for="queue-status">Status</label>
                                    <select id="queue-status">
                                        <option value="">All statuses</option>
                                        <option value="new">New</option>
                                        <option value="investigating">Investigating</option>
                                        <option value="closed">Closed</option>
                                    </select>
                                </div>
                                <div class="queue-filter">
                                    <label for="queue-risk">Risk level</label>
                                    <select id="queue-risk">
                                        <option value="">All risk levels</option>
                                        <option value="high">High</option>
                                        <option value="medium">Medium</option>
                                        <option value="low">Low</option>
                                    </select>
                                </div>
                                <div class="queue-filter">
                                    <label for="queue-sort">Sort by</label>
                                    <select id="queue-sort">
                                        <option value="created_at:desc">Newest first</option>
                                        <option value="created_at:asc">Oldest first</option>
                                        <option value="risk_score:desc">Highest risk first</option>
                                        <option value="risk_score:asc">Lowest risk first</option>
                                    </select>
                                </div>
                            </div>
                            <div class="table-wrap">
                                <table class="queue-table">
                                    <thead><tr><th>ID</th><th>Time</th><th>Risk</th><th>Status</th></tr></thead>
                                    <tbody id="history-body"><tr><td colspan="4" class="hint">Loading history...</td></tr></tbody>
                                </table>
                            </div>
                            <div class="queue-pagination">
                                <span id="queue-range">Showing 0 of 0</span>
                                <div class="queue-pagination-buttons">
                                    <button type="button" id="queue-prev">Prev</button>
                                    <button type="button" id="queue-next">Next</button>
                                </div>
                            </div>
                        </section>
                    </div>
                </main>
            </div>
        </div>

        <script>
            const form = document.getElementById('upload-form');
            const fileInput = document.getElementById('eml-file');
            const dropzone = document.getElementById('dropzone');
            const fileName = document.getElementById('file-name');
            const submitButton = form.querySelector('button[type="submit"]');
            const imapButton = document.getElementById('imap-button');
            const output = document.getElementById('output');
            const statusNode = document.getElementById('status');

            const sumCase = document.getElementById('sum-case');
            const sumSubject = document.getElementById('sum-subject');
            const sumFrom = document.getElementById('sum-from');
            const sumTo = document.getElementById('sum-to');
            const sumRisk = document.getElementById('sum-risk');
            const sumVt = document.getElementById('sum-vt');
            const sumAbuse = document.getElementById('sum-abuse');

            const riskTag = document.getElementById('risk-tag');
            const riskGauge = document.getElementById('risk-gauge');
            const urlBody = document.getElementById('url-body');
            const urlCount = document.getElementById('url-count');
            const reasonsNode = document.getElementById('reasons');
            const ruleCount = document.getElementById('rule-count');
            const ruleScore = document.getElementById('rule-score');
            const finalDecision = document.getElementById('final-decision');
            const sourceRules = document.getElementById('source-rules');
            const sourceMl = document.getElementById('source-ml');
            const sourceIntel = document.getElementById('source-intel');
            const actionsNode = document.getElementById('actions');
            const historyBody = document.getElementById('history-body');
            const intelStatus = document.getElementById('intel-status');
            const vtResults = document.getElementById('vt-results');
            const abuseResults = document.getElementById('abuse-results');
            const queueSearch = document.getElementById('queue-search');
            const queueStatus = document.getElementById('queue-status');
            const queueRisk = document.getElementById('queue-risk');
            const queueSort = document.getElementById('queue-sort');
            const queueCount = document.getElementById('queue-count');
            const queueRange = document.getElementById('queue-range');
            const queuePrev = document.getElementById('queue-prev');
            const queueNext = document.getElementById('queue-next');
            let selectedCaseId = null;
            const queuePageSize = 10;
            let queueOffset = 0;
            let queueTotal = 0;
            let queueSearchTimer = null;

            function showSelectedFile() {
                fileName.textContent = fileInput.files[0]?.name || 'No file selected';
            }

            fileInput.addEventListener('change', showSelectedFile);
            dropzone.addEventListener('dragover', (event) => {
                event.preventDefault();
                dropzone.classList.add('dragover');
            });
            dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
            dropzone.addEventListener('drop', (event) => {
                event.preventDefault();
                dropzone.classList.remove('dragover');
                if (event.dataTransfer.files.length > 0) {
                    fileInput.files = event.dataTransfer.files;
                    showSelectedFile();
                }
            });

            function riskTheme(level) {
                if (level === 'high') {
                    return { bg: 'var(--red-soft)', color: 'var(--red)', border: '#f0b4b4' };
                }
                if (level === 'medium') {
                    return { bg: 'var(--amber-soft)', color: 'var(--amber)', border: '#ecd39a' };
                }
                return { bg: 'var(--teal-soft)', color: 'var(--teal)', border: '#a6e8e3' };
            }

            function updateRisk(analysis) {
                const level = (analysis.risk_level || 'low').toLowerCase();
                const score = Number(analysis.risk_score || 0);

                sumRisk.textContent = `${level.toUpperCase()} (${score}/100)`;
                riskGauge.style.width = `${Math.max(0, Math.min(score, 100))}%`;

                const t = riskTheme(level);
                riskTag.textContent = `${level.toUpperCase()} RISK`;
                riskTag.style.background = t.bg;
                riskTag.style.color = t.color;
                riskTag.style.borderColor = t.border;
            }

            function updateReasons(analysis, enrichment) {
                const reasons = Array.isArray(analysis.reasons) ? analysis.reasons : [];
                const count = Number(analysis.rule_count || reasons.length || 0);
                const score = Number(analysis.risk_score || 0);
                const level = (analysis.risk_level || 'low').toUpperCase();
                const vtRows = Array.isArray(enrichment?.virustotal?.results) ? enrichment.virustotal.results : [];
                const abuseRows = Array.isArray(enrichment?.abuseipdb?.results) ? enrichment.abuseipdb.results : [];
                const intelReasons = [
                    ...vtRows
                        .filter((result) => Number(result.malicious || 0) > 0 || Number(result.suspicious || 0) > 0)
                        .map((result) => ({
                            detail: `VirusTotal flagged ${result.url || 'URL'} (${result.malicious || 0} malicious, ${result.suspicious || 0} suspicious)`,
                            rule: 'virustotal_reputation',
                            points: '0 (advisory)',
                        })),
                    ...abuseRows
                        .filter((result) => Number(result.abuse_confidence_score || 0) >= 50)
                        .map((result) => ({
                            detail: `AbuseIPDB high-risk IP ${result.ip || 'unknown'} (${result.abuse_confidence_score}% confidence)`,
                            rule: 'abuseipdb_reputation',
                            points: '0 (advisory)',
                        })),
                ];
                const allReasons = [...reasons, ...intelReasons];
                ruleCount.textContent = count === 0 ? 'No matches' : `${count} ${count === 1 ? 'rule' : 'rules'}`;
                ruleScore.textContent = `${score}/100`;
                sourceRules.textContent = `${score}/100`;
                if (sourceMl) {
                    if (analysis.ml && analysis.ml.enabled) {
                        sourceMl.textContent = `${analysis.ml.phishing_percent}% (${(analysis.ml.prediction || '').toUpperCase()})`;
                    } else {
                        sourceMl.textContent = 'Not enabled';
                    }
                }
                finalDecision.textContent = `${level} (${score}/100)`;

                if (allReasons.length === 0) {
                    reasonsNode.innerHTML = '<tr><td colspan="3" class="hint">No suspicious rules were triggered.</td></tr>';
                } else {
                    reasonsNode.innerHTML = allReasons
                        .map((r) => `<tr><td>${r.detail || 'Suspicious evidence detected'}</td><td class="mono">${r.rule || 'rule'}</td><td class="points">${typeof r.points === 'number' ? '+' : ''}${r.points || 0}</td></tr>`)
                        .join('');
                }

                const actions = score >= 70
                    ? [
                        { tag: 'CRITICAL', text: 'Quarantine reported message from target recipient mailbox immediately' },
                        { tag: 'BLOCK IOC', text: 'Block confirmed malicious URLs & IP indicators on Gateway / Firewall' },
                        { tag: 'USER AUDIT', text: 'Audit end-user click logs & authentication events for compromise' },
                        { tag: 'ESCALATE', text: 'Escalate incident to Tier-2 SOC Incident Response Team' }
                      ]
                    : score >= 40
                        ? [
                            { tag: 'VERIFY', text: 'Verify sender authentication headers (SPF / DKIM / DMARC) & domain age' },
                            { tag: 'INSPECT', text: 'Inspect extracted URL indicators & shortener redirect targets' },
                            { tag: 'ADVISE', text: 'Notify recipient to avoid clicking embedded links or entering credentials' }
                          ]
                        : [
                            { tag: 'ALLOW', text: 'Benign email — release for normal inbox delivery after analyst check' },
                            { tag: 'MONITOR', text: 'No immediate IOC blocking required — log transaction for metric tracking' }
                          ];
                actionsNode.innerHTML = actions.map((act) => `
                    <li class="action-item action-tag-${act.tag.toLowerCase().replace(/ /g, '-')}">
                        <span class="action-badge">${act.tag}</span>
                        <span class="action-text">${act.text}</span>
                    </li>
                `).join('');
            }

            function updateThreatIntel(enrichment) {
                const vt = enrichment.virustotal || {};
                const abuse = enrichment.abuseipdb || {};
                const summary = enrichment.summary || {};
                const vtRows = Array.isArray(vt.results) ? vt.results : [];
                const abuseRows = Array.isArray(abuse.results) ? abuse.results : [];
                const flaggedUrls = Number(summary.vt_flagged_urls || 0);
                const highRiskIps = Number(summary.abuse_high_risk_ips || 0);

                intelStatus.textContent = `${summary.checked_urls || 0} URLs / ${summary.checked_ips || 0} IPs checked`;
                sourceIntel.textContent = flaggedUrls > 0 || highRiskIps > 0 ? 'High confidence' : 'Advisory';
                vtResults.innerHTML = vtRows.length
                    ? vtRows.map((r) => `<div class="intel-item"><strong>${r.url}</strong><br>Malicious: ${r.malicious ?? '-'} | Suspicious: ${r.suspicious ?? '-'}</div>`).join('')
                    : `<div class="intel-item">${vt.note || 'No VirusTotal results.'}</div>`;
                abuseResults.innerHTML = abuseRows.length
                    ? abuseRows.map((r) => `<div class="intel-item"><strong>${r.ip}</strong><br>Abuse score: ${r.abuse_confidence_score ?? '-'} | Reports: ${r.total_reports ?? '-'}</div>`).join('')
                    : `<div class="intel-item">${abuse.note || 'No AbuseIPDB results.'}</div>`;
            }

            function updateSummary(payload) {
                const parsed = payload.parsed || {};
                const analysis = payload.analysis || {};
                const enrichment = payload.enrichment || {};
                const enrichmentSummary = enrichment.summary || {};

                const caseId = payload.case_id ?? payload.id ?? '-';
                sumCase.textContent = caseId;
                sumSubject.textContent = parsed.subject || '(no subject)';
                sumFrom.textContent = parsed.from || '-';
                sumTo.textContent = Array.isArray(parsed.to) ? parsed.to.length : 0;
                sumVt.textContent = enrichmentSummary.vt_flagged_urls ?? 0;
                sumAbuse.textContent = enrichmentSummary.abuse_high_risk_ips ?? 0;

                updateRisk(analysis);
                updateReasons(analysis, enrichment);
                updateThreatIntel(enrichment);

                const urls = Array.isArray(parsed.urls) ? parsed.urls : [];
                urlCount.textContent = `${urls.length} found`;

                if (urls.length === 0) {
                    urlBody.innerHTML = '<tr><td colspan="2" class="hint">No URLs found in this email.</td></tr>';
                    return;
                }

                urlBody.innerHTML = urls
                    .map((url, idx) => `<tr><td>${idx + 1}</td><td class="mono">${url}</td></tr>`)
                    .join('');
            }

            function setActiveHistoryRow(caseId) {
                const rows = historyBody.querySelectorAll('.history-row');
                rows.forEach((row) => {
                    const rowId = Number(row.getAttribute('data-case-id'));
                    row.classList.toggle('active', rowId === caseId);
                });
            }

            async function loadCaseDetails(caseId) {
                try {
                    statusNode.textContent = `Loading case #${caseId}...`;
                    const response = await fetch(`/history/${caseId}`);
                    const data = await response.json();
                    if (!response.ok) {
                        statusNode.textContent = 'Unable to load selected case.';
                        return;
                    }

                    selectedCaseId = caseId;
                    setActiveHistoryRow(caseId);
                    updateSummary(data);
                    output.textContent = JSON.stringify(data, null, 2);
                    statusNode.textContent = `Loaded case #${caseId}.`;
                } catch (_error) {
                    statusNode.textContent = 'Unable to load selected case.';
                }
            }

            async function updateCaseStatus(caseId, status) {
                try {
                    const response = await fetch(`/history/${caseId}/status`, {
                        method: 'PATCH',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ status }),
                    });
                    if (!response.ok) {
                        statusNode.textContent = `Unable to update status for case #${caseId}.`;
                        return;
                    }
                    statusNode.textContent = `Case #${caseId} marked as ${status}.`;
                } catch (_error) {
                    statusNode.textContent = `Unable to update status for case #${caseId}.`;
                }
            }

            function buildHistoryQuery() {
                const params = new URLSearchParams();
                params.set('limit', String(queuePageSize));
                params.set('offset', String(queueOffset));

                const search = queueSearch.value.trim();
                if (search) params.set('search', search);
                if (queueStatus.value) params.set('status', queueStatus.value);
                if (queueRisk.value) params.set('risk_level', queueRisk.value);

                const [sortBy, sortDir] = queueSort.value.split(':');
                params.set('sort_by', sortBy);
                params.set('sort_dir', sortDir);
                return params.toString();
            }

            async function loadHistory() {
                try {
                    const response = await fetch(`/history?${buildHistoryQuery()}`);
                    const data = await response.json();
                    if (!response.ok) {
                        historyBody.innerHTML = '<tr><td colspan="4" class="hint">Unable to load queue.</td></tr>';
                        return;
                    }

                    const rows = Array.isArray(data.items) ? data.items : [];
                    queueTotal = Number(data.total || 0);
                    queueCount.textContent = `${queueTotal} case${queueTotal === 1 ? '' : 's'}`;

                    const rangeStart = queueTotal === 0 ? 0 : queueOffset + 1;
                    const rangeEnd = Math.min(queueOffset + rows.length, queueTotal);
                    queueRange.textContent = `Showing ${rangeStart}-${rangeEnd} of ${queueTotal}`;
                    queuePrev.disabled = queueOffset === 0;
                    queueNext.disabled = queueOffset + queuePageSize >= queueTotal;

                    if (rows.length === 0) {
                        historyBody.innerHTML = '<tr><td colspan="4" class="hint">No investigations match these filters.</td></tr>';
                        return;
                    }

                    historyBody.innerHTML = rows
                        .map((r) => {
                            const level = (r.risk_level || 'low').toLowerCase();
                            const badgeClass = level === 'high' ? 'sev-high' : level === 'medium' ? 'sev-medium' : 'sev-low';
                            const badgeText = level === 'high' ? 'HIGH' : level === 'medium' ? 'MED' : 'LOW';
                            const rowStatus = (r.status || 'new').toLowerCase();
                            return `<tr class="history-row ${badgeClass}" data-case-id="${r.id}" role="button" tabindex="0" title="Open case #${r.id}">
                                <td class="mono">#${r.id}</td>
                                <td>
                                    <div style="font-weight:600; font-size:0.81rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:180px;">${r.subject || '(no subject)'}</div>
                                    <div style="font-size:0.72rem; color:var(--ink-600);">${r.created_at || '-'}</div>
                                </td>
                                <td><span class="sev-badge ${badgeClass}">${badgeText}</span></td>
                                <td>
                                    <select class="status-select status-${rowStatus}" data-case-id="${r.id}">
                                        <option value="new" ${rowStatus === 'new' ? 'selected' : ''}>New</option>
                                        <option value="investigating" ${rowStatus === 'investigating' ? 'selected' : ''}>Investigating</option>
                                        <option value="closed" ${rowStatus === 'closed' ? 'selected' : ''}>Closed</option>
                                    </select>
                                </td>
                            </tr>`;
                        })
                        .join('');

                    historyBody.querySelectorAll('.history-row').forEach((row) => {
                        const openRow = () => {
                            const id = Number(row.getAttribute('data-case-id'));
                            if (!Number.isNaN(id)) {
                                loadCaseDetails(id);
                            }
                        };
                        row.addEventListener('click', openRow);
                        row.addEventListener('keydown', (event) => {
                            if (event.key === 'Enter' || event.key === ' ') {
                                event.preventDefault();
                                openRow();
                            }
                        });
                    });

                    historyBody.querySelectorAll('.status-select').forEach((select) => {
                        select.addEventListener('click', (event) => event.stopPropagation());
                        select.addEventListener('change', async (event) => {
                            event.stopPropagation();
                            const caseId = Number(select.getAttribute('data-case-id'));
                            const newStatus = select.value;
                            select.className = `status-select status-${newStatus}`;
                            await updateCaseStatus(caseId, newStatus);
                        });
                    });

                    if (selectedCaseId !== null) {
                        setActiveHistoryRow(selectedCaseId);
                    } else if (rows.length > 0) {
                        loadCaseDetails(rows[0].id);
                    }
                } catch (_error) {
                    historyBody.innerHTML = '<tr><td colspan="4" class="hint">Unable to load queue.</td></tr>';
                }
            }

            queueSearch.addEventListener('input', () => {
                clearTimeout(queueSearchTimer);
                queueSearchTimer = setTimeout(() => {
                    queueOffset = 0;
                    loadHistory();
                }, 300);
            });
            queueStatus.addEventListener('change', () => {
                queueOffset = 0;
                loadHistory();
            });
            queueRisk.addEventListener('change', () => {
                queueOffset = 0;
                loadHistory();
            });
            queueSort.addEventListener('change', () => {
                queueOffset = 0;
                loadHistory();
            });
            queuePrev.addEventListener('click', () => {
                queueOffset = Math.max(0, queueOffset - queuePageSize);
                loadHistory();
            });
            queueNext.addEventListener('click', () => {
                if (queueOffset + queuePageSize < queueTotal) {
                    queueOffset += queuePageSize;
                    loadHistory();
                }
            });

            form.addEventListener('submit', async (event) => {
                event.preventDefault();
                const file = fileInput.files[0];
                if (!file) {
                    statusNode.textContent = 'Choose a .eml file first.';
                    return;
                }

                const formData = new FormData();
                formData.append('file', file);

                statusNode.textContent = 'Analyzing and storing case...';
                output.textContent = 'Analyzing...';
                submitButton.disabled = true;
                submitButton.textContent = 'Analyzing...';
                try {
                    const response = await fetch('/upload-eml', {
                        method: 'POST',
                        body: formData,
                    });

                    const data = await response.json();
                    if (!response.ok) {
                        statusNode.textContent = 'Request failed.';
                        output.textContent = JSON.stringify(data, null, 2);
                        return;
                    }

                    statusNode.textContent = `Case #${data.case_id} saved successfully.`;
                    updateSummary(data);
                    output.textContent = JSON.stringify(data, null, 2);
                    selectedCaseId = Number(data.case_id);
                    await loadHistory();
                    setActiveHistoryRow(selectedCaseId);
                } catch (error) {
                    statusNode.textContent = 'Upload failed.';
                    output.textContent = 'Upload failed: ' + error;
                } finally {
                    submitButton.disabled = false;
                    submitButton.textContent = 'Analyze and Save Case';
                }
            });

            imapButton.addEventListener('click', async () => {
                statusNode.textContent = 'Fetching unread mailbox messages...';
                imapButton.disabled = true;
                imapButton.textContent = 'Fetching...';
                try {
                    const response = await fetch('/imap/fetch?limit=10', { method: 'POST' });
                    const data = await response.json();
                    if (!response.ok) {
                        statusNode.textContent = data.detail || 'Mailbox fetch failed.';
                        return;
                    }

                    statusNode.textContent = `${data.processed} mailbox case(s) processed.`;
                    await loadHistory();
                    if (data.results?.length) {
                        const latest = data.results.find((item) => item.status === 'processed');
                        if (latest?.case_id) {
                            selectedCaseId = Number(latest.case_id);
                            await loadCaseDetails(selectedCaseId);
                        }
                    }
                } catch (_error) {
                    statusNode.textContent = 'Mailbox fetch failed.';
                } finally {
                    imapButton.disabled = false;
                    imapButton.textContent = 'Fetch unread mailbox';
                }
            });

            async function loadHealth() {
                try {
                    const response = await fetch('/health');
                    const data = await response.json();
                    const integrations = data.integrations || {};

                    const pillVt = document.getElementById('pill-vt');
                    const pillAbuse = document.getElementById('pill-abuse');
                    const pillImap = document.getElementById('pill-imap');
                    const pillMl = document.getElementById('pill-ml');

                    if (pillVt) pillVt.classList.toggle('active', !!integrations.virustotal_enabled);
                    if (pillAbuse) pillAbuse.classList.toggle('active', !!integrations.abuseipdb_enabled);
                    if (pillImap) pillImap.classList.toggle('active', !!integrations.imap_configured || !!integrations.gmail_oauth_authorized);
                    if (pillMl) pillMl.classList.toggle('active', !!integrations.ml_model_loaded);
                } catch (_e) {}
            }

            loadHealth();
            loadHistory();
        </script>
    </body>
</html>
"""


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "phase": 7,
        "integrations": {
            "virustotal_enabled": bool(os.getenv("VIRUSTOTAL_API_KEY")),
            "abuseipdb_enabled": bool(os.getenv("ABUSEIPDB_API_KEY")),
            "imap_configured": bool(os.getenv("IMAP_HOST") and os.getenv("IMAP_USER")),
            "gmail_oauth_authorized": GMAIL_TOKEN_PATH.exists(),
            "ml_model_loaded": is_model_available(),
        },
    }


@app.get("/history")
def history(
    limit: int = 10,
    offset: int = 0,
    status: str | None = None,
    risk_level: str | None = None,
    search: str | None = None,
    sort_by: str = "created_at",
    sort_dir: str = "desc",
) -> dict:
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 200")
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset must be zero or greater")
    if status and status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")
    if risk_level and risk_level not in {"low", "medium", "high"}:
        raise HTTPException(status_code=400, detail="risk_level must be one of ['low', 'medium', 'high']")
    if sort_by not in {"created_at", "risk_score"}:
        raise HTTPException(status_code=400, detail="sort_by must be one of ['created_at', 'risk_score']")
    if sort_dir not in {"asc", "desc"}:
        raise HTTPException(status_code=400, detail="sort_dir must be one of ['asc', 'desc']")

    rows = list_investigations(
        limit=limit,
        offset=offset,
        status=status,
        risk_level=risk_level,
        search=search,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )
    total = count_investigations(status=status, risk_level=risk_level, search=search)
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


@app.get("/history/{case_id}")
def history_case(case_id: int) -> dict:
    case = get_investigation(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return case


@app.patch("/history/{case_id}/status")
def update_case_status(case_id: int, payload: dict) -> dict:
    status = (payload or {}).get("status", "")
    if status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")

    updated = update_investigation_status(case_id, status)
    if not updated:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return {"case_id": case_id, "status": status}


def process_email(filename: str, raw: bytes) -> int:
    parsed = parse_email(raw)
    ml_result = predict_phishing_text(parsed.get("subject", ""), parsed.get("body_preview", ""))
    analysis = analyze_phishing_risk(parsed, ml_result=ml_result)
    enrichment = enrich_email(parsed)
    return save_investigation(filename, parsed, analysis, enrichment)


@app.post("/upload-eml")
async def upload_eml(file: UploadFile = File(...)) -> dict:
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Please upload a .eml file")

    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    parsed = parse_email(raw)
    ml_result = predict_phishing_text(parsed.get("subject", ""), parsed.get("body_preview", ""))
    analysis = analyze_phishing_risk(parsed, ml_result=ml_result)
    enrichment = enrich_email(parsed)
    case_id = save_investigation(file.filename, parsed, analysis, enrichment)
    return {
        "case_id": case_id,
        "filename": file.filename,
        "parsed": parsed,
        "analysis": analysis,
        "enrichment": enrichment,
    }


@app.post("/imap/fetch")
def fetch_imap(limit: int = 10) -> dict:
    if limit < 1 or limit > 50:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 50")

    host = (os.getenv("IMAP_HOST") or "").strip()
    username = (os.getenv("IMAP_USER") or "").strip()
    if not host or not username:
        raise HTTPException(status_code=400, detail="Set IMAP_HOST and IMAP_USER in .env before fetching mail")

    try:
        access_token = get_access_token(GMAIL_CLIENT_SECRET_PATH, GMAIL_TOKEN_PATH)
        results = fetch_unseen(
            processor=process_email,
            host=host,
            port=int(os.getenv("IMAP_PORT", "993")),
            username=username,
            access_token=access_token,
            folder=(os.getenv("IMAP_FOLDER") or "INBOX").strip(),
            limit=limit,
        )
    except imaplib.IMAP4.error as exc:
        message = str(exc).lower()
        if "authenticationfailed" in message or "invalid credentials" in message:
            detail = "Gmail OAuth authentication failed. Re-authorize with: python -m app.gmail_oauth"
        else:
            detail = "IMAP server rejected the mailbox request. Check IMAP_HOST, IMAP_PORT, and IMAP_FOLDER."
        raise HTTPException(status_code=502, detail=detail) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=f"IMAP connection failed: {exc}") from exc

    return {
        "fetched": len(results),
        "processed": sum(item["status"] == "processed" for item in results),
        "results": results,
    }
