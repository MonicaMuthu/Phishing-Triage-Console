import json
import sqlite3
from pathlib import Path

DB_PATH = Path("triage_history.db")

VALID_STATUSES = {"new", "investigating", "closed"}
VALID_SORT_COLUMNS = {"created_at": "created_at", "risk_score": "risk_score"}


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                filename TEXT NOT NULL,
                subject TEXT,
                sender TEXT,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                parsed_json TEXT NOT NULL,
                analysis_json TEXT NOT NULL
            )
            """
        )

        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(investigations)").fetchall()
        }
        if "enrichment_json" not in columns:
            conn.execute("ALTER TABLE investigations ADD COLUMN enrichment_json TEXT")
        if "status" not in columns:
            conn.execute("ALTER TABLE investigations ADD COLUMN status TEXT NOT NULL DEFAULT 'new'")

        conn.commit()
    finally:
        conn.close()


def save_investigation(filename: str, parsed: dict, analysis: dict, enrichment: dict | None = None) -> int:
    conn = _connect()
    try:
        cursor = conn.execute(
            """
            INSERT INTO investigations (
                filename, subject, sender, risk_score, risk_level, parsed_json, analysis_json, enrichment_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                filename,
                parsed.get("subject", ""),
                parsed.get("from", ""),
                int(analysis.get("risk_score", 0)),
                analysis.get("risk_level", "low"),
                json.dumps(parsed),
                json.dumps(analysis),
                json.dumps(enrichment or {}),
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)
    finally:
        conn.close()


def list_investigations(
    limit: int = 50,
    offset: int = 0,
    status: str | None = None,
    risk_level: str | None = None,
    search: str | None = None,
    sort_by: str = "created_at",
    sort_dir: str = "desc",
) -> list[dict]:
    conn = _connect()
    try:
        clauses: list[str] = []
        params: list = []

        if status and status in VALID_STATUSES:
            clauses.append("status = ?")
            params.append(status)
        if risk_level and risk_level in {"low", "medium", "high"}:
            clauses.append("risk_level = ?")
            params.append(risk_level)
        if search:
            clauses.append("(subject LIKE ? OR sender LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like])

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        order_column = VALID_SORT_COLUMNS.get(sort_by, "created_at")
        order_dir = "ASC" if sort_dir == "asc" else "DESC"

        rows = conn.execute(
            f"""
            SELECT id, created_at, filename, subject, sender, risk_score, risk_level, status
            FROM investigations
            {where_sql}
            ORDER BY {order_column} {order_dir}, id {order_dir}
            LIMIT ? OFFSET ?
            """,
            (*params, limit, offset),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def count_investigations(
    status: str | None = None,
    risk_level: str | None = None,
    search: str | None = None,
) -> int:
    conn = _connect()
    try:
        clauses: list[str] = []
        params: list = []

        if status and status in VALID_STATUSES:
            clauses.append("status = ?")
            params.append(status)
        if risk_level and risk_level in {"low", "medium", "high"}:
            clauses.append("risk_level = ?")
            params.append(risk_level)
        if search:
            clauses.append("(subject LIKE ? OR sender LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like])

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        row = conn.execute(
            f"SELECT COUNT(*) AS total FROM investigations {where_sql}",
            params,
        ).fetchone()
        return int(row["total"])
    finally:
        conn.close()


def update_investigation_status(case_id: int, status: str) -> bool:
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Must be one of {sorted(VALID_STATUSES)}")

    conn = _connect()
    try:
        cursor = conn.execute(
            "UPDATE investigations SET status = ? WHERE id = ?",
            (status, case_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def get_investigation(case_id: int) -> dict | None:
    conn = _connect()
    try:
        row = conn.execute(
            """
            SELECT * FROM investigations WHERE id = ?
            """,
            (case_id,),
        ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["parsed"] = json.loads(data.pop("parsed_json"))
        data["analysis"] = json.loads(data.pop("analysis_json"))
        raw_enrichment = data.pop("enrichment_json", None)
        if raw_enrichment:
            data["enrichment"] = json.loads(raw_enrichment)
        else:
            data["enrichment"] = {}
        return data
    finally:
        conn.close()