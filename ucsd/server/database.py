"""SQLite persistence layer for UCSD analysis history, metadata, and comparisons."""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

DEFAULT_DB_PATH = Path("data/db/ucsd.db")


def get_db_path() -> Path:
    """Return the configured database path, creating parent directories if needed."""
    env_path = os.environ.get("UCSD_DB_PATH")
    p = Path(env_path) if env_path else DEFAULT_DB_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


@contextmanager
def get_connection(db_path: Optional[Path] = None) -> Generator[sqlite3.Connection, None, None]:
    """Yield a connection with foreign keys enabled, WAL mode, and dict-like rows."""
    path = db_path or get_db_path()
    conn = sqlite3.connect(str(path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Optional[Path] = None) -> None:
    """Initialize database tables and indexes."""
    with get_connection(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                file_name TEXT NOT NULL,
                file_size_bytes INTEGER NOT NULL,
                sha256 TEXT,
                package_name TEXT,
                version_code INTEGER,
                version_name TEXT,
                status TEXT NOT NULL,
                error_message TEXT,
                candidate_count INTEGER DEFAULT 0,
                strong_count INTEGER DEFAULT 0,
                unresolved_count INTEGER DEFAULT 0,
                report_json_path TEXT,
                report_html_path TEXT,
                report_data TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_analyses_created_at
            ON analyses(created_at DESC)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_analyses_status
            ON analyses(status)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_analyses_sha256
            ON analyses(sha256)
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS comparisons (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                analysis_ids TEXT NOT NULL,
                target_count INTEGER NOT NULL,
                strong_duplicates_count INTEGER DEFAULT 0,
                proven_conflicts_count INTEGER DEFAULT 0,
                report_data TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_comparisons_created_at
            ON comparisons(created_at DESC)
            """
        )


def create_analysis_record(
    analysis_id: str,
    file_name: str,
    file_size_bytes: int,
    status: str = "running",
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Create a new analysis job record with initial status."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO analyses (
                id, file_name, file_size_bytes, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (analysis_id, file_name, file_size_bytes, status, now_iso, now_iso),
        )
    return get_analysis_record(analysis_id, db_path=db_path)  # type: ignore[return-value]


def update_analysis_record(
    analysis_id: str,
    status: str,
    sha256: Optional[str] = None,
    package_name: Optional[str] = None,
    version_code: Optional[int] = None,
    version_name: Optional[str] = None,
    candidate_count: int = 0,
    strong_count: int = 0,
    unresolved_count: int = 0,
    report_json_path: Optional[str] = None,
    report_html_path: Optional[str] = None,
    report_data: Optional[Dict[str, Any]] = None,
    error_message: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Update an analysis job record after completion or error."""
    now_iso = datetime.now(timezone.utc).isoformat()
    raw_json = json.dumps(report_data) if report_data else None

    with get_connection(db_path) as conn:
        conn.execute(
            """
            UPDATE analyses SET
                status = ?,
                sha256 = COALESCE(?, sha256),
                package_name = COALESCE(?, package_name),
                version_code = COALESCE(?, version_code),
                version_name = COALESCE(?, version_name),
                candidate_count = ?,
                strong_count = ?,
                unresolved_count = ?,
                report_json_path = COALESCE(?, report_json_path),
                report_html_path = COALESCE(?, report_html_path),
                report_data = COALESCE(?, report_data),
                error_message = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                status,
                sha256,
                package_name,
                version_code,
                version_name,
                candidate_count,
                strong_count,
                unresolved_count,
                report_json_path,
                report_html_path,
                raw_json,
                error_message,
                now_iso,
                analysis_id,
            ),
        )
    return get_analysis_record(analysis_id, db_path=db_path)


def get_analysis_record(
    analysis_id: str,
    include_raw_data: bool = False,
    db_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Fetch an analysis record by ID."""
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "SELECT * FROM analyses WHERE id = ?",
            (analysis_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        if not include_raw_data:
            d.pop("report_data", None)
        else:
            if d.get("report_data"):
                try:
                    d["report_data"] = json.loads(d["report_data"])
                except Exception:
                    pass
        return d


def list_analyses(
    page: int = 1,
    page_size: int = 20,
    status: Optional[str] = None,
    query: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """Return paginated analysis records sorted by created_at DESC with total count."""
    offset = max(0, (page - 1) * page_size)
    conditions: List[str] = []
    params: List[Any] = []

    if status:
        conditions.append("status = ?")
        params.append(status)

    if query:
        conditions.append("(file_name LIKE ? OR package_name LIKE ? OR sha256 LIKE ?)")
        wildcard = f"%{query}%"
        params.extend([wildcard, wildcard, wildcard])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with get_connection(db_path) as conn:
        count_cursor = conn.execute(f"SELECT COUNT(*) as total FROM analyses {where_clause}", params)
        total = count_cursor.fetchone()["total"]

        query_sql = f"""
            SELECT id, file_name, file_size_bytes, sha256, package_name, version_code,
                   version_name, status, error_message, candidate_count, strong_count,
                   unresolved_count, report_json_path, report_html_path, created_at, updated_at
            FROM analyses
            {where_clause}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """
        rows = conn.execute(query_sql, params + [page_size, offset]).fetchall()
        items = [dict(r) for r in rows]

    return items, total


def delete_analysis_record(analysis_id: str, db_path: Optional[Path] = None) -> bool:
    """Delete an analysis record from SQLite."""
    with get_connection(db_path) as conn:
        cursor = conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
        return cursor.rowcount > 0


def create_comparison_record(
    comparison_id: str,
    title: str,
    analysis_ids: List[str],
    report_data: Dict[str, Any],
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Store a cross-APK comparison result."""
    now_iso = datetime.now(timezone.utc).isoformat()
    strong_dups = report_data.get("strong_duplicate_static_registrations_count", 0)
    proven = report_data.get("proven_registration_conflicts_count", 0)

    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO comparisons (
                id, title, analysis_ids, target_count, strong_duplicates_count,
                proven_conflicts_count, report_data, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                comparison_id,
                title,
                json.dumps(analysis_ids),
                len(analysis_ids),
                strong_dups,
                proven,
                json.dumps(report_data),
                now_iso,
            ),
        )
    return get_comparison_record(comparison_id, db_path=db_path)  # type: ignore[return-value]


def get_comparison_record(
    comparison_id: str,
    include_raw_data: bool = True,
    db_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieve comparison record by ID."""
    with get_connection(db_path) as conn:
        cursor = conn.execute("SELECT * FROM comparisons WHERE id = ?", (comparison_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["analysis_ids"] = json.loads(d["analysis_ids"])
        except Exception:
            d["analysis_ids"] = []

        if include_raw_data and d.get("report_data"):
            try:
                d["report_data"] = json.loads(d["report_data"])
            except Exception:
                pass
        elif not include_raw_data:
            d.pop("report_data", None)
        return d


def list_comparisons(
    limit: int = 20,
    db_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """List recent comparison records."""
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id, title, analysis_ids, target_count, strong_duplicates_count,
                   proven_conflicts_count, created_at
            FROM comparisons
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["analysis_ids"] = json.loads(d["analysis_ids"])
            except Exception:
                d["analysis_ids"] = []
            result.append(d)
        return result


def get_dashboard_metrics(db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Calculate aggregate statistics from persistent SQLite tables."""
    with get_connection(db_path) as conn:
        # Totals and statuses
        cur = conn.execute(
            """
            SELECT
                COUNT(*) as total_apks,
                SUM(CASE WHEN status IN ('success', 'partial') THEN 1 ELSE 0 END) as successful_count,
                SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as failed_count,
                SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running_count,
                SUM(candidate_count) as total_candidates,
                SUM(strong_count) as total_strong_registrations,
                SUM(unresolved_count) as total_unresolved_patterns
            FROM analyses
            """
        )
        row = cur.fetchone()
        stats = {
            "total_apks": row["total_apks"] or 0,
            "successful_analyses": row["successful_count"] or 0,
            "failed_analyses": row["failed_count"] or 0,
            "running_analyses": row["running_count"] or 0,
            "candidate_only": row["total_candidates"] or 0,
            "strong_static_registrations": row["total_strong_registrations"] or 0,
            "unresolved_patterns": row["total_unresolved_patterns"] or 0,
        }

        # Cross-APK comparisons total conflicts
        cmp_cur = conn.execute(
            """
            SELECT
                COUNT(*) as total_comparisons,
                SUM(strong_duplicates_count) as total_strong_duplicates
            FROM comparisons
            """
        )
        cmp_row = cmp_cur.fetchone()
        stats["total_comparisons"] = cmp_row["total_comparisons"] or 0
        stats["cross_apk_conflicts"] = cmp_row["total_strong_duplicates"] or 0

        # Recent 5 analyses
        recent_cur = conn.execute(
            """
            SELECT id, file_name, file_size_bytes, sha256, package_name,
                   version_name, status, strong_count, candidate_count,
                   unresolved_count, created_at
            FROM analyses
            ORDER BY created_at DESC
            LIMIT 5
            """
        )
        stats["recent_analyses"] = [dict(r) for r in recent_cur.fetchall()]

        # Recent errors
        err_cur = conn.execute(
            """
            SELECT id, file_name, error_message, created_at
            FROM analyses
            WHERE status = 'error' AND error_message IS NOT NULL
            ORDER BY created_at DESC
            LIMIT 5
            """
        )
        stats["recent_errors"] = [dict(r) for r in err_cur.fetchall()]

    return stats
