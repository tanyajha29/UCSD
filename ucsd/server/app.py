"""FastAPI Application for UCSD Web Interface and Analysis REST API."""

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import (
    FastAPI,
    File,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import ucsd
from ucsd.knowledge.repository import UUIDKnowledgeBase
from ucsd.server.database import (
    delete_analysis_record,
    get_analysis_record,
    get_comparison_record,
    get_dashboard_metrics,
    init_db,
    list_analyses,
    list_comparisons,
)
from ucsd.server.service import (
    execute_comparison_job,
    start_analysis_job,
)
from ucsd.server.storage import (
    MAX_UPLOAD_SIZE_BYTES,
    delete_analysis_files,
    get_reports_dir,
    get_workspace_dir,
    save_staged_upload,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database and ensure workspace directories on startup."""
    init_db()
    get_workspace_dir()
    get_reports_dir()
    yield


app = FastAPI(
    title="UCSD API",
    description="Universal Candidate Service Detector — REST API & Analysis Engine",
    version=ucsd.__version__,
    lifespan=lifespan,
)

# Enable CORS for standard local frontend development and production
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Enforce defensive security headers on all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# --- Request & Response Schemas ---

class CreateComparisonRequest(BaseModel):
    analysis_ids: List[str] = Field(..., min_length=2, description="List of at least 2 successful analysis IDs")
    title: Optional[str] = Field(None, description="Optional custom title for this comparison")


# --- API Routes ---

@app.get("/api/health")
async def get_health() -> Dict[str, Any]:
    """Check backend, database, and knowledge-base health status."""
    now_iso = datetime.now(timezone.utc).isoformat()
    kb_ver = "unknown"
    kb_count = 0
    kb_status = "unavailable"

    try:
        kb = UUIDKnowledgeBase()
        meta = kb.get_metadata()
        kb_ver = meta.knowledge_base_version
        kb_count = meta.total_entries
        kb_status = "ready"
    except Exception:
        pass

    return {
        "status": "healthy",
        "analyzer_version": ucsd.__version__,
        "timestamp": now_iso,
        "database": "connected",
        "storage": "ready",
        "knowledge_base": {
            "status": kb_status,
            "version": kb_ver,
            "total_entries": kb_count,
        },
        "available_capabilities": [
            "manifest_ble_scanning",
            "dex_uuid_discovery",
            "intra_method_gatt_tracing",
            "kb_conflict_assessment",
            "cross_apk_duplicate_detection",
            "standalone_html_reporting",
        ],
    }


@app.get("/api/dashboard")
async def get_dashboard() -> Dict[str, Any]:
    """Retrieve real aggregate statistics and recent analyses from SQLite."""
    return get_dashboard_metrics()


@app.post("/api/analyses", status_code=status.HTTP_201_CREATED)
async def upload_and_analyze_apk(
    file: UploadFile = File(...),
) -> Dict[str, Any]:
    """Upload an APK, validate archive integrity, and launch background analysis."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=400,
            detail="Invalid file extension: uploaded file must have a .apk extension",
        )

    # Read uploaded bytes with size enforcement
    content = await file.read()
    file_size = len(content)

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty (0 bytes)")
    if file_size > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed limit of {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB",
        )

    # Stage file securely
    import uuid
    pre_id = str(uuid.uuid4())
    staged_path = save_staged_upload(
        analysis_id=pre_id,
        original_filename=file.filename,
        stream_or_bytes=content,
    )

    # Register job and launch analysis
    record = start_analysis_job(
        file_name=file.filename,
        file_size_bytes=file_size,
        staged_apk_path=staged_path,
        cleanup_apk=False,
        run_async=True,
    )

    return {
        "id": record["id"],
        "status": record["status"],
        "file_name": record["file_name"],
        "file_size_bytes": record["file_size_bytes"],
        "created_at": record["created_at"],
    }


@app.get("/api/analyses")
async def get_analyses_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    query: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Retrieve paginated analysis history with optional search and filtering."""
    items, total = list_analyses(
        page=page,
        page_size=page_size,
        status=status,
        query=query,
    )
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


@app.get("/api/analyses/{analysis_id}")
async def get_analysis_status(analysis_id: str) -> Dict[str, Any]:
    """Retrieve status, metadata, and summary findings for an analysis job."""
    record = get_analysis_record(analysis_id, include_raw_data=False)
    if not record:
        raise HTTPException(status_code=404, detail=f"Analysis job '{analysis_id}' not found")
    return record


@app.get("/api/analyses/{analysis_id}/results")
async def get_analysis_results(analysis_id: str) -> Dict[str, Any]:
    """Retrieve the full structured AnalysisReport JSON for a completed analysis."""
    record = get_analysis_record(analysis_id, include_raw_data=True)
    if not record:
        raise HTTPException(status_code=404, detail=f"Analysis job '{analysis_id}' not found")

    if record.get("status") == "running":
        return {
            "id": record["id"],
            "status": "running",
            "message": "Analysis is currently running",
            "report": None,
        }

    report_data = record.get("report_data")
    if not report_data:
        raise HTTPException(
            status_code=404,
            detail=f"No analysis report payload found for job '{analysis_id}'",
        )

    return {
        "id": record["id"],
        "status": record["status"],
        "file_name": record["file_name"],
        "sha256": record["sha256"],
        "report": report_data,
    }


@app.get("/api/analyses/{analysis_id}/reports/json")
async def download_analysis_json(analysis_id: str):
    """Download the original deterministic JSON report for an analysis."""
    record = get_analysis_record(analysis_id, include_raw_data=False)
    if not record:
        raise HTTPException(status_code=404, detail=f"Analysis job '{analysis_id}' not found")

    path_str = record.get("report_json_path")
    if not path_str or not Path(path_str).is_file():
        raise HTTPException(status_code=404, detail="JSON report file not found on disk")

    file_p = Path(path_str)
    return FileResponse(
        path=str(file_p),
        media_type="application/json",
        filename=file_p.name,
    )


@app.get("/api/analyses/{analysis_id}/reports/html")
async def download_or_view_analysis_html(
    analysis_id: str,
    download: bool = Query(False),
):
    """View inline or download the standalone offline HTML report."""
    record = get_analysis_record(analysis_id, include_raw_data=False)
    if not record:
        raise HTTPException(status_code=404, detail=f"Analysis job '{analysis_id}' not found")

    path_str = record.get("report_html_path")
    if not path_str or not Path(path_str).is_file():
        raise HTTPException(status_code=404, detail="HTML report file not found on disk")

    file_p = Path(path_str)
    if download:
        return FileResponse(
            path=str(file_p),
            media_type="text/html; charset=utf-8",
            filename=file_p.name,
        )

    with open(file_p, "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content)


@app.delete("/api/analyses/{analysis_id}")
async def delete_analysis(analysis_id: str) -> Dict[str, Any]:
    """Delete an analysis record and its generated reports from disk."""
    record = get_analysis_record(analysis_id, include_raw_data=False)
    if not record:
        raise HTTPException(status_code=404, detail=f"Analysis job '{analysis_id}' not found")

    # Clean up files
    delete_analysis_files(
        report_json_path=record.get("report_json_path"),
        report_html_path=record.get("report_html_path"),
    )

    # Delete SQLite record
    deleted = delete_analysis_record(analysis_id)
    if not deleted:
        raise HTTPException(status_code=500, detail="Failed to delete analysis record")

    return {"message": "Analysis deleted successfully", "id": analysis_id}


@app.post("/api/comparisons", status_code=status.HTTP_201_CREATED)
async def create_comparison(payload: CreateComparisonRequest) -> Dict[str, Any]:
    """Execute cross-APK conflict evaluation between 2 or more analyzed APKs."""
    try:
        comparison_record = execute_comparison_job(
            analysis_ids=payload.analysis_ids,
            custom_title=payload.title,
        )
        return comparison_record
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Comparison failed: {str(exc)}")


@app.get("/api/comparisons")
async def get_comparisons_history(limit: int = Query(20, ge=1, le=100)) -> List[Dict[str, Any]]:
    """List recent cross-APK comparison records."""
    return list_comparisons(limit=limit)


@app.get("/api/comparisons/{comparison_id}")
async def get_comparison_detail(comparison_id: str) -> Dict[str, Any]:
    """Retrieve full results of a cross-APK conflict evaluation."""
    rec = get_comparison_record(comparison_id, include_raw_data=True)
    if not rec:
        raise HTTPException(status_code=404, detail=f"Comparison '{comparison_id}' not found")
    return rec


@app.get("/api/knowledge-base")
async def get_knowledge_base_entries() -> Dict[str, Any]:
    """Retrieve all curated Bluetooth SIG and vendor assigned UUID records."""
    try:
        kb = UUIDKnowledgeBase()
        meta = kb.get_metadata()
        entries = kb.all_entries()
        return {
            "metadata": meta.model_dump(),
            "entries": [e.model_dump() for e in entries],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load knowledge base: {str(exc)}")


# --- Static Frontend Mounting (SPA Routing) ---

FRONTEND_DIST_DIR = Path("frontend/dist")

if FRONTEND_DIST_DIR.exists() and (FRONTEND_DIST_DIR / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST_DIR / "assets")), name="assets")

    @app.api_route("/{full_path:path}", methods=["GET", "HEAD"], response_class=HTMLResponse)
    async def serve_spa(full_path: str):
        # Don't intercept API paths
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="API route not found")
        index_file = FRONTEND_DIST_DIR / "index.html"
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
else:
    @app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
    async def landing_page():
        return HTMLResponse(
            """
            <!DOCTYPE html>
            <html>
            <head><title>UCSD API Server</title></head>
            <body style="font-family: sans-serif; background: #0b0f19; color: #f1f5f9; padding: 2rem;">
                <h2>UCSD: Universal Candidate Service Detector</h2>
                <p>FastAPI backend is active. Frontend UI is loading or can be built with <code>npm run build</code>.</p>
                <p>View API Documentation: <a style="color: #38bdf8;" href="/docs">/docs</a></p>
                <p>Health Check: <a style="color: #38bdf8;" href="/api/health">/api/health</a></p>
            </body>
            </html>
            """
        )
