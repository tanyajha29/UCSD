"""Integration tests for UCSD FastAPI server and SQLite persistence layer."""

import io
import os
import shutil
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from ucsd.server.app import app
from ucsd.server.database import (
    get_connection,
    init_db,
    create_analysis_record,
    get_analysis_record,
    list_analyses,
    delete_analysis_record,
)
from ucsd.server.service import (
    start_analysis_job,
    execute_comparison_job,
)


@pytest.fixture(scope="module")
def test_env():
    """Setup isolated temporary SQLite database and workspace directory for tests."""
    temp_dir = Path(tempfile.mkdtemp(prefix="ucsd_test_server_"))
    test_db = temp_dir / "test_ucsd.db"
    test_workspace = temp_dir / "workspace"
    test_reports = temp_dir / "reports"

    test_workspace.mkdir(parents=True, exist_ok=True)
    test_reports.mkdir(parents=True, exist_ok=True)

    old_db = os.environ.get("UCSD_DB_PATH")
    old_ws = os.environ.get("UCSD_WORKSPACE_DIR")
    old_rep = os.environ.get("UCSD_REPORTS_DIR")

    os.environ["UCSD_DB_PATH"] = str(test_db)
    os.environ["UCSD_WORKSPACE_DIR"] = str(test_workspace)
    os.environ["UCSD_REPORTS_DIR"] = str(test_reports)

    init_db(test_db)

    client = TestClient(app)

    yield {
        "client": client,
        "temp_dir": temp_dir,
        "db_path": test_db,
        "workspace": test_workspace,
        "reports": test_reports,
    }

    # Teardown
    if old_db:
        os.environ["UCSD_DB_PATH"] = old_db
    else:
        os.environ.pop("UCSD_DB_PATH", None)

    if old_ws:
        os.environ["UCSD_WORKSPACE_DIR"] = old_ws
    else:
        os.environ.pop("UCSD_WORKSPACE_DIR", None)

    if old_rep:
        os.environ["UCSD_REPORTS_DIR"] = old_rep
    else:
        os.environ.pop("UCSD_REPORTS_DIR", None)

    shutil.rmtree(temp_dir, ignore_errors=True)


def test_health_endpoint(test_env):
    """Verify health check reports healthy, connected database, and available capabilities."""
    client = test_env["client"]
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert data["storage"] == "ready"
    assert data["analyzer_version"] == "0.1.0"
    assert "intra_method_gatt_tracing" in data["available_capabilities"]
    assert data["knowledge_base"]["status"] == "ready"
    assert data["knowledge_base"]["total_entries"] >= 20


def test_dashboard_endpoint_structure(test_env):
    """Verify dashboard endpoint returns required metrics schema."""
    client = test_env["client"]
    resp = client.get("/api/dashboard")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_apks" in data
    assert "successful_analyses" in data
    assert "failed_analyses" in data
    assert "strong_static_registrations" in data
    assert "unresolved_patterns" in data
    assert "candidate_only" in data
    assert "recent_analyses" in data


def test_upload_invalid_extension(test_env):
    """Verify upload rejects non-APK file extensions."""
    client = test_env["client"]
    file_content = b"Not an APK"
    resp = client.post(
        "/api/analyses",
        files={"file": ("test.txt", io.BytesIO(file_content), "text/plain")},
    )
    assert resp.status_code == 400
    assert "Invalid file extension" in resp.json()["detail"]


def test_upload_empty_file(test_env):
    """Verify upload rejects 0-byte file."""
    client = test_env["client"]
    resp = client.post(
        "/api/analyses",
        files={"file": ("empty.apk", io.BytesIO(b""), "application/vnd.android.package-archive")},
    )
    assert resp.status_code == 400
    assert "empty" in resp.json()["detail"].lower()


def test_upload_corrupt_apk(test_env):
    """Verify upload of corrupt/malformed zip is recorded as error."""
    client = test_env["client"]
    corrupt_bytes = b"PK\x03\x04corrupted-archive-data"
    resp = client.post(
        "/api/analyses",
        files={"file": ("corrupt.apk", io.BytesIO(corrupt_bytes), "application/vnd.android.package-archive")},
    )
    assert resp.status_code == 201
    job_id = resp.json()["id"]

    # Poll status until finished
    import time
    for _ in range(15):
        st_resp = client.get(f"/api/analyses/{job_id}")
        if st_resp.json()["status"] != "running":
            break
        time.sleep(0.2)

    st_data = client.get(f"/api/analyses/{job_id}").json()
    assert st_data["status"] == "error"
    assert st_data["error_message"] is not None


def test_upload_and_analyze_service_a(test_env):
    """Upload valid service_a.apk fixture and verify real UCSD analysis results."""
    client = test_env["client"]
    apk_path = Path("demo/inputs/service_a.apk")
    if not apk_path.is_file():
        pytest.skip("demo/inputs/service_a.apk not available")

    with open(apk_path, "rb") as f:
        content = f.read()

    resp = client.post(
        "/api/analyses",
        files={"file": ("service_a.apk", io.BytesIO(content), "application/vnd.android.package-archive")},
    )
    assert resp.status_code == 201
    job_id = resp.json()["id"]

    # Poll status
    import time
    for _ in range(30):
        st_resp = client.get(f"/api/analyses/{job_id}")
        if st_resp.json()["status"] != "running":
            break
        time.sleep(0.3)

    detail = client.get(f"/api/analyses/{job_id}").json()
    assert detail["status"] in ("success", "partial")
    assert detail["package_name"] == "org.example.service_a"
    assert detail["strong_count"] == 1
    assert detail["candidate_count"] == 1

    # Verify structured results endpoint
    res_resp = client.get(f"/api/analyses/{job_id}/results")
    assert res_resp.status_code == 200
    res_data = res_resp.json()
    assert res_data["status"] == "success"
    report = res_data["report"]
    assert report["registration_analysis"]["strong_associations_count"] == 1
    findings = report["registration_analysis"]["findings"]
    assert len(findings) == 1
    assert findings[0]["evidence_level"] == "STRONG_STATIC_ASSOCIATION"
    assert findings[0]["normalized_uuid"] == "0000180d-0000-1000-8000-00805f9b34fb"

    # Verify report downloads
    json_resp = client.get(f"/api/analyses/{job_id}/reports/json")
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers["content-type"]

    html_resp = client.get(f"/api/analyses/{job_id}/reports/html")
    assert html_resp.status_code == 200
    assert "<!DOCTYPE html>" in html_resp.text


def test_upload_and_analyze_client_only(test_env):
    """Upload client_only.apk and verify UUID_CANDIDATE_ONLY evidence."""
    client = test_env["client"]
    apk_path = Path("demo/inputs/client_only.apk")
    if not apk_path.is_file():
        pytest.skip("demo/inputs/client_only.apk not available")

    with open(apk_path, "rb") as f:
        content = f.read()

    resp = client.post(
        "/api/analyses",
        files={"file": ("client_only.apk", io.BytesIO(content), "application/vnd.android.package-archive")},
    )
    assert resp.status_code == 201
    job_id = resp.json()["id"]

    # Poll status
    import time
    for _ in range(30):
        st_resp = client.get(f"/api/analyses/{job_id}")
        if st_resp.json()["status"] != "running":
            break
        time.sleep(0.3)

    detail = client.get(f"/api/analyses/{job_id}").json()
    assert detail["status"] in ("success", "partial")
    assert detail["package_name"] == "org.example.client_only"
    assert detail["strong_count"] == 0
    assert detail["candidate_count"] == 1


def test_cross_apk_comparison(test_env):
    """Upload service_b.apk and compare service_a and service_b for duplicate registration."""
    client = test_env["client"]
    apk_b_path = Path("demo/inputs/service_b.apk")
    if not apk_b_path.is_file():
        pytest.skip("demo/inputs/service_b.apk not available")

    with open(apk_b_path, "rb") as f:
        content_b = f.read()

    resp_b = client.post(
        "/api/analyses",
        files={"file": ("service_b.apk", io.BytesIO(content_b), "application/vnd.android.package-archive")},
    )
    assert resp_b.status_code == 201
    job_id_b = resp_b.json()["id"]

    import time
    for _ in range(30):
        st_resp = client.get(f"/api/analyses/{job_id_b}")
        if st_resp.json()["status"] != "running":
            break
        time.sleep(0.3)

    # Find service_a job ID
    hist = client.get("/api/analyses?query=service_a").json()
    assert hist["total"] >= 1
    job_id_a = hist["items"][0]["id"]

    # Execute comparison
    cmp_resp = client.post(
        "/api/comparisons",
        json={"analysis_ids": [job_id_a, job_id_b], "title": "Test Conflict Comparison"},
    )
    assert cmp_resp.status_code == 201
    cmp_data = cmp_resp.json()
    assert cmp_data["target_count"] == 2
    assert cmp_data["strong_duplicates_count"] == 1

    # Fetch comparison detail
    cmp_id = cmp_data["id"]
    det_resp = client.get(f"/api/comparisons/{cmp_id}")
    assert det_resp.status_code == 200
    report_data = det_resp.json()["report_data"]
    assert report_data["strong_duplicate_static_registrations_count"] == 1


def test_knowledge_base_listing(test_env):
    """Verify knowledge base endpoint returns full list of assigned UUIDs."""
    client = test_env["client"]
    resp = client.get("/api/knowledge-base")
    assert resp.status_code == 200
    data = resp.json()
    assert "entries" in data
    assert len(data["entries"]) >= 20
    first_entry = data["entries"][0]
    assert "normalized_uuid" in first_entry
    assert "name" in first_entry
    assert "source_url" in first_entry


def test_delete_analysis(test_env):
    """Verify analysis deletion removes database record."""
    client = test_env["client"]
    hist = client.get("/api/analyses").json()
    assert hist["total"] > 0
    target_id = hist["items"][-1]["id"]

    del_resp = client.delete(f"/api/analyses/{target_id}")
    assert del_resp.status_code == 200

    check_resp = client.get(f"/api/analyses/{target_id}")
    assert check_resp.status_code == 404
