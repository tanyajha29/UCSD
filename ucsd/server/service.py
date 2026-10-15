"""Analysis execution service layer connecting FastAPI to the UCSD engine."""

import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

from ucsd.conflict.assessor import compare_apks
from ucsd.models import APKMetadata, AnalysisReport
from ucsd.orchestrator import analyze_single_apk
from ucsd.server.database import (
    create_analysis_record,
    create_comparison_record,
    get_analysis_record,
    update_analysis_record,
)
from ucsd.server.storage import (
    cleanup_staged_upload,
    get_reports_dir,
    validate_apk_archive,
)

logger = logging.getLogger(__name__)

# Dedicated thread pool for non-blocking static bytecode analysis
ANALYSIS_EXECUTOR = ThreadPoolExecutor(max_workers=3, thread_name_prefix="ucsd_worker")


def execute_analysis_job(
    analysis_id: str,
    apk_path: Path,
    cleanup_apk: bool = False,
) -> None:
    """Execute the end-to-end UCSD pipeline in a worker thread and update SQLite."""
    reports_dir = get_reports_dir()

    try:
        # Pre-execution validation
        is_valid, validation_err = validate_apk_archive(apk_path)
        if not is_valid:
            update_analysis_record(
                analysis_id=analysis_id,
                status="error",
                error_message=validation_err or "APK validation failed",
            )
            return

        # Run real UCSD static analysis pipeline
        report, json_path, html_path = analyze_single_apk(
            target_path=apk_path,
            out_path=reports_dir,
            skip_ble=False,
            skip_registration=False,
            skip_kb=False,
            generate_html=True,
        )

        # Extract summary counts
        cand_cnt = 0
        strong_cnt = 0
        unres_cnt = 0
        pkg_name = None
        v_code = None
        v_name = None
        sha = None

        if report.metadata:
            meta = report.metadata
            sha = meta.sha256
            if meta.manifest:
                pkg_name = meta.manifest.package_name
                v_code = meta.manifest.version_code
                v_name = meta.manifest.version_name
            if meta.ble_analysis and meta.ble_analysis.uuid_candidates:
                cand_cnt = len(meta.ble_analysis.uuid_candidates)
            if meta.registration_analysis:
                strong_cnt = meta.registration_analysis.strong_associations_count
                unres_cnt = meta.registration_analysis.unresolved_patterns_count

        err_msg = None
        if report.error:
            err_msg = f"{report.error.get('error_type', 'Error')}: {report.error.get('message', 'Analysis encountered an error')}"

        update_analysis_record(
            analysis_id=analysis_id,
            status=report.status,
            sha256=sha,
            package_name=pkg_name,
            version_code=v_code,
            version_name=v_name,
            candidate_count=cand_cnt,
            strong_count=strong_cnt,
            unresolved_count=unres_cnt,
            report_json_path=str(json_path) if json_path else None,
            report_html_path=str(html_path) if html_path else None,
            report_data=report.model_dump(),
            error_message=err_msg,
        )

    except Exception as exc:
        logger.exception("Analysis worker failed for job %s", analysis_id)
        update_analysis_record(
            analysis_id=analysis_id,
            status="error",
            error_message=f"{exc.__class__.__name__}: {str(exc)}",
        )
    finally:
        if cleanup_apk:
            cleanup_staged_upload(apk_path)


def start_analysis_job(
    file_name: str,
    file_size_bytes: int,
    staged_apk_path: Path,
    cleanup_apk: bool = False,
    run_async: bool = True,
) -> Dict[str, Any]:
    """Register job in database and launch execution."""
    analysis_id = str(uuid.uuid4())
    record = create_analysis_record(
        analysis_id=analysis_id,
        file_name=file_name,
        file_size_bytes=file_size_bytes,
        status="running",
    )

    if run_async:
        ANALYSIS_EXECUTOR.submit(
            execute_analysis_job,
            analysis_id,
            staged_apk_path,
            cleanup_apk,
        )
    else:
        execute_analysis_job(analysis_id, staged_apk_path, cleanup_apk)
        record = get_analysis_record(analysis_id)  # type: ignore[assignment]

    return record


def execute_comparison_job(
    analysis_ids: List[str],
    custom_title: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute cross-APK conflict evaluation across selected previously analyzed APKs."""
    if len(analysis_ids) < 2:
        raise ValueError("Cross-APK comparison requires at least 2 distinct analyzed APKs")

    metadata_list: List[APKMetadata] = []
    titles: List[str] = []

    for a_id in analysis_ids:
        rec = get_analysis_record(a_id, include_raw_data=True)
        if not rec:
            raise ValueError(f"Analysis record '{a_id}' not found")
        if rec.get("status") not in ("success", "partial"):
            raise ValueError(f"Analysis record '{a_id}' did not complete successfully (status: {rec.get('status')})")

        raw_data = rec.get("report_data")
        if not raw_data or not raw_data.get("metadata"):
            raise ValueError(f"Analysis record '{a_id}' does not have valid metadata payload")

        meta = APKMetadata.model_validate(raw_data["metadata"])
        metadata_list.append(meta)
        pkg = meta.manifest.package_name if meta.manifest else meta.file_name
        titles.append(pkg)

    # Call real UCSD conflict assessment engine
    report = compare_apks(metadata_list)
    report_dict = report.model_dump()

    comp_id = str(uuid.uuid4())
    default_title = custom_title or f"Comparison: {' vs '.join(titles[:3])}{'...' if len(titles) > 3 else ''}"

    saved_rec = create_comparison_record(
        comparison_id=comp_id,
        title=default_title,
        analysis_ids=analysis_ids,
        report_data=report_dict,
    )
    return saved_rec
