"""Central analysis orchestrator for UCSD.

Coordinates the end-to-end static analysis pipeline:
  APK intake -> BLE indicators -> UUID extraction -> registration analysis -> conflict assessment -> reporting.
Supports both single-APK analysis and multi-APK batch analysis with deterministic sorting,
partial parsing resilience, and simultaneous JSON and HTML report generation.
"""

import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import ucsd
from ucsd.apk_loader import load_apk, normalize_container_path
from ucsd.conflict.assessor import METHODOLOGY_NOTES, assess_single_apk, compare_apks
from ucsd.errors import KnowledgeBaseError, UCSDError
from ucsd.knowledge.repository import UUIDKnowledgeBase
from ucsd.models import APKMetadata, AnalysisReport
from ucsd.reporting.html_generator import (
    generate_batch_html_report,
    generate_single_apk_html_report,
)
from ucsd.reporting.models import BatchAnalysisReport, SingleAPKSummary

DEFAULT_LIMITATIONS = [
    *METHODOLOGY_NOTES,
    "Presence in DEX string pool is not proof of runtime execution or active service advertisement.",
    "Intra-method tracing verifies Dalvik register data flow to BluetoothGattServer.addService(); it does not cover cross-method parameters, dynamic reflection, or native code.",
    "UUID knowledge base lookup performs exact matching against curated public specifications with verifiable provenance. Unknown UUIDs remain strictly unknown.",
    "Categorical evidence levels are qualitative static findings and do not represent calibrated runtime probabilities or risk scores.",
    "Static analysis cannot prove runtime host-level vulnerability or confirmed service squatting without operational device execution.",
]


def _sort_metadata_deterministically(metadata: APKMetadata) -> APKMetadata:
    """Ensure internal collections in APKMetadata are deterministically ordered."""
    # Collections are already sorted in lower modules, but enforce invariants
    if metadata.manifest:
        metadata.manifest.requested_permissions.sort()
        metadata.manifest.declared_permissions.sort()

    if metadata.ble_analysis and metadata.ble_analysis.uuid_candidates:
        metadata.ble_analysis.uuid_candidates.sort(key=lambda c: c.normalized_uuid)

    if metadata.registration_analysis and metadata.registration_analysis.findings:
        metadata.registration_analysis.findings.sort(
            key=lambda f: (
                f.dex_file or "",
                f.class_name or "",
                f.method_name or "",
                f.trace_steps[-1].instruction_offset if f.trace_steps else -1,
                f.normalized_uuid or "",
            )
        )

    if metadata.knowledge_base_assessment and metadata.knowledge_base_assessment.findings:
        metadata.knowledge_base_assessment.findings.sort(key=lambda f: f.normalized_uuid)

    return metadata


def analyze_single_apk(
    target_path: Union[str, Path],
    out_path: Union[str, Path] = "reports",
    skip_ble: bool = False,
    skip_registration: bool = False,
    skip_kb: bool = False,
    generate_html: bool = True,
) -> Tuple[AnalysisReport, Path, Optional[Path]]:
    """Run the complete end-to-end analysis pipeline on a single APK.

    Pipeline:
      1. Intake: file existence, SHA-256 calculation, ZIP CRC integrity, DEX enumeration, manifest parsing.
      2. BLE indicators: permissions, API framework and application classes, method references.
      3. UUID candidate extraction: 128-bit and 16-bit formats, normalization via Bluetooth base UUID.
      4. Registration analysis: BluetoothGattService constructors & addService, intra-method tracing.
      5. Knowledge base assessment: exact-match lookup against curated provenance repository.
      6. Reporting: writes deterministic JSON report and standalone offline HTML report.

    Args:
        target_path: Path to the APK file.
        out_path: Directory or explicit file path for report output.
        skip_ble: Skip Phase 2 BLE indicators.
        skip_registration: Skip Phase 3 GATT service registration analysis.
        skip_kb: Skip Phase 4 UUID knowledge base lookup.
        generate_html: Whether to generate standalone HTML report alongside JSON.

    Returns:
        Tuple of (AnalysisReport, json_report_path, html_report_path).
    """
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    norm_target = normalize_container_path(str(target_path))
    norm_out = normalize_container_path(str(out_path))
    out_target = Path(norm_out)

    kb_ver: Optional[str] = None
    kb_unavailable = False

    # Attempt to query active KB version
    if not skip_kb:
        try:
            kb_inst = UUIDKnowledgeBase()
            kb_ver = kb_inst.get_metadata().knowledge_base_version
        except Exception:
            kb_unavailable = True

    # Precompute output paths
    stem = Path(norm_target).stem
    if out_target.suffix.lower() == ".json":
        json_file = out_target
        html_file = out_target.with_suffix(".html")
        out_target.parent.mkdir(parents=True, exist_ok=True)
    elif out_target.suffix.lower() == ".html":
        html_file = out_target
        json_file = out_target.with_suffix(".json")
        out_target.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_target.mkdir(parents=True, exist_ok=True)
        # We will determine exact base_name once SHA-256 is known or fallback to stem
        json_file = None
        html_file = None

    actual_html_path: Optional[Path] = None

    try:
        metadata = load_apk(
            norm_target,
            scan_ble=not skip_ble,
            scan_registration=not skip_registration,
            scan_knowledge_base=not skip_kb and not kb_unavailable,
        )
        metadata = _sort_metadata_deterministically(metadata)

        lims = list(DEFAULT_LIMITATIONS)
        status = "success"
        if kb_unavailable and not skip_kb:
            status = "partial"
            lims.append("Knowledge base dataset unavailable; UUID provenance matching was omitted.")

        if json_file is None:
            prefix = metadata.sha256[:12] if metadata.sha256 else "unknown"
            base_name = f"{stem}_{prefix}_report"
            json_file = out_target / f"{base_name}.json"
            html_file = out_target / f"{base_name}.html"

        if generate_html:
            actual_html_path = html_file

        report = AnalysisReport(
            status=status,
            timestamp=now_iso,
            target=norm_target,
            analyzer_version=ucsd.__version__,
            knowledge_base_version=kb_ver,
            metadata=metadata,
            ble_analysis=metadata.ble_analysis,
            registration_analysis=metadata.registration_analysis,
            knowledge_base_assessment=metadata.knowledge_base_assessment,
            limitations=lims,
            html_report_path=str(actual_html_path) if actual_html_path else None,
            error=None,
        )

    except UCSDError as err:
        if json_file is None:
            base_name = f"{stem}_report"
            json_file = out_target / f"{base_name}.json"
            html_file = out_target / f"{base_name}.html"

        if generate_html:
            actual_html_path = html_file

        report = AnalysisReport(
            status="error",
            timestamp=now_iso,
            target=norm_target,
            analyzer_version=ucsd.__version__,
            knowledge_base_version=kb_ver,
            metadata=None,
            ble_analysis=None,
            registration_analysis=None,
            knowledge_base_assessment=None,
            limitations=list(DEFAULT_LIMITATIONS),
            html_report_path=str(actual_html_path) if actual_html_path else None,
            error=err.to_dict(),
        )
    except Exception as exc:
        if json_file is None:
            base_name = f"{stem}_report"
            json_file = out_target / f"{base_name}.json"
            html_file = out_target / f"{base_name}.html"

        if generate_html:
            actual_html_path = html_file

        report = AnalysisReport(
            status="error",
            timestamp=now_iso,
            target=norm_target,
            analyzer_version=ucsd.__version__,
            knowledge_base_version=kb_ver,
            metadata=None,
            ble_analysis=None,
            registration_analysis=None,
            knowledge_base_assessment=None,
            limitations=list(DEFAULT_LIMITATIONS),
            html_report_path=str(actual_html_path) if actual_html_path else None,
            error={
                "error_type": exc.__class__.__name__,
                "message": str(exc),
            },
        )

    # Determine output paths
    stem = Path(norm_target).stem
    if out_target.suffix.lower() == ".json":
        json_file = out_target
        html_file = out_target.with_suffix(".html")
        out_target.parent.mkdir(parents=True, exist_ok=True)
    elif out_target.suffix.lower() == ".html":
        html_file = out_target
        json_file = out_target.with_suffix(".json")
        out_target.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_target.mkdir(parents=True, exist_ok=True)
        if report.metadata and report.metadata.sha256:
            prefix = report.metadata.sha256[:12]
            base_name = f"{stem}_{prefix}_report"
        else:
            base_name = f"{stem}_report"
        json_file = out_target / f"{base_name}.json"
        html_file = out_target / f"{base_name}.html"

    # Write HTML report if requested
    actual_html_path: Optional[Path] = None
    if generate_html:
        html_content = generate_single_apk_html_report(report)
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        actual_html_path = html_file
        report.html_report_path = str(html_file)

    # Write JSON report
    with open(json_file, "w", encoding="utf-8") as f:
        f.write(report.model_dump_json(indent=2))

    return report, json_file, actual_html_path


def batch_analyze(
    targets_or_dir: Union[str, Path, List[Union[str, Path]]],
    out_dir: Union[str, Path] = "reports",
    skip_ble: bool = False,
    skip_registration: bool = False,
    skip_kb: bool = False,
    generate_html: bool = True,
) -> Tuple[BatchAnalysisReport, Path, Optional[Path]]:
    """Run batch analysis and cross-comparison across multiple APKs.

    Finds all APKs in the specified directory or list of paths, analyzes each one,
    writes individual per-APK JSON and HTML reports, and executes cross-APK conflict
    evaluation to produce an aggregated batch report in JSON and HTML.

    Args:
        targets_or_dir: Directory path containing APKs, or list of APK file paths.
        out_dir: Directory to save all per-APK and batch reports.
        skip_ble: Skip Phase 2 BLE indicators.
        skip_registration: Skip Phase 3 GATT service registration analysis.
        skip_kb: Skip Phase 4 UUID knowledge base lookup.
        generate_html: Whether to generate standalone HTML reports alongside JSON.

    Returns:
        Tuple of (BatchAnalysisReport, batch_json_path, batch_html_path).
    """
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    norm_out_dir = normalize_container_path(str(out_dir))
    out_path = Path(norm_out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # Collect target APK paths deterministically
    apk_paths: List[Path] = []
    target_desc: str = ""

    if isinstance(targets_or_dir, (str, Path)):
        p = Path(normalize_container_path(str(targets_or_dir)))
        if p.is_dir():
            target_desc = str(p)
            for item in sorted(p.iterdir()):
                if item.is_file() and item.suffix.lower() == ".apk":
                    apk_paths.append(item)
        elif p.is_file():
            target_desc = str(p.parent)
            apk_paths.append(p)
        else:
            target_desc = str(p)
    else:
        target_desc = f"{len(targets_or_dir)} specified target(s)"
        for t in targets_or_dir:
            p = Path(normalize_container_path(str(t)))
            if p.is_file() and p.suffix.lower() == ".apk":
                apk_paths.append(p)

    apk_paths = sorted(list(set(apk_paths)), key=lambda x: x.name)

    # Retrieve KB version
    kb_ver: Optional[str] = None
    if not skip_kb:
        try:
            kb_inst = UUIDKnowledgeBase()
            kb_ver = kb_inst.get_metadata().knowledge_base_version
        except Exception:
            kb_ver = None

    successful_metadata: List[APKMetadata] = []
    apk_summaries: List[SingleAPKSummary] = []
    failed_targets: List[Dict[str, Any]] = []

    # Analyze each APK
    for apk_path in apk_paths:
        rep, json_p, html_p = analyze_single_apk(
            target_path=apk_path,
            out_path=out_path,
            skip_ble=skip_ble,
            skip_registration=skip_registration,
            skip_kb=skip_kb,
            generate_html=generate_html,
        )

        if rep.status in ("success", "partial") and rep.metadata:
            meta = rep.metadata
            successful_metadata.append(meta)

            cand_cnt = len(meta.ble_analysis.uuid_candidates) if meta.ble_analysis else 0
            strong_cnt = meta.registration_analysis.strong_associations_count if meta.registration_analysis else 0
            unres_cnt = meta.registration_analysis.unresolved_patterns_count if meta.registration_analysis else 0

            summary = SingleAPKSummary(
                file_name=meta.file_name,
                file_path=meta.file_path,
                sha256=meta.sha256,
                package_name=meta.manifest.package_name if meta.manifest else None,
                version_code=meta.manifest.version_code if meta.manifest else None,
                version_name=meta.manifest.version_name if meta.manifest else None,
                candidate_count=cand_cnt,
                strong_registrations_count=strong_cnt,
                unresolved_registrations_count=unres_cnt,
                status=rep.status,
                report_json_path=str(json_p),
                report_html_path=str(html_p) if html_p else None,
            )
            apk_summaries.append(summary)
        else:
            err_dict = rep.error or {"error_type": "AnalysisError", "message": "Unknown analysis error"}
            failed_targets.append({
                "target": str(apk_path),
                "error_type": err_dict.get("error_type", "Error"),
                "message": err_dict.get("message", "Intake failed"),
            })

    # Cross-APK conflict assessment
    cross_conflicts = None
    if len(successful_metadata) >= 2:
        cross_conflicts = compare_apks(successful_metadata)

    # Determine batch status
    if not failed_targets and successful_metadata:
        batch_status = "success"
    elif successful_metadata and failed_targets:
        batch_status = "partial"
    else:
        batch_status = "error"

    # Sort summaries deterministically
    apk_summaries.sort(key=lambda s: s.file_name)
    failed_targets.sort(key=lambda f: f["target"])

    batch_json_path = out_path / "batch_report.json"
    batch_html_path = out_path / "batch_report.html"
    actual_batch_html: Optional[Path] = batch_html_path if generate_html else None

    batch_report = BatchAnalysisReport(
        status=batch_status,
        timestamp=now_iso,
        analyzer_version=ucsd.__version__,
        knowledge_base_version=kb_ver,
        target_directory=target_desc,
        total_targets=len(apk_paths),
        successful_count=len(successful_metadata),
        failed_count=len(failed_targets),
        apk_summaries=apk_summaries,
        cross_apk_conflicts=cross_conflicts,
        failed_targets=failed_targets,
        limitations=list(DEFAULT_LIMITATIONS),
        html_report_path=str(actual_batch_html) if actual_batch_html else None,
    )

    # Write HTML
    if generate_html and actual_batch_html:
        batch_html_content = generate_batch_html_report(batch_report)
        with open(actual_batch_html, "w", encoding="utf-8") as f:
            f.write(batch_html_content)

    # Write JSON
    with open(batch_json_path, "w", encoding="utf-8") as f:
        f.write(batch_report.model_dump_json(indent=2))

    return batch_report, batch_json_path, actual_batch_html

