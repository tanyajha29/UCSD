"""Comprehensive test suite for Phase 5: integration, orchestrator, and analyst-facing reporting."""

import json
from pathlib import Path
import pytest

from ucsd.cli import main
from ucsd.models import (
    AnalysisReport,
    APKMetadata,
    DEXInfo,
    ManifestMetadata,
)
from ucsd.orchestrator import analyze_single_apk, batch_analyze
from ucsd.registration.models import (
    EvidenceLevel,
    RegistrationAnalysisResult,
    RegistrationFinding,
    UnresolvedReason,
)
from ucsd.reporting.html_generator import (
    esc,
    generate_batch_html_report,
    generate_single_apk_html_report,
)
from ucsd.reporting.models import BatchAnalysisReport, SingleAPKSummary


class TestHTMLGenerator:
    """Test suite for HTML report generation, strict escaping, and offline independence."""

    def test_esc_helper_strictly_escapes_xss_characters(self):
        """Verify esc() escapes HTML characters, quotes, and script injection payloads."""
        assert esc("<script>alert('xss')</script>") == "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        assert esc('"><img src=x onerror=alert(1)>') == "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"
        assert esc("normal_string_123") == "normal_string_123"
        assert esc(None) == ""
        assert esc(42) == "42"

    def test_single_apk_html_escaping_untrusted_input(self):
        """Verify generate_single_apk_html_report strictly escapes APK-controlled strings."""
        malicious_manifest = ManifestMetadata(
            package_name="<script>alert('pkg')</script>",
            version_code=100,
            version_name="1.0\" onclick=\"alert('ver')",
            min_sdk_version=21,
            target_sdk_version=33,
            requested_permissions=["<script>alert('perm')</script>"],
            declared_permissions=[],
            activities=["<script>alert('act')</script>"],
        )
        malicious_meta = APKMetadata(
            file_path="/app/samples/<img src=x onerror=1>.apk",
            file_name="<img src=x onerror=1>.apk",
            file_size_bytes=1000,
            sha256="deadbeef" * 8,
            is_valid_zip=True,
            is_multidex=False,
            dex_count=1,
            dex_files=[DEXInfo(name="classes.dex", sha256="1234" * 16, size_bytes=500)],
            manifest=malicious_manifest,
            ble_analysis=None,
            registration_analysis=None,
            knowledge_base_assessment=None,
        )
        report = AnalysisReport(
            status="success",
            timestamp="2026-10-04T00:00:00Z",
            target="<script>alert('target')</script>",
            analyzer_version="0.1.0",
            knowledge_base_version="1.0.0",
            metadata=malicious_meta,
            ble_analysis=None,
            registration_analysis=None,
            knowledge_base_assessment=None,
            limitations=["Standard limitation <script>"],
            html_report_path=None,
            error=None,
        )

        html_out = generate_single_apk_html_report(report)

        # Raw tags must NOT exist anywhere in the generated HTML
        assert "<script>alert('pkg')</script>" not in html_out
        assert "<script>alert('perm')</script>" not in html_out
        assert "<script>alert('act')</script>" not in html_out
        assert "<img src=x onerror=1>" not in html_out
        assert '1.0" onclick=' not in html_out

        # Escaped entities must be present
        assert "&lt;script&gt;alert(&#x27;pkg&#x27;)&lt;/script&gt;" in html_out
        assert "&lt;img src=x onerror=1&gt;" in html_out
        assert "&quot; onclick=&quot;" in html_out

    def test_offline_standalone_nature_no_external_cdns(self):
        """Verify generated HTML has zero external dependencies and works completely offline."""
        report = AnalysisReport(
            status="success",
            timestamp="2026-10-04T00:00:00Z",
            target="/app/samples/test.apk",
            analyzer_version="0.1.0",
            knowledge_base_version="1.0.0",
            metadata=None,
            ble_analysis=None,
            registration_analysis=None,
            knowledge_base_assessment=None,
            limitations=["Limitation note"],
            html_report_path=None,
            error=None,
        )
        html_out = generate_single_apk_html_report(report)

        # Must not load external stylesheets, fonts, or scripts
        assert "<link rel=\"stylesheet\" href=\"http" not in html_out
        assert "<script src=\"http" not in html_out
        assert "fonts.googleapis.com" not in html_out
        assert "cdnjs.cloudflare.com" not in html_out
        assert "cdn.jsdelivr.net" not in html_out
        assert "<style>" in html_out

    def test_html_report_distinct_evidence_tiers_and_limitations(self):
        """Verify HTML report cleanly renders distinct badges and diagnosis for all three evidence tiers."""
        f_strong = RegistrationFinding(
            evidence_level=EvidenceLevel.STRONG_STATIC_ASSOCIATION,
            normalized_uuid="0000180d-0000-1000-8000-00805f9b34fb",
            dex_file="classes.dex",
            class_name="com.test.GattManager",
            method_name="registerHeartRate",
            descriptor="()V",
            diagnosis="Verified intra-method registration for Heart Rate",
        )
        f_unres = RegistrationFinding(
            evidence_level=EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED,
            normalized_uuid=None,
            dex_file="classes.dex",
            class_name="com.test.GattManager",
            method_name="registerParam",
            descriptor="(Landroid/bluetooth/BluetoothGattService;)V",
            diagnosis="Registration pattern detected with cross-method parameter",
            unresolved_reason=UnresolvedReason.CROSS_METHOD_SERVICE_OBJECT,
        )
        f_cand = RegistrationFinding(
            evidence_level=EvidenceLevel.UUID_CANDIDATE_ONLY,
            normalized_uuid="0000180f-0000-1000-8000-00805f9b34fb",
            dex_file="classes.dex",
            class_name="com.test.Constants",
            method_name="<clinit>",
            descriptor="()V",
            diagnosis="Candidate UUID detected without registration call site",
            unresolved_reason=UnresolvedReason.NO_REGISTRATION_CALL_SITE,
        )

        reg_res = RegistrationAnalysisResult(
            has_gatt_registrations=True,
            total_add_service_calls=2,
            total_service_constructions=1,
            strong_associations_count=1,
            unresolved_patterns_count=1,
            candidate_only_count=1,
            findings=[f_strong, f_unres, f_cand],
        )

        limitations = [
            "Dalvik bytecode analysis is strictly intra-method; inter-procedural paths are reported as unresolved.",
            "Dynamic reflection is outside static analysis scope.",
        ]

        report = AnalysisReport(
            status="success",
            timestamp="2026-10-05T00:00:00Z",
            target="/app/samples/tiers_test.apk",
            analyzer_version="0.1.0",
            knowledge_base_version="1.0.0",
            registration_analysis=reg_res,
            limitations=limitations,
        )

        html_out = generate_single_apk_html_report(report)

        # Check that all 3 distinct badges are rendered
        assert "STRONG STATIC" in html_out
        assert "UNRESOLVED (CROSS_METHOD_SERVICE_OBJECT)" in html_out
        assert "CANDIDATE ONLY" in html_out

        # Check banner for strong registrations
        assert "HIGH-CONFIDENCE STATIC REGISTRATIONS DETECTED" in html_out

        # Check limitations section
        assert "Analytical Boundaries & Methodological Limitations" in html_out
        for lim in limitations:
            assert esc(lim) in html_out

        # Check JSON serialization preserves distinct categorical strings
        rep_json = json.loads(report.model_dump_json())
        findings_json = rep_json["registration_analysis"]["findings"]
        assert len(findings_json) == 3
        assert findings_json[0]["evidence_level"] == "STRONG_STATIC_ASSOCIATION"
        assert findings_json[1]["evidence_level"] == "REGISTRATION_PATTERN_UUID_UNRESOLVED"
        assert findings_json[2]["evidence_level"] == "UUID_CANDIDATE_ONLY"



class TestOrchestratorSingleAPK:
    """Test suite for single-APK orchestrator pipeline execution."""

    def test_analyze_single_apk_produces_both_json_and_html(self, ble_single_dex_apk: Path, tmp_path: Path):
        """Verify analyze_single_apk produces both JSON and HTML report files by default."""
        rep, json_path, html_path = analyze_single_apk(
            target_path=ble_single_dex_apk,
            out_path=tmp_path / "reports",
            generate_html=True,
        )

        assert rep.status == "success"
        assert json_path.is_file()
        assert html_path is not None
        assert html_path.is_file()

        # Validate JSON content
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert data["analyzer_version"] == "0.1.0"
        assert data["metadata"]["sha256"] is not None
        assert len(data["limitations"]) > 0

        # Validate HTML content
        html_text = html_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html_text
        assert "org.example.bleapp" in html_text
        assert data["metadata"]["sha256"] in html_text
        assert "Bluetooth &amp; BLE Static Indicators" in html_text

    def test_analyze_single_apk_error_generates_both_reports(self, corrupt_zip_apk: Path, tmp_path: Path):
        """Verify corrupt APK generates structured error reports in both JSON and HTML."""
        rep, json_path, html_path = analyze_single_apk(
            target_path=corrupt_zip_apk,
            out_path=tmp_path / "err_reports",
            generate_html=True,
        )

        assert rep.status == "error"
        assert rep.error is not None
        assert rep.error["error_type"] == "CorruptZipAPKError"
        assert json_path.is_file()
        assert html_path is not None
        assert html_path.is_file()

        # HTML displays error alert
        html_text = html_path.read_text(encoding="utf-8")
        assert "CorruptZipAPKError" in html_text
        assert "alert-danger" in html_text

    def test_analyze_single_apk_suppress_html(self, valid_single_dex_apk: Path, tmp_path: Path):
        """Verify generate_html=False suppresses HTML report generation."""
        rep, json_path, html_path = analyze_single_apk(
            target_path=valid_single_dex_apk,
            out_path=tmp_path / "no_html",
            generate_html=False,
        )

        assert json_path.is_file()
        assert html_path is None
        html_files = list((tmp_path / "no_html").glob("*.html"))
        assert len(html_files) == 0


class TestBatchAnalysisOrchestration:
    """Test suite for multi-APK batch analysis, error isolation, and cross-comparison."""

    def test_batch_analyze_directory_with_conflicts_and_failures(
        self,
        conflict_apk_a: Path,
        conflict_apk_b: Path,
        negative_candidate_apk: Path,
        corrupt_zip_apk: Path,
        tmp_path: Path,
    ):
        """Verify batch analysis processes valid APKs, isolates failures, and computes cross conflicts."""
        # Create a dedicated directory with 2 conflict APKs, 2 candidate-only duplicate APKs, and 1 corrupt APK
        batch_input_dir = tmp_path / "batch_input"
        batch_input_dir.mkdir(parents=True, exist_ok=True)

        import shutil
        shutil.copy(conflict_apk_a, batch_input_dir / "conflict_a.apk")
        shutil.copy(conflict_apk_b, batch_input_dir / "conflict_b.apk")
        shutil.copy(corrupt_zip_apk, batch_input_dir / "corrupted.apk")

        from tests.generate_fixtures import build_dex_with_strings, build_minimal_axml, create_apk_archive
        shared_cand_uuid = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
        create_apk_archive(
            batch_input_dir / "candidate_1.apk",
            build_minimal_axml("org.example.cand1", 1, "1.0", ["android.permission.BLUETOOTH"]),
            [("classes.dex", build_dex_with_strings([shared_cand_uuid]))],
        )
        create_apk_archive(
            batch_input_dir / "candidate_2.apk",
            build_minimal_axml("org.example.cand2", 2, "2.0", ["android.permission.BLUETOOTH"]),
            [("classes.dex", build_dex_with_strings([shared_cand_uuid]))],
        )

        out_dir = tmp_path / "batch_out"
        batch_rep, json_path, html_path = batch_analyze(
            targets_or_dir=batch_input_dir,
            out_dir=out_dir,
            generate_html=True,
        )

        # Batch counts
        assert batch_rep.total_targets == 5
        assert batch_rep.successful_count == 4
        assert batch_rep.failed_count == 1
        assert batch_rep.status == "partial"  # 4 passed, 1 failed

        # Verify failed target is cleanly recorded
        assert len(batch_rep.failed_targets) == 1
        assert "corrupted.apk" in batch_rep.failed_targets[0]["target"]
        assert batch_rep.failed_targets[0]["error_type"] == "CorruptZipAPKError"

        # Verify cross-APK conflict evaluation ran across the 4 valid APKs
        conf = batch_rep.cross_apk_conflicts
        assert conf is not None
        assert conf.total_apks_analyzed == 4
        assert conf.strong_duplicate_static_registrations_count == 1
        assert conf.duplicate_candidates_unregistered_count == 1

        # Verify batch files written
        assert json_path.is_file()
        assert html_path is not None
        assert html_path.is_file()

        # Verify individual per-APK reports written
        individual_jsons = list(out_dir.glob("*_report.json"))
        # 1 batch_report.json + 5 per-APK reports = 6
        assert len(individual_jsons) == 6

        # Verify HTML content contains cross-APK overlap banner
        batch_html = html_path.read_text(encoding="utf-8")
        assert "Strong Duplicate Static Registrations" in batch_html
        assert "0000180d-0000-1000-8000-00805f9b34fb" in batch_html
        assert "HIGH-CONFIDENCE STATIC OVERLAP" in batch_html
        assert "Duplicate Candidate Strings (No Dual Static Registration)" in batch_html
        assert "corrupted.apk" in batch_html


class TestCLIPhase5Integration:
    """Test suite for CLI analyze and batch subcommands in Phase 5."""

    def test_cli_analyze_produces_both_reports(self, ble_single_dex_apk: Path, tmp_path: Path):
        """Verify CLI analyze generates both JSON and HTML reports by default."""
        reports_dir = tmp_path / "cli_reports"
        exit_code = main(["analyze", str(ble_single_dex_apk), "--out", str(reports_dir), "--quiet"])

        assert exit_code == 0
        json_reports = list(reports_dir.glob("*.json"))
        html_reports = list(reports_dir.glob("*.html"))
        assert len(json_reports) == 1
        assert len(html_reports) == 1

    def test_cli_analyze_no_html_flag(self, ble_single_dex_apk: Path, tmp_path: Path):
        """Verify CLI analyze --no-html suppresses HTML report."""
        reports_dir = tmp_path / "no_html_cli"
        exit_code = main(["analyze", str(ble_single_dex_apk), "--out", str(reports_dir), "--no-html", "--quiet"])

        assert exit_code == 0
        json_reports = list(reports_dir.glob("*.json"))
        html_reports = list(reports_dir.glob("*.html"))
        assert len(json_reports) == 1
        assert len(html_reports) == 0

    def test_cli_batch_command(self, conflict_apk_a: Path, conflict_apk_b: Path, tmp_path: Path):
        """Verify CLI batch command analyzes multiple targets and outputs batch reports."""
        batch_dir = tmp_path / "batch_samples"
        batch_dir.mkdir(parents=True, exist_ok=True)
        import shutil
        shutil.copy(conflict_apk_a, batch_dir / "app_a.apk")
        shutil.copy(conflict_apk_b, batch_dir / "app_b.apk")

        out_dir = tmp_path / "batch_reports"
        exit_code = main(["batch", str(batch_dir), "--out", str(out_dir), "--quiet"])

        assert exit_code == 0
        assert (out_dir / "batch_report.json").is_file()
        assert (out_dir / "batch_report.html").is_file()

        with open(out_dir / "batch_report.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["total_targets"] == 2
        assert data["successful_count"] == 2
        assert data["cross_apk_conflicts"]["strong_duplicate_static_registrations_count"] == 1

    def test_deterministic_output_across_runs(self, ble_single_dex_apk: Path, tmp_path: Path):
        """Verify analysis produces deterministically ordered findings and output across multiple runs."""
        dir1 = tmp_path / "run1"
        dir2 = tmp_path / "run2"

        analyze_single_apk(ble_single_dex_apk, dir1, generate_html=True)
        analyze_single_apk(ble_single_dex_apk, dir2, generate_html=True)

        j1 = next(dir1.glob("*.json"))
        j2 = next(dir2.glob("*.json"))

        with open(j1, "r", encoding="utf-8") as f:
            d1 = json.load(f)
        with open(j2, "r", encoding="utf-8") as f:
            d2 = json.load(f)

        # Excluding timestamps and output-directory-specific paths, output must be strictly identical
        d1.pop("timestamp")
        d2.pop("timestamp")
        d1.pop("html_report_path", None)
        d2.pop("html_report_path", None)
        assert d1 == d2

