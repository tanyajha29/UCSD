"""Unit and integration tests for independent APK validator and comparator."""

import json
from pathlib import Path

from ucsd.models import APKMetadata, DEXInfo, ManifestMetadata
from ucsd.validation.cli import main, run_validate
from ucsd.validation.comparator import compare_metadata
from ucsd.validation.inspector import compute_file_sha256, inspect_apk_independently
from ucsd.validation.models import ComparisonStatus, IndependentAPKMetadata, IndependentDEXInfo
from ucsd.validation.reporter import generate_markdown, write_reports


class TestIndependentValidator:
    """Test suite for independent validation module."""

    def test_compute_file_sha256(self, valid_single_dex_apk: Path):
        """Verify independent SHA-256 calculation."""
        digest = compute_file_sha256(valid_single_dex_apk)
        assert len(digest) == 64
        assert isinstance(digest, str)

    def test_inspect_apk_independently(self, valid_single_dex_apk: Path):
        """Verify independent inspection on fixture without Androguard."""
        meta = inspect_apk_independently(str(valid_single_dex_apk))

        assert isinstance(meta, IndependentAPKMetadata)
        assert meta.is_valid_zip is True
        assert meta.has_manifest is True
        assert meta.has_dex is True
        assert meta.dex_count == 1
        assert meta.is_multidex is False
        assert len(meta.dex_files) == 1
        assert meta.dex_files[0].name == "classes.dex"
        assert meta.file_size_bytes > 0
        assert len(meta.sha256) == 64

    def test_comparator_exact_match(self):
        """Verify comparator reports PASS when all properties match."""
        ucsd_data = {
            "sha256": "abcdef123456" * 5 + "abcd",
            "file_size_bytes": 1024,
            "is_valid_zip": True,
            "dex_count": 1,
            "is_multidex": False,
            "dex_files": [{"name": "classes.dex", "sha256": "1111" * 16, "size_bytes": 500}],
            "manifest": {
                "package_name": "com.test.app",
                "version_code": 10,
                "version_name": "1.0",
                "min_sdk_version": 21,
                "target_sdk_version": 33,
                "requested_permissions": ["android.permission.INTERNET"],
                "declared_permissions": ["com.test.CUSTOM_PERM"],
            },
        }

        indep_data = IndependentAPKMetadata(
            file_path="/app/samples/test.apk",
            file_name="test.apk",
            file_size_bytes=1024,
            sha256="abcdef123456" * 5 + "abcd",
            is_valid_zip=True,
            has_manifest=True,
            has_dex=True,
            is_multidex=False,
            dex_count=1,
            dex_files=[IndependentDEXInfo(name="classes.dex", sha256="1111" * 16, size_bytes=500)],
            package_name="com.test.app",
            version_code=10,
            version_name="1.0",
            min_sdk_version=21,
            target_sdk_version=33,
            compile_sdk_version=33,
            uses_permissions=["android.permission.INTERNET"],
            uses_permissions_sdk_23=[],
            requested_permissions=["android.permission.INTERNET"],
            requested_permissions_count=1,
            declared_permissions=["com.test.CUSTOM_PERM"],
            declared_permissions_count=1,
            tool_metadata={"aapt_tool": "aapt v0.2"},
        )

        report = compare_metadata(ucsd_data, indep_data)

        assert report.verdict == "PASS"
        assert report.mismatches == 0
        assert report.matches > 0

    def test_comparator_detects_mismatch(self):
        """Verify comparator reports FAIL when discrepancies exist."""
        ucsd_data = {
            "sha256": "aaa" * 21 + "a",
            "file_size_bytes": 1000,
            "is_valid_zip": True,
            "dex_count": 1,
            "is_multidex": False,
            "dex_files": [{"name": "classes.dex", "sha256": "1111" * 16, "size_bytes": 500}],
            "manifest": {
                "package_name": "com.test.app",
                "version_code": 10,
                "version_name": "1.0",
                "min_sdk_version": 21,
                "target_sdk_version": 33,
                "requested_permissions": [],
                "declared_permissions": [],
            },
        }

        indep_data = IndependentAPKMetadata(
            file_path="/app/samples/test.apk",
            file_name="test.apk",
            file_size_bytes=2000,  # Deliberate mismatch
            sha256="bbb" * 21 + "b",  # Deliberate mismatch
            is_valid_zip=True,
            has_manifest=True,
            has_dex=True,
            is_multidex=False,
            dex_count=1,
            dex_files=[IndependentDEXInfo(name="classes.dex", sha256="1111" * 16, size_bytes=500)],
            package_name="com.test.DIFFERENT",  # Deliberate mismatch
            version_code=20,  # Deliberate mismatch
            version_name="2.0",
            min_sdk_version=21,
            target_sdk_version=33,
            uses_permissions=[],
            uses_permissions_sdk_23=[],
            requested_permissions=[],
            requested_permissions_count=0,
            declared_permissions=[],
            declared_permissions_count=0,
            tool_metadata={},
        )

        report = compare_metadata(ucsd_data, indep_data)

        assert report.verdict == "FAIL"
        assert report.mismatches >= 4

        mismatched_fields = [c.field for c in report.comparisons if c.status == ComparisonStatus.MISMATCH]
        assert "package_name" in mismatched_fields
        assert "version_code" in mismatched_fields
        assert "file_size_bytes" in mismatched_fields
        assert "sha256" in mismatched_fields

    def test_validation_reporter_output(self, tmp_path: Path):
        """Verify generation of both Markdown and JSON validation reports."""
        ucsd_data = {
            "sha256": "abc" * 21 + "a",
            "file_size_bytes": 100,
            "is_valid_zip": True,
            "dex_count": 1,
            "is_multidex": False,
            "dex_files": [{"name": "classes.dex", "sha256": "1111" * 16, "size_bytes": 50}],
            "manifest": {
                "package_name": "com.test.report",
                "version_code": 1,
                "version_name": "1.0",
                "min_sdk_version": 21,
                "target_sdk_version": 30,
                "requested_permissions": [],
                "declared_permissions": [],
            },
        }
        indep_data = IndependentAPKMetadata(
            file_path="/app/samples/report_test.apk",
            file_name="report_test.apk",
            file_size_bytes=100,
            sha256="abc" * 21 + "a",
            is_valid_zip=True,
            has_manifest=True,
            has_dex=True,
            is_multidex=False,
            dex_count=1,
            dex_files=[IndependentDEXInfo(name="classes.dex", sha256="1111" * 16, size_bytes=50)],
            package_name="com.test.report",
            version_code=1,
            version_name="1.0",
            min_sdk_version=21,
            target_sdk_version=30,
            compile_sdk_version=30,
            uses_permissions=[],
            uses_permissions_sdk_23=[],
            requested_permissions=[],
            requested_permissions_count=0,
            declared_permissions=[],
            declared_permissions_count=0,
            tool_metadata={"aapt_tool": "aapt v0.2"},
        )

        report = compare_metadata(ucsd_data, indep_data)
        json_path, md_path = write_reports(report, tmp_path, stem="test_report")

        assert json_path.is_file()
        assert md_path.is_file()

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["verdict"] == "PASS"

        with open(md_path, "r", encoding="utf-8") as f:
            md_text = f.read()
        assert "PHASE 1 VALIDATION VERDICT: PASS" in md_text

    def test_validation_cli_integration(self, tmp_path: Path):
        """Verify validation CLI execution and exit code on real validation APK."""
        validation_apk = Path("/app/samples/validation.apk")
        reports_dir = tmp_path / "val_reports"

        if validation_apk.is_file():
            exit_code = main(["validate", str(validation_apk), "--out", str(reports_dir)])
            assert exit_code == 0
            assert reports_dir.is_dir()
            json_files = list(reports_dir.glob("*_comparison.json"))
            md_files = list(reports_dir.glob("*_comparison.md"))
            assert len(json_files) == 1
            assert len(md_files) == 1

            with open(json_files[0], "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["verdict"] == "PASS"
            assert data["mismatches"] == 0
        else:
            # Fallback if validation.apk is not mounted
            assert main([]) == 2
