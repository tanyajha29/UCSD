"""Integration tests for the UCSD command-line interface."""

import json
from pathlib import Path
from ucsd.cli import main, run_analyze


class TestCLI:
    """Test suite for ucsd.cli."""

    def test_cli_analyze_success(self, valid_single_dex_apk: Path, tmp_path: Path):
        """Verify successful CLI analysis writes a valid JSON report and returns 0."""
        reports_dir = tmp_path / "reports"
        exit_code = main(["analyze", str(valid_single_dex_apk), "--out", str(reports_dir)])

        assert exit_code == 0
        assert reports_dir.is_dir()

        report_files = list(reports_dir.glob("*.json"))
        assert len(report_files) == 1

        with open(report_files[0], "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["error"] is None
        assert data["metadata"]["file_name"] == "valid_single_dex.apk"
        assert data["metadata"]["manifest"]["package_name"] == "org.example.singledex"
        assert data["metadata"]["dex_count"] == 1

    def test_cli_analyze_failure_corrupt(self, corrupt_zip_apk: Path, tmp_path: Path):
        """Verify analysis of corrupt file returns exit code 1 and writes error report."""
        reports_dir = tmp_path / "reports"
        exit_code = main(["analyze", str(corrupt_zip_apk), "--out", str(reports_dir)])

        assert exit_code == 1
        report_files = list(reports_dir.glob("*.json"))
        assert len(report_files) == 1

        with open(report_files[0], "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "error"
        assert data["metadata"] is None
        assert data["error"]["error_type"] == "CorruptZipAPKError"

    def test_cli_explicit_output_file(self, valid_single_dex_apk: Path, tmp_path: Path):
        """Verify CLI writes to a specific JSON file when target ends with .json."""
        report_file = tmp_path / "custom_output.json"
        exit_code = run_analyze(str(valid_single_dex_apk), str(report_file), quiet=True)

        assert exit_code == 0
        assert report_file.is_file()

        with open(report_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"

    def test_cli_missing_command(self):
        """Verify CLI returns exit code 2 when no subcommand is provided."""
        assert main([]) == 2
