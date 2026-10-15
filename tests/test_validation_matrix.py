"""Phase 6: Controlled validation and regression test matrix for UCSD.

This module validates the actual capabilities, boundary conditions, and failure
modes of UCSD against deterministic controlled fixtures with known ground truth.
All test cases correspond to explicit entries in the Phase 6 test matrix.
"""

import hashlib
import json
from pathlib import Path
import pytest

from ucsd.orchestrator import analyze_single_apk, batch_analyze
from ucsd.registration.models import EvidenceLevel, UnresolvedReason
from ucsd.conflict.models import ConflictCondition


class TestValidationMatrixInvalidInputs:
    """Matrix Category 1: Invalid APK Input Handling (TC-INV-01 to TC-INV-06)."""

    def test_tc_inv_01_corrupt_zip(self, corrupt_zip_apk: Path, tmp_path: Path):
        """TC-INV-01: Truncated/corrupted ZIP archive raises CorruptZipAPKError and produces error report."""
        out_dir = tmp_path / "reports"
        report, json_p, html_p = analyze_single_apk(corrupt_zip_apk, out_path=out_dir, generate_html=True)
        assert report.status == "error"
        assert report.error is not None
        assert "CorruptZipAPKError" in report.error.get("error_type", "")
        assert json_p.exists()
        assert html_p is not None and html_p.exists()

    def test_tc_inv_02_renamed_text(self, renamed_text_apk: Path, tmp_path: Path):
        """TC-INV-02: Plain text file with .apk extension raises CorruptZipAPKError."""
        out_dir = tmp_path / "reports"
        report, json_p, html_p = analyze_single_apk(renamed_text_apk, out_path=out_dir, generate_html=True)
        assert report.status == "error"
        assert report.error is not None
        assert "CorruptZipAPKError" in report.error.get("error_type", "")

    def test_tc_inv_03_empty_file(self, empty_apk: Path, tmp_path: Path):
        """TC-INV-03: Zero-byte file raises EmptyFileAPKError."""
        out_dir = tmp_path / "reports"
        report, json_p, html_p = analyze_single_apk(empty_apk, out_path=out_dir, generate_html=True)
        assert report.status == "error"
        assert report.error is not None
        assert "EmptyFileAPKError" in report.error.get("error_type", "")

    def test_tc_inv_04_non_existent_file(self, non_existent_apk: Path, tmp_path: Path):
        """TC-INV-04: Non-existent file path raises FileNotFoundAPKError."""
        out_dir = tmp_path / "reports"
        report, json_p, html_p = analyze_single_apk(non_existent_apk, out_path=out_dir, generate_html=True)
        assert report.status == "error"
        assert report.error is not None
        assert "FileNotFoundAPKError" in report.error.get("error_type", "")

    def test_tc_inv_05_zip_without_dex(self, zip_without_dex_apk: Path, tmp_path: Path):
        """TC-INV-05: ZIP archive with manifest but missing DEX files raises MissingDEXError."""
        out_dir = tmp_path / "reports"
        report, json_p, html_p = analyze_single_apk(zip_without_dex_apk, out_path=out_dir, generate_html=True)
        assert report.status == "error"
        assert report.error is not None
        assert "MissingDEXError" in report.error.get("error_type", "")

    def test_tc_inv_06_zip_without_manifest(self, zip_without_manifest_apk: Path, tmp_path: Path):
        """TC-INV-06: ZIP archive with DEX files but missing AndroidManifest.xml raises MissingManifestError."""
        out_dir = tmp_path / "reports"
        report, json_p, html_p = analyze_single_apk(zip_without_manifest_apk, out_path=out_dir, generate_html=True)
        assert report.status == "error"
        assert report.error is not None
        assert "MissingManifestError" in report.error.get("error_type", "")


class TestValidationMatrixBLEIndicators:
    """Matrix Categories 2, 3, 4: BLE Permissions, Client-Only BLE, Unused UUIDs."""

    def test_tc_ble_perm_no_service_api(self, ble_perm_no_service_api_apk: Path, tmp_path: Path):
        """TC-BLE-PERM-01: BLE permissions present in manifest without any Bluetooth service APIs in DEX."""
        out_dir = tmp_path / "reports"
        report, json_p, html_p = analyze_single_apk(ble_perm_no_service_api_apk, out_path=out_dir)
        assert report.status == "success"
        assert report.metadata is not None
        assert report.ble_analysis is not None
        assert report.registration_analysis is not None

        # Manifest contains Bluetooth permissions
        perms = report.metadata.manifest.requested_permissions if report.metadata.manifest else []
        assert "android.permission.BLUETOOTH" in perms
        assert "android.permission.BLUETOOTH_CONNECT" in perms

        # API indicators show NO GATT server or client
        assert report.ble_analysis.api_indicators.has_gatt_server is False
        assert report.ble_analysis.api_indicators.has_gatt_client is False

        # Registrations: exactly 0
        assert report.registration_analysis.total_add_service_calls == 0
        assert report.registration_analysis.strong_associations_count == 0

        # Discovered UUID candidate is strictly candidate-only
        assert len(report.ble_analysis.uuid_candidates) == 1
        cand = report.ble_analysis.uuid_candidates[0]
        assert cand.normalized_uuid == "0000180a-0000-1000-8000-00805f9b34fb"

        # Finding classification must be UUID_CANDIDATE_ONLY
        finding = next(
            f for f in report.registration_analysis.findings
            if f.normalized_uuid == "0000180a-0000-1000-8000-00805f9b34fb"
        )
        assert finding.evidence_level == EvidenceLevel.UUID_CANDIDATE_ONLY
        assert finding.unresolved_reason == UnresolvedReason.NO_REGISTRATION_CALL_SITE

    def test_tc_ble_client_only(self, client_only_ble_apk: Path, tmp_path: Path):
        """TC-BLE-CLIENT-01: Client-only BLE calls (discoverServices) with candidate UUID, NO GATT server."""
        out_dir = tmp_path / "reports"
        report, json_p, html_p = analyze_single_apk(client_only_ble_apk, out_path=out_dir)
        assert report.status == "success"
        assert report.ble_analysis is not None
        assert report.registration_analysis is not None

        # Client detected, Server NOT detected
        assert report.ble_analysis.api_indicators.has_gatt_client is True
        assert report.ble_analysis.api_indicators.has_gatt_server is False

        # Zero GATT server registrations
        assert report.registration_analysis.total_add_service_calls == 0
        assert report.registration_analysis.strong_associations_count == 0

        # Candidate remains strictly UUID_CANDIDATE_ONLY
        finding = next(
            f for f in report.registration_analysis.findings
            if f.normalized_uuid == "0000180d-0000-1000-8000-00805f9b34fb"
        )
        assert finding.evidence_level == EvidenceLevel.UUID_CANDIDATE_ONLY
        assert finding.unresolved_reason == UnresolvedReason.NO_REGISTRATION_CALL_SITE

    def test_tc_unused_uuid_constant(self, negative_candidate_apk: Path, tmp_path: Path):
        """TC-UNUSED-UUID-01: Candidate UUID present in DEX string pool but unused by service APIs."""
        out_dir = tmp_path / "reports"
        report, json_p, html_p = analyze_single_apk(negative_candidate_apk, out_path=out_dir)
        assert report.status == "success"
        assert report.ble_analysis is not None
        assert report.registration_analysis is not None

        assert len(report.ble_analysis.uuid_candidates) == 1
        cand = report.ble_analysis.uuid_candidates[0]
        assert cand.normalized_uuid == "0000180d-0000-1000-8000-00805f9b34fb"

        # Registration must not promote unused UUID
        assert report.registration_analysis.strong_associations_count == 0
        finding = report.registration_analysis.findings[0]
        assert finding.evidence_level == EvidenceLevel.UUID_CANDIDATE_ONLY
        assert finding.unresolved_reason == UnresolvedReason.NO_REGISTRATION_CALL_SITE


class TestValidationMatrixRegistrationPatterns:
    """Matrix Categories 5, 6: Supported and Unresolved GATT Service Registration Patterns."""

    def test_tc_reg_strong_association(self, conflict_apk_a: Path, tmp_path: Path):
        """TC-REG-STRONG-01: Canonical intra-method literal UUID -> constructor -> addService."""
        out_dir = tmp_path / "reports"
        report, json_p, html_p = analyze_single_apk(conflict_apk_a, out_path=out_dir)
        assert report.status == "success"
        assert report.registration_analysis is not None

        assert report.registration_analysis.strong_associations_count == 1
        finding = next(
            f for f in report.registration_analysis.findings
            if f.evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION
        )
        assert finding.normalized_uuid == "0000180d-0000-1000-8000-00805f9b34fb"
        assert finding.class_name == "org.example.service_a.GattService"
        assert finding.method_name == "registerService"
        assert len(finding.trace_steps) == 4

        # Verify trace step sequence
        opcodes = [s.opcode for s in finding.trace_steps]
        assert "const-string" in opcodes
        assert "invoke-static" in opcodes
        assert "invoke-direct" in opcodes
        assert "invoke-virtual" in opcodes

    def test_tc_reg_unresolved_cross_method_service(self, unresolved_registration_apk: Path, tmp_path: Path):
        """TC-REG-UNRESOLVED-01: addService() called with cross-method/parameter service object."""
        out_dir = tmp_path / "reports"
        report, json_p, html_p = analyze_single_apk(unresolved_registration_apk, out_path=out_dir)
        assert report.status == "success"
        assert report.registration_analysis is not None

        assert report.registration_analysis.total_add_service_calls == 1
        assert report.registration_analysis.strong_associations_count == 0
        assert report.registration_analysis.unresolved_patterns_count == 1

        finding = next(
            f for f in report.registration_analysis.findings
            if f.evidence_level == EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED
        )
        assert finding.unresolved_reason == UnresolvedReason.CROSS_METHOD_SERVICE_OBJECT
        assert finding.normalized_uuid is None
        assert finding.registration_site is not None

    def test_tc_reg_unresolved_service_without_add(self, service_constructed_without_add_service_apk: Path, tmp_path: Path):
        """TC-REG-UNRESOLVED-02: BluetoothGattService constructed with literal UUID, but addService() never invoked."""
        out_dir = tmp_path / "reports"
        report, json_p, html_p = analyze_single_apk(service_constructed_without_add_service_apk, out_path=out_dir)
        assert report.status == "success"
        assert report.registration_analysis is not None

        assert report.registration_analysis.total_service_constructions == 1
        assert report.registration_analysis.total_add_service_calls == 0
        assert report.registration_analysis.strong_associations_count == 0
        assert report.registration_analysis.unresolved_patterns_count == 1

        finding = next(
            f for f in report.registration_analysis.findings
            if f.evidence_level == EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED
        )
        assert finding.unresolved_reason == UnresolvedReason.SERVICE_CONSTRUCTED_WITHOUT_LOCAL_ADD_SERVICE
        assert finding.normalized_uuid == "0000180d-0000-1000-8000-00805f9b34fb"
        assert finding.construction_site is not None
        assert finding.registration_site is None


class TestValidationMatrixCrossAPKConflicts:
    """Matrix Categories 7, 8: Cross-APK Conflicts (Duplicate Candidates vs Duplicate Registrations)."""

    def test_tc_conflict_duplicate_candidate_no_registration(
        self,
        conflict_apk_a: Path,
        negative_candidate_apk: Path,
        tmp_path: Path,
    ):
        """TC-CONFLICT-DUPLICATE-CAND-01: Shared UUID candidate without dual static registrations."""
        out_dir = tmp_path / "reports"
        batch_report, b_json_p, b_html_p = batch_analyze([conflict_apk_a, negative_candidate_apk], out_dir=out_dir)

        assert batch_report.successful_count == 2
        conflicts = batch_report.cross_apk_conflicts
        assert conflicts is not None

        # Must NOT claim strong duplicate static registration
        assert conflicts.strong_duplicate_static_registrations_count == 0

        # Must report duplicate candidate without registration
        assert conflicts.duplicate_candidates_unregistered_count == 1
        cand_matches = [a for a in conflicts.assessments if a.condition == ConflictCondition.DUPLICATE_CANDIDATE_NO_REGISTRATION]
        assert len(cand_matches) == 1
        cand_match = cand_matches[0]
        assert cand_match.normalized_uuid == "0000180d-0000-1000-8000-00805f9b34fb"
        assert cand_match.condition == ConflictCondition.DUPLICATE_CANDIDATE_NO_REGISTRATION

    def test_tc_conflict_duplicate_strong_registration(
        self,
        conflict_apk_a: Path,
        conflict_apk_b: Path,
        tmp_path: Path,
    ):
        """TC-CONFLICT-DUPLICATE-STRONG-01: Two distinct APKs statically register the exact same UUID."""
        out_dir = tmp_path / "reports"
        batch_report, b_json_p, b_html_p = batch_analyze([conflict_apk_a, conflict_apk_b], out_dir=out_dir)

        assert batch_report.successful_count == 2
        conflicts = batch_report.cross_apk_conflicts
        assert conflicts is not None

        assert conflicts.strong_duplicate_static_registrations_count == 1
        strong_matches = [a for a in conflicts.assessments if a.condition == ConflictCondition.STRONG_DUPLICATE_STATIC_REGISTRATION]
        assert len(strong_matches) == 1
        match = strong_matches[0]
        assert match.normalized_uuid == "0000180d-0000-1000-8000-00805f9b34fb"
        assert match.condition == ConflictCondition.STRONG_DUPLICATE_STATIC_REGISTRATION
        assert match.is_proven is True

        # Check evidence contains both packages
        packages = {e.package_name for e in match.participating_apks}
        assert packages == {"org.example.service_a", "org.example.service_b"}


class TestValidationMatrixGracefulDegradationAndIntegrity:
    """Matrix Category 9: Missing/Degraded Inputs & Input Immutability."""

    def test_tc_input_degrade_missing_knowledge_base(self, conflict_apk_a: Path, tmp_path: Path, monkeypatch):
        """TC-INPUT-DEGRADE-01: Unavailable knowledge base degrades gracefully to partial status."""
        out_dir = tmp_path / "reports"

        def _raise_kb_error(*args, **kwargs):
            raise Exception("Simulated missing knowledge base dataset")

        monkeypatch.setattr("ucsd.orchestrator.UUIDKnowledgeBase", _raise_kb_error)

        report, json_p, html_p = analyze_single_apk(
            conflict_apk_a,
            out_path=out_dir,
            skip_kb=False,
        )
        assert report.status == "partial"
        assert any("Knowledge base" in lim for lim in report.limitations)
        assert report.registration_analysis is not None
        assert report.registration_analysis.strong_associations_count == 1

    def test_tc_input_degrade_batch_with_corrupt_apk(
        self,
        conflict_apk_a: Path,
        corrupt_zip_apk: Path,
        tmp_path: Path,
    ):
        """TC-INPUT-DEGRADE-02: Batch analysis isolates corrupted target into failed_targets."""
        out_dir = tmp_path / "reports"
        batch_report, b_json_p, b_html_p = batch_analyze([conflict_apk_a, corrupt_zip_apk], out_dir=out_dir)

        assert batch_report.total_targets == 2
        assert batch_report.successful_count == 1
        assert batch_report.failed_count == 1
        assert len(batch_report.failed_targets) == 1
        failed = batch_report.failed_targets[0]
        assert "CorruptZipAPKError" in failed["error_type"]

    def test_tc_immutability_sample_apks_unmodified(self):
        """TC-IMMUTABILITY-01: Verifies that analysis leaves input APKs strictly unmodified."""
        samples_dir = Path("/app/samples")
        if not samples_dir.exists():
            pytest.skip("Samples directory /app/samples not mounted")

        apk_files = list(samples_dir.glob("*.apk"))
        if not apk_files:
            pytest.skip("No APKs found in /app/samples")

        for apk_path in apk_files:
            # Measure SHA-256 and size before
            with open(apk_path, "rb") as f:
                content_before = f.read()
            hash_before = hashlib.sha256(content_before).hexdigest()
            size_before = len(content_before)

            # Analyze without modifying
            report, json_p, html_p = analyze_single_apk(apk_path, out_path=Path("/app/reports"), generate_html=False)
            assert report.metadata is not None
            assert report.metadata.sha256 == hash_before

            # Measure SHA-256 and size after
            with open(apk_path, "rb") as f:
                content_after = f.read()
            hash_after = hashlib.sha256(content_after).hexdigest()
            size_after = len(content_after)

            assert hash_before == hash_after, f"APK {apk_path.name} was modified during analysis!"
            assert size_before == size_after, f"APK {apk_path.name} changed size during analysis!"
