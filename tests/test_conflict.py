"""Comprehensive test suite for Phase 4: UUID knowledge base and conflict assessment."""

import json
from pathlib import Path
import pytest

from ucsd.apk_loader import load_apk
from ucsd.ble.models import (
    BLEAnalysisResult,
    BLEApiIndicators,
    BLEPermissions,
    UUIDCandidate,
    UUIDEvidence,
)
from ucsd.cli import main, run_analyze, run_compare
from ucsd.conflict.assessor import assess_single_apk, compare_apks
from ucsd.conflict.models import (
    ConflictCondition,
    CrossAPKConflictReport,
    SingleAPKKnowledgeAssessment,
)
from ucsd.knowledge.repository import UUIDKnowledgeBase
from ucsd.models import (
    APKMetadata,
    AnalysisReport,
    DEXInfo,
    ManifestMetadata,
)
from ucsd.registration.models import (
    EvidenceLevel,
    RegistrationAnalysisResult,
    RegistrationFinding,
    TraceStep,
    UnresolvedReason,
)


def _make_dummy_apk_metadata(
    pkg_name: str,
    file_name: str,
    sha256: str,
    findings: list,
    candidates: list,
) -> APKMetadata:
    """Helper creating minimal APKMetadata for conflict testing."""
    manifest = ManifestMetadata(
        package_name=pkg_name,
        version_code=100,
        version_name="1.0",
        min_sdk_version=21,
        target_sdk_version=33,
    )
    reg_analysis = RegistrationAnalysisResult(
        has_gatt_registrations=any(f.evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION for f in findings),
        total_add_service_calls=len(findings),
        total_service_constructions=len(findings),
        strong_associations_count=sum(1 for f in findings if f.evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION),
        unresolved_patterns_count=sum(1 for f in findings if f.evidence_level == EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED),
        candidate_only_count=sum(1 for f in findings if f.evidence_level == EvidenceLevel.UUID_CANDIDATE_ONLY),
        findings=findings,
    )
    cand_models = []
    for c in candidates:
        ev = UUIDEvidence(
            original_text=c,
            normalized_uuid=c,
            format_type="canonical-128",
            dex_file="classes.dex",
            class_name="com.test.Dummy",
            method_name="dummy",
            extraction_method="bytecode_instruction",
        )
        cand_models.append(
            UUIDCandidate(
                normalized_uuid=c,
                is_bluetooth_sig_range=False,
                occurrence_count=1,
                evidence=[ev],
            )
        )

    ble_analysis = BLEAnalysisResult(
        has_ble_indicators=True,
        permissions=BLEPermissions(),
        api_indicators=BLEApiIndicators(),
        uuid_candidates=cand_models,
        candidate_summary={},
        summary_notes=[],
    )

    return APKMetadata(
        file_path=f"/app/samples/{file_name}",
        file_name=file_name,
        file_size_bytes=10000,
        sha256=sha256,
        is_valid_zip=True,
        is_multidex=False,
        dex_count=1,
        dex_files=[DEXInfo(name="classes.dex", sha256=sha256, size_bytes=5000)],
        manifest=manifest,
        ble_analysis=ble_analysis,
        registration_analysis=reg_analysis,
        knowledge_base_assessment=None,
    )


class TestConflictConditionSeparation:
    """Test suite ensuring conflict conditions are strictly separated according to evidence."""

    def test_strong_duplicate_registration_conflict(self):
        """Scenario A: Two distinct APKs both have STRONG_STATIC_ASSOCIATION for same UUID."""
        shared_uuid = "0000180d-0000-1000-8000-00805f9b34fb"

        trace1 = [
            TraceStep(step_index=0, step_type="load_uuid_string", instruction_offset=10, opcode="const-string", details={}),
            TraceStep(step_index=1, step_type="add_service_registration", instruction_offset=40, opcode="invoke-virtual", details={}),
        ]
        finding1 = RegistrationFinding(
            evidence_level=EvidenceLevel.STRONG_STATIC_ASSOCIATION,
            normalized_uuid=shared_uuid,
            dex_file="classes.dex",
            class_name="com.app.heartrate.HeartManager",
            method_name="startServer",
            descriptor="()V",
            diagnosis="Verified registration in App A",
            trace_steps=trace1,
        )

        trace2 = [
            TraceStep(step_index=0, step_type="load_uuid_string", instruction_offset=20, opcode="const-string", details={}),
            TraceStep(step_index=1, step_type="add_service_registration", instruction_offset=60, opcode="invoke-virtual", details={}),
        ]
        finding2 = RegistrationFinding(
            evidence_level=EvidenceLevel.STRONG_STATIC_ASSOCIATION,
            normalized_uuid=shared_uuid,
            dex_file="classes.dex",
            class_name="org.other.wearable.BleServer",
            method_name="registerHeartRate",
            descriptor="()V",
            diagnosis="Verified registration in App B",
            trace_steps=trace2,
        )

        apk1 = _make_dummy_apk_metadata("com.app.heartrate", "app_a.apk", "1111" * 16, [finding1], [shared_uuid])
        apk2 = _make_dummy_apk_metadata("org.other.wearable", "app_b.apk", "2222" * 16, [finding2], [shared_uuid])

        report = compare_apks([apk1, apk2])

        assert report.total_apks_analyzed == 2
        assert report.strong_duplicate_static_registrations_count == 1
        assert report.proven_registration_conflicts_count == 1
        assert report.duplicate_candidates_unregistered_count == 0

        conflict = report.assessments[0]
        assert conflict.normalized_uuid == shared_uuid
        assert conflict.condition == ConflictCondition.STRONG_DUPLICATE_STATIC_REGISTRATION
        assert conflict.is_proven is True
        assert conflict.is_proven_service_conflict is True
        assert len(conflict.participating_apks) == 2

        # Verify explainability: shows both APK package identities and methods
        pkgs = {ev.package_name for ev in conflict.participating_apks}
        assert pkgs == {"com.app.heartrate", "org.other.wearable"}
        methods = {ev.method_name for ev in conflict.participating_apks}
        assert methods == {"startServer", "registerHeartRate"}
        assert "high-confidence static overlap and may warrant runtime/host-context validation" in conflict.explanation

    def test_duplicate_candidate_no_registration_evidence(self):
        """Scenario B: Duplicate candidate string across APKs without dual static registration."""
        shared_uuid = "cd59ba31-5729-b3bb-cb29-732b59eb61aa"

        # Neither app registers this UUID; it's merely a string constant
        apk1 = _make_dummy_apk_metadata("com.app.first", "first.apk", "3333" * 16, [], [shared_uuid])
        apk2 = _make_dummy_apk_metadata("com.app.second", "second.apk", "4444" * 16, [], [shared_uuid])

        report = compare_apks([apk1, apk2])

        assert report.proven_registration_conflicts_count == 0
        assert report.duplicate_candidates_unregistered_count == 1

        assessment = report.assessments[0]
        assert assessment.condition == ConflictCondition.DUPLICATE_CANDIDATE_NO_REGISTRATION
        assert assessment.is_proven_service_conflict is False
        assert "NOT a proven service conflict" in assessment.explanation

    def test_one_app_registers_one_app_has_candidate_only(self):
        """Verify when one app registers and second app only contains string, it is NOT proven collision."""
        shared_uuid = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"  # Nordic NUS

        finding1 = RegistrationFinding(
            evidence_level=EvidenceLevel.STRONG_STATIC_ASSOCIATION,
            normalized_uuid=shared_uuid,
            dex_file="classes.dex",
            class_name="com.nus.server.NUSManager",
            method_name="initServer",
            descriptor="()V",
            diagnosis="App 1 registers NUS",
            trace_steps=[],
        )

        apk1 = _make_dummy_apk_metadata("com.nus.server", "server.apk", "5555" * 16, [finding1], [shared_uuid])
        apk2 = _make_dummy_apk_metadata("com.nus.client", "client.apk", "6666" * 16, [], [shared_uuid])

        report = compare_apks([apk1, apk2])

        assert report.proven_registration_conflicts_count == 0
        assert report.duplicate_candidates_unregistered_count == 1
        ass = report.assessments[0]
        assert ass.condition == ConflictCondition.DUPLICATE_CANDIDATE_NO_REGISTRATION
        assert ass.is_proven_service_conflict is False

    def test_known_assigned_standard_match_single_apk(self):
        """Scenario C: Known standard Bluetooth SIG UUID in single APK."""
        sig_uuid = "0000180f-0000-1000-8000-00805f9b34fb"  # Battery Service
        finding = RegistrationFinding(
            evidence_level=EvidenceLevel.STRONG_STATIC_ASSOCIATION,
            normalized_uuid=sig_uuid,
            dex_file="classes.dex",
            class_name="com.battery.Service",
            method_name="setup",
            descriptor="()V",
            diagnosis="Battery setup",
            trace_steps=[],
        )
        apk = _make_dummy_apk_metadata("com.battery.app", "batt.apk", "7777" * 16, [finding], [sig_uuid])

        report = compare_apks([apk])
        assert report.known_standard_matches_count == 1
        ass = report.assessments[0]
        assert ass.condition == ConflictCondition.KNOWN_ASSIGNED_STANDARD_MATCH
        assert ass.is_proven_service_conflict is False
        assert ass.knowledge_base_match is not None
        assert ass.knowledge_base_match.name == "Battery Service"
        assert "not indicative of conflict or malicious intent" in ass.explanation

    def test_known_system_vendor_match_single_apk(self):
        """Scenario D: Known system/vendor UUID in single APK."""
        fast_pair_uuid = "0000fe2c-0000-1000-8000-00805f9b34fb"  # Google Fast Pair
        apk = _make_dummy_apk_metadata("com.google.nearby", "nearby.apk", "8888" * 16, [], [fast_pair_uuid])

        report = compare_apks([apk])
        assert report.known_system_vendor_matches_count == 1
        ass = report.assessments[0]
        assert ass.condition == ConflictCondition.KNOWN_SYSTEM_OR_VENDOR_MATCH
        assert ass.knowledge_base_match is not None
        assert ass.knowledge_base_match.name == "Google Fast Pair Service"
        assert ass.knowledge_base_match.is_system_or_vendor is True
        assert "developers.google.com" in ass.knowledge_base_match.source_url

    def test_unresolved_registration_overlap_across_apks(self):
        """Scenario E: Unresolved registration patterns across APKs."""
        unres_uuid = "00001812-0000-1000-8000-00805f9b34fb"  # HID
        f1 = RegistrationFinding(
            evidence_level=EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED,
            normalized_uuid=unres_uuid,
            dex_file="classes.dex",
            class_name="com.hid.App1",
            method_name="reg1",
            descriptor="()V",
            diagnosis="Unresolved 1",
            unresolved_reason=UnresolvedReason.CROSS_METHOD_SERVICE_OBJECT,
        )
        f2 = RegistrationFinding(
            evidence_level=EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED,
            normalized_uuid=unres_uuid,
            dex_file="classes.dex",
            class_name="com.hid.App2",
            method_name="reg2",
            descriptor="()V",
            diagnosis="Unresolved 2",
            unresolved_reason=UnresolvedReason.FIELD_BASED_SERVICE_OBJECT,
        )
        apk1 = _make_dummy_apk_metadata("com.hid.app1", "hid1.apk", "9999" * 16, [f1], [unres_uuid])
        apk2 = _make_dummy_apk_metadata("com.hid.app2", "hid2.apk", "aaaa" * 16, [f2], [unres_uuid])

        report = compare_apks([apk1, apk2])
        assert report.proven_registration_conflicts_count == 0
        ass = report.assessments[0]
        assert ass.condition == ConflictCondition.UNRESOLVED_REGISTRATION_OVERLAP
        assert ass.is_proven_service_conflict is False

    def test_identical_package_name_across_apks_no_cross_conflict(self):
        """Test: Two APK versions with the same package name do not trigger cross-APK conflict."""
        shared_uuid = "0000180d-0000-1000-8000-00805f9b34fb"
        f1 = RegistrationFinding(
            evidence_level=EvidenceLevel.STRONG_STATIC_ASSOCIATION,
            normalized_uuid=shared_uuid,
            dex_file="classes.dex",
            class_name="com.example.ServiceV1",
            method_name="reg",
            descriptor="()V",
            diagnosis="V1 Registration",
        )
        f2 = RegistrationFinding(
            evidence_level=EvidenceLevel.STRONG_STATIC_ASSOCIATION,
            normalized_uuid=shared_uuid,
            dex_file="classes.dex",
            class_name="com.example.ServiceV2",
            method_name="reg",
            descriptor="()V",
            diagnosis="V2 Registration",
        )
        # Both APKs have identical package name "com.example.sameapp"
        apk_v1 = _make_dummy_apk_metadata("com.example.sameapp", "app_v1.apk", "1111" * 16, [f1], [shared_uuid])
        apk_v2 = _make_dummy_apk_metadata("com.example.sameapp", "app_v2.apk", "2222" * 16, [f2], [shared_uuid])

        report = compare_apks([apk_v1, apk_v2])
        # Must NOT be counted as STRONG_DUPLICATE_STATIC_REGISTRATION because it's the same package identity
        assert report.strong_duplicate_static_registrations_count == 0
        assert report.proven_registration_conflicts_count == 0
        assert report.total_apks_analyzed == 2

    def test_asymmetric_registration_overlap_strong_and_unresolved(self):
        """Test: Asymmetric registration overlap (one strong, one unresolved) yields UNRESOLVED_REGISTRATION_OVERLAP."""
        shared_uuid = "0000180d-0000-1000-8000-00805f9b34fb"
        f_strong = RegistrationFinding(
            evidence_level=EvidenceLevel.STRONG_STATIC_ASSOCIATION,
            normalized_uuid=shared_uuid,
            dex_file="classes.dex",
            class_name="com.app.Strong",
            method_name="reg",
            descriptor="()V",
            diagnosis="Strong local flow",
        )
        f_unres = RegistrationFinding(
            evidence_level=EvidenceLevel.REGISTRATION_PATTERN_UUID_UNRESOLVED,
            normalized_uuid=shared_uuid,
            dex_file="classes.dex",
            class_name="com.app.Unres",
            method_name="reg",
            descriptor="()V",
            diagnosis="Unresolved parameter",
            unresolved_reason=UnresolvedReason.CROSS_METHOD_SERVICE_OBJECT,
        )
        apk_strong = _make_dummy_apk_metadata("com.app.strong", "strong.apk", "3333" * 16, [f_strong], [shared_uuid])
        apk_unres = _make_dummy_apk_metadata("com.app.unres", "unres.apk", "4444" * 16, [f_unres], [shared_uuid])

        report = compare_apks([apk_strong, apk_unres])
        assert report.strong_duplicate_static_registrations_count == 0
        assert report.proven_registration_conflicts_count == 0

        ass = next(a for a in report.assessments if a.normalized_uuid == shared_uuid)
        assert ass.condition == ConflictCondition.UNRESOLVED_REGISTRATION_OVERLAP
        assert ass.is_proven is False
        assert ass.is_proven_service_conflict is False
        assert "NOT classified as a proven service conflict" in ass.explanation

    def test_duplicate_candidate_strings_never_proven_conflict(self):
        """Test: Identical UUID candidate strings across multiple APKs without GATT registrations are never proven conflicts."""
        common_uuid = "12345678-1234-5678-1234-567812345678"
        apk1 = _make_dummy_apk_metadata("com.util.app1", "app1.apk", "aaaa" * 16, [], [common_uuid])
        apk2 = _make_dummy_apk_metadata("com.util.app2", "app2.apk", "bbbb" * 16, [], [common_uuid])
        apk3 = _make_dummy_apk_metadata("com.util.app3", "app3.apk", "cccc" * 16, [], [common_uuid])

        report = compare_apks([apk1, apk2, apk3])
        assert report.total_apks_analyzed == 3
        assert report.strong_duplicate_static_registrations_count == 0
        assert report.proven_registration_conflicts_count == 0
        assert report.duplicate_candidates_unregistered_count == 1

        ass = next(a for a in report.assessments if a.normalized_uuid == common_uuid)
        assert ass.condition == ConflictCondition.DUPLICATE_CANDIDATE_NO_REGISTRATION
        assert ass.is_proven is False
        assert ass.is_proven_service_conflict is False
        assert len(ass.participating_apks) == 3



class TestSingleAPKKnowledgeAssessment:
    """Test suite for single APK knowledge base assessment integration."""

    def test_single_apk_assessment(self, ble_single_dex_apk: Path):
        """Verify load_apk runs knowledge base assessment on synthetic APK."""
        metadata = load_apk(ble_single_dex_apk, scan_knowledge_base=True)

        assert metadata.knowledge_base_assessment is not None
        kb_ass = metadata.knowledge_base_assessment
        assert isinstance(kb_ass, SingleAPKKnowledgeAssessment)
        assert kb_ass.total_candidates_checked > 0

        # ble_single_dex_apk contains Heart Rate (0000180d) and Battery (0x180F)
        assert kb_ass.known_standard_matches_count >= 2
        standard_uuids = [f.normalized_uuid for f in kb_ass.findings if f.condition == ConflictCondition.KNOWN_ASSIGNED_STANDARD_MATCH]
        assert "0000180d-0000-1000-8000-00805f9b34fb" in standard_uuids

    def test_skip_kb_flag_in_load_apk(self, ble_single_dex_apk: Path):
        """Verify scan_knowledge_base=False suppresses knowledge base assessment."""
        metadata = load_apk(ble_single_dex_apk, scan_knowledge_base=False)
        assert metadata.knowledge_base_assessment is None


class TestCLIConflictCommands:
    """Test suite for CLI analyze and compare commands."""

    def test_cli_analyze_produces_kb_assessment(self, ble_single_dex_apk: Path, tmp_path: Path):
        """Verify analyze produces knowledge_base_assessment block in JSON output."""
        out_file = tmp_path / "report_kb.json"
        exit_code = run_analyze(str(ble_single_dex_apk), str(out_file), quiet=True)

        assert exit_code == 0
        assert out_file.is_file()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert "knowledge_base_assessment" in data
        assert data["knowledge_base_assessment"] is not None
        assert data["knowledge_base_assessment"]["known_standard_matches_count"] >= 2

    def test_cli_analyze_skip_kb_flag(self, ble_single_dex_apk: Path, tmp_path: Path):
        """Verify --skip-kb suppresses knowledge base block."""
        reports_dir = tmp_path / "reports_skip_kb"
        exit_code = main([
            "analyze",
            str(ble_single_dex_apk),
            "--skip-kb",
            "--out",
            str(reports_dir),
            "--quiet",
        ])

        assert exit_code == 0
        report_files = list(reports_dir.glob("*.json"))
        assert len(report_files) == 1

        with open(report_files[0], "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["knowledge_base_assessment"] is None

    def test_cli_compare_command_with_reports(self, ble_single_dex_apk: Path, ble_multidex_apk: Path, tmp_path: Path):
        """Verify compare command runs on two analysis reports and writes conflict_report.json."""
        rep1 = tmp_path / "rep1.json"
        rep2 = tmp_path / "rep2.json"

        assert run_analyze(str(ble_single_dex_apk), str(rep1), quiet=True) == 0
        assert run_analyze(str(ble_multidex_apk), str(rep2), quiet=True) == 0

        out_conflict = tmp_path / "conflict_report.json"
        exit_code = run_compare([str(rep1), str(rep2)], str(out_conflict), quiet=True)

        assert exit_code == 0
        assert out_conflict.is_file()

        with open(out_conflict, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["total_apks_analyzed"] == 2
        assert "proven_registration_conflicts_count" in data
        assert "methodology_and_limitations" in data
        assert len(data["methodology_and_limitations"]) > 0

    def test_cli_compare_requires_at_least_two_targets(self, valid_single_dex_apk: Path, tmp_path: Path):
        """Verify compare command returns exit code 2 when fewer than 2 targets provided."""
        exit_code = main(["compare", str(valid_single_dex_apk), "--out", str(tmp_path)])
        assert exit_code == 2


class TestSampleAPKConflictEvaluation:
    """Test suite running knowledge base assessment against the real sample APK."""

    def test_sample_apk_kb_assessment(self):
        """Verify real F-Droid APK candidate UUIDs are evaluated against KB accurately."""
        sample_path = Path("/app/samples/validation.apk")
        if not sample_path.is_file():
            pytest.skip("Sample APK not present at /app/samples/validation.apk")

        meta = load_apk(str(sample_path), scan_ble=True, scan_registration=True, scan_knowledge_base=True)
        assert meta.knowledge_base_assessment is not None
        kb_ass = meta.knowledge_base_assessment

        assert kb_ass.total_candidates_checked == 88

        # In F-Droid, none of the candidates match curated Bluetooth SIG or vendor entries;
        # all 88 candidate UUIDs correctly remain unknown (unknown UUIDs remain unknown).
        assert kb_ass.unknown_candidates_count == 88
        assert kb_ass.known_standard_matches_count == 0
        assert kb_ass.known_system_vendor_matches_count == 0

        # Zero false claims of system/vendor or standards without source
        for f in kb_ass.findings:
            if f.condition == ConflictCondition.KNOWN_SYSTEM_OR_VENDOR_MATCH:
                assert f.knowledge_base_match is not None
                assert f.knowledge_base_match.is_system_or_vendor is True
                assert f.knowledge_base_match.source_url.startswith("http")

        # In single APK, proven service conflicts must be 0
        assert all(f.is_proven_service_conflict is False for f in kb_ass.findings)


class TestEndToEndControlledConflict:
    """End-to-end controlled conflict and negative duplicate tests with realistic fixtures."""

    def test_end_to_end_controlled_conflict(self, conflict_apk_a: Path, conflict_apk_b: Path):
        """Verify end-to-end load_apk and compare_apks detects STRONG_DUPLICATE_STATIC_REGISTRATION.

        Both APK A and APK B independently implement Dalvik bytecode that constructs
        a BluetoothGattService with UUID 0000180d-0000-1000-8000-00805f9b34fb and calls
        BluetoothGattServer.addService().
        """
        shared_uuid = "0000180d-0000-1000-8000-00805f9b34fb"

        meta_a = load_apk(conflict_apk_a)
        meta_b = load_apk(conflict_apk_b)

        # 1. Verify individual analyzers produce STRONG_STATIC_ASSOCIATION
        assert meta_a.manifest.package_name == "org.example.service_a"
        assert meta_a.registration_analysis is not None
        assert meta_a.registration_analysis.strong_associations_count == 1
        finding_a = meta_a.registration_analysis.findings[0]
        assert finding_a.evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION
        assert finding_a.normalized_uuid == shared_uuid

        assert meta_b.manifest.package_name == "org.example.service_b"
        assert meta_b.registration_analysis is not None
        assert meta_b.registration_analysis.strong_associations_count == 1
        finding_b = meta_b.registration_analysis.findings[0]
        assert finding_b.evidence_level == EvidenceLevel.STRONG_STATIC_ASSOCIATION
        assert finding_b.normalized_uuid == shared_uuid

        # 2. Compare the two APKs through cross-comparison pipeline
        report = compare_apks([meta_a, meta_b])

        assert report.total_apks_analyzed == 2
        assert report.strong_duplicate_static_registrations_count == 1
        assert report.proven_registration_conflicts_count == 1

        # 3. Locate the assessment for the shared UUID
        ass_matches = [a for a in report.assessments if a.normalized_uuid == shared_uuid]
        assert len(ass_matches) == 1
        ass = ass_matches[0]

        assert ass.condition == ConflictCondition.STRONG_DUPLICATE_STATIC_REGISTRATION
        assert ass.is_proven is True
        assert ass.is_proven_service_conflict is True
        assert len(ass.participating_apks) == 2

        # 4. Verify explainability: package identities, SHA-256, UUID, method, instruction offset, diagnosis
        pkgs = {ev.package_name for ev in ass.participating_apks}
        assert pkgs == {"org.example.service_a", "org.example.service_b"}

        sha256s = {ev.sha256 for ev in ass.participating_apks}
        assert len(sha256s) == 2
        assert meta_a.sha256 in sha256s
        assert meta_b.sha256 in sha256s

        methods = {ev.method_name for ev in ass.participating_apks}
        assert methods == {"registerService"}

        # Instruction offsets must be present and non-negative
        for ev in ass.participating_apks:
            assert ev.instruction_offset is not None
            assert ev.instruction_offset >= 0
            assert "STRONG_STATIC_ASSOCIATION" in ev.diagnosis or "verified" in ev.diagnosis.lower()

        # Explanation must be conservative and explainable
        assert "Two distinct APKs" in ass.explanation
        assert "high-confidence static overlap and may warrant runtime/host-context validation" in ass.explanation

    def test_end_to_end_negative_candidate_duplicate(
        self, conflict_apk_a: Path, negative_candidate_apk: Path
    ):
        """Verify duplicate candidate strings across APKs without dual registration yields DUPLICATE_CANDIDATE_NO_REGISTRATION."""
        shared_uuid = "0000180d-0000-1000-8000-00805f9b34fb"

        meta_a = load_apk(conflict_apk_a)
        meta_neg = load_apk(negative_candidate_apk)

        assert meta_a.registration_analysis.strong_associations_count == 1
        assert meta_neg.registration_analysis.strong_associations_count == 0

        report = compare_apks([meta_a, meta_neg])

        assert report.total_apks_analyzed == 2
        assert report.strong_duplicate_static_registrations_count == 0
        assert report.proven_registration_conflicts_count == 0
        assert report.duplicate_candidates_unregistered_count == 1

        ass_matches = [a for a in report.assessments if a.normalized_uuid == shared_uuid]
        assert len(ass_matches) == 1
        ass = ass_matches[0]

        assert ass.condition == ConflictCondition.DUPLICATE_CANDIDATE_NO_REGISTRATION
        assert ass.is_proven is False
        assert ass.is_proven_service_conflict is False
        assert "NOT a proven service conflict" in ass.explanation
        assert len(ass.participating_apks) == 2

    def test_end_to_end_cli_compare_workflow(
        self, conflict_apk_a: Path, conflict_apk_b: Path, tmp_path: Path
    ):
        """Verify full end-to-end CLI workflow from APKs to analysis JSON to compare JSON."""
        shared_uuid = "0000180d-0000-1000-8000-00805f9b34fb"
        report_a = tmp_path / "app_a_report.json"
        report_b = tmp_path / "app_b_report.json"
        conflict_out = tmp_path / "conflict_report.json"

        assert run_analyze(str(conflict_apk_a), str(report_a), quiet=True) == 0
        assert run_analyze(str(conflict_apk_b), str(report_b), quiet=True) == 0

        exit_code = run_compare([str(report_a), str(report_b)], str(conflict_out), quiet=True)
        assert exit_code == 0
        assert conflict_out.is_file()

        with open(conflict_out, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["total_apks_analyzed"] == 2
        assert data["strong_duplicate_static_registrations_count"] == 1
        assert data["proven_registration_conflicts_count"] == 1

        ass = next(a for a in data["assessments"] if a["normalized_uuid"] == shared_uuid)
        assert ass["condition"] == "STRONG_DUPLICATE_STATIC_REGISTRATION"
        assert ass["is_proven"] is True
        assert len(ass["participating_apks"]) == 2

        part_a = next(p for p in ass["participating_apks"] if p["package_name"] == "org.example.service_a")
        part_b = next(p for p in ass["participating_apks"] if p["package_name"] == "org.example.service_b")
        assert part_a["method_name"] == "registerService"
        assert part_b["method_name"] == "registerService"
        assert part_a["instruction_offset"] is not None
        assert part_b["instruction_offset"] is not None


