"""Comprehensive test suite for UCSD Phase 2: BLE indicators and UUID extraction."""

import json
from pathlib import Path
import pytest

from ucsd.apk_loader import load_apk
from ucsd.ble.extractor import extract_bluetooth_permissions, scan_ble_indicators
from ucsd.ble.models import (
    BLEAnalysisResult,
    BLEApiIndicators,
    BLEPermissions,
    UUIDCandidate,
    UUIDEvidence,
)
from ucsd.ble.normalizer import (
    BLUETOOTH_BASE_UUID,
    classify_uuid_format,
    expand_16bit_uuid,
    extract_short_hex,
    is_bluetooth_sig_range,
    lookup_sig_name,
    normalize_uuid,
)
from ucsd.cli import run_analyze
from ucsd.errors import InvalidUUIDError
from ucsd.models import ManifestMetadata


class TestUUIDNormalization:
    """Test suite for UUID normalization, format classification, and Base UUID expansion."""

    def test_normalize_canonical_128_lowercase(self):
        """Verify standard lowercase canonical 128-bit UUID is preserved."""
        raw = "cd59ba31-5729-b3bb-cb29-732b59eb61aa"
        assert normalize_uuid(raw) == "cd59ba31-5729-b3bb-cb29-732b59eb61aa"
        assert classify_uuid_format(raw) == "canonical-128"

    def test_normalize_canonical_128_uppercase(self):
        """Verify uppercase canonical 128-bit UUID is normalized to lowercase."""
        raw = "CD59BA31-5729-B3BB-CB29-732B59EB61AA"
        assert normalize_uuid(raw) == "cd59ba31-5729-b3bb-cb29-732b59eb61aa"
        assert classify_uuid_format(raw) == "canonical-128"

    def test_normalize_16bit_prefixed(self):
        """Verify 0x-prefixed 16-bit UUID expands using Bluetooth Base UUID."""
        raw = "0x180D"
        expected = "0000180d-0000-1000-8000-00805f9b34fb"
        assert normalize_uuid(raw) == expected
        assert classify_uuid_format(raw) == "bluetooth-16-prefixed"

    def test_normalize_16bit_raw(self):
        """Verify raw 4-character hex 16-bit UUID expands using Bluetooth Base UUID."""
        raw = "180f"
        expected = "0000180f-0000-1000-8000-00805f9b34fb"
        assert normalize_uuid(raw) == expected
        assert classify_uuid_format(raw) == "bluetooth-16-raw"

    def test_normalize_32bit_hex(self):
        """Verify 32-bit hex expands using Bluetooth Base UUID."""
        prefixed = "0x00001800"
        raw = "00001800"
        expected = "00001800-0000-1000-8000-00805f9b34fb"
        assert normalize_uuid(prefixed) == expected
        assert normalize_uuid(raw) == expected
        assert classify_uuid_format(prefixed) == "bluetooth-32-prefixed"
        assert classify_uuid_format(raw) == "bluetooth-32-raw"

    def test_normalize_raw_128_unhyphenated(self):
        """Verify 32-hex character unhyphenated string is normalized to hyphenated form."""
        raw = "cd59ba315729b3bbcb29732b59eb61aa"
        expected = "cd59ba31-5729-b3bb-cb29-732b59eb61aa"
        assert normalize_uuid(raw) == expected
        assert classify_uuid_format(raw) == "raw-128-hex"

    def test_bluetooth_sig_range_detection(self):
        """Verify correct detection of Bluetooth Base UUID range."""
        sig_uuid = "0000180d-0000-1000-8000-00805f9b34fb"
        custom_uuid = "cd59ba31-5729-b3bb-cb29-732b59eb61aa"
        assert is_bluetooth_sig_range(sig_uuid) is True
        assert is_bluetooth_sig_range(custom_uuid) is False

    def test_extract_short_hex_and_name_lookup(self):
        """Verify 16-bit short ID extraction and human-readable SIG service name lookup."""
        hr_uuid = "0000180d-0000-1000-8000-00805f9b34fb"
        short_hex = extract_short_hex(hr_uuid)
        assert short_hex == "180d"
        assert lookup_sig_name(short_hex) == "Heart Rate"

        batt_uuid = "0000180f-0000-1000-8000-00805f9b34fb"
        assert lookup_sig_name(extract_short_hex(batt_uuid)) == "Battery Service"

        custom_uuid = "cd59ba31-5729-b3bb-cb29-732b59eb61aa"
        assert extract_short_hex(custom_uuid) is None
        assert lookup_sig_name(extract_short_hex(custom_uuid)) is None


class TestUUIDMalformedRejection:
    """Test suite ensuring malformed, invalid, or unsupported UUID candidates are rejected safely."""

    def test_reject_empty_string(self):
        """Reject empty string."""
        with pytest.raises(InvalidUUIDError):
            normalize_uuid("")

    def test_reject_non_hex_characters(self):
        """Reject values containing invalid non-hexadecimal characters."""
        with pytest.raises(InvalidUUIDError):
            normalize_uuid("0x180G")
        with pytest.raises(InvalidUUIDError):
            normalize_uuid("180Z")
        with pytest.raises(InvalidUUIDError):
            normalize_uuid("zzzzzzzz-0000-1000-8000-00805f9b34fb")

    def test_reject_invalid_lengths(self):
        """Reject values with incorrect lengths for 16-bit or 128-bit UUIDs."""
        with pytest.raises(InvalidUUIDError):
            normalize_uuid("180")  # 3 chars
        with pytest.raises(InvalidUUIDError):
            normalize_uuid("18000")  # 5 chars
        with pytest.raises(InvalidUUIDError):
            normalize_uuid("0x180")  # 5 chars prefixed
        with pytest.raises(InvalidUUIDError):
            normalize_uuid("0000180d-0000-1000-8000-00805f9b34f")  # 35 chars
        with pytest.raises(InvalidUUIDError):
            normalize_uuid("0000180d-0000-1000-8000-00805f9b34fba")  # 37 chars

    def test_reject_invalid_separators(self):
        """Reject 128-bit UUID candidates with invalid separators (e.g. underscores)."""
        with pytest.raises(InvalidUUIDError):
            normalize_uuid("0000180d_0000_1000_8000_00805f9b34fb")

    def test_reject_non_string_types(self):
        """Reject non-string types with structured error."""
        with pytest.raises(InvalidUUIDError):
            normalize_uuid(12345)  # type: ignore
        with pytest.raises(InvalidUUIDError):
            normalize_uuid(None)  # type: ignore


class TestBLEAnalysisFixtures:
    """Test suite for BLE indicator detection and candidate extraction across synthetic fixtures."""

    def test_ble_permissions_classification(self):
        """Verify classification of modern BLE vs classic Bluetooth permissions."""
        manifest = ManifestMetadata(
            package_name="com.test",
            requested_permissions=[
                "android.permission.INTERNET",
                "android.permission.BLUETOOTH",
                "android.permission.BLUETOOTH_ADMIN",
                "android.permission.BLUETOOTH_SCAN",
                "android.permission.BLUETOOTH_CONNECT",
            ],
            declared_permissions=["com.test.permission.CUSTOM_BLUETOOTH"],
        )
        perms = extract_bluetooth_permissions(manifest)
        assert perms.has_ble_permission is True
        assert perms.has_classic_permission is True
        assert len(perms.requested) == 4
        assert "android.permission.BLUETOOTH_SCAN" in perms.requested
        assert "android.permission.BLUETOOTH_CONNECT" in perms.requested
        assert len(perms.declared) == 1

    def test_no_ble_apk(self, no_ble_apk: Path):
        """Verify non-BLE APK produces no BLE indicators, no candidates, and has_ble_indicators=False."""
        meta = load_apk(no_ble_apk, scan_ble=True)
        assert meta.ble_analysis is not None
        ble = meta.ble_analysis

        assert ble.has_ble_indicators is False
        assert len(ble.uuid_candidates) == 0
        assert ble.permissions.has_ble_permission is False
        assert ble.permissions.has_classic_permission is False
        assert len(ble.api_indicators.referenced_methods) == 0
        assert len(ble.api_indicators.framework_classes) == 0

    def test_ble_single_dex_apk(self, ble_single_dex_apk: Path):
        """Verify BLE APK intake extracts permissions and UUID candidates correctly."""
        meta = load_apk(ble_single_dex_apk, scan_ble=True)
        assert meta.ble_analysis is not None
        ble = meta.ble_analysis

        assert ble.has_ble_indicators is True
        assert ble.permissions.has_ble_permission is True
        assert len(ble.permissions.requested) == 3

        # Candidates check
        assert len(ble.uuid_candidates) == 3
        cand_map = {c.normalized_uuid: c for c in ble.uuid_candidates}

        # 1. 0000180d-0000-1000-8000-00805f9b34fb (Heart Rate)
        assert "0000180d-0000-1000-8000-00805f9b34fb" in cand_map
        c1 = cand_map["0000180d-0000-1000-8000-00805f9b34fb"]
        assert c1.is_bluetooth_sig_range is True
        assert c1.sig_name == "Heart Rate"
        assert c1.short_hex == "180d"

        # 2. 0x180F -> 0000180f-0000-1000-8000-00805f9b34fb (Battery Service)
        assert "0000180f-0000-1000-8000-00805f9b34fb" in cand_map
        c2 = cand_map["0000180f-0000-1000-8000-00805f9b34fb"]
        assert c2.is_bluetooth_sig_range is True
        assert c2.sig_name == "Battery Service"

        # 3. 12345678-1234-5678-1234-567812345678 (Custom)
        assert "12345678-1234-5678-1234-567812345678" in cand_map
        c3 = cand_map["12345678-1234-5678-1234-567812345678"]
        assert c3.is_bluetooth_sig_range is False
        assert c3.sig_name is None

    def test_ble_multidex_deduplication(self, ble_multidex_apk: Path):
        """Verify Multi-DEX APK deduplicates identical candidates across classes.dex and classes2.dex."""
        meta = load_apk(ble_multidex_apk, scan_ble=True)
        assert meta.ble_analysis is not None
        ble = meta.ble_analysis

        assert meta.is_multidex is True
        assert meta.dex_count == 2
        cand_map = {c.normalized_uuid: c for c in ble.uuid_candidates}

        # 00001800-0000-1000-8000-00805f9b34fb appears in both classes.dex and classes2.dex
        shared_uuid = "00001800-0000-1000-8000-00805f9b34fb"
        assert shared_uuid in cand_map
        shared_cand = cand_map[shared_uuid]

        # Occurrence count reflects both DEX occurrences
        assert shared_cand.occurrence_count == 2
        dex_files_found = {ev.dex_file for ev in shared_cand.evidence}
        assert "classes.dex" in dex_files_found
        assert "classes2.dex" in dex_files_found
        assert len(shared_cand.evidence) == 2


class TestSampleAPKBLEAnalysis:
    """Test suite inspecting the real sample APK (/app/samples/validation.apk)."""

    SAMPLE_APK = Path("/app/samples/validation.apk")

    @pytest.mark.skipif(
        not Path("/app/samples/validation.apk").exists(),
        reason="Real sample APK /app/samples/validation.apk not present",
    )
    def test_sample_apk_ble_analysis(self):
        """Verify static BLE indicator detection and candidate extraction on real APK."""
        meta = load_apk(self.SAMPLE_APK, scan_ble=True)
        assert meta.ble_analysis is not None
        ble = meta.ble_analysis

        # 1. Indicator flag
        assert ble.has_ble_indicators is True

        # 2. Permissions check: F-Droid requests 5 Bluetooth permissions
        perms = ble.permissions
        assert perms.has_ble_permission is True
        assert perms.has_classic_permission is True
        assert "android.permission.BLUETOOTH_SCAN" in perms.requested
        assert "android.permission.BLUETOOTH_CONNECT" in perms.requested
        assert "android.permission.BLUETOOTH_ADVERTISE" in perms.requested
        assert "android.permission.BLUETOOTH" in perms.requested
        assert "android.permission.BLUETOOTH_ADMIN" in perms.requested

        # 3. Framework & App classes referenced
        assert "android.bluetooth.BluetoothAdapter" in ble.api_indicators.framework_classes
        assert "android.bluetooth.BluetoothDevice" in ble.api_indicators.framework_classes
        assert "org.fdroid.fdroid.nearby.BluetoothConstants" in ble.api_indicators.app_classes

        # 4. Custom UUID candidate with bytecode instruction evidence
        cand_map = {c.normalized_uuid: c for c in ble.uuid_candidates}
        fdroid_uuid = "cd59ba31-5729-b3bb-cb29-732b59eb61aa"
        assert fdroid_uuid in cand_map

        fdroid_cand = cand_map[fdroid_uuid]
        assert fdroid_cand.is_bluetooth_sig_range is False
        assert fdroid_cand.occurrence_count >= 2

        # Check instruction evidence location
        bytecode_ev = [
            e for e in fdroid_cand.evidence if e.extraction_method == "bytecode_instruction"
        ]
        assert len(bytecode_ev) >= 1
        assert bytecode_ev[0].dex_file == "classes2.dex"
        assert bytecode_ev[0].class_name == "org.fdroid.fdroid.nearby.BluetoothConstants"
        assert bytecode_ev[0].method_name == "fdroidUuid"

        # Check string pool evidence location
        pool_ev = [
            e for e in fdroid_cand.evidence if e.extraction_method == "string_pool"
        ]
        assert len(pool_ev) >= 1
        assert pool_ev[0].dex_file == "classes2.dex"

        # 5. Verify NO registration verdict
        # Candidates are pure data models without registration fields
        for cand in ble.uuid_candidates:
            assert hasattr(cand, "normalized_uuid")
            assert not hasattr(cand, "is_registered")
            assert not hasattr(cand, "registration_verdict")

        # 6. Verify analytical summary notes
        assert len(ble.summary_notes) >= 5
        notes_str = " ".join(ble.summary_notes)
        assert "not proof of runtime use" in notes_str
        assert "not proof of server-side service registration" in notes_str
        assert "No UUID is marked as registered" in notes_str
        assert "false-positive sources" in notes_str


class TestCLIPhase2Integration:
    """Test suite for CLI analyze command with Phase 2 BLE output."""

    @pytest.mark.skipif(
        not Path("/app/samples/validation.apk").exists(),
        reason="Real sample APK /app/samples/validation.apk not present",
    )
    def test_cli_analyze_produces_ble_report(self, tmp_path: Path):
        """Verify CLI produces JSON report containing both metadata and ble_analysis."""
        rep_file = tmp_path / "cli_test_report.json"
        code = run_analyze(
            target_path="/app/samples/validation.apk",
            out_path=str(rep_file),
            skip_ble=False,
            quiet=True,
        )
        assert code == 0
        assert rep_file.is_file()

        with open(rep_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert "metadata" in data
        assert "ble_analysis" in data
        assert data["ble_analysis"]["has_ble_indicators"] is True
        assert len(data["ble_analysis"]["uuid_candidates"]) > 0

    @pytest.mark.skipif(
        not Path("/app/samples/validation.apk").exists(),
        reason="Real sample APK /app/samples/validation.apk not present",
    )
    def test_cli_analyze_skip_ble(self, tmp_path: Path):
        """Verify --skip-ble flag leaves ble_analysis null."""
        rep_file = tmp_path / "skip_ble_report.json"
        code = run_analyze(
            target_path="/app/samples/validation.apk",
            out_path=str(rep_file),
            skip_ble=True,
            quiet=True,
        )
        assert code == 0
        assert rep_file.is_file()

        with open(rep_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["metadata"] is not None
        assert data["ble_analysis"] is None
