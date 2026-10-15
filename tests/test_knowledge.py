"""Test suite for UUID knowledge base, provenance validation, and lookup engine."""

import json
from pathlib import Path
import pytest
from pydantic import ValidationError

from ucsd.errors import InvalidKnowledgeBaseError, KnowledgeBaseError
from ucsd.knowledge.models import (
    KnowledgeBaseEntry,
    KnowledgeBaseLookupResult,
    KnowledgeBaseMetadata,
    SourceType,
)
from ucsd.knowledge.repository import UUIDKnowledgeBase


class TestUUIDKnowledgeBase:
    """Test suite for UUIDKnowledgeBase repository operations."""

    def test_load_default_knowledge_base(self):
        """Verify default knowledge base loads successfully with curated entries."""
        kb = UUIDKnowledgeBase()
        meta = kb.get_metadata()

        assert isinstance(meta, KnowledgeBaseMetadata)
        assert meta.total_entries >= 20
        assert meta.knowledge_base_version == "1.0.0"
        assert meta.schema_version == "1.0"
        assert "provenance" in meta.provenance_policy.lower()

        entries = kb.all_entries()
        assert len(entries) == meta.total_entries

    def test_exact_match_standard_bluetooth_sig(self):
        """Verify exact match lookup for Bluetooth SIG assigned numbers."""
        kb = UUIDKnowledgeBase()

        # Heart Rate Service (0x180D)
        res = kb.lookup("0000180d-0000-1000-8000-00805f9b34fb")
        assert res.is_known is True
        assert res.entry is not None
        assert res.entry.name == "Heart Rate Service"
        assert res.entry.source_type == SourceType.STANDARDS_ORGANIZATION
        assert "bluetooth.com" in res.entry.source_url
        assert res.entry.is_system_or_vendor is False
        assert len(res.entry.analyst_notes) > 0

    def test_normalization_before_lookup(self):
        """Verify uppercase and 16-bit hex formats normalize before lookup."""
        kb = UUIDKnowledgeBase()

        # Uppercase canonical
        res_upper = kb.lookup("0000180D-0000-1000-8000-00805F9B34FB")
        assert res_upper.is_known is True
        assert res_upper.normalized_query_uuid == "0000180d-0000-1000-8000-00805f9b34fb"

        # 16-bit prefixed
        res_16 = kb.lookup("0x180D")
        assert res_16.is_known is True
        assert res_16.normalized_query_uuid == "0000180d-0000-1000-8000-00805f9b34fb"

        # 16-bit raw hex
        res_raw = kb.lookup("180f")
        assert res_raw.is_known is True
        assert res_raw.entry.name == "Battery Service"

    def test_exact_match_sourced_system_and_vendor(self):
        """Verify exact match lookup for sourced OS and hardware vendor identifiers."""
        kb = UUIDKnowledgeBase()

        # Google Fast Pair (0xFE2C)
        res_gp = kb.lookup("0000fe2c-0000-1000-8000-00805f9b34fb")
        assert res_gp.is_known is True
        assert res_gp.entry.is_system_or_vendor is True
        assert res_gp.entry.source_type == SourceType.OS_VENDOR
        assert "developers.google.com" in res_gp.entry.source_url

        # Nordic UART Service (NUS)
        res_nus = kb.lookup("6e400001-b5a3-f393-e0a9-e50e24dcca9e")
        assert res_nus.is_known is True
        assert res_nus.entry.is_system_or_vendor is True
        assert res_nus.entry.source_type == SourceType.HARDWARE_VENDOR
        assert "nordicsemi.com" in res_nus.entry.source_url

        # AOSP BluetoothChat sample UUID
        res_aosp = kb.lookup("fa87c0d0-afac-11de-8a39-0800200c9a66")
        assert res_aosp.is_known is True
        assert res_aosp.entry.is_system_or_vendor is True
        assert res_aosp.entry.source_type == SourceType.OS_VENDOR

    def test_unknown_uuid_remains_unknown(self):
        """Verify uncurated or random UUIDs remain unknown without false assumptions."""
        kb = UUIDKnowledgeBase()
        unknown_uuid = "cd59ba31-5729-b3bb-cb29-732b59eb61aa"

        res = kb.lookup(unknown_uuid)
        assert res.is_known is False
        assert res.entry is None
        assert res.normalized_query_uuid == unknown_uuid

    def test_malformed_lookup_rejection(self):
        """Verify malformed input string does not error and returns is_known=False."""
        kb = UUIDKnowledgeBase()
        res = kb.lookup("invalid-uuid-string-12345")
        assert res.is_known is False
        assert res.entry is None
        assert res.normalized_query_uuid is None

    def test_missing_provenance_rejection(self, tmp_path: Path):
        """Verify dataset with missing mandatory provenance fails validation."""
        bad_kb = tmp_path / "bad_kb.json"
        data = {
            "knowledge_base_version": "1.0",
            "schema_version": "1.0",
            "last_updated": "2026-10-04",
            "entries": [
                {
                    "normalized_uuid": "0000180d-0000-1000-8000-00805f9b34fb",
                    "name": "Heart Rate",
                    # Missing source_name, source_url, source_type
                    "analyst_notes": "Test",
                }
            ],
        }
        with open(bad_kb, "w", encoding="utf-8") as f:
            json.dump(data, f)

        with pytest.raises(InvalidKnowledgeBaseError) as exc_info:
            UUIDKnowledgeBase(bad_kb)
        assert "lacks mandatory 'source_name'" in str(exc_info.value)

    def test_duplicate_uuid_rejection(self, tmp_path: Path):
        """Verify dataset containing duplicate normalized UUIDs is rejected."""
        dup_kb = tmp_path / "dup_kb.json"
        data = {
            "knowledge_base_version": "1.0",
            "schema_version": "1.0",
            "last_updated": "2026-10-04",
            "entries": [
                {
                    "normalized_uuid": "0000180d-0000-1000-8000-00805f9b34fb",
                    "name": "Heart Rate 1",
                    "source_name": "Bluetooth SIG",
                    "source_url": "https://bluetooth.com",
                    "source_type": "STANDARDS_ORGANIZATION",
                    "analyst_notes": "First",
                },
                {
                    "normalized_uuid": "0000180d-0000-1000-8000-00805f9b34fb",
                    "name": "Heart Rate Duplicate",
                    "source_name": "Bluetooth SIG",
                    "source_url": "https://bluetooth.com",
                    "source_type": "STANDARDS_ORGANIZATION",
                    "analyst_notes": "Second",
                },
            ],
        }
        with open(dup_kb, "w", encoding="utf-8") as f:
            json.dump(data, f)

        with pytest.raises(InvalidKnowledgeBaseError) as exc_info:
            UUIDKnowledgeBase(dup_kb)
        assert "Duplicate UUID entry" in str(exc_info.value)

    def test_invalid_uuid_in_dataset_rejection(self, tmp_path: Path):
        """Verify dataset containing an invalid UUID string is rejected."""
        invalid_kb = tmp_path / "invalid_kb.json"
        data = {
            "knowledge_base_version": "1.0",
            "schema_version": "1.0",
            "last_updated": "2026-10-04",
            "entries": [
                {
                    "normalized_uuid": "NOT-A-VALID-UUID",
                    "name": "Invalid",
                    "source_name": "Test",
                    "source_url": "https://test.com",
                    "source_type": "STANDARDS_ORGANIZATION",
                    "analyst_notes": "Test",
                }
            ],
        }
        with open(invalid_kb, "w", encoding="utf-8") as f:
            json.dump(data, f)

        with pytest.raises(InvalidKnowledgeBaseError) as exc_info:
            UUIDKnowledgeBase(invalid_kb)
        assert "invalid uuid" in str(exc_info.value).lower()


    def test_nonexistent_dataset_path(self, tmp_path: Path):
        """Verify KnowledgeBaseError is raised when file does not exist."""
        with pytest.raises(KnowledgeBaseError):
            UUIDKnowledgeBase(tmp_path / "does_not_exist.json")

    def test_entry_immutability(self):
        """Verify KnowledgeBaseEntry cannot be modified after construction."""
        kb = UUIDKnowledgeBase()
        res = kb.lookup("0000180d-0000-1000-8000-00805f9b34fb")
        entry = res.entry
        assert entry is not None

        with pytest.raises(ValidationError):
            entry.name = "Modified Name"
