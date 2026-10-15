"""Tests for APK intake, SHA-256 calculation, ZIP integrity, and multidex loading."""

import pytest
from pathlib import Path

from ucsd.apk_loader import calculate_sha256, load_apk
from ucsd.errors import (
    CorruptZipAPKError,
    EmptyFileAPKError,
    FileNotFoundAPKError,
    MissingDEXError,
    MissingManifestError,
)
from ucsd.models import APKMetadata


class TestAPKLoader:
    """Test suite for ucsd.apk_loader."""

    def test_valid_single_dex_apk(self, valid_single_dex_apk: Path):
        """Verify intake of a valid single-DEX APK."""
        metadata = load_apk(valid_single_dex_apk)

        assert isinstance(metadata, APKMetadata)
        assert metadata.file_name == "valid_single_dex.apk"
        assert metadata.is_valid_zip is True
        assert metadata.is_multidex is False
        assert metadata.dex_count == 1
        assert len(metadata.dex_files) == 1
        assert metadata.dex_files[0].name == "classes.dex"
        assert len(metadata.dex_files[0].sha256) == 64
        assert metadata.dex_files[0].size_bytes > 0

        # Manifest checks
        assert metadata.manifest is not None
        assert metadata.manifest.package_name == "org.example.singledex"
        assert metadata.manifest.version_code == 100
        assert metadata.manifest.version_name == "1.0.0"
        assert metadata.manifest.min_sdk_version == 21
        assert metadata.manifest.target_sdk_version == 33
        assert "android.permission.INTERNET" in metadata.manifest.requested_permissions
        assert "android.permission.ACCESS_NETWORK_STATE" in metadata.manifest.requested_permissions

    def test_valid_multidex_apk(self, valid_multidex_apk: Path):
        """Verify intake of a valid Multi-DEX APK."""
        metadata = load_apk(valid_multidex_apk)

        assert isinstance(metadata, APKMetadata)
        assert metadata.file_name == "valid_multidex.apk"
        assert metadata.is_valid_zip is True
        assert metadata.is_multidex is True
        assert metadata.dex_count == 2
        assert len(metadata.dex_files) == 2

        # Check natural sorting of DEX entries
        assert metadata.dex_files[0].name == "classes.dex"
        assert metadata.dex_files[1].name == "classes2.dex"

        # Unique hashes for different DEX files
        assert metadata.dex_files[0].sha256 != metadata.dex_files[1].sha256

        # Manifest checks
        assert metadata.manifest is not None
        assert metadata.manifest.package_name == "org.example.multidex"
        assert metadata.manifest.version_code == 200

    def test_reproducible_sha256(self, valid_single_dex_apk: Path):
        """Verify that SHA-256 computation is deterministic and reproducible."""
        hash1 = calculate_sha256(valid_single_dex_apk)
        hash2 = calculate_sha256(valid_single_dex_apk)
        meta = load_apk(valid_single_dex_apk)

        assert hash1 == hash2
        assert meta.sha256 == hash1
        assert len(hash1) == 64

    def test_reject_non_existent_file(self, non_existent_apk: Path):
        """Verify safe rejection when the file does not exist."""
        with pytest.raises(FileNotFoundAPKError) as exc_info:
            load_apk(non_existent_apk)
        assert "not found" in exc_info.value.message.lower()

    def test_reject_empty_file(self, empty_apk: Path):
        """Verify safe rejection when the file is 0 bytes."""
        with pytest.raises(EmptyFileAPKError) as exc_info:
            load_apk(empty_apk)
        assert "empty" in exc_info.value.message.lower()

    def test_reject_renamed_text_file(self, renamed_text_apk: Path):
        """Verify safe rejection of a non-ZIP file with a .apk extension."""
        with pytest.raises(CorruptZipAPKError) as exc_info:
            load_apk(renamed_text_apk)
        assert "not a valid zip" in exc_info.value.message.lower()

    def test_reject_corrupt_zip(self, corrupt_zip_apk: Path):
        """Verify safe rejection when the ZIP archive is corrupt or truncated."""
        with pytest.raises(CorruptZipAPKError) as exc_info:
            load_apk(corrupt_zip_apk)
        assert "zip" in exc_info.value.message.lower()

    def test_reject_zip_without_dex(self, zip_without_dex_apk: Path):
        """Verify safe rejection when the archive has no DEX files."""
        with pytest.raises(MissingDEXError) as exc_info:
            load_apk(zip_without_dex_apk)
        assert "classes*.dex" in exc_info.value.message

    def test_reject_zip_without_manifest(self, zip_without_manifest_apk: Path):
        """Verify safe rejection when the archive has no AndroidManifest.xml."""
        with pytest.raises(MissingManifestError) as exc_info:
            load_apk(zip_without_manifest_apk)
        assert "androidmanifest.xml" in exc_info.value.message.lower()
