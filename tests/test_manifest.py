"""Tests for Android manifest extraction and no-invention constraints."""

from unittest.mock import MagicMock
from ucsd.manifest import _clean_list, _safe_int, extract_manifest_metadata
from ucsd.models import ManifestMetadata


class TestManifestExtraction:
    """Test suite for ucsd.manifest."""

    def test_safe_int_valid_inputs(self):
        """Verify _safe_int correctly parses various representations."""
        assert _safe_int(123) == 123
        assert _safe_int("456") == 456
        assert _safe_int("0x1a") == 26
        assert _safe_int(" 789 ") == 789

    def test_safe_int_invalid_or_missing(self):
        """Verify _safe_int returns None without inventing numbers."""
        assert _safe_int(None) is None
        assert _safe_int("") is None
        assert _safe_int("   ") is None
        assert _safe_int("unknown") is None
        assert _safe_int("version_one") is None

    def test_clean_list(self):
        """Verify _clean_list deduplicates, sorts, and filters empty strings."""
        raw = ["android.permission.INTERNET", None, "", "  ", "android.permission.CAMERA", "android.permission.INTERNET"]
        result = _clean_list(raw)
        assert result == ["android.permission.CAMERA", "android.permission.INTERNET"]

    def test_clean_list_empty(self):
        assert _clean_list(None) == []
        assert _clean_list([]) == []

    def test_extract_manifest_no_invented_metadata(self):
        """Verify that when attributes are missing, None or [] is returned, not invented values."""
        # Empty mock object with no getters returning data
        mock_apk = MagicMock()
        mock_apk.get_package.return_value = None
        mock_apk.get_androidversion_code.return_value = None
        mock_apk.get_androidversion_name.return_value = None
        mock_apk.get_min_sdk_version.return_value = None
        mock_apk.get_target_sdk_version.return_value = None
        mock_apk.get_max_sdk_version.return_value = None
        mock_apk.get_permissions.return_value = []
        mock_apk.get_declared_permissions.return_value = []
        mock_apk.get_activities.return_value = []
        mock_apk.get_services.return_value = []
        mock_apk.get_receivers.return_value = []
        mock_apk.get_providers.return_value = []
        mock_apk.get_main_activity.return_value = None

        meta = extract_manifest_metadata(mock_apk)
        assert isinstance(meta, ManifestMetadata)
        assert meta.package_name is None
        assert meta.version_code is None
        assert meta.version_name is None
        assert meta.min_sdk_version is None
        assert meta.target_sdk_version is None
        assert meta.max_sdk_version is None
        assert meta.requested_permissions == []
        assert meta.declared_permissions == []
        assert meta.activities == []
        assert meta.services == []
        assert meta.receivers == []
        assert meta.providers == []
        assert meta.main_activity is None

    def test_extract_manifest_populated(self):
        """Verify manifest extraction with populated mock."""
        mock_apk = MagicMock()
        mock_apk.get_package.return_value = "com.test.app"
        mock_apk.get_androidversion_code.return_value = "10"
        mock_apk.get_androidversion_name.return_value = "1.0-alpha"
        mock_apk.get_min_sdk_version.return_value = "21"
        mock_apk.get_target_sdk_version.return_value = 33
        mock_apk.get_max_sdk_version.return_value = None
        mock_apk.get_permissions.return_value = ["android.permission.INTERNET"]
        mock_apk.get_declared_permissions.return_value = ["com.test.CUSTOM_PERM"]
        mock_apk.get_activities.return_value = ["com.test.app.MainActivity"]
        mock_apk.get_services.return_value = ["com.test.app.SyncService"]
        mock_apk.get_receivers.return_value = []
        mock_apk.get_providers.return_value = []
        mock_apk.get_main_activity.return_value = "com.test.app.MainActivity"

        meta = extract_manifest_metadata(mock_apk)
        assert meta.package_name == "com.test.app"
        assert meta.version_code == 10
        assert meta.version_name == "1.0-alpha"
        assert meta.min_sdk_version == 21
        assert meta.target_sdk_version == 33
        assert meta.max_sdk_version is None
        assert meta.requested_permissions == ["android.permission.INTERNET"]
        assert meta.declared_permissions == ["com.test.CUSTOM_PERM"]
        assert meta.activities == ["com.test.app.MainActivity"]
        assert meta.services == ["com.test.app.SyncService"]
        assert meta.main_activity == "com.test.app.MainActivity"
