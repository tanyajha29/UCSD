"""Android manifest metadata extraction for UCSD static analysis."""

from typing import Any, List, Optional
from ucsd.errors import ManifestParsingError
from ucsd.models import ManifestMetadata


def _safe_int(value: Any) -> Optional[int]:
    """Safely convert a string, int, or hex representation to an int, or None.

    Does not invent default values if conversion fails.
    """
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        val = value.strip()
        if not val:
            return None
        # Try decimal conversion
        try:
            return int(val, 10)
        except ValueError:
            pass
        # Try hexadecimal conversion (e.g. 0x1a)
        try:
            return int(val, 16)
        except ValueError:
            pass
    return None


def _clean_list(items: Any) -> List[str]:
    """Return a deduplicated, sorted list of non-empty string items."""
    if not items:
        return []
    clean_set = set()
    for item in items:
        if item is not None:
            s = str(item).strip()
            if s:
                clean_set.add(s)
    return sorted(clean_set)


def extract_manifest_metadata(apk_obj: Any) -> ManifestMetadata:
    """Extract normalized ManifestMetadata from an Androguard APK instance.

    Args:
        apk_obj: Loaded Androguard APK object.

    Returns:
        ManifestMetadata model with extracted attributes.

    Raises:
        ManifestParsingError: If manifest extraction encounters unrecoverable errors.
    """
    try:
        # Package Name
        raw_pkg = getattr(apk_obj, "get_package", lambda: None)()
        pkg_name = str(raw_pkg).strip() if raw_pkg else None

        # Version Code and Version Name
        raw_vcode = getattr(apk_obj, "get_androidversion_code", lambda: None)()
        vcode = _safe_int(raw_vcode)

        raw_vname = getattr(apk_obj, "get_androidversion_name", lambda: None)()
        vname = str(raw_vname).strip() if raw_vname else None

        # SDK Versions
        min_sdk = _safe_int(getattr(apk_obj, "get_min_sdk_version", lambda: None)())
        target_sdk = _safe_int(getattr(apk_obj, "get_target_sdk_version", lambda: None)())
        max_sdk = _safe_int(getattr(apk_obj, "get_max_sdk_version", lambda: None)())

        # Permissions
        raw_permissions = getattr(apk_obj, "get_permissions", lambda: [])()
        req_permissions = _clean_list(raw_permissions)

        raw_declared = getattr(apk_obj, "get_declared_permissions", lambda: [])()
        decl_permissions = _clean_list(raw_declared)

        # Components
        activities = _clean_list(getattr(apk_obj, "get_activities", lambda: [])())
        services = _clean_list(getattr(apk_obj, "get_services", lambda: [])())
        receivers = _clean_list(getattr(apk_obj, "get_receivers", lambda: [])())
        providers = _clean_list(getattr(apk_obj, "get_providers", lambda: [])())

        # Main Activity
        raw_main = getattr(apk_obj, "get_main_activity", lambda: None)()
        main_activity = str(raw_main).strip() if raw_main else None

        return ManifestMetadata(
            package_name=pkg_name,
            version_code=vcode,
            version_name=vname,
            min_sdk_version=min_sdk,
            target_sdk_version=target_sdk,
            max_sdk_version=max_sdk,
            requested_permissions=req_permissions,
            declared_permissions=decl_permissions,
            activities=activities,
            services=services,
            receivers=receivers,
            providers=providers,
            main_activity=main_activity,
        )
    except Exception as exc:
        raise ManifestParsingError(
            message=f"Failed to extract Android manifest metadata: {exc}",
            details=str(exc),
        ) from exc
