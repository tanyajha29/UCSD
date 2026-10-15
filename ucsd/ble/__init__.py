"""UCSD Phase 2: BLE indicator detection and UUID candidate extraction."""

from ucsd.ble.extractor import scan_ble_indicators, extract_bluetooth_permissions
from ucsd.ble.models import (
    BLEAnalysisResult,
    BLEApiIndicators,
    BLEMethodReference,
    BLEPermissions,
    UUIDCandidate,
    UUIDEvidence,
)
from ucsd.ble.normalizer import (
    BLUETOOTH_BASE_UUID,
    expand_16bit_uuid,
    is_bluetooth_sig_range,
    normalize_uuid,
)

__all__ = [
    "scan_ble_indicators",
    "extract_bluetooth_permissions",
    "BLEAnalysisResult",
    "BLEApiIndicators",
    "BLEMethodReference",
    "BLEPermissions",
    "UUIDCandidate",
    "UUIDEvidence",
    "BLUETOOTH_BASE_UUID",
    "expand_16bit_uuid",
    "is_bluetooth_sig_range",
    "normalize_uuid",
]
