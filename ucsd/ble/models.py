"""Data models for BLE indicator detection and UUID candidate extraction."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class BLEPermissions(BaseModel):
    """Bluetooth and BLE permissions extracted from manifest."""
    model_config = ConfigDict(frozen=True)

    requested: List[str] = Field(default_factory=list, description="Requested Bluetooth permissions")
    declared: List[str] = Field(default_factory=list, description="Declared Bluetooth permissions")
    has_ble_permission: bool = Field(False, description="True if any modern BLE permission is requested (SCAN, CONNECT, ADVERTISE)")
    has_classic_permission: bool = Field(False, description="True if legacy Bluetooth permission is requested (BLUETOOTH, BLUETOOTH_ADMIN, etc.)")


class BLEMethodReference(BaseModel):
    """Reference to a Bluetooth/BLE API method in DEX bytecode."""
    model_config = ConfigDict(frozen=True)

    dex_file: str = Field(..., description="DEX file containing the method reference, e.g. classes2.dex")
    class_name: str = Field(..., description="Class name of the referenced method")
    method_name: str = Field(..., description="Method name")
    descriptor: str = Field(..., description="Method signature descriptor")


class BLEApiIndicators(BaseModel):
    """Static indicators of Bluetooth and BLE API usage in DEX bytecode."""
    model_config = ConfigDict(frozen=True)

    framework_classes: List[str] = Field(default_factory=list, description="Referenced android.bluetooth.* framework classes")
    app_classes: List[str] = Field(default_factory=list, description="Application or library classes implementing Bluetooth functionality")
    referenced_methods: List[BLEMethodReference] = Field(default_factory=list, description="Referenced Bluetooth methods")
    has_gatt_client: bool = Field(False, description="Indicator: references BluetoothGatt or GATT client methods")
    has_gatt_server: bool = Field(False, description="Indicator: references BluetoothGattServer or GATT server methods")
    has_le_scanner: bool = Field(False, description="Indicator: references BluetoothLeScanner or ScanCallback")
    has_le_advertiser: bool = Field(False, description="Indicator: references BluetoothLeAdvertiser or AdvertiseCallback")
    has_classic_bluetooth: bool = Field(False, description="Indicator: references BluetoothAdapter/BluetoothSocket classic APIs")


class UUIDEvidence(BaseModel):
    """Single evidence point for a candidate UUID."""
    model_config = ConfigDict(frozen=True)

    original_text: str = Field(..., description="Original raw matched string")
    normalized_uuid: str = Field(..., description="Normalized canonical 128-bit lowercase UUID")
    format_type: str = Field(..., description="Detected format: canonical-128, bluetooth-16-prefixed, bluetooth-16-raw, bluetooth-32-prefixed, bluetooth-32-raw, raw-128-hex")
    dex_file: str = Field(..., description="DEX file name, e.g. classes.dex")
    class_name: Optional[str] = Field(None, description="Enclosing class name if extracted from bytecode instruction")
    method_name: Optional[str] = Field(None, description="Enclosing method name if extracted from bytecode instruction")
    extraction_method: str = Field(..., description="'bytecode_instruction' or 'string_pool'")
    context_string: Optional[str] = Field(None, description="Containing string if candidate was embedded in a larger string")


class UUIDCandidate(BaseModel):
    """Deduplicated UUID candidate with aggregated evidence."""
    model_config = ConfigDict(frozen=True)

    normalized_uuid: str = Field(..., description="Canonical lowercase 128-bit UUID")
    is_bluetooth_sig_range: bool = Field(..., description="True if within the Bluetooth Base UUID range")
    short_hex: Optional[str] = Field(None, description="4-digit hex if within Bluetooth Base UUID range")
    sig_name: Optional[str] = Field(None, description="Human-readable Bluetooth SIG service/characteristic name if known")
    occurrence_count: int = Field(..., description="Total occurrence count across all evidence locations")
    evidence: List[UUIDEvidence] = Field(default_factory=list, description="All distinct evidence locations")


class BLEAnalysisResult(BaseModel):
    """Complete Phase 2 static BLE analysis result."""
    model_config = ConfigDict(frozen=True)

    has_ble_indicators: bool = Field(..., description="True if any BLE permissions, APIs, or UUID candidates are present")
    permissions: BLEPermissions = Field(..., description="Bluetooth permissions analysis")
    api_indicators: BLEApiIndicators = Field(..., description="Bluetooth API usage indicators")
    uuid_candidates: List[UUIDCandidate] = Field(default_factory=list, description="Extracted UUID candidates with evidence")
    candidate_summary: Dict[str, int] = Field(default_factory=dict, description="Summary counts of candidates")
    summary_notes: List[str] = Field(default_factory=list, description="Analytical caveats, false-positive notes, and missing context")
