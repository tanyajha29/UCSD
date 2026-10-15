"""Normalized data models for UCSD APK intake and static metadata."""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class DEXInfo(BaseModel):
    """Metadata for an individual Dalvik Executable (DEX) file in the APK."""
    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="File name of the DEX inside the APK, e.g., classes.dex")
    sha256: str = Field(..., description="Hex-encoded SHA-256 checksum of the DEX file")
    size_bytes: int = Field(..., description="Byte size of the uncompressed DEX file")


class ManifestMetadata(BaseModel):
    """Extracted metadata from AndroidManifest.xml."""
    model_config = ConfigDict(frozen=True)

    package_name: Optional[str] = Field(None, description="Android application package ID")
    version_code: Optional[int] = Field(None, description="Internal integer version code")
    version_name: Optional[str] = Field(None, description="User-facing version string")
    min_sdk_version: Optional[int] = Field(None, description="Minimum supported Android API level")
    target_sdk_version: Optional[int] = Field(None, description="Target Android API level")
    max_sdk_version: Optional[int] = Field(None, description="Maximum supported Android API level")
    requested_permissions: List[str] = Field(default_factory=list, description="Sorted list of permissions requested by <uses-permission>")
    declared_permissions: List[str] = Field(default_factory=list, description="Sorted list of permissions defined by <permission>")
    activities: List[str] = Field(default_factory=list, description="Sorted list of declared Activity component classes")
    services: List[str] = Field(default_factory=list, description="Sorted list of declared Service component classes")
    receivers: List[str] = Field(default_factory=list, description="Sorted list of declared BroadcastReceiver component classes")
    providers: List[str] = Field(default_factory=list, description="Sorted list of declared ContentProvider component classes")
    main_activity: Optional[str] = Field(None, description="Class name of the launchable main activity if declared")


class APKMetadata(BaseModel):
    """Normalized metadata for a validated APK intake."""
    model_config = ConfigDict(frozen=True)

    file_path: str = Field(..., description="Normalized path of the analyzed APK")
    file_name: str = Field(..., description="Base filename of the APK")
    file_size_bytes: int = Field(..., description="Total byte size of the APK file")
    sha256: str = Field(..., description="Hex-encoded SHA-256 digest of the entire APK file")
    is_valid_zip: bool = Field(..., description="Indicates if the archive passed full ZIP CRC integrity checks")
    is_multidex: bool = Field(..., description="True if the APK contains more than one DEX file")
    dex_count: int = Field(..., description="Number of DEX files detected in the APK")
    dex_files: List[DEXInfo] = Field(default_factory=list, description="Metadata for each DEX file in the APK")
    manifest: Optional[ManifestMetadata] = Field(None, description="Parsed manifest metadata, or None if unavailable")
    ble_analysis: Optional["BLEAnalysisResult"] = Field(None, description="Static BLE indicators and UUID candidate extraction results")
    registration_analysis: Optional["RegistrationAnalysisResult"] = Field(None, description="Phase 3 GATT service registration analysis results")
    knowledge_base_assessment: Optional["SingleAPKKnowledgeAssessment"] = Field(None, description="Phase 4 UUID knowledge base lookup results")


class AnalysisReport(BaseModel):
    """Structured report produced by the UCSD analysis engine."""
    status: str = Field(..., description="'success', 'partial', or 'error'")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp of the analysis run")
    target: str = Field(..., description="Target path supplied to the CLI")
    analyzer_version: str = Field("0.1.0", description="UCSD static analyzer version")
    knowledge_base_version: Optional[str] = Field(None, description="UUID knowledge base dataset version if loaded")
    metadata: Optional[APKMetadata] = Field(None, description="APK metadata on successful analysis")
    ble_analysis: Optional["BLEAnalysisResult"] = Field(None, description="Phase 2 BLE indicators and UUID candidates report")
    registration_analysis: Optional["RegistrationAnalysisResult"] = Field(None, description="Phase 3 GATT service registration analysis report")
    knowledge_base_assessment: Optional["SingleAPKKnowledgeAssessment"] = Field(None, description="Phase 4 UUID knowledge base lookup report")
    limitations: List[str] = Field(default_factory=list, description="Methodology caveats and analytical limitations")
    html_report_path: Optional[str] = Field(None, description="Path to generated standalone HTML report if written")
    error: Optional[Dict[str, Any]] = Field(None, description="Structured error details if analysis failed")


from ucsd.ble.models import BLEAnalysisResult
from ucsd.registration.models import RegistrationAnalysisResult
from ucsd.conflict.models import SingleAPKKnowledgeAssessment
APKMetadata.model_rebuild()
AnalysisReport.model_rebuild()



