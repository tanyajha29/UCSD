"""Data models for independent APK validation and comparison reporting."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ComparisonStatus(str, Enum):
    """Status outcomes for an individual comparison field."""
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    NOT_VERIFIABLE = "NOT_VERIFIABLE"


class ComparisonField(BaseModel):
    """Record comparing a single attribute between UCSD and the independent tool."""
    model_config = ConfigDict(frozen=True)

    field: str = Field(..., description="Name of the evaluated metadata property")
    ucsd: Any = Field(..., description="Value extracted by UCSD (Androguard engine)")
    independent: Any = Field(..., description="Value extracted by independent validator (aapt/zipfile/hashlib)")
    status: ComparisonStatus = Field(..., description="Result of comparison: MATCH, MISMATCH, or NOT_VERIFIABLE")
    explanation: str = Field(..., description="Detailed explanation of the comparison result or normalization rule")


class IndependentDEXInfo(BaseModel):
    """Metadata for an individual DEX archive member independently verified."""
    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Member filename, e.g. classes.dex")
    sha256: str = Field(..., description="Independently computed SHA-256 of uncompressed DEX member")
    size_bytes: int = Field(..., description="Uncompressed size in bytes")


class IndependentAPKMetadata(BaseModel):
    """Normalized metadata produced strictly without Androguard."""
    model_config = ConfigDict(frozen=True)

    file_path: str = Field(..., description="Target file path")
    file_name: str = Field(..., description="Base filename")
    file_size_bytes: int = Field(..., description="Total file size in bytes from filesystem stat")
    sha256: str = Field(..., description="Independently computed SHA-256 of entire file")
    is_valid_zip: bool = Field(..., description="Result of standard library zipfile.testzip() CRC check")
    has_manifest: bool = Field(..., description="Whether AndroidManifest.xml exists in the archive")
    has_dex: bool = Field(..., description="Whether any classes*.dex exists in the archive")
    is_multidex: bool = Field(..., description="True if more than 1 classes*.dex member is present")
    dex_count: int = Field(..., description="Count of classes*.dex members")
    dex_files: List[IndependentDEXInfo] = Field(default_factory=list, description="Independently enumerated DEX members")

    # Manifest metadata extracted via aapt
    package_name: Optional[str] = Field(None, description="Package ID extracted from aapt")
    version_code: Optional[int] = Field(None, description="versionCode extracted from aapt")
    version_name: Optional[str] = Field(None, description="versionName extracted from aapt")
    min_sdk_version: Optional[int] = Field(None, description="sdkVersion extracted from aapt")
    target_sdk_version: Optional[int] = Field(None, description="targetSdkVersion extracted from aapt")
    compile_sdk_version: Optional[int] = Field(None, description="compileSdkVersion extracted from aapt")
    uses_permissions: List[str] = Field(default_factory=list, description="List of standard <uses-permission> items from aapt")
    uses_permissions_sdk_23: List[str] = Field(default_factory=list, description="List of conditional <uses-permission-sdk-23> items from aapt")
    requested_permissions: List[str] = Field(default_factory=list, description="Combined requested permissions (uses-permission + uses-permission-sdk-23)")
    requested_permissions_count: int = Field(0, description="Count of combined requested permissions")
    declared_permissions: List[str] = Field(default_factory=list, description="Sorted list of declared custom permissions from aapt")
    declared_permissions_count: int = Field(0, description="Count of declared permissions")
    tool_metadata: Dict[str, str] = Field(default_factory=dict, description="Metadata regarding independent tools used")


class ValidationReport(BaseModel):
    """Complete comparative validation report."""
    model_config = ConfigDict(frozen=True)

    target: str = Field(..., description="Analyzed APK target path")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp of validation run")
    verdict: str = Field(..., description="'PASS' if 0 mismatches, otherwise 'FAIL'")
    total_comparisons: int = Field(..., description="Total number of evaluated fields")
    matches: int = Field(..., description="Number of MATCH results")
    mismatches: int = Field(..., description="Number of MISMATCH results")
    not_verifiable: int = Field(..., description="Number of NOT_VERIFIABLE results")
    comparisons: List[ComparisonField] = Field(default_factory=list, description="Detailed field comparisons")
    independent_metadata: IndependentAPKMetadata = Field(..., description="Full independent metadata")
