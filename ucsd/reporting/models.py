"""Data models for analyst-facing reporting and batch analysis."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from ucsd.conflict.models import CrossAPKConflictReport


class SingleAPKSummary(BaseModel):
    """High-level summary of an individual APK analyzed in a batch."""
    model_config = ConfigDict(frozen=True)

    file_name: str = Field(..., description="Base filename of the analyzed APK")
    file_path: str = Field(..., description="Full path to the APK")
    sha256: str = Field(..., description="SHA-256 digest of the APK file")
    package_name: Optional[str] = Field(None, description="Android application package ID")
    version_code: Optional[int] = Field(None, description="Application version code")
    version_name: Optional[str] = Field(None, description="Application user-facing version")
    candidate_count: int = Field(0, description="Total unique UUID candidates extracted")
    strong_registrations_count: int = Field(0, description="Number of STRONG_STATIC_ASSOCIATION registrations")
    unresolved_registrations_count: int = Field(0, description="Number of REGISTRATION_PATTERN_UUID_UNRESOLVED")
    status: str = Field("success", description="'success' or 'partial'")
    report_json_path: Optional[str] = Field(None, description="Path to generated per-APK JSON report")
    report_html_path: Optional[str] = Field(None, description="Path to generated per-APK HTML report")


class BatchAnalysisReport(BaseModel):
    """Aggregated batch analysis and cross-comparison report for multiple APKs."""
    model_config = ConfigDict(frozen=True)

    status: str = Field(..., description="'success', 'partial', or 'error'")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp of the batch run")
    analyzer_version: str = Field("0.1.0", description="UCSD static analyzer version")
    knowledge_base_version: Optional[str] = Field(None, description="UUID knowledge base version if loaded")
    target_directory: Optional[str] = Field(None, description="Input directory or target descriptor")
    total_targets: int = Field(..., description="Total APK files considered for batch analysis")
    successful_count: int = Field(..., description="Number of APKs successfully processed")
    failed_count: int = Field(..., description="Number of APKs that failed processing")
    apk_summaries: List[SingleAPKSummary] = Field(default_factory=list, description="Per-APK summary metrics")
    cross_apk_conflicts: Optional[CrossAPKConflictReport] = Field(None, description="Multi-APK conflict assessment")
    failed_targets: List[Dict[str, Any]] = Field(default_factory=list, description="Details of targets that failed analysis")
    limitations: List[str] = Field(default_factory=list, description="Methodology caveats and analytical limitations")
    html_report_path: Optional[str] = Field(None, description="Path to generated standalone batch HTML report")
