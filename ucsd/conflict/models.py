"""Data models for UUID conflict assessment and cross-APK comparison."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from ucsd.knowledge.models import KnowledgeBaseEntry, KnowledgeBaseMetadata


class ConflictCondition(str, Enum):
    """Categorical conflict and classification conditions for UUID assessment.

    Strictly conservative: static analysis establishes static evidence overlap,
    never confirmed runtime vulnerability or runtime collision.
    """
    # 1. Matches an open Bluetooth SIG standard specification
    KNOWN_ASSIGNED_STANDARD_MATCH = "KNOWN_ASSIGNED_STANDARD_MATCH"

    # 2. Matches an OS vendor or hardware vendor specification with verified provenance
    KNOWN_SYSTEM_OR_VENDOR_MATCH = "KNOWN_SYSTEM_OR_VENDOR_MATCH"

    # 3. Two or more distinct analyzed APK packages both have STRONG_STATIC_ASSOCIATION for the same UUID
    STRONG_DUPLICATE_STATIC_REGISTRATION = "STRONG_DUPLICATE_STATIC_REGISTRATION"

    # 4. Duplicate candidate strings across APKs without dual verified static registration
    DUPLICATE_CANDIDATE_NO_REGISTRATION = "DUPLICATE_CANDIDATE_NO_REGISTRATION"

    # 5. Overlapping registration call sites across APKs where one or both patterns are unresolved
    UNRESOLVED_REGISTRATION_OVERLAP = "UNRESOLVED_REGISTRATION_OVERLAP"

    # 6. Candidate present in an APK but unconflicted and unknown in KB
    UNKNOWN_UNCONFLICTED = "UNKNOWN_UNCONFLICTED"


class CrossAPKEvidence(BaseModel):
    """Specific evidence point for a UUID within a particular analyzed APK."""
    model_config = ConfigDict(frozen=True)

    package_name: Optional[str] = Field(None, description="Android package name from manifest")
    version_code: Optional[int] = Field(None, description="Application version code")
    version_name: Optional[str] = Field(None, description="Application version string")
    file_name: str = Field(..., description="APK file base name")
    sha256: str = Field(..., description="APK SHA-256 digest")
    evidence_level: str = Field(..., description="STRONG_STATIC_ASSOCIATION, REGISTRATION_PATTERN_UUID_UNRESOLVED, or UUID_CANDIDATE_ONLY")
    class_name: Optional[str] = Field(None, description="Declaring class name where UUID is used or registered")
    method_name: Optional[str] = Field(None, description="Declaring method name")
    descriptor: Optional[str] = Field(None, description="Method descriptor signature")
    dex_file: Optional[str] = Field(None, description="DEX file containing the observation, e.g. classes.dex")
    instruction_offset: Optional[int] = Field(None, description="Bytecode offset in bytes if instruction-level evidence")
    diagnosis: str = Field(..., description="Factual description of the static finding in this APK")


class UUIDConflictAssessment(BaseModel):
    """Explainable conflict assessment for a single normalized UUID."""
    model_config = ConfigDict(frozen=True)

    normalized_uuid: str = Field(..., description="Canonical 128-bit lowercase hyphenated UUID")
    condition: ConflictCondition = Field(..., description="Categorical condition assigned to this UUID")
    is_proven: bool = Field(False, description="True when multiple distinct APK packages both demonstrate verified strong static association registering the identical GATT service UUID according to UCSD static analysis evidence criteria. Indicates high-confidence static overlap, NOT confirmed runtime collision.")
    is_proven_service_conflict: bool = Field(False, description="Compatibility alias for is_proven strictly under static evidence criteria")
    explanation: str = Field(..., description="Plain-language technical explanation of the condition, provenance, and static conflict status")
    knowledge_base_match: Optional[KnowledgeBaseEntry] = Field(None, description="Matched knowledge base entry if known, None otherwise")
    participating_apks: List[CrossAPKEvidence] = Field(default_factory=list, description="All participating APKs referencing this UUID")


class SingleAPKKnowledgeAssessment(BaseModel):
    """Knowledge base assessment embedded in single-APK analysis reports."""
    model_config = ConfigDict(frozen=True)

    total_candidates_checked: int = Field(..., description="Total unique UUID candidates checked against KB")
    known_standard_matches_count: int = Field(..., description="Count of Bluetooth SIG standard matches")
    known_system_vendor_matches_count: int = Field(..., description="Count of sourced OS/vendor matches")
    unknown_candidates_count: int = Field(..., description="Count of candidate UUIDs with no KB match")
    findings: List[UUIDConflictAssessment] = Field(default_factory=list, description="Assessment for each candidate UUID")


class CrossAPKConflictReport(BaseModel):
    """Structured report produced by multi-APK cross-comparison."""
    model_config = ConfigDict(frozen=True)

    total_apks_analyzed: int = Field(..., description="Number of distinct APKs included in cross-comparison")
    total_unique_uuids_evaluated: int = Field(..., description="Number of unique normalized UUIDs evaluated")
    strong_duplicate_static_registrations_count: int = Field(..., description="Count of STRONG_DUPLICATE_STATIC_REGISTRATION occurrences")
    proven_registration_conflicts_count: int = Field(..., description="Compatibility alias for strong_duplicate_static_registrations_count")
    duplicate_candidates_unregistered_count: int = Field(..., description="Count of DUPLICATE_CANDIDATE_NO_REGISTRATION occurrences")
    known_standard_matches_count: int = Field(..., description="Count of Bluetooth SIG standard matches")
    known_system_vendor_matches_count: int = Field(..., description="Count of sourced system/vendor matches")
    unknown_uuids_count: int = Field(..., description="Count of UUIDs with no matching knowledge base record")
    assessments: List[UUIDConflictAssessment] = Field(default_factory=list, description="All evaluated conflict assessments")
    knowledge_base_metadata: KnowledgeBaseMetadata = Field(..., description="Metadata of the knowledge base used for evaluation")
    methodology_and_limitations: List[str] = Field(default_factory=list, description="Explicit methodology rules, caveats, and dataset constraints")
