"""Data models for versioned UUID knowledge base and identifier provenance."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class SourceType(str, Enum):
    """Verifiable source categorization for UUID provenance."""
    STANDARDS_ORGANIZATION = "STANDARDS_ORGANIZATION"
    OS_VENDOR = "OS_VENDOR"
    HARDWARE_VENDOR = "HARDWARE_VENDOR"
    DEVELOPER_SPECIFICATION = "DEVELOPER_SPECIFICATION"


class KnowledgeBaseEntry(BaseModel):
    """Individual curated UUID entry with strict verifiable provenance."""
    model_config = ConfigDict(frozen=True)

    normalized_uuid: str = Field(..., description="Canonical 128-bit lowercase hyphenated UUID")
    name: str = Field(..., description="Human-readable service, characteristic, or descriptor name")
    category: str = Field(..., description="Category: e.g. bluetooth_sig_service, system_service, vendor_service")
    source_name: str = Field(..., description="Authoritative publisher or specification name")
    source_url: str = Field(..., description="Publicly accessible URL to authoritative documentation")
    source_type: SourceType = Field(..., description="Provenance categorization")
    source_version_or_date: Optional[str] = Field(None, description="Document version or date when known")
    is_system_or_vendor: bool = Field(False, description="True if proprietary or platform-assigned rather than open standard")
    analyst_notes: str = Field(..., description="Technical context and analyst observations (factual, no speculation)")


class KnowledgeBaseMetadata(BaseModel):
    """Metadata describing the active UUID knowledge base dataset."""
    model_config = ConfigDict(frozen=True)

    knowledge_base_version: str = Field(..., description="Semantic version of the dataset")
    schema_version: str = Field(..., description="Schema version")
    last_updated: str = Field(..., description="Date of dataset currency (YYYY-MM-DD)")
    total_entries: int = Field(..., description="Count of curated identifiers in the repository")
    provenance_policy: str = Field(..., description="Statement of provenance and sourcing standards")


class KnowledgeBaseLookupResult(BaseModel):
    """Result of querying the knowledge base with a candidate UUID."""
    model_config = ConfigDict(frozen=True)

    is_known: bool = Field(..., description="True if normalized UUID matches an entry in the knowledge base")
    query_uuid: str = Field(..., description="Original query string provided to lookup")
    normalized_query_uuid: Optional[str] = Field(None, description="Normalized 128-bit query string if valid")
    entry: Optional[KnowledgeBaseEntry] = Field(None, description="Curated entry if found, None otherwise")
