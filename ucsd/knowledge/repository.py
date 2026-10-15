"""Repository and loader for curated UUID knowledge base."""

import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

from ucsd.ble.normalizer import normalize_uuid
from ucsd.errors import InvalidKnowledgeBaseError, InvalidUUIDError, KnowledgeBaseError
from ucsd.knowledge.models import (
    KnowledgeBaseEntry,
    KnowledgeBaseLookupResult,
    KnowledgeBaseMetadata,
    SourceType,
)

DEFAULT_CANDIDATE_PATHS = [
    Path("/app/data/uuid_knowledge_base.json"),
    Path(__file__).resolve().parents[2] / "data" / "uuid_knowledge_base.json",
]


class UUIDKnowledgeBase:
    """Thread-safe, read-only repository of curated UUIDs with verified provenance."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        """Initialize the knowledge base by loading and validating the JSON dataset.

        Args:
            db_path: Optional path to the knowledge base JSON file. If None, default
                     container and workspace paths are checked.

        Raises:
            KnowledgeBaseError: If dataset file is not found or unreadable.
            InvalidKnowledgeBaseError: If schema validation fails, provenance is missing,
                                       or duplicate/invalid UUIDs are present.
        """
        self._db_path = self._resolve_db_path(db_path)
        self._entries: Dict[str, KnowledgeBaseEntry] = {}
        self._metadata: Optional[KnowledgeBaseMetadata] = None
        self._load_and_validate()

    @staticmethod
    def _resolve_db_path(db_path: Optional[Union[str, Path]]) -> Path:
        if db_path is not None:
            p = Path(db_path).resolve()
            if not p.is_file():
                raise KnowledgeBaseError(f"Knowledge base dataset not found at specified path: {p}")
            return p

        for candidate in DEFAULT_CANDIDATE_PATHS:
            if candidate.is_file():
                return candidate.resolve()

        raise KnowledgeBaseError(
            f"Knowledge base dataset not found at default locations: "
            f"{[str(p) for p in DEFAULT_CANDIDATE_PATHS]}"
        )

    def _load_and_validate(self) -> None:
        """Parse, validate, and index all entries in the JSON dataset."""
        try:
            with open(self._db_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
        except Exception as exc:
            raise InvalidKnowledgeBaseError(
                f"Failed to read knowledge base JSON from {self._db_path}: {exc}",
                details=str(exc),
            ) from exc

        if not isinstance(raw_data, dict):
            raise InvalidKnowledgeBaseError("Knowledge base root must be a JSON object")

        kb_version = raw_data.get("knowledge_base_version")
        schema_version = raw_data.get("schema_version")
        last_updated = raw_data.get("last_updated")
        provenance_policy = raw_data.get("provenance_policy", "")
        raw_entries = raw_data.get("entries")

        if not kb_version or not schema_version or not last_updated:
            raise InvalidKnowledgeBaseError(
                "Knowledge base missing required metadata (knowledge_base_version, schema_version, last_updated)"
            )

        if not isinstance(raw_entries, list):
            raise InvalidKnowledgeBaseError("Knowledge base 'entries' must be a JSON list")

        seen_uuids: Set[str] = set()
        entries_dict: Dict[str, KnowledgeBaseEntry] = {}

        for idx, entry_raw in enumerate(raw_entries):
            if not isinstance(entry_raw, dict):
                raise InvalidKnowledgeBaseError(f"Entry at index {idx} is not a JSON object")

            raw_uuid = entry_raw.get("normalized_uuid")
            if not raw_uuid:
                raise InvalidKnowledgeBaseError(f"Entry at index {idx} lacks mandatory 'normalized_uuid'")

            # Strict provenance verification: source_name, source_url, source_type are mandatory
            source_name = entry_raw.get("source_name")
            source_url = entry_raw.get("source_url")
            source_type_str = entry_raw.get("source_type")
            analyst_notes = entry_raw.get("analyst_notes")

            if not source_name or not str(source_name).strip():
                raise InvalidKnowledgeBaseError(f"Entry {raw_uuid} lacks mandatory 'source_name' provenance")
            if not source_url or not str(source_url).strip():
                raise InvalidKnowledgeBaseError(f"Entry {raw_uuid} lacks mandatory 'source_url' provenance")
            if not source_type_str or source_type_str not in SourceType.__members__:
                raise InvalidKnowledgeBaseError(
                    f"Entry {raw_uuid} has invalid or missing 'source_type': {source_type_str}. "
                    f"Must be one of {[s.name for s in SourceType]}"
                )
            if not analyst_notes or not str(analyst_notes).strip():
                raise InvalidKnowledgeBaseError(f"Entry {raw_uuid} lacks mandatory 'analyst_notes'")

            # Validate and normalize UUID format
            try:
                norm_uuid = normalize_uuid(raw_uuid)
            except InvalidUUIDError as err:
                raise InvalidKnowledgeBaseError(
                    f"Entry at index {idx} has invalid UUID '{raw_uuid}': {err}"
                ) from err

            if norm_uuid in seen_uuids:
                raise InvalidKnowledgeBaseError(
                    f"Duplicate UUID entry in knowledge base: '{norm_uuid}'"
                )
            seen_uuids.add(norm_uuid)

            entry_model = KnowledgeBaseEntry(
                normalized_uuid=norm_uuid,
                name=entry_raw.get("name", "Unknown"),
                category=entry_raw.get("category", "unclassified"),
                source_name=str(source_name).strip(),
                source_url=str(source_url).strip(),
                source_type=SourceType(source_type_str),
                source_version_or_date=entry_raw.get("source_version_or_date"),
                is_system_or_vendor=bool(entry_raw.get("is_system_or_vendor", False)),
                analyst_notes=str(analyst_notes).strip(),
            )
            entries_dict[norm_uuid] = entry_model

        self._entries = entries_dict
        self._metadata = KnowledgeBaseMetadata(
            knowledge_base_version=str(kb_version),
            schema_version=str(schema_version),
            last_updated=str(last_updated),
            total_entries=len(entries_dict),
            provenance_policy=str(provenance_policy),
        )

    def get_metadata(self) -> KnowledgeBaseMetadata:
        """Return dataset version, provenance policy, and currency metadata."""
        if self._metadata is None:
            raise KnowledgeBaseError("Knowledge base is uninitialized")
        return self._metadata

    def lookup(self, uuid_str: str) -> KnowledgeBaseLookupResult:
        """Perform exact match lookup against the knowledge base after strict normalization.

        Args:
            uuid_str: Input UUID string (canonical 128-bit, 16-bit hex, or unhyphenated).

        Returns:
            KnowledgeBaseLookupResult containing match status and curated entry if found.
            Unknown UUIDs remain unknown (is_known=False, entry=None).
        """
        try:
            norm_uuid = normalize_uuid(uuid_str)
        except InvalidUUIDError:
            return KnowledgeBaseLookupResult(
                is_known=False,
                query_uuid=uuid_str,
                normalized_query_uuid=None,
                entry=None,
            )

        entry = self._entries.get(norm_uuid)
        return KnowledgeBaseLookupResult(
            is_known=entry is not None,
            query_uuid=uuid_str,
            normalized_query_uuid=norm_uuid,
            entry=entry,
        )

    def all_entries(self) -> List[KnowledgeBaseEntry]:
        """Return all curated entries in deterministic sorted order by normalized UUID."""
        return [self._entries[k] for k in sorted(self._entries.keys())]

    def get_known_uuids(self) -> Set[str]:
        """Return set of all normalized UUIDs present in the knowledge base."""
        return set(self._entries.keys())
