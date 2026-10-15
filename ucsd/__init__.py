"""UCSD: UUID Confusion Static Detection."""

__version__ = "0.1.0"

from ucsd.apk_loader import load_apk, calculate_sha256
from ucsd.errors import (
    UCSDError,
    APKIntakeError,
    FileNotFoundAPKError,
    EmptyFileAPKError,
    CorruptZipAPKError,
    MissingManifestError,
    MissingDEXError,
    ManifestParsingError,
    CorruptAPKError,
)
from ucsd.models import APKMetadata, DEXInfo, ManifestMetadata, AnalysisReport
from ucsd.orchestrator import analyze_single_apk, batch_analyze

__all__ = [
    "load_apk",
    "calculate_sha256",
    "analyze_single_apk",
    "batch_analyze",
    "UCSDError",
    "APKIntakeError",
    "FileNotFoundAPKError",
    "EmptyFileAPKError",
    "CorruptZipAPKError",
    "MissingManifestError",
    "MissingDEXError",
    "ManifestParsingError",
    "CorruptAPKError",
    "APKMetadata",
    "DEXInfo",
    "ManifestMetadata",
    "AnalysisReport",
]

