"""Structured exception hierarchy for UCSD APK intake and static analysis."""

from typing import Optional, Dict, Any


class UCSDError(Exception):
    """Base class for all UCSD exceptions."""

    def __init__(self, message: str, details: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        """Serialize error for structured report output."""
        data: Dict[str, Any] = {
            "error_type": self.__class__.__name__,
            "message": self.message,
        }
        if self.details:
            data["details"] = self.details
        return data


class APKIntakeError(UCSDError):
    """Base exception for errors encountered during APK intake and validation."""

    def __init__(
        self,
        message: str,
        path: Optional[str] = None,
        details: Optional[str] = None,
    ):
        super().__init__(message, details)
        self.path = path

    def to_dict(self) -> Dict[str, Any]:
        data = super().to_dict()
        if self.path:
            data["path"] = self.path
        return data


class FileNotFoundAPKError(APKIntakeError):
    """Raised when the specified APK file does not exist on disk."""
    pass


class EmptyFileAPKError(APKIntakeError):
    """Raised when the target APK file is empty (0 bytes)."""
    pass


class CorruptZipAPKError(APKIntakeError):
    """Raised when the file is not a valid ZIP archive or fails CRC checks."""
    pass


class MissingManifestError(APKIntakeError):
    """Raised when the APK archive lacks an AndroidManifest.xml file."""
    pass


class MissingDEXError(APKIntakeError):
    """Raised when the APK archive contains no Dalvik Executable (classes*.dex) files."""
    pass


class ManifestParsingError(APKIntakeError):
    """Raised when AndroidManifest.xml cannot be parsed or decoded."""
    pass


class CorruptAPKError(APKIntakeError):
    """Raised when Androguard fails to parse the APK due to internal corruption."""
    pass


class InvalidUUIDError(UCSDError):
    """Raised when a UUID candidate string is malformed, invalid, or unsupported."""
    pass


class BLEExtractionError(UCSDError):
    """Raised when extraction of BLE indicators or DEX bytecode fails."""
    pass


class KnowledgeBaseError(UCSDError):
    """Base exception for UUID knowledge base operations."""
    pass


class InvalidKnowledgeBaseError(KnowledgeBaseError):
    """Raised when the knowledge base dataset fails validation or contains duplicate/invalid entries."""
    pass


class ConflictAssessmentError(UCSDError):
    """Raised when conflict assessment across APKs fails."""
    pass


