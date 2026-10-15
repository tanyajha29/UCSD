"""APK intake, integrity verification, and metadata loader for UCSD."""

import hashlib
import os
import re
import zipfile
from pathlib import Path
from typing import List, Tuple, Union

try:
    from androguard.core.apk import APK
except ImportError:
    from androguard.core.bytecodes.apk import APK

from ucsd.errors import (
    CorruptAPKError,
    CorruptZipAPKError,
    EmptyFileAPKError,
    FileNotFoundAPKError,
    MissingDEXError,
    MissingManifestError,
)
from ucsd.manifest import extract_manifest_metadata
from ucsd.models import APKMetadata, DEXInfo

_DEX_PATTERN = re.compile(r"^classes(\d+)?\.dex$")


def normalize_container_path(path_str: str) -> str:
    """Normalize MSYS2/Git-Bash auto-converted paths inside a Linux container.

    On Windows, Git Bash prepends 'C:/Program Files/Git' to POSIX paths like '/app/...'.
    This function detects and restores the intended container-root path.
    """
    if os.name == "posix":
        match = re.match(r"^[A-Za-z]:[\\/].*?([\\/]app[\\/].*)$", path_str)
        if match:
            return match.group(1).replace("\\", "/")
    return path_str


def calculate_sha256(file_path: Union[str, Path], chunk_size: int = 65536) -> str:
    """Calculate reproducible SHA-256 hash of a file using streaming reads."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _natural_dex_sort_key(name: str) -> Tuple[int, str]:
    """Sort key for DEX files to ensure deterministic ordering (classes.dex, classes2.dex, ...)."""
    match = _DEX_PATTERN.match(name)
    if not match:
        return (9999, name)
    suffix = match.group(1)
    if suffix is None:
        return (1, name)
    return (int(suffix), name)


def validate_zip_integrity(file_path: Union[str, Path]) -> zipfile.ZipFile:
    """Validate that the file is a readable ZIP archive and passes CRC integrity checks.

    Raises:
        CorruptZipAPKError: If the file is not a valid ZIP or has corrupt members.
    """
    path_str = str(file_path)
    if not zipfile.is_zipfile(path_str):
        raise CorruptZipAPKError(
            message=f"File is not a valid ZIP archive or has an invalid header: {path_str}",
            path=path_str,
        )

    try:
        zf = zipfile.ZipFile(path_str, "r")
        first_bad = zf.testzip()
        if first_bad is not None:
            zf.close()
            raise CorruptZipAPKError(
                message=f"ZIP CRC check failed for corrupt archive member '{first_bad}' in: {path_str}",
                path=path_str,
                details=f"Corrupt member: {first_bad}",
            )
        return zf
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise CorruptZipAPKError(
            message=f"Failed to read ZIP archive: {exc}",
            path=path_str,
            details=str(exc),
        ) from exc


def load_apk(
    file_path: Union[str, Path],
    scan_ble: bool = True,
    scan_registration: bool = True,
    scan_knowledge_base: bool = True,
) -> APKMetadata:
    """Validate, inspect, and extract metadata from an Android APK file.

    Performs layered verification:
    1. File existence and non-zero size.
    2. Reproducible SHA-256 digest computation.
    3. ZIP format and CRC checksum integrity.
    4. Required Android archive structure (AndroidManifest.xml and classes*.dex).
    5. DEX extraction (single-dex and multi-dex).
    6. Manifest component and permission extraction.
    7. Phase 2 BLE indicators and UUID candidate extraction (if scan_ble=True).
    8. Phase 3 GATT service registration detection (if scan_registration=True).
    9. Phase 4 UUID knowledge base lookup (if scan_knowledge_base=True).

    Args:
        file_path: Path to the target APK file.
        scan_ble: Whether to perform Phase 2 BLE analysis (default: True).
        scan_registration: Whether to perform Phase 3 registration detection (default: True).
        scan_knowledge_base: Whether to perform Phase 4 knowledge base matching (default: True).

    Returns:
        APKMetadata instance containing validated metadata.




    Raises:
        FileNotFoundAPKError: Target file does not exist.
        EmptyFileAPKError: Target file is empty (0 bytes).
        CorruptZipAPKError: Target file is not a valid or intact ZIP.
        MissingManifestError: AndroidManifest.xml missing from archive.
        MissingDEXError: No classes*.dex found in archive.
        CorruptAPKError: Androguard failed to parse APK internals.
    """
    cleaned_path = normalize_container_path(str(file_path))
    path = Path(cleaned_path).resolve()
    path_str = str(path)

    # 1. Existence check
    if not path.is_file():
        raise FileNotFoundAPKError(
            message=f"APK file not found: {path_str}",
            path=path_str,
        )

    # 2. Non-empty check
    file_size = path.stat().st_size
    if file_size == 0:
        raise EmptyFileAPKError(
            message=f"APK file is empty (0 bytes): {path_str}",
            path=path_str,
        )

    # 3. SHA-256 calculation
    apk_sha256 = calculate_sha256(path)

    # 4. ZIP format and integrity verification
    zf = validate_zip_integrity(path)
    try:
        namelist = zf.namelist()

        # Check AndroidManifest.xml presence
        if "AndroidManifest.xml" not in namelist:
            raise MissingManifestError(
                message=f"Archive lacks mandatory AndroidManifest.xml: {path_str}",
                path=path_str,
            )

        # Check classes*.dex presence and collect all DEX entries
        dex_names = [name for name in namelist if _DEX_PATTERN.match(name)]
        if not dex_names:
            raise MissingDEXError(
                message=f"Archive contains no Dalvik Executable (classes*.dex) files: {path_str}",
                path=path_str,
            )

        # Sort DEX files naturally (classes.dex, classes2.dex, ...)
        dex_names.sort(key=_natural_dex_sort_key)

        dex_infos: List[DEXInfo] = []
        for name in dex_names:
            dex_bytes = zf.read(name)
            dex_hash = hashlib.sha256(dex_bytes).hexdigest()
            dex_infos.append(
                DEXInfo(
                    name=name,
                    sha256=dex_hash,
                    size_bytes=len(dex_bytes),
                )
            )
    finally:
        zf.close()

    # 5. Androguard intake and manifest extraction
    try:
        apk_obj = APK(path_str)
    except Exception as exc:
        raise CorruptAPKError(
            message=f"Androguard failed to parse APK internals: {exc}",
            path=path_str,
            details=str(exc),
        ) from exc

    manifest_meta = extract_manifest_metadata(apk_obj)

    ble_analysis = None
    if scan_ble:
        from ucsd.ble.extractor import scan_ble_indicators
        ble_analysis = scan_ble_indicators(path_str, manifest_meta)

    registration_analysis = None
    if scan_registration:
        from ucsd.registration.detector import detect_gatt_registrations
        candidate_uuids = [c.normalized_uuid for c in ble_analysis.uuid_candidates] if ble_analysis else None
        registration_analysis = detect_gatt_registrations(path_str, candidate_uuids=candidate_uuids)

    dex_count = len(dex_infos)
    is_multidex = dex_count > 1

    interim_meta = APKMetadata(
        file_path=path_str,
        file_name=path.name,
        file_size_bytes=file_size,
        sha256=apk_sha256,
        is_valid_zip=True,
        is_multidex=is_multidex,
        dex_count=dex_count,
        dex_files=dex_infos,
        manifest=manifest_meta,
        ble_analysis=ble_analysis,
        registration_analysis=registration_analysis,
        knowledge_base_assessment=None,
    )

    knowledge_base_assessment = None
    if scan_knowledge_base:
        try:
            from ucsd.conflict.assessor import assess_single_apk
            knowledge_base_assessment = assess_single_apk(interim_meta)
        except Exception:
            knowledge_base_assessment = None

    return APKMetadata(
        file_path=path_str,
        file_name=path.name,
        file_size_bytes=file_size,
        sha256=apk_sha256,
        is_valid_zip=True,
        is_multidex=is_multidex,
        dex_count=dex_count,
        dex_files=dex_infos,
        manifest=manifest_meta,
        ble_analysis=ble_analysis,
        registration_analysis=registration_analysis,
        knowledge_base_assessment=knowledge_base_assessment,
    )



