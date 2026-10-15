"""Secure workspace and storage management for APK uploads and reports."""

import os
import re
import shutil
import zipfile
from pathlib import Path
from typing import Optional, Tuple

MAX_UPLOAD_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB limit
DEFAULT_WORKSPACE_DIR = Path("workspace/uploads")
DEFAULT_REPORTS_DIR = Path("reports")


def get_workspace_dir() -> Path:
    """Return the configured upload workspace directory, creating if absent."""
    env_dir = os.environ.get("UCSD_WORKSPACE_DIR")
    p = Path(env_dir) if env_dir else DEFAULT_WORKSPACE_DIR
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_reports_dir() -> Path:
    """Return the configured reports output directory, creating if absent."""
    env_dir = os.environ.get("UCSD_REPORTS_DIR")
    p = Path(env_dir) if env_dir else DEFAULT_REPORTS_DIR
    p.mkdir(parents=True, exist_ok=True)
    return p


def sanitize_filename(filename: str) -> str:
    """Strictly sanitize an uploaded filename to prevent directory traversal or injection."""
    # Strip any directory path components
    base = os.path.basename(filename.strip().replace("\\", "/"))
    # Keep only safe characters: alphanumeric, dash, underscore, dot
    clean = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", base)
    # Ensure it ends with .apk
    if not clean.lower().endswith(".apk"):
        clean = f"{clean}.apk"
    return clean or "upload.apk"


def validate_apk_archive(file_path: Path) -> Tuple[bool, Optional[str]]:
    """Validate that the target file is a genuine, uncorrupted ZIP archive containing at least one DEX file."""
    if not file_path.is_file():
        return False, "File does not exist"

    size = file_path.stat().st_size
    if size == 0:
        return False, "Uploaded file is empty (0 bytes)"
    if size > MAX_UPLOAD_SIZE_BYTES:
        return False, f"File size exceeds maximum allowed limit of {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB"

    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            # Check CRC integrity of the zip entries
            corrupt = zf.testzip()
            if corrupt is not None:
                return False, f"Corrupted file inside APK archive: {corrupt}"

            # Check for DEX presence
            names = zf.namelist()
            has_dex = any(n.endswith(".dex") for n in names)
            if not has_dex:
                return False, "Invalid APK: archive does not contain Dalvik Executable (classes.dex) files"

            # Check for AndroidManifest.xml
            has_manifest = "AndroidManifest.xml" in names
            if not has_manifest:
                return False, "Invalid APK: archive does not contain AndroidManifest.xml"

    except zipfile.BadZipFile:
        return False, "File is not a valid ZIP/APK archive"
    except Exception as exc:
        return False, f"Failed to validate APK archive: {str(exc)}"

    return True, None


def save_staged_upload(
    analysis_id: str,
    original_filename: str,
    stream_or_bytes,
) -> Path:
    """Save an incoming file stream to the dedicated workspace with a UUID prefix."""
    clean_name = sanitize_filename(original_filename)
    workspace = get_workspace_dir()
    target_path = workspace / f"{analysis_id}_{clean_name}"

    with open(target_path, "wb") as f:
        if isinstance(stream_or_bytes, (bytes, bytearray)):
            f.write(stream_or_bytes)
        else:
            # Assume file-like object
            shutil.copyfileobj(stream_or_bytes, f)

    return target_path


def cleanup_staged_upload(target_path: Path) -> None:
    """Safely remove a staged APK from the workspace."""
    try:
        if target_path and target_path.exists() and target_path.is_file():
            target_path.unlink()
    except Exception:
        pass


def delete_analysis_files(
    report_json_path: Optional[str] = None,
    report_html_path: Optional[str] = None,
) -> None:
    """Clean up associated report files when an analysis is deleted."""
    for p_str in (report_json_path, report_html_path):
        if p_str:
            try:
                p = Path(p_str)
                if p.exists() and p.is_file():
                    p.unlink()
            except Exception:
                pass
