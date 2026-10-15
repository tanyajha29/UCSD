"""Independent APK inspection using AOSP aapt, standard zipfile, and hashlib.

This module explicitly DOES NOT import or invoke Androguard.
It provides a completely decoupled ground truth extractor for APK static metadata.
"""

import hashlib
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple

from ucsd.apk_loader import normalize_container_path
from ucsd.validation.models import IndependentAPKMetadata, IndependentDEXInfo

_DEX_RE = re.compile(r"^classes(\d+)?\.dex$")


def _natural_dex_sort_key(name: str) -> Tuple[int, str]:
    """Sort key for DEX files (classes.dex, classes2.dex, classes3.dex...)."""
    match = _DEX_RE.match(name)
    if not match:
        return (9999, name)
    suffix = match.group(1)
    if suffix is None:
        return (1, name)
    return (int(suffix), name)


def compute_file_sha256(file_path: Path, chunk_size: int = 65536) -> str:
    """Independently compute file SHA-256 using standard hashlib streaming."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def get_aapt_tool_info() -> str:
    """Retrieve version information from the installed aapt binary."""
    aapt_bin = shutil.which("aapt")
    if not aapt_bin:
        return "aapt: NOT_FOUND"
    try:
        res = subprocess.run(
            [aapt_bin, "version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return res.stdout.strip()
    except Exception as exc:
        return f"aapt: error retrieving version ({exc})"


def inspect_apk_independently(apk_path: str) -> IndependentAPKMetadata:
    """Perform independent static extraction on an APK without using Androguard.

    Args:
        apk_path: Path to the APK file.

    Returns:
        IndependentAPKMetadata containing decoupled ground truth.
    """
    clean_path_str = normalize_container_path(str(apk_path))
    path = Path(clean_path_str).resolve()

    if not path.is_file():
        raise FileNotFoundError(f"Target APK does not exist: {path}")

    # 1. File identity
    file_size = path.stat().st_size
    file_sha256 = compute_file_sha256(path)

    # 2. Archive & DEX inspection via Python standard library zipfile
    is_valid_zip = False
    has_manifest = False
    has_dex = False
    dex_infos: List[IndependentDEXInfo] = []

    if zipfile.is_zipfile(str(path)):
        try:
            with zipfile.ZipFile(str(path), "r") as zf:
                # testzip returns None if all member CRC32s match
                first_bad = zf.testzip()
                if first_bad is None:
                    is_valid_zip = True

                namelist = zf.namelist()
                has_manifest = "AndroidManifest.xml" in namelist

                dex_names = [n for n in namelist if _DEX_RE.match(n)]
                has_dex = len(dex_names) > 0
                dex_names.sort(key=_natural_dex_sort_key)

                for name in dex_names:
                    data = zf.read(name)
                    d_hash = hashlib.sha256(data).hexdigest()
                    dex_infos.append(
                        IndependentDEXInfo(
                            name=name,
                            sha256=d_hash,
                            size_bytes=len(data),
                        )
                    )
        except Exception:
            is_valid_zip = False

    dex_count = len(dex_infos)
    is_multidex = dex_count > 1

    # 3. Android Manifest & Package metadata extraction via AOSP aapt
    aapt_bin = shutil.which("aapt")
    tool_info = get_aapt_tool_info()

    package_name: Optional[str] = None
    version_code: Optional[int] = None
    version_name: Optional[str] = None
    min_sdk_version: Optional[int] = None
    target_sdk_version: Optional[int] = None
    compile_sdk_version: Optional[int] = None
    requested_permissions: List[str] = []
    declared_permissions: List[str] = []

    if aapt_bin and is_valid_zip:
        # aapt dump badging
        try:
            badging_proc = subprocess.run(
                [aapt_bin, "dump", "badging", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            badging_out = badging_proc.stdout

            # Parse package line: package: name='...' versionCode='...' versionName='...'
            pkg_m = re.search(
                r"package:\s+name='([^']+)'\s+versionCode='([^']*)'\s+versionName='([^']*)'",
                badging_out,
            )
            if pkg_m:
                package_name = pkg_m.group(1).strip() or None
                raw_vcode = pkg_m.group(2).strip()
                if raw_vcode:
                    try:
                        version_code = int(raw_vcode, 10)
                    except ValueError:
                        pass
                raw_vname = pkg_m.group(3).strip()
                version_name = raw_vname if raw_vname else None

            # Parse compileSdkVersion: compileSdkVersion='37'
            compile_m = re.search(r"compileSdkVersion='([^']+)'", badging_out)
            if compile_m:
                try:
                    compile_sdk_version = int(compile_m.group(1), 10)
                except ValueError:
                    pass

            # Parse sdkVersion (minSdk): sdkVersion:'24'
            min_sdk_m = re.search(r"sdkVersion:'([^']+)'", badging_out)
            if min_sdk_m:
                try:
                    min_sdk_version = int(min_sdk_m.group(1), 10)
                except ValueError:
                    pass

            # Parse targetSdkVersion: targetSdkVersion:'37'
            target_sdk_m = re.search(r"targetSdkVersion:'([^']+)'", badging_out)
            if target_sdk_m:
                try:
                    target_sdk_version = int(target_sdk_m.group(1), 10)
                except ValueError:
                    pass

            # Parse standard requested permissions from badging
            standard_req = re.findall(
                r"^uses-permission:\s+name='([^']+)'",
                badging_out,
                re.MULTILINE,
            )
            uses_permissions = sorted(set(standard_req))

            # Parse conditional permissions (uses-permission-sdk-23)
            sdk23_req = re.findall(
                r"^uses-permission-sdk-23:\s+name='([^']+)'",
                badging_out,
                re.MULTILINE,
            )
            uses_permissions_sdk_23 = sorted(set(sdk23_req))

            # Combined requested permissions
            requested_permissions = sorted(set(uses_permissions + uses_permissions_sdk_23))
        except Exception:
            pass

        # aapt dump permissions to extract declared custom permissions
        try:
            perm_proc = subprocess.run(
                [aapt_bin, "dump", "permissions", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            perm_out = perm_proc.stdout

            # Match 'permission: <permission_name>' lines
            decl_matches = re.findall(
                r"^permission:\s+([^\s]+)",
                perm_out,
                re.MULTILINE,
            )
            declared_permissions = sorted(set(decl_matches))

            # Also verify if any additional uses-permission were listed
            more_req = re.findall(
                r"^uses-permission:\s+name='([^']+)'",
                perm_out,
                re.MULTILINE,
            )
            for p in more_req:
                if p not in uses_permissions:
                    uses_permissions.append(p)
                if p not in requested_permissions:
                    requested_permissions.append(p)
            uses_permissions.sort()
            requested_permissions.sort()
        except Exception:
            pass

    return IndependentAPKMetadata(
        file_path=str(path),
        file_name=path.name,
        file_size_bytes=file_size,
        sha256=file_sha256,
        is_valid_zip=is_valid_zip,
        has_manifest=has_manifest,
        has_dex=has_dex,
        is_multidex=is_multidex,
        dex_count=dex_count,
        dex_files=dex_infos,
        package_name=package_name,
        version_code=version_code,
        version_name=version_name,
        min_sdk_version=min_sdk_version,
        target_sdk_version=target_sdk_version,
        compile_sdk_version=compile_sdk_version,
        uses_permissions=uses_permissions,
        uses_permissions_sdk_23=uses_permissions_sdk_23,
        requested_permissions=requested_permissions,
        requested_permissions_count=len(requested_permissions),
        declared_permissions=declared_permissions,
        declared_permissions_count=len(declared_permissions),
        tool_metadata={
            "aapt_tool": tool_info,
            "zip_checker": "python-zipfile-crc32",
            "hash_algorithm": "python-hashlib-sha256",
        },
    )
