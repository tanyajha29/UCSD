# UCSD Phase 1: Independent APK Validation Report

**Target APK:** `/app/samples/validation.apk`  
**Timestamp:** `2026-10-04T14:22:04.762733+00:00`  
**Validation Verdict:** **PASS**  

## 1. Summary Statistics

| Metric | Value |
| :--- | :--- |
| **Total Fields Evaluated** | 17 |
| **Matches** | 16 |
| **Mismatches** | 0 |
| **Not Verifiable** | 1 |
| **Overall Verdict** | PASS |

## 2. Independent Inspection Tooling

This validation was performed independently of UCSD's internal parser:
- **UCSD Analyzer:** Androguard v4.1.4 (core APK engine)
- **Manifest / Package Tool:** `Android Asset Packaging Tool, v0.2-debian`
- **Archive & DEX Validator:** `python-zipfile-crc32`
- **Integrity Hasher:** `python-hashlib-sha256`

## 3. Field-by-Field Comparison

| Property | UCSD Value | Independent Value | Status | Explanation |
| :--- | :--- | :--- | :---: | :--- |
| `sha256` | `83d3fe522281c3cb89fce3bc05038f81b3c3b...` | `83d3fe522281c3cb89fce3bc05038f81b3c3b...` | MATCH | File SHA-256 checksum: both sources independently report exact match '83d3fe522281c3cb89fce3bc05038f81b3c3b32c108536941f184c5f9bb53778'. |
| `file_size_bytes` | `12537183` | `12537183` | MATCH | Total file size in bytes: both sources independently report exact match '12537183'. |
| `is_valid_zip` | `True` | `True` | MATCH | ZIP CRC32 archive integrity: both sources independently report exact match 'True'. |
| `package_name` | `org.fdroid.fdroid` | `org.fdroid.fdroid` | MATCH | Android application package identifier: both sources independently report exact match 'org.fdroid.fdroid'. |
| `version_code` | `2000051` | `2000051` | MATCH | Internal integer version code: both sources independently report exact match '2000051'. |
| `version_name` | `2.0.1` | `2.0.1` | MATCH | Display version string: both sources independently report exact match '2.0.1'. |
| `min_sdk_version` | `24` | `24` | MATCH | Minimum supported Android API level: both sources independently report exact match '24'. |
| `target_sdk_version` | `37` | `37` | MATCH | Target Android API level: both sources independently report exact match '37'. |
| `compile_sdk_version` | `None` | `37` | *NOT_VERIFIABLE* | UCSD Phase 1 schema does not extract compileSdkVersion; independent aapt tool reports compileSdkVersion='37'. |
| `requested_permissions_count` | `30` | `30` | MATCH | Count of standard <uses-permission> items: both sources independently report exact match '30'. |
| `requested_permissions` | `30 items` | `30 items` | MATCH | Exact set match for all 30 standard <uses-permission> entries. Note: aapt also identified conditional permission tag(s) <uses-permission-sdk-23>: ['android.permission.ACCESS_COARSE_LOCATION']. |
| `declared_permissions_count` | `2` | `2` | MATCH | Count of custom declared <permission> definitions: both sources independently report exact match '2'. |
| `declared_permissions` | `2 items` | `2 items` | MATCH | Exact match on custom declared permissions: ['org.fdroid.fdroid.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'org.fdroid.fdroid.permission.UPDATE_REPOS']. |
| `dex_count` | `3` | `3` | MATCH | Count of classes*.dex archive entries: both sources independently report exact match '3'. |
| `is_multidex` | `True` | `True` | MATCH | Multi-DEX indicator (dex_count > 1): both sources independently report exact match 'True'. |
| `dex_names` | `3 items` | `3 items` | MATCH | Exact match for DEX members: ['classes.dex', 'classes2.dex', 'classes3.dex']. |
| `dex_checksums_and_sizes` | `3 items` | `3 items` | MATCH | All individual DEX members have identical uncompressed byte sizes and SHA-256 checksums. |

## 4. In-Depth Permission Analysis

Android permissions fall into requested permissions (`<uses-permission>`), conditional permissions (`<uses-permission-sdk-23>`), and custom declared permissions (`<permission>`).

- **Standard `<uses-permission>`:** Both UCSD and aapt extract exactly **30** permissions (100% identical).
- **Conditional `<uses-permission-sdk-23>`:** aapt identified 1 conditional entry: `['android.permission.ACCESS_COARSE_LOCATION']`.
- **Custom Declared `<permission>`:** Both UCSD and aapt report exactly **2** declared custom permissions: `['org.fdroid.fdroid.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'org.fdroid.fdroid.permission.UPDATE_REPOS']`.

## 5. DEX Archive Member Verification

| Member Name | Uncompressed Size | SHA-256 Digest |
| :--- | :--- | :--- |
| `classes.dex` | 9,295,512 bytes | `4cafa3b5bb47b0065ba8311285193d5aff7cdf0e9a388c108ed44d58e1ad47d8` |
| `classes2.dex` | 9,622,304 bytes | `68cf25128f1fb190db2ab4fdfda3f3f07045a4a6e757a2388c16eaf95b8b186e` |
| `classes3.dex` | 1,661,772 bytes | `b0731845fa5d685e306b73b04d728f63e1f08de226a247032669408afc386ff5` |

- **Multi-DEX Status:** `True` (3 DEX members detected).

## 6. Final Evidence-Based Verdict

> [!NOTE]
> **PHASE 1 VALIDATION VERDICT: PASS**
>
> All verifiable metadata properties extracted by UCSD (file digest, file size, package identifier, version codes, SDK targets, standard requested permissions, custom declared permissions, DEX counts, DEX member names, and per-DEX checksums) have been corroborated by independent Android SDK tooling (`aapt`) and standard library archive inspection without discrepancy.
