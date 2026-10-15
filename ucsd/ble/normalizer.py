"""UUID normalization, format validation, and Bluetooth Base UUID expansion."""

import re
from typing import Optional, Tuple
from ucsd.errors import InvalidUUIDError

# Bluetooth Base UUID: 00000000-0000-1000-8000-00805F9B34FB
BLUETOOTH_BASE_SUFFIX = "-0000-1000-8000-00805f9b34fb"
BLUETOOTH_BASE_UUID = f"00000000{BLUETOOTH_BASE_SUFFIX}"

# Regex patterns
CANONICAL_UUID_EXACT_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

CANONICAL_UUID_SEARCH_RE = re.compile(
    r"\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b"
)

HEX16_PREFIXED_EXACT_RE = re.compile(r"^0[xX]([0-9a-fA-F]{4})$")
HEX16_PREFIXED_SEARCH_RE = re.compile(r"\b0[xX]([0-9a-fA-F]{4})\b")

HEX16_RAW_EXACT_RE = re.compile(r"^[0-9a-fA-F]{4}$")

HEX32_PREFIXED_EXACT_RE = re.compile(r"^0[xX]([0-9a-fA-F]{8})$")
HEX32_PREFIXED_SEARCH_RE = re.compile(r"\b0[xX]([0-9a-fA-F]{8})\b")

HEX32_RAW_EXACT_RE = re.compile(r"^[0-9a-fA-F]{8}$")

HEX128_RAW_EXACT_RE = re.compile(r"^[0-9a-fA-F]{32}$")

# Bluetooth SIG Assigned Numbers (Services, Characteristics, Descriptors)
KNOWN_SIG_NAMES = {
    # Services (0x1800 - 0x1830)
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    "1802": "Immediate Alert",
    "1803": "Link Loss",
    "1804": "Tx Power",
    "1805": "Current Time Service",
    "1806": "Reference Time Update",
    "1807": "Next DST Change",
    "1808": "Glucose",
    "1809": "Health Thermometer",
    "180a": "Device Information",
    "180d": "Heart Rate",
    "180e": "Phone Alert Status",
    "180f": "Battery Service",
    "1810": "Blood Pressure",
    "1811": "Alert Notification",
    "1812": "Human Interface Device",
    "1813": "Scan Parameters",
    "1814": "Running Speed and Cadence",
    "1815": "Automation IO",
    "1816": "Cycling Speed and Cadence",
    "1818": "Cycling Power",
    "1819": "Location and Navigation",
    "181a": "Environmental Sensing",
    "181b": "Body Composition",
    "181c": "User Data",
    "181d": "Weight Scale",
    "181e": "Bond Management",
    "181f": "Continuous Glucose Monitoring",
    "1820": "Internet Protocol Support",
    "1821": "Indoor Positioning",
    "1822": "Pulse Oximeter",
    "1823": "HTTP Proxy",
    "1824": "Transport Discovery",
    "1825": "Object Transfer",
    "1826": "Fitness Machine",
    "1827": "Mesh Provisioning",
    "1828": "Mesh Proxy",
    "1829": "Reconnection Configuration",
    # Common Characteristics (0x2A00 - 0x2A50)
    "2a00": "Device Name",
    "2a01": "Appearance",
    "2a02": "Peripheral Privacy Flag",
    "2a03": "Reconnection Address",
    "2a04": "Peripheral Preferred Connection Parameters",
    "2a05": "Service Changed",
    "2a06": "Alert Level",
    "2a19": "Battery Level",
    "2a23": "System ID",
    "2a24": "Model Number String",
    "2a25": "Serial Number String",
    "2a26": "Firmware Revision String",
    "2a27": "Hardware Revision String",
    "2a28": "Software Revision String",
    "2a29": "Manufacturer Name String",
    "2a37": "Heart Rate Measurement",
    "2a38": "Body Sensor Location",
    "2a39": "Heart Rate Control Point",
    # Descriptors (0x2900 - 0x2905)
    "2900": "Characteristic Extended Properties",
    "2901": "Characteristic User Description",
    "2902": "Client Characteristic Configuration",
    "2903": "Server Characteristic Configuration",
    "2904": "Characteristic Presentation Format",
    "2905": "Characteristic Aggregate Format",
}


def expand_16bit_uuid(hex_str: str) -> str:
    """Expand a 16-bit hex value to the standard 128-bit Bluetooth Base UUID.

    Format: 0000xxxx-0000-1000-8000-00805f9b34fb

    Args:
        hex_str: 4-digit hexadecimal string (with or without 0x prefix).

    Returns:
        Canonical 128-bit lowercase UUID string.

    Raises:
        InvalidUUIDError: If value is not a valid 4-digit hex string.
    """
    if not isinstance(hex_str, str):
        raise InvalidUUIDError(f"Expected string for 16-bit UUID expansion, got {type(hex_str).__name__}")

    val = hex_str.strip()
    if val.lower().startswith("0x"):
        val = val[2:]

    if len(val) != 4 or not all(c in "0123456789abcdefABCDEF" for c in val):
        raise InvalidUUIDError(f"Invalid 16-bit hex value: '{hex_str}'")

    return f"0000{val.lower()}{BLUETOOTH_BASE_SUFFIX}"


def is_bluetooth_sig_range(normalized_uuid: str) -> bool:
    """Return True if the UUID is based on the Bluetooth Base UUID."""
    return normalized_uuid.lower().endswith(BLUETOOTH_BASE_SUFFIX)


def extract_short_hex(normalized_uuid: str) -> Optional[str]:
    """Extract 4-digit 16-bit short ID if UUID falls in 0000xxxx Base UUID range."""
    u = normalized_uuid.lower()
    if is_bluetooth_sig_range(u) and u.startswith("0000"):
        return u[4:8]
    return None


def lookup_sig_name(short_hex: Optional[str]) -> Optional[str]:
    """Look up human-readable name for a 16-bit Bluetooth SIG assigned UUID."""
    if not short_hex:
        return None
    return KNOWN_SIG_NAMES.get(short_hex.lower())


def classify_uuid_format(val: str) -> Optional[str]:
    """Identify the UUID format type of the given string, or None if unrecognized."""
    if not isinstance(val, str):
        return None
    raw = val.strip()
    if CANONICAL_UUID_EXACT_RE.match(raw):
        return "canonical-128"
    if HEX16_PREFIXED_EXACT_RE.match(raw):
        return "bluetooth-16-prefixed"
    if HEX16_RAW_EXACT_RE.match(raw):
        return "bluetooth-16-raw"
    if HEX32_PREFIXED_EXACT_RE.match(raw):
        return "bluetooth-32-prefixed"
    if HEX32_RAW_EXACT_RE.match(raw):
        return "bluetooth-32-raw"
    if HEX128_RAW_EXACT_RE.match(raw):
        return "raw-128-hex"
    return None


def normalize_uuid(val: str) -> str:
    """Normalize any supported UUID candidate format into canonical 128-bit lowercase.

    Supported formats:
    1. Canonical 128-bit hyphenated (e.g. '0000180d-0000-1000-8000-00805f9b34fb')
    2. Bluetooth 16-bit prefixed (e.g. '0x180D' or '0X180D') -> expanded via Base UUID
    3. Bluetooth 16-bit raw (e.g. '180D') -> expanded via Base UUID
    4. Bluetooth 32-bit prefixed (e.g. '0x0000180D') -> expanded via Base UUID
    5. Bluetooth 32-bit raw (e.g. '0000180D') -> expanded via Base UUID
    6. Raw 128-bit hex (32 characters without hyphens) -> formatted with standard hyphens

    Raises:
        InvalidUUIDError: If value is empty, has non-hex characters, incorrect length, or invalid separators.
    """
    if not isinstance(val, str):
        raise InvalidUUIDError(f"UUID must be a string, got {type(val).__name__}")

    raw = val.strip()
    if not raw:
        raise InvalidUUIDError("UUID string cannot be empty")

    # 1. Canonical 128-bit format check
    if CANONICAL_UUID_EXACT_RE.match(raw):
        return raw.lower()

    # 2. Bluetooth 16-bit prefixed: 0xXXXX
    m16_pre = HEX16_PREFIXED_EXACT_RE.match(raw)
    if m16_pre:
        return expand_16bit_uuid(m16_pre.group(1))

    # 3. Bluetooth 16-bit raw: XXXX
    if HEX16_RAW_EXACT_RE.match(raw):
        return expand_16bit_uuid(raw)

    # 4. Bluetooth 32-bit prefixed: 0xXXXXXXXX
    m32_pre = HEX32_PREFIXED_EXACT_RE.match(raw)
    if m32_pre:
        return f"{m32_pre.group(1).lower()}{BLUETOOTH_BASE_SUFFIX}"

    # 5. Bluetooth 32-bit raw: XXXXXXXX
    if HEX32_RAW_EXACT_RE.match(raw):
        return f"{raw.lower()}{BLUETOOTH_BASE_SUFFIX}"

    # 6. Raw 128-bit unhyphenated hex: 32 hex chars
    if HEX128_RAW_EXACT_RE.match(raw):
        h = raw.lower()
        return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

    # Check for specific malformed formats to provide descriptive errors
    if len(raw) == 36 and ("_" in raw or " " in raw or ":" in raw):
        raise InvalidUUIDError(f"Invalid UUID separator in 128-bit candidate: '{val}'")

    if raw.lower().startswith("0x") and len(raw) not in (6, 10):
        raise InvalidUUIDError(f"Invalid length for prefixed hex UUID candidate: '{val}'")

    raise InvalidUUIDError(f"Malformed or unsupported UUID string: '{val}'")
