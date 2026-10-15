"""Generator for minimal synthetic APK and DEX fixtures for testing."""

import hashlib
import io
import struct
import zlib
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple


def build_string_pool_utf8(strings: List[str]) -> bytes:
    """Build a standard Android RES_STRING_POOL binary chunk (UTF-8)."""
    offsets: List[int] = []
    str_data = bytearray()
    for s in strings:
        offsets.append(len(str_data))
        encoded = s.encode("utf-8")
        c_len = len(s)
        b_len = len(encoded)
        # lengths for utf-8 string pool: 1 byte char len, 1 byte byte len (for len < 128)
        str_data.extend(struct.pack("BB", c_len, b_len) + encoded + b"\x00")

    # Pad to 4-byte boundary
    while len(str_data) % 4 != 0:
        str_data.append(0)

    header_size = 28
    offsets_bytes = b"".join(struct.pack("<I", off) for off in offsets)
    strings_start = header_size + len(offsets_bytes)
    chunk_size = strings_start + len(str_data)

    pool_hdr = struct.pack(
        "<HHIIIIII",
        0x0001,         # RES_STRING_POOL_TYPE
        header_size,    # 28 bytes
        chunk_size,     # Total chunk size
        len(strings),   # String count
        0,              # Style count
        0x100,          # Flags (UTF-8)
        strings_start,  # Offset to string data
        0,              # Offset to style data
    )
    return pool_hdr + offsets_bytes + bytes(str_data)


def build_minimal_axml(
    package_name: str = "org.example.testapp",
    version_code: int = 42,
    version_name: str = "1.2.3",
    permissions: Optional[List[str]] = None,
    activities: Optional[List[str]] = None,
    min_sdk: int = 21,
    target_sdk: int = 33,
) -> bytes:
    """Generate a minimal valid Android Binary XML (AXML) for AndroidManifest.xml."""
    if permissions is None:
        permissions = ["android.permission.INTERNET"]
    if activities is None:
        activities = ["org.example.testapp.MainActivity"]

    uri_android = "http://schemas.android.com/apk/res/android"
    prefix_android = "android"

    # Collect all unique strings
    all_strings = [
        "manifest",
        "package",
        package_name,
        "versionCode",
        "versionName",
        version_name,
        prefix_android,
        uri_android,
        "uses-sdk",
        "minSdkVersion",
        "targetSdkVersion",
        "uses-permission",
        "name",
        "application",
        "activity",
    ]
    for p in permissions:
        if p not in all_strings:
            all_strings.append(p)
    for a in activities:
        if a not in all_strings:
            all_strings.append(a)

    s_map = {s: i for i, s in enumerate(all_strings)}
    pool_bytes = build_string_pool_utf8(all_strings)

    body = bytearray()

    # 1. Start namespace android
    body += struct.pack("<HHIIIII", 0x0100, 16, 24, 1, 0xFFFFFFFF, s_map[prefix_android], s_map[uri_android])

    # 2. Start element <manifest>
    manifest_attrs = bytearray()
    # package="..." (no namespace)
    manifest_attrs += struct.pack("<IIIHBBI", 0xFFFFFFFF, s_map["package"], s_map[package_name], 8, 0, 0x03, s_map[package_name])
    # android:versionCode=version_code
    manifest_attrs += struct.pack("<IIIHBBI", s_map[uri_android], s_map["versionCode"], 0xFFFFFFFF, 8, 0, 0x10, version_code)
    # android:versionName=version_name
    manifest_attrs += struct.pack("<IIIHBBI", s_map[uri_android], s_map["versionName"], s_map[version_name], 8, 0, 0x03, s_map[version_name])

    body += struct.pack("<HHIIIIIHHHHHH", 0x0102, 16, 36 + len(manifest_attrs), 1, 0xFFFFFFFF, 0xFFFFFFFF, s_map["manifest"], 20, 20, 3, 0, 0, 0)
    body += manifest_attrs

    # 3. <uses-sdk android:minSdkVersion=... android:targetSdkVersion=...>
    sdk_attrs = bytearray()
    sdk_attrs += struct.pack("<IIIHBBI", s_map[uri_android], s_map["minSdkVersion"], 0xFFFFFFFF, 8, 0, 0x10, min_sdk)
    sdk_attrs += struct.pack("<IIIHBBI", s_map[uri_android], s_map["targetSdkVersion"], 0xFFFFFFFF, 8, 0, 0x10, target_sdk)
    body += struct.pack("<HHIIIIIHHHHHH", 0x0102, 16, 36 + len(sdk_attrs), 2, 0xFFFFFFFF, 0xFFFFFFFF, s_map["uses-sdk"], 20, 20, 2, 0, 0, 0)
    body += sdk_attrs
    body += struct.pack("<HHIIIII", 0x0103, 16, 24, 2, 0xFFFFFFFF, 0xFFFFFFFF, s_map["uses-sdk"])

    # 4. <uses-permission android:name="...">
    for perm in permissions:
        perm_attrs = bytearray()
        perm_attrs += struct.pack("<IIIHBBI", s_map[uri_android], s_map["name"], s_map[perm], 8, 0, 0x03, s_map[perm])
        body += struct.pack("<HHIIIIIHHHHHH", 0x0102, 16, 36 + len(perm_attrs), 3, 0xFFFFFFFF, 0xFFFFFFFF, s_map["uses-permission"], 20, 20, 1, 0, 0, 0)
        body += perm_attrs
        body += struct.pack("<HHIIIII", 0x0103, 16, 24, 3, 0xFFFFFFFF, 0xFFFFFFFF, s_map["uses-permission"])

    # 5. <application>
    body += struct.pack("<HHIIIIIHHHHHH", 0x0102, 16, 36, 4, 0xFFFFFFFF, 0xFFFFFFFF, s_map["application"], 20, 20, 0, 0, 0, 0)

    # 6. Activities inside <application>
    for act in activities:
        act_attrs = bytearray()
        act_attrs += struct.pack("<IIIHBBI", s_map[uri_android], s_map["name"], s_map[act], 8, 0, 0x03, s_map[act])
        body += struct.pack("<HHIIIIIHHHHHH", 0x0102, 16, 36 + len(act_attrs), 5, 0xFFFFFFFF, 0xFFFFFFFF, s_map["activity"], 20, 20, 1, 0, 0, 0)
        body += act_attrs
        body += struct.pack("<HHIIIII", 0x0103, 16, 24, 5, 0xFFFFFFFF, 0xFFFFFFFF, s_map["activity"])

    # End <application>
    body += struct.pack("<HHIIIII", 0x0103, 16, 24, 6, 0xFFFFFFFF, 0xFFFFFFFF, s_map["application"])

    # End <manifest>
    body += struct.pack("<HHIIIII", 0x0103, 16, 24, 7, 0xFFFFFFFF, 0xFFFFFFFF, s_map["manifest"])

    # End namespace android
    body += struct.pack("<HHIIIII", 0x0101, 16, 24, 8, 0xFFFFFFFF, s_map[prefix_android], s_map[uri_android])

    total_size = 8 + len(pool_bytes) + len(body)
    file_hdr = struct.pack("<HHI", 0x0003, 8, total_size)
    return file_hdr + pool_bytes + bytes(body)


def build_minimal_dex(marker: bytes = b"") -> bytes:
    """Generate a minimal valid Dalvik Executable (DEX v035) header."""
    # DEX Header size is 112 bytes (0x70)
    # Plus a small map list: 4 bytes size (1), then 1 MapItem (12 bytes) = 16 bytes
    # Total size = 112 + 16 = 128 bytes
    header_size = 0x70
    map_off = header_size
    file_size = 128 + len(marker)

    # Map list at offset 112: 1 entry (TYPE_HEADER_ITEM = 0x0000, unused=0, size=1, offset=0)
    map_list = struct.pack("<IHHII", 1, 0x0000, 0, 1, 0)
    payload = map_list + marker
    # Pad to 4 bytes
    while len(payload) % 4 != 0:
        payload += b"\x00"
    file_size = header_size + len(payload)

    # Initial header without checksum and signature
    magic = b"dex\n035\x00"
    endian_tag = 0x12345678

    hdr_part1 = magic  # 8 bytes
    # 4 bytes checksum, 20 bytes signature to be filled later
    hdr_part2 = struct.pack(
        "<IIIIIIIIIIIIII",
        file_size,   # file_size
        header_size, # header_size
        endian_tag,  # endian_tag
        0, 0,        # link_size, link_off
        map_off,     # map_off
        0, 0,        # string_ids_size, string_ids_off
        0, 0,        # type_ids_size, type_ids_off
        0, 0,        # proto_ids_size, proto_ids_off
        0, 0,        # field_ids_size, field_ids_off
    )
    hdr_part3 = struct.pack(
        "<IIII",
        0, 0,        # method_ids_size, method_ids_off
        0, 0,        # class_defs_size, class_defs_off
    )
    hdr_part4 = struct.pack(
        "<II",
        len(payload), map_off # data_size, data_off
    )

    rest_of_file = hdr_part2 + hdr_part3 + hdr_part4 + payload
    # Calculate SHA1 signature of rest_of_file
    sha1_sig = hashlib.sha1(rest_of_file).digest()  # 20 bytes

    # Calculate adler32 checksum of (sha1_sig + rest_of_file)
    adler = zlib.adler32(sha1_sig + rest_of_file) & 0xFFFFFFFF
    checksum_bytes = struct.pack("<I", adler)

    return hdr_part1 + checksum_bytes + sha1_sig + rest_of_file


def uleb128(val: int) -> bytes:
    """Encode an integer as unsigned LEB128."""
    res = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val != 0:
            res.append(b | 0x80)
        else:
            res.append(b)
            break
    return bytes(res)


def build_dex_with_strings(strings: List[str]) -> bytes:
    """Generate a valid DEX (v035) containing a string pool."""
    sorted_strings = sorted(list(set(strings)))
    str_data = bytearray()
    offsets: List[int] = []
    for s in sorted_strings:
        offsets.append(len(str_data))
        encoded = s.encode("utf-8")
        str_data.extend(uleb128(len(s)) + encoded + b"\x00")

    header_size = 0x70
    string_ids_off = header_size
    string_ids_size = len(sorted_strings)
    string_ids_bytes = b"".join(
        struct.pack("<I", string_ids_off + string_ids_size * 4 + off) for off in offsets
    )
    data_off = string_ids_off + len(string_ids_bytes)
    data_bytes = bytes(str_data)

    map_off = data_off + len(data_bytes)
    while map_off % 4 != 0:
        data_bytes += b"\x00"
        map_off = data_off + len(data_bytes)

    map_items = [
        (0x0000, 1, 0),
        (0x0001, string_ids_size, string_ids_off),
        (0x2002, string_ids_size, data_off),
        (0x1000, 1, map_off),
    ]
    map_payload = struct.pack("<I", len(map_items)) + b"".join(
        struct.pack("<HHII", it[0], 0, it[1], it[2]) for it in map_items
    )

    total_file_size = map_off + len(map_payload)

    hdr_part1 = b"dex\n035\x00"
    hdr_part2 = struct.pack(
        "<IIIIIIIIIIIIII",
        total_file_size,
        header_size,
        0x12345678,
        0,
        0,
        map_off,
        string_ids_size,
        string_ids_off,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    hdr_part3 = struct.pack("<IIII", 0, 0, 0, 0)
    hdr_part4 = struct.pack("<II", len(data_bytes) + len(map_payload), data_off)

    body = string_ids_bytes + data_bytes + map_payload
    rest = hdr_part2 + hdr_part3 + hdr_part4 + body
    sha1_sig = hashlib.sha1(rest).digest()
    adler = zlib.adler32(sha1_sig + rest) & 0xFFFFFFFF
    return hdr_part1 + struct.pack("<I", adler) + sha1_sig + rest


def build_dex_with_gatt_registration(
    uuid_str: str = "0000180d-0000-1000-8000-00805f9b34fb",
    class_name: str = "Lcom/test/GattManager;",
) -> bytes:
    """Generate a valid DEX containing Dalvik bytecode that statically registers a GATT service.

    Bytecode sequence:
      const-string v0, <uuid_str>
      invoke-static {v0}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;
      move-result-object v1
      const/4 v2, 0
      new-instance v3, Landroid/bluetooth/BluetoothGattService;
      invoke-direct {v3, v1, v2}, Landroid/bluetooth/BluetoothGattService;-><init>(Ljava/util/UUID;I)V
      invoke-virtual {v4, v3}, Landroid/bluetooth/BluetoothGattServer;->addService(Landroid/bluetooth/BluetoothGattService;)Z
      return-void
    """
    strings = sorted(list(set([
        "(Landroid/bluetooth/BluetoothGattService;)Z",
        "(Ljava/lang/String;)Ljava/util/UUID;",
        "(Ljava/util/UUID;I)V",
        "()V",
        "<init>",
        "I",
        "Landroid/bluetooth/BluetoothGattServer;",
        "Landroid/bluetooth/BluetoothGattService;",
        class_name,
        "Ljava/lang/Object;",
        "Ljava/lang/String;",
        "Ljava/util/UUID;",
        "V",
        "ZL",
        "LL",
        "VLI",
        "Z",
        "addService",
        "fromString",
        "registerService",
        uuid_str,
    ])))
    s_map = {s: i for i, s in enumerate(strings)}

    types = sorted(list(set([
        "I",
        "Landroid/bluetooth/BluetoothGattServer;",
        "Landroid/bluetooth/BluetoothGattService;",
        class_name,
        "Ljava/lang/Object;",
        "Ljava/lang/String;",
        "Ljava/util/UUID;",
        "V",
        "Z",
    ])))
    t_map = {t: i for i, t in enumerate(types)}

    str_data = bytearray()
    str_offsets: List[int] = []
    for s in strings:
        str_offsets.append(len(str_data))
        enc = s.encode("utf-8")
        str_data.extend(uleb128(len(s)) + enc + b"\x00")

    header_size = 0x70
    string_ids_off = header_size
    string_ids_size = len(strings)
    string_ids_len = string_ids_size * 4

    type_ids_off = string_ids_off + string_ids_len
    type_ids_size = len(types)
    type_ids_len = type_ids_size * 4

    proto_ids_off = type_ids_off + type_ids_len
    proto_ids_size = 4
    proto_ids_len = proto_ids_size * 12

    method_ids_off = proto_ids_off + proto_ids_len
    method_ids_size = 4
    method_ids_len = method_ids_size * 8

    class_defs_off = method_ids_off + method_ids_len
    class_defs_size = 1
    class_defs_len = class_defs_size * 32

    data_off = class_defs_off + class_defs_len

    str_data_off = data_off
    tl1_bytes = struct.pack("<II", 1, t_map["Landroid/bluetooth/BluetoothGattService;"])
    tl2_bytes = struct.pack("<II", 1, t_map["Ljava/lang/String;"])
    tl3_bytes = struct.pack("<IHH", 2, t_map["Ljava/util/UUID;"], t_map["I"])

    insns = [
        (0x00 << 8) | 0x1A, s_map[uuid_str],
        (0x10 << 8) | 0x71, 3, 0x0000,
        (0x01 << 8) | 0x0C,
        (0x02 << 8) | 0x12,
        (0x03 << 8) | 0x22, t_map["Landroid/bluetooth/BluetoothGattService;"],
        (0x30 << 8) | 0x70, 1, (2 << 8) | (1 << 4) | 3,
        (0x20 << 8) | 0x6E, 0, (3 << 4) | 4,
        0x000E,
    ]
    insns_bytes = b"".join(struct.pack("<H", w) for w in insns)
    code_hdr = struct.pack("<HHHHII", 6, 0, 3, 0, 0, len(insns))
    code_bytes = code_hdr + insns_bytes
    while len(code_bytes) % 4 != 0:
        code_bytes += b"\x00"

    data_section = bytearray(str_data)
    while len(data_section) % 4 != 0:
        data_section += b"\x00"

    tl1_off = data_off + len(data_section)
    data_section.extend(tl1_bytes)

    tl2_off = data_off + len(data_section)
    data_section.extend(tl2_bytes)

    tl3_off = data_off + len(data_section)
    data_section.extend(tl3_bytes)
    while len(data_section) % 4 != 0:
        data_section += b"\x00"

    code_off = data_off + len(data_section)
    data_section.extend(code_bytes)

    cdata = uleb128(0) + uleb128(0) + uleb128(1) + uleb128(0)
    cdata += uleb128(2) + uleb128(9) + uleb128(code_off)
    while len(cdata) % 4 != 0:
        cdata += b"\x00"
    cdata_off = data_off + len(data_section)
    data_section.extend(cdata)

    while len(data_section) % 4 != 0:
        data_section += b"\x00"
    map_off = data_off + len(data_section)

    map_items = [
        (0x0000, 1, 0),
        (0x0001, string_ids_size, string_ids_off),
        (0x0002, type_ids_size, type_ids_off),
        (0x0003, proto_ids_size, proto_ids_off),
        (0x0005, method_ids_size, method_ids_off),
        (0x0006, class_defs_size, class_defs_off),
        (0x1000, 1, map_off),
        (0x1001, 3, tl1_off),
        (0x2000, 1, cdata_off),
        (0x2001, 1, code_off),
        (0x2002, string_ids_size, str_data_off),
    ]
    map_bytes = struct.pack("<I", len(map_items)) + b"".join(
        struct.pack("<HHII", it[0], 0, it[1], it[2]) for it in map_items
    )
    data_section.extend(map_bytes)

    string_ids_bytes = b"".join(
        struct.pack("<I", str_data_off + off) for off in str_offsets
    )
    type_ids_bytes = b"".join(
        struct.pack("<I", s_map[t]) for t in types
    )
    proto_ids_bytes = (
        struct.pack("<III", s_map["V"], t_map["V"], 0) +
        struct.pack("<III", s_map["ZL"], t_map["Z"], tl1_off) +
        struct.pack("<III", s_map["LL"], t_map["Ljava/util/UUID;"], tl2_off) +
        struct.pack("<III", s_map["VLI"], t_map["V"], tl3_off)
    )
    method_ids_bytes = (
        struct.pack("<HHI", t_map["Landroid/bluetooth/BluetoothGattServer;"], 1, s_map["addService"]) +
        struct.pack("<HHI", t_map["Landroid/bluetooth/BluetoothGattService;"], 3, s_map["<init>"]) +
        struct.pack("<HHI", t_map[class_name], 0, s_map["registerService"]) +
        struct.pack("<HHI", t_map["Ljava/util/UUID;"], 2, s_map["fromString"])
    )
    class_defs_bytes = struct.pack(
        "<IIIIIIII",
        t_map[class_name],
        1,
        t_map["Ljava/lang/Object;"],
        0,
        0xFFFFFFFF,
        0,
        cdata_off,
        0,
    )

    body = string_ids_bytes + type_ids_bytes + proto_ids_bytes + method_ids_bytes + class_defs_bytes + bytes(data_section)
    total_file_size = header_size + len(body)
    data_size = len(data_section)

    hdr_part1 = b"dex\n035\x00"
    hdr_part2 = struct.pack(
        "<IIIIIIIIIIIIII",
        total_file_size,
        header_size,
        0x12345678,
        0, 0,
        map_off,
        string_ids_size, string_ids_off,
        type_ids_size, type_ids_off,
        proto_ids_size, proto_ids_off,
        0, 0,
    )
    hdr_part3 = struct.pack(
        "<IIII",
        method_ids_size, method_ids_off,
        class_defs_size, class_defs_off,
    )
    hdr_part4 = struct.pack("<II", data_size, data_off)

    rest = hdr_part2 + hdr_part3 + hdr_part4 + body
    sha1_sig = hashlib.sha1(rest).digest()
    adler = zlib.adler32(sha1_sig + rest) & 0xFFFFFFFF

    return hdr_part1 + struct.pack("<I", adler) + sha1_sig + rest


def build_dex_with_service_without_add_service(
    uuid_str: str = "0000180d-0000-1000-8000-00805f9b34fb",
    class_name: str = "Lcom/test/UnusedServiceManager;",
) -> bytes:
    """Generate a valid DEX where BluetoothGattService is constructed locally with a literal UUID, but addService() is never called."""
    strings = sorted(list(set([
        "(Landroid/bluetooth/BluetoothGattService;)Z",
        "(Ljava/lang/String;)Ljava/util/UUID;",
        "(Ljava/util/UUID;I)V",
        "()V",
        "<init>",
        "I",
        "Landroid/bluetooth/BluetoothGattServer;",
        "Landroid/bluetooth/BluetoothGattService;",
        class_name,
        "Ljava/lang/Object;",
        "Ljava/lang/String;",
        "Ljava/util/UUID;",
        "V",
        "ZL",
        "LL",
        "VLI",
        "Z",
        "addService",
        "fromString",
        "registerService",
        uuid_str,
    ])))
    s_map = {s: i for i, s in enumerate(strings)}

    types = sorted(list(set([
        "I",
        "Landroid/bluetooth/BluetoothGattServer;",
        "Landroid/bluetooth/BluetoothGattService;",
        class_name,
        "Ljava/lang/Object;",
        "Ljava/lang/String;",
        "Ljava/util/UUID;",
        "V",
        "Z",
    ])))
    t_map = {t: i for i, t in enumerate(types)}

    str_data = bytearray()
    str_offsets: List[int] = []
    for s in strings:
        str_offsets.append(len(str_data))
        enc = s.encode("utf-8")
        str_data.extend(uleb128(len(s)) + enc + b"\x00")

    header_size = 0x70
    string_ids_off = header_size
    string_ids_size = len(strings)
    string_ids_len = string_ids_size * 4

    type_ids_off = string_ids_off + string_ids_len
    type_ids_size = len(types)
    type_ids_len = type_ids_size * 4

    proto_ids_off = type_ids_off + type_ids_len
    proto_ids_size = 4
    proto_ids_len = proto_ids_size * 12

    method_ids_off = proto_ids_off + proto_ids_len
    method_ids_size = 4
    method_ids_len = method_ids_size * 8

    class_defs_off = method_ids_off + method_ids_len
    class_defs_size = 1
    class_defs_len = class_defs_size * 32

    data_off = class_defs_off + class_defs_len

    str_data_off = data_off
    tl1_bytes = struct.pack("<II", 1, t_map["Landroid/bluetooth/BluetoothGattService;"])
    tl2_bytes = struct.pack("<II", 1, t_map["Ljava/lang/String;"])
    tl3_bytes = struct.pack("<IHH", 2, t_map["Ljava/util/UUID;"], t_map["I"])

    # Notice: BluetoothGattService constructed locally, but addService is never invoked
    insns = [
        (0x00 << 8) | 0x1A, s_map[uuid_str],
        (0x10 << 8) | 0x71, 3, 0x0000,
        (0x01 << 8) | 0x0C,
        (0x02 << 8) | 0x12,
        (0x03 << 8) | 0x22, t_map["Landroid/bluetooth/BluetoothGattService;"],
        (0x30 << 8) | 0x70, 1, (2 << 8) | (1 << 4) | 3,
        0x000E,
    ]
    insns_bytes = b"".join(struct.pack("<H", w) for w in insns)
    code_hdr = struct.pack("<HHHHII", 6, 0, 3, 0, 0, len(insns))
    code_bytes = code_hdr + insns_bytes
    while len(code_bytes) % 4 != 0:
        code_bytes += b"\x00"

    data_section = bytearray(str_data)
    while len(data_section) % 4 != 0:
        data_section += b"\x00"

    tl1_off = data_off + len(data_section)
    data_section.extend(tl1_bytes)

    tl2_off = data_off + len(data_section)
    data_section.extend(tl2_bytes)

    tl3_off = data_off + len(data_section)
    data_section.extend(tl3_bytes)
    while len(data_section) % 4 != 0:
        data_section += b"\x00"

    code_off = data_off + len(data_section)
    data_section.extend(code_bytes)

    cdata = uleb128(0) + uleb128(0) + uleb128(1) + uleb128(0)
    cdata += uleb128(2) + uleb128(9) + uleb128(code_off)
    while len(cdata) % 4 != 0:
        cdata += b"\x00"
    cdata_off = data_off + len(data_section)
    data_section.extend(cdata)

    while len(data_section) % 4 != 0:
        data_section += b"\x00"
    map_off = data_off + len(data_section)

    map_items = [
        (0x0000, 1, 0),
        (0x0001, string_ids_size, string_ids_off),
        (0x0002, type_ids_size, type_ids_off),
        (0x0003, proto_ids_size, proto_ids_off),
        (0x0005, method_ids_size, method_ids_off),
        (0x0006, class_defs_size, class_defs_off),
        (0x1000, 1, map_off),
        (0x1001, 3, tl1_off),
        (0x2000, 1, cdata_off),
        (0x2001, 1, code_off),
        (0x2002, string_ids_size, str_data_off),
    ]
    map_bytes = struct.pack("<I", len(map_items)) + b"".join(
        struct.pack("<HHII", it[0], 0, it[1], it[2]) for it in map_items
    )
    data_section.extend(map_bytes)

    string_ids_bytes = b"".join(
        struct.pack("<I", str_data_off + off) for off in str_offsets
    )
    type_ids_bytes = b"".join(
        struct.pack("<I", s_map[t]) for t in types
    )
    proto_ids_bytes = (
        struct.pack("<III", s_map["V"], t_map["V"], 0) +
        struct.pack("<III", s_map["ZL"], t_map["Z"], tl1_off) +
        struct.pack("<III", s_map["LL"], t_map["Ljava/util/UUID;"], tl2_off) +
        struct.pack("<III", s_map["VLI"], t_map["V"], tl3_off)
    )
    method_ids_bytes = (
        struct.pack("<HHI", t_map["Landroid/bluetooth/BluetoothGattServer;"], 1, s_map["addService"]) +
        struct.pack("<HHI", t_map["Landroid/bluetooth/BluetoothGattService;"], 3, s_map["<init>"]) +
        struct.pack("<HHI", t_map[class_name], 0, s_map["registerService"]) +
        struct.pack("<HHI", t_map["Ljava/util/UUID;"], 2, s_map["fromString"])
    )
    class_defs_bytes = struct.pack(
        "<IIIIIIII",
        t_map[class_name],
        1,
        t_map["Ljava/lang/Object;"],
        0,
        0xFFFFFFFF,
        0,
        cdata_off,
        0,
    )

    body = string_ids_bytes + type_ids_bytes + proto_ids_bytes + method_ids_bytes + class_defs_bytes + bytes(data_section)
    total_file_size = header_size + len(body)
    data_size = len(data_section)

    hdr_part1 = b"dex\n035\x00"
    hdr_part2 = struct.pack(
        "<IIIIIIIIIIIIII",
        total_file_size,
        header_size,
        0x12345678,
        0, 0,
        map_off,
        string_ids_size, string_ids_off,
        type_ids_size, type_ids_off,
        proto_ids_size, proto_ids_off,
        0, 0,
    )
    hdr_part3 = struct.pack(
        "<IIII",
        method_ids_size, method_ids_off,
        class_defs_size, class_defs_off,
    )
    hdr_part4 = struct.pack("<II", data_size, data_off)

    rest = hdr_part2 + hdr_part3 + hdr_part4 + body
    sha1_sig = hashlib.sha1(rest).digest()
    adler = zlib.adler32(sha1_sig + rest) & 0xFFFFFFFF

    return hdr_part1 + struct.pack("<I", adler) + sha1_sig + rest


def build_dex_with_unresolved_add_service(
    class_name: str = "Lcom/test/UnresolvedServerManager;",
) -> bytes:
    """Generate a valid DEX containing an addService() call where the service object originates from an uninitialized/parameter register."""
    strings = sorted(list(set([
        "(Landroid/bluetooth/BluetoothGattService;)Z",
        "()V",
        "<init>",
        "Landroid/bluetooth/BluetoothGattServer;",
        "Landroid/bluetooth/BluetoothGattService;",
        class_name,
        "Ljava/lang/Object;",
        "V",
        "Z",
        "ZL",
        "addService",
        "registerExternal",
    ])))
    s_map = {s: i for i, s in enumerate(strings)}

    types = sorted(list(set([
        "Landroid/bluetooth/BluetoothGattServer;",
        "Landroid/bluetooth/BluetoothGattService;",
        class_name,
        "Ljava/lang/Object;",
        "V",
        "Z",
    ])))
    t_map = {t: i for i, t in enumerate(types)}

    str_data = bytearray()
    str_offsets: List[int] = []
    for s in strings:
        str_offsets.append(len(str_data))
        enc = s.encode("utf-8")
        str_data.extend(uleb128(len(s)) + enc + b"\x00")

    header_size = 0x70
    string_ids_off = header_size
    string_ids_size = len(strings)
    string_ids_len = string_ids_size * 4

    type_ids_off = string_ids_off + string_ids_len
    type_ids_size = len(types)
    type_ids_len = type_ids_size * 4

    proto_ids_off = type_ids_off + type_ids_len
    proto_ids_size = 2
    proto_ids_len = proto_ids_size * 12

    method_ids_off = proto_ids_off + proto_ids_len
    method_ids_size = 2
    method_ids_len = method_ids_size * 8

    class_defs_off = method_ids_off + method_ids_len
    class_defs_size = 1
    class_defs_len = class_defs_size * 32

    data_off = class_defs_off + class_defs_len
    str_data_off = data_off

    tl1_bytes = struct.pack("<II", 1, t_map["Landroid/bluetooth/BluetoothGattService;"])

    # invoke-virtual {v0, v1}, BluetoothGattServer.addService; service in v1 is not initialized locally!
    insns = [
        (0x20 << 8) | 0x6E, 0, (1 << 4) | 0,
        0x000E,
    ]
    insns_bytes = b"".join(struct.pack("<H", w) for w in insns)
    code_hdr = struct.pack("<HHHHII", 4, 0, 2, 0, 0, len(insns))
    code_bytes = code_hdr + insns_bytes
    while len(code_bytes) % 4 != 0:
        code_bytes += b"\x00"

    data_section = bytearray(str_data)
    while len(data_section) % 4 != 0:
        data_section += b"\x00"

    tl1_off = data_off + len(data_section)
    data_section.extend(tl1_bytes)
    while len(data_section) % 4 != 0:
        data_section += b"\x00"

    code_off = data_off + len(data_section)
    data_section.extend(code_bytes)

    cdata = uleb128(0) + uleb128(0) + uleb128(1) + uleb128(0)
    cdata += uleb128(1) + uleb128(9) + uleb128(code_off)
    while len(cdata) % 4 != 0:
        cdata += b"\x00"
    cdata_off = data_off + len(data_section)
    data_section.extend(cdata)

    while len(data_section) % 4 != 0:
        data_section += b"\x00"
    map_off = data_off + len(data_section)

    map_items = [
        (0x0000, 1, 0),
        (0x0001, string_ids_size, string_ids_off),
        (0x0002, type_ids_size, type_ids_off),
        (0x0003, proto_ids_size, proto_ids_off),
        (0x0005, method_ids_size, method_ids_off),
        (0x0006, class_defs_size, class_defs_off),
        (0x1000, 1, map_off),
        (0x1001, 1, tl1_off),
        (0x2000, 1, cdata_off),
        (0x2001, 1, code_off),
        (0x2002, string_ids_size, str_data_off),
    ]
    map_bytes = struct.pack("<I", len(map_items)) + b"".join(
        struct.pack("<HHII", it[0], 0, it[1], it[2]) for it in map_items
    )
    data_section.extend(map_bytes)

    string_ids_bytes = b"".join(
        struct.pack("<I", str_data_off + off) for off in str_offsets
    )
    type_ids_bytes = b"".join(
        struct.pack("<I", s_map[t]) for t in types
    )
    proto_ids_bytes = (
        struct.pack("<III", s_map["V"], t_map["V"], 0) +
        struct.pack("<III", s_map["ZL"], t_map["Z"], tl1_off)
    )
    method_ids_bytes = (
        struct.pack("<HHI", t_map["Landroid/bluetooth/BluetoothGattServer;"], 1, s_map["addService"]) +
        struct.pack("<HHI", t_map[class_name], 0, s_map["registerExternal"])
    )
    class_defs_bytes = struct.pack(
        "<IIIIIIII",
        t_map[class_name],
        1,
        t_map["Ljava/lang/Object;"],
        0,
        0xFFFFFFFF,
        0,
        cdata_off,
        0,
    )

    body = string_ids_bytes + type_ids_bytes + proto_ids_bytes + method_ids_bytes + class_defs_bytes + bytes(data_section)
    total_file_size = header_size + len(body)
    data_size = len(data_section)

    hdr_part1 = b"dex\n035\x00"
    hdr_part2 = struct.pack(
        "<IIIIIIIIIIIIII",
        total_file_size,
        header_size,
        0x12345678,
        0, 0,
        map_off,
        string_ids_size, string_ids_off,
        type_ids_size, type_ids_off,
        proto_ids_size, proto_ids_off,
        0, 0,
    )
    hdr_part3 = struct.pack("<IIII", method_ids_size, method_ids_off, class_defs_size, class_defs_off)
    hdr_part4 = struct.pack("<II", data_size, data_off)

    rest = hdr_part2 + hdr_part3 + hdr_part4 + body
    sha1_sig = hashlib.sha1(rest).digest()
    adler = zlib.adler32(sha1_sig + rest) & 0xFFFFFFFF

    return hdr_part1 + struct.pack("<I", adler) + sha1_sig + rest


def build_dex_with_client_only_ble(
    uuid_str: str = "0000180d-0000-1000-8000-00805f9b34fb",
    class_name: str = "Lcom/test/ClientBleManager;",
) -> bytes:
    """Generate a valid DEX containing BLE Client API references and a candidate UUID, but NO server registration APIs."""
    strings = sorted(list(set([
        "()V",
        "()Z",
        "<init>",
        "Landroid/bluetooth/BluetoothGatt;",
        class_name,
        "Ljava/lang/Object;",
        "Ljava/lang/String;",
        "V",
        "Z",
        "discoverServices",
        "runClient",
        uuid_str,
    ])))
    s_map = {s: i for i, s in enumerate(strings)}

    types = sorted(list(set([
        "Landroid/bluetooth/BluetoothGatt;",
        class_name,
        "Ljava/lang/Object;",
        "Ljava/lang/String;",
        "V",
        "Z",
    ])))
    t_map = {t: i for i, t in enumerate(types)}

    str_data = bytearray()
    str_offsets: List[int] = []
    for s in strings:
        str_offsets.append(len(str_data))
        enc = s.encode("utf-8")
        str_data.extend(uleb128(len(s)) + enc + b"\x00")

    header_size = 0x70
    string_ids_off = header_size
    string_ids_size = len(strings)
    string_ids_len = string_ids_size * 4

    type_ids_off = string_ids_off + string_ids_len
    type_ids_size = len(types)
    type_ids_len = type_ids_size * 4

    proto_ids_off = type_ids_off + type_ids_len
    proto_ids_size = 2
    proto_ids_len = proto_ids_size * 12

    method_ids_off = proto_ids_off + proto_ids_len
    method_ids_size = 2
    method_ids_len = method_ids_size * 8

    class_defs_off = method_ids_off + method_ids_len
    class_defs_size = 1
    class_defs_len = class_defs_size * 32

    data_off = class_defs_off + class_defs_len
    str_data_off = data_off

    insns = [
        (0x00 << 8) | 0x1A, s_map[uuid_str],
        (0x10 << 8) | 0x6E, 0, 1,
        0x000E,
    ]
    insns_bytes = b"".join(struct.pack("<H", w) for w in insns)
    code_hdr = struct.pack("<HHHHII", 4, 0, 1, 0, 0, len(insns))
    code_bytes = code_hdr + insns_bytes
    while len(code_bytes) % 4 != 0:
        code_bytes += b"\x00"

    data_section = bytearray(str_data)
    while len(data_section) % 4 != 0:
        data_section += b"\x00"

    code_off = data_off + len(data_section)
    data_section.extend(code_bytes)

    cdata = uleb128(0) + uleb128(0) + uleb128(1) + uleb128(0)
    cdata += uleb128(1) + uleb128(9) + uleb128(code_off)
    while len(cdata) % 4 != 0:
        cdata += b"\x00"
    cdata_off = data_off + len(data_section)
    data_section.extend(cdata)

    while len(data_section) % 4 != 0:
        data_section += b"\x00"
    map_off = data_off + len(data_section)

    map_items = [
        (0x0000, 1, 0),
        (0x0001, string_ids_size, string_ids_off),
        (0x0002, type_ids_size, type_ids_off),
        (0x0003, proto_ids_size, proto_ids_off),
        (0x0005, method_ids_size, method_ids_off),
        (0x0006, class_defs_size, class_defs_off),
        (0x1000, 1, map_off),
        (0x2000, 1, cdata_off),
        (0x2001, 1, code_off),
        (0x2002, string_ids_size, str_data_off),
    ]
    map_bytes = struct.pack("<I", len(map_items)) + b"".join(
        struct.pack("<HHII", it[0], 0, it[1], it[2]) for it in map_items
    )
    data_section.extend(map_bytes)

    string_ids_bytes = b"".join(
        struct.pack("<I", str_data_off + off) for off in str_offsets
    )
    type_ids_bytes = b"".join(
        struct.pack("<I", s_map[t]) for t in types
    )
    proto_ids_bytes = (
        struct.pack("<III", s_map["V"], t_map["V"], 0) +
        struct.pack("<III", s_map["Z"], t_map["Z"], 0)
    )
    method_ids_bytes = (
        struct.pack("<HHI", t_map["Landroid/bluetooth/BluetoothGatt;"], 1, s_map["discoverServices"]) +
        struct.pack("<HHI", t_map[class_name], 0, s_map["runClient"])
    )
    class_defs_bytes = struct.pack(
        "<IIIIIIII",
        t_map[class_name],
        1,
        t_map["Ljava/lang/Object;"],
        0,
        0xFFFFFFFF,
        0,
        cdata_off,
        0,
    )

    body = string_ids_bytes + type_ids_bytes + proto_ids_bytes + method_ids_bytes + class_defs_bytes + bytes(data_section)
    total_file_size = header_size + len(body)
    data_size = len(data_section)

    hdr_part1 = b"dex\n035\x00"
    hdr_part2 = struct.pack(
        "<IIIIIIIIIIIIII",
        total_file_size,
        header_size,
        0x12345678,
        0, 0,
        map_off,
        string_ids_size, string_ids_off,
        type_ids_size, type_ids_off,
        proto_ids_size, proto_ids_off,
        0, 0,
    )
    hdr_part3 = struct.pack("<IIII", method_ids_size, method_ids_off, class_defs_size, class_defs_off)
    hdr_part4 = struct.pack("<II", data_size, data_off)

    rest = hdr_part2 + hdr_part3 + hdr_part4 + body
    sha1_sig = hashlib.sha1(rest).digest()
    adler = zlib.adler32(sha1_sig + rest) & 0xFFFFFFFF

    return hdr_part1 + struct.pack("<I", adler) + sha1_sig + rest




def create_apk_archive(
    target_path: Path,
    manifest_bytes: Optional[bytes] = None,
    dex_files: Optional[List[Tuple[str, bytes]]] = None,
) -> Path:
    """Create a test APK archive at target_path."""
    if manifest_bytes is None:
        manifest_bytes = build_minimal_axml()
    if dex_files is None:
        dex_files = [("classes.dex", build_minimal_dex())]

    target_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if manifest_bytes:
            zf.writestr("AndroidManifest.xml", manifest_bytes)
        for name, data in dex_files:
            zf.writestr(name, data)

    return target_path
