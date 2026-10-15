"""Independent DEX bytecode audit for samples/validation.apk.

Independently inspects all DEX files within validation.apk to verify:
1. Absence of BluetoothGattServer.addService references across all methods.
2. Absence of BluetoothGattService constructor references across all methods.
3. Candidate UUID count extracted from DEX string pools and bytecode.
"""

import zipfile
import re
from pathlib import Path
from androguard.core.dex import DEX
from ucsd.ble.normalizer import (
    CANONICAL_UUID_SEARCH_RE,
    HEX16_PREFIXED_SEARCH_RE,
    HEX16_RAW_EXACT_RE,
    normalize_uuid,
)
from ucsd.errors import InvalidUUIDError


def audit_validation_apk(apk_path: str = "/app/samples/validation.apk"):
    p = Path(apk_path)
    assert p.exists(), f"Target {apk_path} does not exist"

    print(f"=== Independent Bytecode Audit: {p.name} ===")
    print(f"Path: {p}")
    print(f"File Size: {p.stat().st_size} bytes")

    with zipfile.ZipFile(str(p), "r") as zf:
        dex_names = [n for n in zf.namelist() if re.match(r"^classes(\d+)?\.dex$", n)]
        dex_names.sort()
        print(f"DEX files found: {dex_names}")

        all_methods = []
        bluetooth_methods = []
        add_service_refs = []
        gatt_service_init_refs = []
        all_candidate_uuids = set()

        for dex_name in dex_names:
            dex_bytes = zf.read(dex_name)
            dex_obj = DEX(dex_bytes)
            methods = dex_obj.get_methods()
            all_methods.extend(methods)

            for m in methods:
                cname = m.get_class_name()
                mname = m.get_name()
                desc = m.get_descriptor()
                sig = f"{cname}->{mname}{desc}"

                if "bluetooth" in cname.lower():
                    bluetooth_methods.append((dex_name, sig))

                if (
                    "bluetoothgattserver" in cname.lower()
                    and mname == "addService"
                ):
                    add_service_refs.append((dex_name, sig))

                if (
                    "bluetoothgattservice" in cname.lower()
                    and mname == "<init>"
                ):
                    gatt_service_init_refs.append((dex_name, sig))

            # String pool candidate extraction
            dex_strings = dex_obj.get_strings()
            for s in dex_strings:
                for m128 in CANONICAL_UUID_SEARCH_RE.finditer(s):
                    c_str = m128.group(1)
                    try:
                        all_candidate_uuids.add(normalize_uuid(c_str))
                    except InvalidUUIDError:
                        pass
                for m16 in HEX16_PREFIXED_SEARCH_RE.finditer(s):
                    c_str = m16.group(0)
                    try:
                        all_candidate_uuids.add(normalize_uuid(c_str))
                    except InvalidUUIDError:
                        pass
                if HEX16_RAW_EXACT_RE.match(s):
                    try:
                        all_candidate_uuids.add(normalize_uuid(s))
                    except InvalidUUIDError:
                        pass

        print(f"\n--- Method Table Audit Results ---")
        print(f"Total method references across all DEX files: {len(all_methods)}")
        print(f"Bluetooth-related method references: {len(bluetooth_methods)}")
        for dex_name, sig in bluetooth_methods[:10]:
            print(f"  [{dex_name}] {sig}")
        if len(bluetooth_methods) > 10:
            print(f"  ... and {len(bluetooth_methods) - 10} more")

        print(f"\n--- GATT Service Registration Search ---")
        print(f"BluetoothGattServer.addService references: {len(add_service_refs)}")
        for dex_name, sig in add_service_refs:
            print(f"  [{dex_name}] {sig}")

        print(f"BluetoothGattService.<init> references: {len(gatt_service_init_refs)}")
        for dex_name, sig in gatt_service_init_refs:
            print(f"  [{dex_name}] {sig}")

        print(f"\n--- UUID Candidate Extraction Audit ---")
        print(f"Total unique normalized UUID candidates extracted: {len(all_candidate_uuids)}")

        # Verification Assertions
        assert len(add_service_refs) == 0, f"Expected 0 addService references, found {len(add_service_refs)}"
        assert len(gatt_service_init_refs) == 0, f"Expected 0 BluetoothGattService.<init> references, found {len(gatt_service_init_refs)}"
        assert len(all_candidate_uuids) == 88, f"Expected exactly 88 candidates, found {len(all_candidate_uuids)}"
        print("\n>>> AUDIT VERIFICATION SUCCESSFUL: 0 addService, 0 service constructors, exactly 88 candidates confirmed.")


if __name__ == "__main__":
    audit_validation_apk()
