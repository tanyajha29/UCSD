"""Script to generate approved deterministic demo sample APKs in demo/inputs/."""

from pathlib import Path
import sys

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root))

from tests.generate_fixtures import (
    build_dex_with_client_only_ble,
    build_dex_with_gatt_registration,
    build_minimal_axml,
    create_apk_archive,
)

DEMO_INPUTS = repo_root / "demo" / "inputs"
DEMO_INPUTS.mkdir(parents=True, exist_ok=True)

# 1. service_a.apk: GATT Server Positive Registration (Heart Rate UUID)
create_apk_archive(
    target_path=DEMO_INPUTS / "service_a.apk",
    manifest_bytes=build_minimal_axml(
        package_name="org.example.service_a",
        version_code=100,
        version_name="1.0.0",
        permissions=["android.permission.BLUETOOTH", "android.permission.BLUETOOTH_CONNECT"],
        activities=["org.example.service_a.MainActivity"],
    ),
    dex_files=[
        (
            "classes.dex",
            build_dex_with_gatt_registration(
                "0000180d-0000-1000-8000-00805f9b34fb",
                "Lorg/example/service_a/GattService;",
            ),
        ),
    ],
)
print("Created demo/inputs/service_a.apk")

# 2. service_b.apk: Distinct Application with Matching Heart Rate GATT Service
create_apk_archive(
    target_path=DEMO_INPUTS / "service_b.apk",
    manifest_bytes=build_minimal_axml(
        package_name="org.example.service_b",
        version_code=200,
        version_name="2.0.0",
        permissions=["android.permission.BLUETOOTH", "android.permission.BLUETOOTH_CONNECT"],
        activities=["org.example.service_b.MainActivity"],
    ),
    dex_files=[
        (
            "classes.dex",
            build_dex_with_gatt_registration(
                "0000180d-0000-1000-8000-00805f9b34fb",
                "Lorg/example/service_b/GattServer;",
            ),
        ),
    ],
)
print("Created demo/inputs/service_b.apk")

# 3. client_only.apk: Client-Only BLE Application (Candidate UUID Only, No Server)
create_apk_archive(
    target_path=DEMO_INPUTS / "client_only.apk",
    manifest_bytes=build_minimal_axml(
        package_name="org.example.client_only",
        version_code=300,
        version_name="3.0.0",
        permissions=["android.permission.BLUETOOTH", "android.permission.BLUETOOTH_CONNECT"],
        activities=["org.example.client_only.MainActivity"],
    ),
    dex_files=[
        (
            "classes.dex",
            build_dex_with_client_only_ble(
                uuid_str="0000180d-0000-1000-8000-00805f9b34fb",
                class_name="Lorg/example/client_only/BleClient;",
            ),
        ),
    ],
)
print("Created demo/inputs/client_only.apk")
