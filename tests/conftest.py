"""Pytest fixtures for UCSD static analysis test suite."""

import pytest
from pathlib import Path
from tests.generate_fixtures import (
    build_minimal_axml,
    build_minimal_dex,
    create_apk_archive,
)


@pytest.fixture
def valid_single_dex_apk(tmp_path: Path) -> Path:
    """Fixture producing a minimal valid single-DEX Android APK."""
    apk_path = tmp_path / "valid_single_dex.apk"
    return create_apk_archive(
        target_path=apk_path,
        manifest_bytes=build_minimal_axml(
            package_name="org.example.singledex",
            version_code=100,
            version_name="1.0.0",
            permissions=["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"],
            activities=["org.example.singledex.MainActivity"],
            min_sdk=21,
            target_sdk=33,
        ),
        dex_files=[("classes.dex", build_minimal_dex(b"classes1"))],
    )


@pytest.fixture
def valid_multidex_apk(tmp_path: Path) -> Path:
    """Fixture producing a valid Multi-DEX Android APK (classes.dex and classes2.dex)."""
    apk_path = tmp_path / "valid_multidex.apk"
    return create_apk_archive(
        target_path=apk_path,
        manifest_bytes=build_minimal_axml(
            package_name="org.example.multidex",
            version_code=200,
            version_name="2.0.0",
            permissions=["android.permission.CAMERA"],
            activities=["org.example.multidex.HomeActivity"],
            min_sdk=24,
            target_sdk=34,
        ),
        dex_files=[
            ("classes.dex", build_minimal_dex(b"main_dex")),
            ("classes2.dex", build_minimal_dex(b"secondary_dex")),
        ],
    )


@pytest.fixture
def corrupt_zip_apk(tmp_path: Path) -> Path:
    """Fixture producing a corrupt ZIP file (truncated ZIP data)."""
    apk_path = tmp_path / "corrupt_archive.apk"
    # Write PK header followed by random corrupted bytes
    with open(apk_path, "wb") as f:
        f.write(b"PK\x03\x04" + b"\xFF" * 100)
    return apk_path


@pytest.fixture
def renamed_text_apk(tmp_path: Path) -> Path:
    """Fixture producing a plain text file with a .apk extension."""
    apk_path = tmp_path / "renamed_text.apk"
    with open(apk_path, "w", encoding="utf-8") as f:
        f.write("This is a plain ASCII text file renamed to .apk")
    return apk_path


@pytest.fixture
def zip_without_dex_apk(tmp_path: Path) -> Path:
    """Fixture producing a valid ZIP archive containing AndroidManifest.xml but NO DEX files."""
    apk_path = tmp_path / "no_dex.apk"
    return create_apk_archive(
        target_path=apk_path,
        manifest_bytes=build_minimal_axml(),
        dex_files=[],
    )


@pytest.fixture
def zip_without_manifest_apk(tmp_path: Path) -> Path:
    """Fixture producing a valid ZIP archive containing DEX files but NO AndroidManifest.xml."""
    apk_path = tmp_path / "no_manifest.apk"
    return create_apk_archive(
        target_path=apk_path,
        manifest_bytes=b"",  # Empty manifest will be skipped
        dex_files=[("classes.dex", build_minimal_dex())],
    )


@pytest.fixture
def empty_apk(tmp_path: Path) -> Path:
    """Fixture producing an empty (0-byte) file."""
    apk_path = tmp_path / "empty.apk"
    apk_path.touch()
    return apk_path


@pytest.fixture
def non_existent_apk(tmp_path: Path) -> Path:
    """Fixture producing a path that does not exist."""
    return tmp_path / "does_not_exist.apk"


@pytest.fixture
def ble_single_dex_apk(tmp_path: Path) -> Path:
    """Fixture producing a valid APK with BLE permissions and UUID candidates in a single DEX."""
    apk_path = tmp_path / "ble_single_dex.apk"
    from tests.generate_fixtures import build_dex_with_strings
    return create_apk_archive(
        target_path=apk_path,
        manifest_bytes=build_minimal_axml(
            package_name="org.example.bleapp",
            version_code=10,
            version_name="1.0",
            permissions=[
                "android.permission.BLUETOOTH",
                "android.permission.BLUETOOTH_SCAN",
                "android.permission.BLUETOOTH_CONNECT",
            ],
            activities=["org.example.bleapp.MainActivity"],
        ),
        dex_files=[
            (
                "classes.dex",
                build_dex_with_strings([
                    "0000180d-0000-1000-8000-00805f9b34fb",
                    "0x180F",
                    "12345678-1234-5678-1234-567812345678",
                ]),
            )
        ],
    )


@pytest.fixture
def ble_multidex_apk(tmp_path: Path) -> Path:
    """Fixture producing a valid Multi-DEX APK with BLE UUIDs across classes.dex and classes2.dex."""
    apk_path = tmp_path / "ble_multidex.apk"
    from tests.generate_fixtures import build_dex_with_strings
    return create_apk_archive(
        target_path=apk_path,
        manifest_bytes=build_minimal_axml(
            package_name="org.example.blemex",
            version_code=20,
            version_name="2.0",
            permissions=[
                "android.permission.BLUETOOTH",
                "android.permission.BLUETOOTH_ADVERTISE",
            ],
            activities=["org.example.blemex.MainActivity"],
        ),
        dex_files=[
            (
                "classes.dex",
                build_dex_with_strings([
                    "00001800-0000-1000-8000-00805f9b34fb",
                    "0x2A37",
                ]),
            ),
            (
                "classes2.dex",
                build_dex_with_strings([
                    "00001800-0000-1000-8000-00805f9b34fb",  # Shared UUID to test deduplication across DEX
                    "abcdef01-2345-6789-abcd-ef0123456789",
                ]),
            ),
        ],
    )


@pytest.fixture
def no_ble_apk(tmp_path: Path) -> Path:
    """Fixture producing a valid APK with NO Bluetooth permissions and NO candidate UUIDs."""
    apk_path = tmp_path / "no_ble.apk"
    from tests.generate_fixtures import build_dex_with_strings
    return create_apk_archive(
        target_path=apk_path,
        manifest_bytes=build_minimal_axml(
            package_name="org.example.noble",
            version_code=1,
            version_name="0.1",
            permissions=["android.permission.INTERNET", "android.permission.CAMERA"],
            activities=["org.example.noble.MainActivity"],
        ),
        dex_files=[
            (
                "classes.dex",
                build_dex_with_strings([
                    "hello_world",
                    "main_activity",
                    "some_regular_string",
                ]),
            )
        ],
    )


@pytest.fixture
def conflict_apk_a(tmp_path: Path) -> Path:
    """Fixture producing APK A with verified static GATT registration for end-to-end conflict testing."""
    from tests.generate_fixtures import build_dex_with_gatt_registration
    apk_path = tmp_path / "conflict_app_a.apk"
    return create_apk_archive(
        target_path=apk_path,
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


@pytest.fixture
def conflict_apk_b(tmp_path: Path) -> Path:
    """Fixture producing APK B with verified static GATT registration for end-to-end conflict testing."""
    from tests.generate_fixtures import build_dex_with_gatt_registration
    apk_path = tmp_path / "conflict_app_b.apk"
    return create_apk_archive(
        target_path=apk_path,
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


@pytest.fixture
def negative_candidate_apk(tmp_path: Path) -> Path:
    """Fixture producing an APK containing the same UUID string but NO GATT registration bytecode."""
    from tests.generate_fixtures import build_dex_with_strings
    apk_path = tmp_path / "negative_candidate.apk"
    return create_apk_archive(
        target_path=apk_path,
        manifest_bytes=build_minimal_axml(
            package_name="org.example.candidate_only",
            version_code=300,
            version_name="3.0.0",
            permissions=["android.permission.BLUETOOTH"],
            activities=["org.example.candidate_only.MainActivity"],
        ),
        dex_files=[
            (
                "classes.dex",
                build_dex_with_strings([
                    "0000180d-0000-1000-8000-00805f9b34fb",
                ]),
            ),
        ],
    )


@pytest.fixture
def client_only_ble_apk(tmp_path: Path) -> Path:
    """Fixture producing an APK referencing BLE Client APIs and candidate UUID, with NO GATT Server registration."""
    from tests.generate_fixtures import build_dex_with_client_only_ble
    apk_path = tmp_path / "client_only_ble.apk"
    return create_apk_archive(
        target_path=apk_path,
        manifest_bytes=build_minimal_axml(
            package_name="org.example.client_only",
            version_code=400,
            version_name="4.0.0",
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


@pytest.fixture
def ble_perm_no_service_api_apk(tmp_path: Path) -> Path:
    """Fixture producing an APK declaring BLE permissions in manifest, but referencing NO Bluetooth service APIs in DEX."""
    from tests.generate_fixtures import build_dex_with_strings
    apk_path = tmp_path / "ble_perm_no_services.apk"
    return create_apk_archive(
        target_path=apk_path,
        manifest_bytes=build_minimal_axml(
            package_name="org.example.ble_perm_no_services",
            version_code=500,
            version_name="5.0.0",
            permissions=[
                "android.permission.BLUETOOTH",
                "android.permission.BLUETOOTH_SCAN",
                "android.permission.BLUETOOTH_CONNECT",
                "android.permission.BLUETOOTH_ADVERTISE",
            ],
            activities=["org.example.ble_perm_no_services.MainActivity"],
        ),
        dex_files=[
            (
                "classes.dex",
                build_dex_with_strings([
                    "0000180a-0000-1000-8000-00805f9b34fb",
                    "normal_string_constant",
                ]),
            ),
        ],
    )


@pytest.fixture
def unresolved_registration_apk(tmp_path: Path) -> Path:
    """Fixture producing an APK with BluetoothGattServer.addService() where the service object is unresolved (cross-method)."""
    from tests.generate_fixtures import build_dex_with_unresolved_add_service
    apk_path = tmp_path / "unresolved_registration.apk"
    return create_apk_archive(
        target_path=apk_path,
        manifest_bytes=build_minimal_axml(
            package_name="org.example.unresolved_reg",
            version_code=600,
            version_name="6.0.0",
            permissions=["android.permission.BLUETOOTH", "android.permission.BLUETOOTH_CONNECT"],
            activities=["org.example.unresolved_reg.MainActivity"],
        ),
        dex_files=[
            (
                "classes.dex",
                build_dex_with_unresolved_add_service(
                    class_name="Lorg/example/unresolved_reg/ServerHelper;",
                ),
            ),
        ],
    )


@pytest.fixture
def service_constructed_without_add_service_apk(tmp_path: Path) -> Path:
    """Fixture producing an APK where BluetoothGattService is constructed locally with literal UUID, but addService() is never called."""
    from tests.generate_fixtures import build_dex_with_service_without_add_service
    apk_path = tmp_path / "service_constructed_no_add.apk"
    return create_apk_archive(
        target_path=apk_path,
        manifest_bytes=build_minimal_axml(
            package_name="org.example.service_no_add",
            version_code=700,
            version_name="7.0.0",
            permissions=["android.permission.BLUETOOTH", "android.permission.BLUETOOTH_CONNECT"],
            activities=["org.example.service_no_add.MainActivity"],
        ),
        dex_files=[
            (
                "classes.dex",
                build_dex_with_service_without_add_service(
                    uuid_str="0000180d-0000-1000-8000-00805f9b34fb",
                    class_name="Lorg/example/service_no_add/Factory;",
                ),
            ),
        ],
    )



