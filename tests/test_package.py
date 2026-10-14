"""`.pastry` package format: round trips, wrong passwords, tampering, malformed and hostile input."""
import base64
import json
import struct
from datetime import datetime, timedelta, timezone

import pytest

from pastry import package as pk
from pastry.crypto import KdfParams

FAST = KdfParams(time_cost=1, memory_cost=8192, parallelism=1)
PW = "correct horse battery"
NOW = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
ENTRIES = [{
    "name": "Ubuntu AI Server", "url": "https://ai.example.internal", "username": "admin",
    "password": "MARKER-pw-7f3a", "notes": "MARKER-notes-9c21",
    "fields": [{"name": "API Key", "value": "MARKER-api-5e88", "secret": True},
               {"name": "Host", "value": "example.internal", "secret": False}],
}]


def make(entries=ENTRIES, password=PW, allow_copy=True, expires_at=None, name="server-access"):
    return pk.build_package(entries, password, name, allow_copy=allow_copy, expires_at=expires_at,
                            kdf=FAST, now=NOW)


def header_len(data):
    return struct.unpack(">I", data[9:13])[0]


# ----- round trips ------------------------------------------------------------


def test_round_trip_preserves_every_field():
    header, entries = pk.open_package(make(), PW)
    assert header.name == "server-access"
    assert header.access == "offline" and header.allow_copy is True
    assert entries == [{**ENTRIES[0], "fields": ENTRIES[0]["fields"]}]


def test_round_trip_keeps_copy_flag_and_expiry():
    expiry = NOW + timedelta(minutes=15)
    header, _ = pk.open_package(make(allow_copy=False, expires_at=expiry), PW)
    assert header.allow_copy is False
    assert header.expires_at == expiry.isoformat(timespec="seconds")
    assert header.expired(NOW + timedelta(minutes=14)) is False
    assert header.expired(NOW + timedelta(minutes=15)) is True


def test_package_has_magic_and_version():
    data = make()
    assert data.startswith(b"PSTRYPKG\x01")


def test_each_package_uses_fresh_keys_and_salts():
    a, b = make(), make()
    assert a != b
    assert pk.read_header(a)[0].salt != pk.read_header(b)[0].salt


# ----- passwords ---------------------------------------------------------------


def test_wrong_password_is_rejected_without_detail():
    with pytest.raises(pk.PackageError) as info:
        pk.open_package(make(), "not the password at all")
    assert str(info.value) == "The password is wrong, or the package has been modified."
    assert "MARKER" not in str(info.value)


def test_password_length_is_enforced_when_building():
    with pytest.raises(pk.PackageError):
        make(password="short")


# ----- tampering ---------------------------------------------------------------


@pytest.mark.parametrize("where", ["header", "wrapped_dek", "payload", "tail"])
def test_any_byte_change_is_detected(where):
    data = bytearray(make())
    hl = header_len(data)
    index = {
        "header": 13 + hl // 2,              # inside the authenticated header
        "wrapped_dek": 13 + hl + 20,          # inside the wrapped key
        "payload": len(data) - 40,            # inside the encrypted payload
        "tail": len(data) - 1,                # the final authentication tag
    }[where]
    data[index] ^= 0x01
    with pytest.raises(pk.PackageError):
        pk.open_package(bytes(data), PW)


def test_header_expiry_edit_is_detected():
    data = make(expires_at=NOW + timedelta(hours=1))
    text = data.decode("latin-1")
    edited = text.replace("2026-10-14T13:00:00+00:00", "2030-10-14T13:00:00+00:00").encode("latin-1")
    assert edited != data and len(edited) == len(data)
    with pytest.raises(pk.PackageError, match="modified"):
        pk.open_package(edited, PW)


def test_truncation_is_detected():
    data = make()
    with pytest.raises(pk.PackageError):
        pk.open_package(data[:-1], PW)
    with pytest.raises(pk.PackageError, match="truncated"):
        pk.open_package(data[: 20], PW)


def test_appended_bytes_are_detected():
    with pytest.raises(pk.PackageError):
        pk.open_package(make() + b"\x00", PW)


# ----- structure and hostile input --------------------------------------------


def test_rejects_non_package_files():
    with pytest.raises(pk.PackageError, match="not a Pastry package"):
        pk.read_header(b'{"name": "json renamed to .pastry"}' * 4)


def test_rejects_unknown_format_version():
    data = bytearray(make())
    data[8] = 2
    with pytest.raises(pk.PackageError, match="Unsupported package format version"):
        pk.read_header(bytes(data))


def test_rejects_oversized_header_length_without_reading_past_end():
    data = make()
    bad = data[:9] + struct.pack(">I", 10**9) + data[13:]
    with pytest.raises(pk.PackageError, match="header length"):
        pk.read_header(bad)


def test_rejects_zero_header_length():
    data = make()
    with pytest.raises(pk.PackageError):
        pk.read_header(data[:9] + struct.pack(">I", 0) + data[13:])


def _with_header(obj):
    """Build a structurally valid file around an arbitrary header object (for negative tests)."""
    header = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    prefix = b"PSTRYPKG" + bytes([1]) + struct.pack(">I", len(header)) + header
    return prefix + bytes(61 + 13 + 40)


def _good_header(**overrides):
    obj = {
        "kind": "pastry-package", "name": "x", "created_at": NOW.isoformat(timespec="seconds"),
        "access": "offline", "allow_copy": True, "expires_at": None,
        "kdf": {"algorithm": "argon2id", "time_cost": 1, "memory_cost": 8192, "parallelism": 1,
                "salt": base64.b64encode(bytes(16)).decode()},
    }
    obj.update(overrides)
    return obj


def test_rejects_unexpected_header_keys():
    with pytest.raises(pk.PackageError, match="Malformed"):
        pk.read_header(_with_header(_good_header(extra_key="smuggled")))


def test_rejects_wrong_kind_and_bad_types():
    with pytest.raises(pk.PackageError):
        pk.read_header(_with_header(_good_header(kind="other")))
    with pytest.raises(pk.PackageError):
        pk.read_header(_with_header(_good_header(allow_copy="yes")))


def test_rejects_hostile_key_derivation_cost():
    """A crafted file must not force gigabytes of memory use on the viewer."""
    huge = _good_header()
    huge["kdf"]["memory_cost"] = 4 * 1024 * 1024
    with pytest.raises(pk.PackageError, match="outside the allowed range"):
        pk.read_header(_with_header(huge))
    slow = _good_header()
    slow["kdf"]["time_cost"] = 10_000
    with pytest.raises(pk.PackageError, match="outside the allowed range"):
        pk.read_header(_with_header(slow))


def test_rejects_malformed_salt_and_timestamps():
    bad_salt = _good_header()
    bad_salt["kdf"]["salt"] = "not base64!!"
    with pytest.raises(pk.PackageError):
        pk.read_header(_with_header(bad_salt))
    bad_time = _good_header(created_at="yesterday")
    with pytest.raises(pk.PackageError):
        pk.read_header(_with_header(bad_time))


def test_rejects_oversized_header():
    huge_name = _good_header(name="x" * 20000)
    with pytest.raises(pk.PackageError):
        pk.read_header(_with_header(huge_name))


def test_rejects_files_over_the_size_limit(tmp_path):
    path = tmp_path / "big.pastry"
    path.write_bytes(b"\x00" * (pk.MAX_FILE_BYTES + 1))
    with pytest.raises(pk.PackageError, match="larger"):
        pk.read_package_file(path)


def test_read_package_file_refuses_directories_and_non_files(tmp_path):
    with pytest.raises(pk.PackageError):
        pk.read_package_file(tmp_path)


def test_build_refuses_oversized_content():
    too_many = [{"name": f"e{i}", "username": "", "password": "", "notes": "", "fields": []}
                for i in range(pk.MAX_ENTRIES + 1)]
    with pytest.raises(pk.PackageError, match="1 to"):
        make(entries=too_many)
    long_value = [{"name": "e", "password": "p" * 5001}]
    with pytest.raises(pk.PackageError, match="longer than"):
        make(entries=long_value)
    many_fields = [{"name": "e", "fields": [{"name": "f", "value": "v"}] * (pk.MAX_FIELDS + 1)}]
    with pytest.raises(pk.PackageError, match="custom fields"):
        make(entries=many_fields)


def test_payload_envelope_must_match_the_declared_structure(tmp_path):
    """A validly encrypted payload with the wrong shape is rejected after decryption."""
    from pastry import crypto

    header_obj = _good_header()
    header = json.dumps(header_obj, separators=(",", ":"), sort_keys=True).encode()
    prefix = b"PSTRYPKG" + bytes([1]) + struct.pack(">I", len(header)) + header
    salt = base64.b64decode(header_obj["kdf"]["salt"])
    kek = crypto.derive_key(PW, salt, FAST)
    dek = crypto.new_key()
    wrapped = crypto.seal(kek, bytes(dek), prefix)
    sealed = crypto.seal(dek, b'{"v":1,"entries":"not a list"}', prefix)
    with pytest.raises(pk.PackageError, match="malformed"):
        pk.open_package(prefix + wrapped + sealed, PW)


def test_entry_limit_is_checked_again_when_opened():
    from pastry import crypto

    header_obj = _good_header()
    header = json.dumps(header_obj, separators=(",", ":"), sort_keys=True).encode()
    prefix = b"PSTRYPKG" + bytes([1]) + struct.pack(">I", len(header)) + header
    salt = base64.b64decode(header_obj["kdf"]["salt"])
    kek = crypto.derive_key(PW, salt, FAST)
    dek = crypto.new_key()
    wrapped = crypto.seal(kek, bytes(dek), prefix)
    payload = json.dumps({"v": 1, "entries": [{"name": "e"}] * (pk.MAX_ENTRIES + 1)}).encode()
    sealed = crypto.seal(dek, payload, prefix)
    with pytest.raises(pk.PackageError):
        pk.open_package(prefix + wrapped + sealed, PW)


# ----- no plaintext ------------------------------------------------------------


def test_file_contains_no_plaintext_credentials():
    data = make()
    for marker in (b"MARKER-pw-7f3a", b"MARKER-notes-9c21", b"MARKER-api-5e88", b"admin", PW.encode()):
        assert marker not in data, marker


def test_inspect_reveals_metadata_only():
    header = pk.inspect_package(make(name="Sharing label"))
    assert header.name == "Sharing label"
    # inspect output (header) must not contain any entry content
    assert b"MARKER" not in pk.read_header(make())[0].raw


def test_safe_filename_never_contains_path_parts():
    assert pk.safe_filename("../../etc/passwd") == "etc-passwd.pastry"
    assert pk.safe_filename("a/b\\c") == "a-b-c.pastry"
    assert pk.safe_filename("///") == "package.pastry"
    assert "/" not in pk.safe_filename("x" * 500)


def test_header_name_cannot_carry_control_characters():
    with pytest.raises(pk.PackageError):
        make(name="bad\nname")
