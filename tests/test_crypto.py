import pytest

from pastry import crypto
from pastry.crypto import CryptoError, KdfParams

FAST = KdfParams(time_cost=1, memory_cost=8192, parallelism=1)


def test_seal_and_open_round_trip():
    key = crypto.new_key()
    blob = crypto.seal(key, b"secret value", b"aad")
    assert crypto.open_sealed(key, blob, b"aad") == b"secret value"


def test_wrong_key_is_rejected():
    blob = crypto.seal(crypto.new_key(), b"secret", b"aad")
    with pytest.raises(CryptoError):
        crypto.open_sealed(crypto.new_key(), blob, b"aad")


def test_tampered_ciphertext_is_rejected():
    key = crypto.new_key()
    blob = bytearray(crypto.seal(key, b"secret", b"aad"))
    blob[-1] ^= 0x01
    with pytest.raises(CryptoError):
        crypto.open_sealed(key, bytes(blob), b"aad")


def test_aad_binds_ciphertext_to_its_context():
    key = crypto.new_key()
    blob = crypto.seal(key, b"secret", b"entry-1")
    with pytest.raises(CryptoError):
        crypto.open_sealed(key, blob, b"entry-2")


def test_nonces_are_unique_for_identical_plaintext():
    key = crypto.new_key()
    first = crypto.seal(key, b"same", b"aad")
    second = crypto.seal(key, b"same", b"aad")
    assert first != second
    assert first[1:13] != second[1:13]


def test_unknown_format_is_rejected():
    with pytest.raises(CryptoError):
        crypto.open_sealed(crypto.new_key(), b"\x09" + b"\x00" * 40, b"")


def test_password_hash_verifies_only_the_right_password():
    encoded = crypto.hash_password("correct horse battery", FAST)
    assert encoded.startswith("$argon2id$")
    assert crypto.verify_password_hash(encoded, "correct horse battery")
    assert not crypto.verify_password_hash(encoded, "wrong horse battery")


def test_derived_key_depends_on_password_and_salt():
    salt = crypto.new_salt()
    a = crypto.derive_key("password-one-long", salt, FAST)
    b = crypto.derive_key("password-one-long", salt, FAST)
    c = crypto.derive_key("password-two-long", salt, FAST)
    d = crypto.derive_key("password-one-long", crypto.new_salt(), FAST)
    assert a == b and len(a) == 32
    assert a != c and a != d


def test_wipe_zeroes_buffer():
    buf = bytearray(b"\x01\x02\x03")
    crypto.wipe(buf)
    assert buf == bytearray(3)
