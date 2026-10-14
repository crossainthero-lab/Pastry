"""Server-enforced packages: release protocol, expiry, one-time races, revocation, isolation.

Uses a simulated clock (no sleeps) and an isolated temporary database."""
import base64
import secrets
import sqlite3
import threading
from datetime import datetime, timezone

import pytest

from pastry import crypto
from pastry import package as pk
from pastry import release as rel
from pastry.crypto import KdfParams
from pastry.db import Store
from pastry.release import NewPackage, ReleaseError, ReleaseService
from tests.conftest import FakeClock

KDF = KdfParams(time_cost=1, memory_cost=8192, parallelism=1)
PW = "package password 2026"
URL = "https://pastry.example.ts.net"
ENTRY = {"name": "Ubuntu AI Server", "username": "admin", "password": "SERVER-SECRET-1",
         "notes": "", "url": "", "fields": []}


class LocalTransport:
    """In-process transport: same contract as release_client.HttpTransport, no network."""

    def __init__(self, service):
        self.service = service

    def _call(self, fn, *args):
        from pastry.release_client import ReleaseRefused
        try:
            return fn(*args)
        except ReleaseError as exc:
            raise ReleaseRefused(exc.status, exc.code, exc.message) from None

    def status(self, capability):
        return self._call(self.service.status, rel.decode_capability(capability))

    def challenge(self, capability):
        return self._call(self.service.challenge, rel.decode_capability(capability))

    def redeem(self, capability, nonce, proof_b64):
        return self._call(self.service.redeem, rel.decode_capability(capability), nonce,
                          base64.b64decode(proof_b64))


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "pastry.db")
    s.init()
    return s


@pytest.fixture
def svc(store, clock, tmp_path):
    kek = rel.load_or_create_kek(tmp_path / "release.key")
    return ReleaseService(store, kek, clock)


def make_package(svc, store, clock, *, policy="after_open", seconds=300, absolute=None, owner="owner"):
    """Create a server-enforced package the same way web.py does, against the release service."""
    salt = crypto.new_salt()
    k_pw, k_auth = pk.derive_keys(PW, salt, KDF)
    crypto.wipe(k_pw)
    k_r = secrets.token_bytes(32)
    capability = secrets.token_bytes(32)
    now = clock.now
    policy_obj = {"type": policy}
    if policy == "after_open":
        policy_obj["seconds"] = seconds
    if policy == "absolute":
        policy_obj["expires_at"] = datetime.fromtimestamp(absolute, timezone.utc).isoformat(timespec="seconds")
    pid = svc.create(NewPackage(owner, capability, policy, seconds if policy == "after_open" else None,
                                absolute if policy == "absolute" else None, 1, b"meta", b"", k_r, k_auth), now)
    data = pk.build_server_package([ENTRY], "Server access", allow_copy=False, policy=policy_obj,
                                   release_url=URL, package_id=pid, capability=capability, salt=salt,
                                   kdf=KDF, k_r=k_r, now=datetime.fromtimestamp(now, timezone.utc))
    svc.set_file(pid, data, owner)
    cap_text = rel.encode_capability(capability)
    return {"id": pid, "data": data, "capability": capability, "cap_text": cap_text, "k_auth": k_auth}


from pastry.release_client import ReleaseRefused  # noqa: E402  (client-visible error type)


def redeem_once(svc, pkg, password=PW, transport=None):
    """Full client-side protocol, without the viewer."""
    from pastry.release_client import open_server_package
    return open_server_package(pkg["data"], password, transport or LocalTransport(svc))


def blobs_erased(store, pid):
    with sqlite3.connect(store.path) as conn:
        row = conn.execute("SELECT release_blob, auth_blob, state FROM packages WHERE id=?", (pid,)).fetchone()
    return row[0] is None and row[1] is None, row[2]


# ----- happy path and the no-password-only rule -----------------------------------


def test_release_opens_the_package_and_records_the_window(svc, store, clock):
    pkg = make_package(svc, store, clock)
    release = redeem_once(svc, pkg)
    assert release.entries[0]["password"] == "SERVER-SECRET-1"
    expected = datetime.fromtimestamp(clock.now + 300, timezone.utc).isoformat(timespec="seconds")
    assert release.expires_at == expected


def test_file_and_password_alone_cannot_decrypt_a_server_package(svc, store, clock):
    pkg = make_package(svc, store, clock)
    with pytest.raises(pk.PackageError, match="server-enforced"):
        pk.open_package(pkg["data"], PW)
    # Even deriving every password-based key does not open the payload.
    header, offset = pk.read_header(pkg["data"])
    k_pw, _ = pk.derive_keys(PW, header.salt, header.kdf)
    with pytest.raises(pk.PackageError):
        pk.open_with_release_key(pkg["data"], bytes(k_pw))


def test_wrong_password_is_refused_and_does_not_reveal_package_contents(svc, store, clock):
    from pastry.release_client import ReleaseRefused, open_server_package

    pkg = make_package(svc, store, clock)
    with pytest.raises(ReleaseRefused) as info:
        open_server_package(pkg["data"], "wrong password 9999", LocalTransport(svc))
    assert info.value.code == "bad_password"
    assert "SERVER-SECRET" not in str(info.value)


def test_redeem_response_never_contains_the_release_key_in_clear(svc, store, clock):
    pkg = make_package(svc, store, clock)
    nonce = svc.challenge(pkg["capability"])
    answer = svc.redeem(pkg["capability"], nonce, pk.proof_for(pkg["k_auth"], pkg["id"], nonce))
    assert set(answer) == {"package_id", "wrapped_key", "expires_at"}
    with sqlite3.connect(store.path) as conn:
        raw = conn.execute("SELECT release_blob FROM packages WHERE id=?", (pkg["id"],)).fetchone()[0]
    assert base64.b64decode(answer["wrapped_key"]) != raw  # wrapped, not the sealed row either


# ----- nonces and replay ----------------------------------------------------------


def test_replayed_redeem_fails_because_the_nonce_is_single_use(svc, store, clock):
    pkg = make_package(svc, store, clock)
    nonce = svc.challenge(pkg["capability"])
    proof = pk.proof_for(pkg["k_auth"], pkg["id"], nonce)
    svc.redeem(pkg["capability"], nonce, proof)
    with pytest.raises(ReleaseError) as info:
        svc.redeem(pkg["capability"], nonce, proof)
    assert info.value.code == "bad_challenge"


def test_a_wrong_proof_still_consumes_the_nonce(svc, store, clock):
    pkg = make_package(svc, store, clock)
    nonce = svc.challenge(pkg["capability"])
    with pytest.raises(ReleaseError) as info:
        svc.redeem(pkg["capability"], nonce, b"\x00" * 32)
    assert info.value.code == "bad_password"
    with pytest.raises(ReleaseError) as info:  # the same nonce cannot be tried again
        svc.redeem(pkg["capability"], nonce, pk.proof_for(pkg["k_auth"], pkg["id"], nonce))
    assert info.value.code == "bad_challenge"


def test_nonce_expires_after_two_minutes(svc, store, clock):
    pkg = make_package(svc, store, clock)
    nonce = svc.challenge(pkg["capability"])
    clock.advance(rel.NONCE_TTL_SECONDS + 1)
    with pytest.raises(ReleaseError) as info:
        svc.redeem(pkg["capability"], nonce, pk.proof_for(pkg["k_auth"], pkg["id"], nonce))
    assert info.value.code == "bad_challenge"


def test_proof_is_bound_to_the_package_id(svc, store, clock):
    pkg = make_package(svc, store, clock)
    other = make_package(svc, store, clock)
    nonce = svc.challenge(pkg["capability"])
    wrong = pk.proof_for(pkg["k_auth"], other["id"], nonce)  # proof for another package id
    with pytest.raises(ReleaseError) as info:
        svc.redeem(pkg["capability"], nonce, wrong)
    assert info.value.code == "bad_password"


def test_a_nonce_from_one_package_cannot_redeem_another(svc, store, clock):
    first = make_package(svc, store, clock)
    second = make_package(svc, store, clock)
    nonce = svc.challenge(first["capability"])
    with pytest.raises(ReleaseError) as info:
        svc.redeem(second["capability"], nonce, pk.proof_for(second["k_auth"], second["id"], nonce))
    assert info.value.code == "bad_challenge"


# ----- expiry -----------------------------------------------------------------------


def test_after_open_window_starts_at_first_release_and_ends_on_server_clock(svc, store, clock):
    pkg = make_package(svc, store, clock, seconds=300)
    assert svc.status(pkg["capability"])["state"] == "active"  # not yet opened: still active
    redeem_once(svc, pkg)
    clock.advance(299)
    redeem_once(svc, pkg)  # reopen inside the window is allowed
    clock.advance(2)
    assert svc.status(pkg["capability"])["state"] == "expired"
    with pytest.raises(ReleaseError) as info:
        svc.challenge(pkg["capability"])
    assert info.value.status == 410 and info.value.code == "expired"


def test_reopening_does_not_extend_the_window(svc, store, clock):
    pkg = make_package(svc, store, clock, seconds=300)
    first = redeem_once(svc, pkg)
    clock.advance(200)
    second = redeem_once(svc, pkg)
    assert first.expires_at == second.expires_at


def test_expiry_erases_release_material(svc, store, clock):
    pkg = make_package(svc, store, clock, seconds=300)
    redeem_once(svc, pkg)
    clock.advance(301)
    svc.status(pkg["capability"])  # any access settles the state
    erased, state = blobs_erased(store, pkg["id"])
    assert erased and state == "expired"


def test_sweep_erases_expired_packages_without_touching_vault_rows(svc, store, clock):
    with sqlite3.connect(store.path) as conn:
        conn.execute("INSERT INTO entries (uid, meta_blob, content_blob) VALUES ('a'*32, x'00', x'00')")
    pkg = make_package(svc, store, clock, seconds=300)
    redeem_once(svc, pkg)
    clock.advance(301)
    assert svc.sweep() == 1
    erased, state = blobs_erased(store, pkg["id"])
    assert erased and state == "expired"
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0] == 1


def test_absolute_deadline_is_fixed_at_creation(svc, store, clock):
    pkg = make_package(svc, store, clock, policy="absolute", absolute=clock.now + 600)
    clock.advance(599)
    redeem_once(svc, pkg)
    clock.advance(2)
    with pytest.raises(ReleaseRefused) as info:
        redeem_once(svc, pkg)
    assert info.value.code == "expired"


# ----- one-time redemption and races -------------------------------------------


def test_one_time_package_is_released_once(svc, store, clock):
    pkg = make_package(svc, store, clock, policy="one_time")
    redeem_once(svc, pkg)
    with pytest.raises(ReleaseRefused) as info:
        redeem_once(svc, pkg)
    assert info.value.status == 409 and info.value.code == "consumed"
    assert blobs_erased(store, pkg["id"])[0]


def test_concurrent_redemptions_of_a_one_time_package_release_exactly_once(store, clock, tmp_path):
    kek = rel.load_or_create_kek(tmp_path / "release.key")
    svc = ReleaseService(store, kek, clock)
    pkg = make_package(svc, store, clock, policy="one_time")
    nonces = [svc.challenge(pkg["capability"]) for _ in range(12)]
    proofs = [pk.proof_for(pkg["k_auth"], pkg["id"], n) for n in nonces]
    results, errors = [], []
    barrier = threading.Barrier(len(nonces))

    def attempt(nonce, proof):
        barrier.wait()
        try:
            results.append(svc.redeem(pkg["capability"], nonce, proof))
        except ReleaseError as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=attempt, args=(n, p)) for n, p in zip(nonces, proofs)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 1
    assert len(errors) == len(nonces) - 1
    assert set(errors) == {"consumed"}


# ----- revocation and deletion -----------------------------------------------------


def test_revocation_prevents_all_future_releases_and_erases_keys(svc, store, clock):
    pkg = make_package(svc, store, clock, seconds=3600)
    redeem_once(svc, pkg)
    svc.revoke("owner", pkg["id"])
    with pytest.raises(ReleaseError) as info:
        svc.challenge(pkg["capability"])
    assert info.value.code == "revoked"
    assert blobs_erased(store, pkg["id"]) == (True, "revoked")


def test_revoked_package_refuses_a_proof_computed_before_revocation(svc, store, clock):
    pkg = make_package(svc, store, clock, seconds=3600)
    nonce = svc.challenge(pkg["capability"])
    proof = pk.proof_for(pkg["k_auth"], pkg["id"], nonce)
    svc.revoke("owner", pkg["id"])
    with pytest.raises(ReleaseError) as info:
        svc.redeem(pkg["capability"], nonce, proof)
    assert info.value.code == "revoked"


def test_delete_removes_only_that_package(svc, store, clock):
    keep = make_package(svc, store, clock)
    drop = make_package(svc, store, clock)
    svc.delete("owner", drop["id"])
    with sqlite3.connect(store.path) as conn:
        ids = [r[0] for r in conn.execute("SELECT id FROM packages")]
    assert ids == [keep["id"]]


# ----- isolation and malformed input --------------------------------------------------


def test_other_owners_cannot_see_list_download_revoke_or_delete(svc, store, clock):
    pkg = make_package(svc, store, clock, owner="owner")
    assert svc.list_for("someone-else") == []
    with pytest.raises(ReleaseError):
        svc.get_file("someone-else", pkg["id"])
    with pytest.raises(ReleaseError):
        svc.revoke("someone-else", pkg["id"])
    with pytest.raises(ReleaseError):
        svc.delete("someone-else", pkg["id"])
    assert svc.status(pkg["capability"])["state"] == "active"


def test_unknown_and_malformed_capabilities_look_identical(svc):
    # Malformed text is rejected before any lookup.
    for bad in ("", "x", "not+base64/valid=="):
        with pytest.raises(ReleaseError) as info:
            rel.decode_capability(bad)
        assert info.value.status == 404 and "not available" in info.value.message
    # A well-formed capability that matches nothing gets the same answer.
    with pytest.raises(ReleaseError) as info:
        svc.status(secrets.token_bytes(32))
    assert info.value.status == 404 and "not available" in info.value.message


def test_proof_must_be_exactly_32_bytes_at_the_api(svc, store, clock):
    pkg = make_package(svc, store, clock)
    nonce = svc.challenge(pkg["capability"])
    with pytest.raises(ReleaseError):
        svc.redeem(pkg["capability"], nonce, b"short")


def test_package_without_release_key_is_unreleasable(store, clock, tmp_path):
    """A restore without config/release.key leaves packages that cannot be released."""
    good = ReleaseService(store, rel.load_or_create_kek(tmp_path / "a.key"), clock)
    pkg = make_package(good, store, clock)
    other_kek = ReleaseService(store, secrets.token_bytes(32), clock)
    nonce = other_kek.challenge(pkg["capability"])  # no key needed to issue a nonce
    proof = pk.proof_for(pkg["k_auth"], pkg["id"], nonce)
    with pytest.raises(ReleaseError) as info:  # but the release itself needs release_kek
        other_kek.redeem(pkg["capability"], nonce, proof)
    assert info.value.status == 503


def test_package_header_fields_are_validated():
    base = {"kind": "pastry-package", "name": "x", "created_at": "2026-10-14T12:00:00+00:00",
            "access": "server", "allow_copy": False, "policy": {"type": "after_open", "seconds": 300},
            "package_id": 1, "capability": base64.urlsafe_b64encode(bytes(32)).rstrip(b"=").decode(),
            "release_url": URL, "kdf": {"algorithm": "argon2id", "time_cost": 1, "memory_cost": 8192,
                                       "parallelism": 1, "salt": base64.b64encode(bytes(16)).decode()}}
    import json, struct
    def build(obj):
        header = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
        return b"PSTRYPKG" + bytes([1]) + struct.pack(">I", len(header)) + header + bytes(200)
    pk.read_header(build(base))  # valid baseline
    for mutate in (
        lambda o: o.update(policy={"type": "after_open", "seconds": 7}),   # window not offered
        lambda o: o.update(release_url="http://evil.example"),            # plain HTTP off-loopback
        lambda o: o.update(capability="short"),
        lambda o: o.update(package_id="one"),
        lambda o: o.update(policy={"type": "absolute"}),
    ):
        obj = json.loads(json.dumps(base))
        mutate(obj)
        with pytest.raises(pk.PackageError):
            pk.read_header(build(obj))
