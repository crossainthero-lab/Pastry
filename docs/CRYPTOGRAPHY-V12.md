# Pastry v1.2 cryptography: `.pastry` packages

Status of this document: design for the parts that are implemented on `feature/v1.2-secure-sharing`, plus the parts that are **not implemented**. Read the "Not implemented" section before relying on anything.

## 1. Scope

Implemented in this branch:

- **Offline encrypted packages** (`.pastry`, mode "offline"). Opened with the package password alone, without contacting any server.

Not implemented (disabled, see section 7):

- Multi-user accounts and per-user key hierarchy.
- Entry sharing with X25519 envelope wrapping.
- Server-enforced expiring packages (release secret, key-release protocol, redemption).

## 2. Trust model

- The **package password** is the only secret needed to open an offline package. Anyone holding the file and the password can read it, indefinitely, and can copy it.
- The **vault master password and vault key are never used** for packages. A package contains no vault key, no private key and no session material.
- The sender chooses the package password and gives it to the recipient through another channel. Pastry does not transmit it.
- An **advisory expiry** is stored in the authenticated header. The viewer enforces it, but a modified viewer can ignore it. It is not a security guarantee.

## 3. File layout (version 1)

```
offset  size      field
0       8         magic            ASCII "PSTRYPKG"
8       1         format version   0x01
9       4         header length    big-endian u32, must be <= 16384
13      H         header           UTF-8 JSON object (plaintext, authenticated)
13+H    61        wrapped DEK      AES-256-GCM(KEK, DEK) = version(1) || nonce(12) || ct(32) || tag(16)
13+H+61 rest      payload          AES-256-GCM(DEK, plaintext JSON) = version(1) || nonce(12) || ct || tag
```

Any file that does not match this layout is rejected. The viewer never trusts a length field before checking it against the file size.

### Header JSON (allowed keys only)

| Key | Type | Notes |
|---|---|---|
| `kind` | string | must be `"pastry-package"` |
| `name` | string, 1 to 100 chars | user-chosen label, **plaintext** (visible to anyone holding the file) |
| `created_at` | ISO 8601 UTC string | |
| `access` | string | `"offline"` in this version |
| `allow_copy` | bool | advisory for the viewer, see section 6 |
| `expires_at` | ISO 8601 UTC string or null | advisory, see section 6 |
| `kdf` | object | `algorithm: "argon2id"`, `time_cost`, `memory_cost` (KiB), `parallelism`, `salt` (base64, 16 bytes) |

Parameter bounds enforced on read, to stop a crafted file from forcing huge memory use: `time_cost` 1 to 10, `memory_cost` 8192 to 262144 KiB, `parallelism` 1 to 8.

## 4. Keys and encryption

1. Generate a random 256-bit **DEK** (data-encryption key) per package, from `secrets`.
2. Derive a 256-bit **KEK** from the package password: Argon2id with a random 16-byte salt, using the header's parameters.
3. Wrap the DEK under the KEK with AES-256-GCM. The AAD is the header prefix (magic, version, length and header bytes), so the header is authenticated.
4. Encrypt the payload with AES-256-GCM under the DEK, using the same AAD.

The DEK is independent of the vault key. Changing the package password requires re-wrapping the DEK, and changing the DEK requires re-encrypting the payload. Both are constructions available in this format, but only creation is implemented.

Nonces are 96-bit values from `secrets.token_bytes` for every seal. Each package uses a fresh DEK and salt, so a nonce is never reused under the same key.

## 5. Payload

UTF-8 JSON, at most 1 MiB, with this shape:

```json
{"v": 1, "entries": [{"name": "...", "url": "...", "username": "...", "password": "...",
                       "notes": "...", "fields": [{"name": "...", "value": "...", "secret": true}]}]}
```

Limits: at most 200 entries, names up to 200 characters, passwords up to 5000, notes up to 10000, at most 200 fields per entry. Unknown keys are rejected.

The payload is not compressed. Compression before encryption can leak information about the plaintext length, so it was left out.

## 6. Viewer behaviour and what it can and cannot enforce

- **Expiry (advisory):** when the viewer opens a package whose `expires_at` has passed, it refuses. While open, it re-checks the time and closes the view at expiry. A modified or non-Pastry program can ignore this. Local clocks can be changed.
- **Allow copy:** when false, the viewer hides and disables its Copy action. It cannot stop terminal selection, screenshots, transcription or OS-level copying. It is not DRM.
- **Local deletion:** the viewer can delete the exact file it was given, when the user asks. It does not scan for or delete other files. Filesystem deletion does not securely erase SSD blocks, backups or copies.
- **Clipboard clearing:** after a configured delay the viewer clears the clipboard only if it still holds the value Pastry copied, so unrelated clipboard contents are not overwritten. This is best effort.

## 7. Not implemented

- **Mode B, server-enforced expiry.** Would need a release secret held by the originating server, an authenticated key-release protocol that never sends the package password in plaintext, rate limiting of redemptions, and atomic one-time redemption. None of this exists. The timed and one-time access types are refused by the API with status 501.
- **Multi-user accounts and sharing.** A per-user key hierarchy and X25519-based envelope wrapping for recipients would be needed. The sharing design requires its own review, so the endpoints are not present. `pastry admin create-user` continues to refuse.
- **Package management UI** (list, revoke, delete). Packages are not recorded on the server, so there is nothing to revoke.

## 8. Errors

Wrong password, tampered header, tampered payload and corrupted wrapping all produce the same message: *the password is wrong, or the package has been modified*. The decryption layer does not report which check failed, to avoid giving an oracle. Malformed structure (bad magic, bad lengths, invalid JSON, out-of-range parameters) is reported separately, because it reveals nothing about the password.

## 9. Known limits of this design

- The package name and creation time are plaintext.
- File size and the number of bytes reveal approximately how much is stored.
- An Argon2id-protected password can still be guessed offline by anyone with the file. Use a long, random package password. The export dialog offers a generator. Passwords under 12 characters are refused.

---

## 10. Server-enforced packages (access "server", design version 1)

Status: designed and implemented in this branch. **Self-review only. This has not been independently reviewed, and must not be treated as reviewed.**

### 10.1 Goal and rule

A server-enforced package must not be decryptable from the file and the package password alone. Decryption needs a **release key** `K_r` that only the originating Pastry server releases, after a successful release protocol. There is no code path that derives the payload key from the password. Nothing in the file is password-verifiable offline.

### 10.2 Keys

| Name | Size | Created by | Lives where | Purpose |
|---|---|---|---|---|
| `K_r` release key | 256-bit random | server, at export | server DB, sealed under `release_kek` | wraps the package DEK |
| `DEK` package data key | 256-bit random | server, at export | only in the file (wrapped by `K_r`) and in memory | encrypts the payload |
| `K_pw` | 256-bit | derived | memory only, both sides | Argon2id(package password, salt, params) |
| `K_auth` | 256-bit | derived | server DB sealed under `release_kek`; client memory | HKDF-SHA256(`K_pw`, info `pastry-release-auth/v1`) |
| `release_kek` | 256-bit random | server, first use | `config/release.key`, mode 0600, **excluded from backups** | seals `K_r` and `K_auth` at rest |
| capability | 256-bit random | server, at export | in the file header; server stores SHA-256 of it | identifies the package to the release API |
| nonce | 256-bit random | server, per challenge | server DB, single use, 120 s | prevents replay |

Primitives: AES-256-GCM (`cryptography`), Argon2id (`argon2-cffi`), HKDF-SHA256 and HMAC-SHA256 (`cryptography` / `hmac`), `secrets` for randomness. Nonces for AES-GCM are random 96-bit values.

### 10.3 File layout (access "server")

Same envelope as offline packages (magic, version 1, length, header JSON), but:

- `wrapped_dek` = AES-256-GCM(`K_r`, `DEK`, aad = header prefix). The file holds **no** password-derived ciphertext.
- `payload` = AES-256-GCM(`DEK`, payload JSON, aad = header prefix).
- Header adds: `policy` (`after_open` with `seconds`, `absolute` with `expires_at`, or `one_time`), `package_id`, `capability` (base64), `release_url` (https origin of the issuing server), and `kdf` with `salt` for `K_pw`.

### 10.4 Release protocol (TLS to the issuing server)

1. **Status** `POST /release/v1/status {capability}`: returns `active | expired | revoked | consumed` and, when relevant, `expires_at`. Unknown capability returns 404. Rate-limited.
2. **Challenge** `POST /release/v1/challenge {capability}`: if the package is not active, returns its state (410 or 409). If active, returns a fresh single-use nonce `n`. The nonce is stored with its package ID and a 120-second expiry.
3. **Client** derives `K_pw` and `K_auth` from the password and salt, then computes `proof = HMAC-SHA256(K_auth, "pastry-release-proof/v1" || package_id || n)`.
4. **Redeem** `POST /release/v1/redeem {capability, nonce, proof}`. In one `BEGIN IMMEDIATE` transaction the server:
   - deletes the nonce (it can be used once, whether or not the proof is right);
   - rechecks the package state against the server clock;
   - verifies `proof` against the stored `K_auth` using a constant-time comparison;
   - on success, for an `after_open` package with no prior release, sets `expires_at = now + seconds`; for a `one_time` package, sets state `consumed`;
   - returns `wrap = AES-256-GCM(K_auth, K_r, aad = "pastry-release-wrap/v1" || package_id || n)`. The key is wrapped under `K_auth` so a TLS-terminating intermediary still cannot read it.
5. The client unwraps `K_r`, then decrypts the DEK and payload. All key material is wiped after the viewer closes.

### 10.5 Policy and state machine

- `after_open`: the timer starts at the first successful release. Later releases during the window are allowed, so the recipient can reopen. Expiry is absolute once started.
- `absolute`: `expires_at` is fixed at creation.
- `one_time`: the first successful release consumes the package. Later attempts report "already redeemed".
- Manual revocation by the owner is available at any time.
- Terminal states (`expired`, `revoked`, `consumed`) erase `K_r` and `K_auth` from the database. The file can then never be decrypted by any server path.
- Every transition runs in `BEGIN IMMEDIATE`, so concurrent redemptions are serialised. Two concurrent requests for a one-time package produce exactly one release.

### 10.6 Rate limits and oracles

- Failed proofs: 5 per capability in 15 minutes, then a 15-minute lockout for that capability.
- Challenges: 30 per client address per minute. Behind Tailscale Serve, all clients share one local address, so this limit is shared too. The capability limit is the one that matters.
- A wrong password returns the same message whether or not the package exists, so a guess yields no information beyond "not accepted". State messages (expired, revoked, consumed) are shown only to a holder of the capability, and they describe the package, not the password.

### 10.7 Threat analysis

| Scenario | Outcome |
|---|---|
| File plus password, no server | Cannot decrypt. There is no password-only path. |
| File, password and capability, after revoke or expiry | Server refuses. `K_r` has been erased. |
| File and password, server reachable, package active | Decrypts, by design, after the release protocol. |
| Recipient already holds `K_r` after a release | **Can decrypt the file indefinitely.** The server cannot take back a key it has already released. |
| Replay of a redeem request | Fails: the nonce is single-use. |
| Wrong password guesses | Each guess needs a challenge and a redeem, is rate-limited per capability, and reveals nothing beyond "not accepted". |
| Stolen server DB alone | `K_r` and `K_auth` are sealed. Not decryptable without `release_kek`. |
| Stolen server DB plus `release.key` | Attacker can guess the password offline against `K_auth` (Argon2id cost), then obtain `K_r`. Serious. Mitigation: keep `release.key` out of backups, and keep file permissions tight. |
| Malicious file with a different `release_url` | The CLI shows the host and asks for confirmation before sending anything. A host the user confirms receives an offline-guessable proof. Mitigation: check the host. |
| Sender's server sees the password at export | The password passes through the server once, in memory, to derive `K_pw` and `K_auth`. It is not stored. This is an accepted trust in the issuing server, which the sender runs. |
| Oracle through package state | State is shown only to capability holders, and it describes the package, not the password. |
| Vault compromise | Release tables are separate, and the release API never reads vault tables or sessions. Vault keys are not involved. |

### 10.8 What is not prevented

- A recipient who has obtained `K_r` can keep a copy of it, and the file, indefinitely. The server cannot prevent this, and the viewer cannot either. Expiry only stops future server releases.
- Python and the operating system may keep copies of keys and plaintext in memory or swap. Best-effort clearing only.
- The "one-time" guarantee is about server releases, not about what the recipient retains.

---

## 11. Interaction with entry sharing (1.2.0rc1)

- A package is built from the entries the requester may see. Owned entries are always allowed. A shared entry is packaged only if its owner granted the **export** permission to that account, and a protected entry only after its separate password has been entered in that session.
- The package carries decrypted content under the package's own keys. It is independent of the sharing envelopes, so revoking a share does not affect packages already created. Revoking a timed package is a separate action on the Packages page.
- Server-enforced packages remain bound to the account that created them (`packages.owner` is the account ID).
- Release keys and the sharing key-binding MAC both derive from `config/release.key`, which is excluded from backups.
