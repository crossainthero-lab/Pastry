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
