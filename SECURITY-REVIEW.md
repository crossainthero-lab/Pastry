# Pastry Security Review (v1.1)

**Status: internal review by the developer and automated tests only. This is not an independent security audit, and nothing here should be read as one.**

Pastry is a single-user, self-hosted vault. This document covers the threat model, the cryptographic design, the findings from the v1.1 audit (with how each was verified), what changed, what remains open, and what was deliberately not built.

---

## 1. Scope and status summary

| Area | v1.1 status |
|---|---|
| Entry data encryption at rest | Implemented. All entry fields and timestamps are inside AES-256-GCM blobs. |
| v1 vault migration | Implemented and tested on a frozen v1 fixture, including rollback after an injected failure. |
| Separate-password entries | Implemented. Throttled persistently. Auto re-lock after inactivity. |
| Login and unlock throttling | Persistent in SQLite. Survives restarts. |
| Sessions | Listing, revocation of one or all other sessions, sign-out, and session invalidation on password change. |
| Backups | Versioned format with checksums and a manifest. `pastry backup verify`. Atomic writes. Legacy v1 archives still restorable. |
| **Multi-user accounts** | **Not implemented.** The `create-user` and `disable-user` commands refuse. See section 8. |
| **Entry sharing** | **Not implemented.** No sharing code or routes exist. See section 8. |

---

## 2. Threat model

**Assets.** Credentials in the vault (passwords, usernames, notes, custom fields, names, URLs and categories); the master password; the vault key; backup and export archives.

**Trusted.** The owner's own device while the owner is signed in, and the local operating system account running Pastry.

**Adversaries considered.**

1. *Network attacker* on the LAN or internet who can reach the HTTP port: mitigated by binding to 127.0.0.1, HTTPS for remote access, a Host allow-list, strict cookies, CSRF and origin checks, and throttled login.
2. *Cross-site attacker* who can lure the owner's browser to a page: mitigated by SameSite=Strict cookies, Fetch Metadata and Origin checks, CSRF tokens on every state-changing route, and `Referrer-Policy: same-origin`.
3. *Thief of a disk, a backup, or an export file*: protected by Argon2id-derived keys. Without the master password or export passphrase, the contents are AES-GCM ciphertext. Plaintext metadata is limited to row IDs and random per-entry UIDs.
4. *Local user without root*: can read only files their account can read. Pastry creates all files with mode 0600 and directories with 0700, and runs under a umask of 077.
5. *Attacker with code execution as the Pastry user, or root, while the server is running*: **out of scope for confidentiality.** The server holds the vault key and unlocked keys in memory. See section 6.
6. *Malicious browser extension or compromised browser*: out of scope. It can read what the page shows.

---

## 3. Cryptographic design

| Purpose | Construction | Library |
|---|---|---|
| Master password verification | Argon2id hash (argon2 encoded form, random salt) | argon2-cffi |
| Key-encryption key (KEK) | Argon2id, 64 MiB, 3 passes, 4 lanes, 32-byte output, random 16-byte salt | argon2-cffi (`hash_secret_raw`) |
| Vault key (DEK) | 256-bit random from `secrets`, wrapped with AES-256-GCM under the KEK | cryptography |
| Entry metadata blob | AES-256-GCM under the DEK, AAD `pastry:meta2:<uid>` | cryptography |
| Normal entry content | AES-256-GCM under the DEK, AAD `pastry:content:<uid>:U` | cryptography |
| Protected entry content | AES-256-GCM under a per-entry key derived with Argon2id from the entry's separate password, AAD `pastry:content:<uid>:L` | cryptography |
| Export | Argon2id key from the export passphrase, AES-256-GCM, AAD `pastry:export:v1` | cryptography |
| Session tokens | 256-bit `secrets.token_urlsafe`; the server stores only its SHA-256 digest | hashlib |
| CSRF tokens | 256-bit random per session, compared in constant time | secrets, hmac |

**Nonces.** Every AES-GCM seal uses a fresh random 96-bit nonce from `secrets`. A test checks 5,000 nonces for uniqueness. Random nonces are safe for as long as the number of messages under one key stays far below about 2^32. Each entry write uses one message, so a personal vault is very far from that limit. The DEK is only rewrapped when the master password changes, and content keys are never reused across entries because they are random per entry.

**Rewrapping.** A master password change derives a new KEK, wraps the same DEK, and verifies that the new password returns the same DEK before the file is replaced. No entry is re-encrypted.

**AAD binding.** Each blob's AAD includes its entry's random UID and its layer. Moving a blob to another entry, or from one layer to another, makes authentication fail. A test checks this.

**Key handling.** Keys are `bytearray` values, overwritten on lock, sign-out and session expiry. Python may still hold copies, so this is best-effort only.

---

## 4. Database layout (schema v2)

| Column | Content | Plaintext? |
|---|---|---|
| `entries.id` | Integer row ID | Yes (not sensitive) |
| `entries.uid` | Random 128-bit identifier, used as AAD | Yes (random, not sensitive) |
| `entries.meta_blob` | name, url, category, favourite, created/updated timestamps, locked flag, lock salt, lock KDF parameters | **No**, sealed under the DEK |
| `entries.content_blob` | username, password, notes, custom fields | **No**, sealed under the DEK or the entry key |
| `rate_limits` | Failure timestamps and lockout deadlines (keys like `login-ip:<address>`) | Operational metadata only |
| `meta` | Schema version, session timeout setting | Operational only |

Blob sizes and row count remain visible. They reveal the approximate size of each entry and how many entries exist.

**Correction to the v1.1 request.** The v1 database already encrypted entry names, URLs and categories. The plaintext in v1 was limited to timestamps, the locked flag and the separate-password salt and parameters. Those are now sealed too. This was verified against the v1 fixture: the string "2026-" appeared in plaintext, and "Plain Server", "example.com" and "Servers" did not.

---

## 5. Migration v1 → v2

- `pastry migrate` checks that the database is schema v1 and that the master password unwraps the vault key.
- It creates a full backup in `backups/` before changing anything.
- It runs in one `BEGIN IMMEDIATE` transaction. It builds `entries_v2`, copying each content blob byte-for-byte, and re-seals each metadata blob with the v2 AAD. It then decrypts every new metadata blob to verify it, and only then drops the old table.
- Any exception rolls the transaction back. Tests confirm that the database file is byte-identical after an injected failure at row 1, and that a clean retry succeeds.
- The server refuses to start, and refuses requests with HTTP 503, while the database is not schema v2.
- Separate-password locks are preserved because the content blob and its salt and parameters are carried over unchanged. A test unlocks a migrated v1 entry with its original password.

**Rollback** after a successful migration: stop the server, then `pastry restore backups/pastry-backup-<pre-migration>.tar.gz`. The restore keeps the current files as `*.before-restore-*`.

---

## 6. Server-side decryption model and its limits

Pastry decrypts on the server, because search and rendering happen there. Consequences:

- While a session is open, the server holds the DEK in memory. Unlocked separate-password keys are held until they are idle for `entry_idle_minutes` (default 5), until locked, or until the session ends.
- Anyone who can read the server process memory can read the vault while it is unlocked. That includes root and malware running as the Pastry user.
- The database, backups and exports, taken alone, do not expose content. An offline attacker needs the master password (or the export passphrase), and must pay the Argon2id cost for each guess.
- Protected entries stay sealed even while the vault is unlocked, until their own password is entered in that session. This is enforced by cryptography: the DEK cannot open them (a test checks this by decrypting the raw blob with the DEK and expecting failure).

---

## 7. Audit findings

Severities are the developer's estimate, for a single-user self-hosted tool. "Verified" means reproduced or confirmed by reading the code and running a test. "Fixed" means a v1.1 change plus a test. Items that are not fixed say so.

| # | Severity | Finding | How verified | Status |
|---|---|---|---|---|
| 1 | Medium | Timestamps and separate-password lock state were plaintext in the database, so the database leaked when entries were created and when they were protected. | Searched the v1 fixture: "2026-" present; `locked` and `lock_salt` in plaintext columns. | **Fixed** in v2 (metadata sealed). Tests: `test_timestamps_and_lock_state_are_not_plaintext`, `test_migrated_database_has_no_plaintext_metadata`. |
| 2 | Medium | Login and separate-password throttling lived in process memory. A restart reset all counters, so an attacker who could trigger restarts (for example by crashing the service) got fresh guesses. | Read `sessions.py` in v1: `FailureLimiter` used dictionaries only. | **Fixed**: SQLite-backed `SqlRateLimiter`. Tests: lockout survives restart, for login and for entries. |
| 3 | Medium | A separate-password entry stayed decrypted for the rest of the session, even when the owner had walked away from it. | Read `sessions.py` in v1: `unlocked` was never expired. | **Fixed**: per-entry idle expiry. Tests: relock after idle, touching the entry resets the timer, listing does not reset it, writes after relock are refused. |
| 4 | Medium | No way to see or revoke other sessions. A lost phone with an open session stayed signed in until the idle timeout. | Route list in v1: no session listing or revocation routes. | **Fixed**: `/api/sessions`, revoke one, log out others. Tests cover each. |
| 5 | Low | Backup archives had no integrity check, so a corrupted or altered archive could replace the vault with no warning. | Read `backup.py` in v1: restore only checked SQLite integrity and JSON parsing. | **Fixed**: SHA-256 manifest, count check, `pastry backup verify`. Tests: flipped byte detected, count tampering detected, foreign archives refused, corrupted archive never touches the active vault. |
| 6 | Low | An interrupted backup could leave a `.part` file. | Read `create_backup` in v1. | **Fixed**: partial file removed on failure. Test. |
| 7 | Low | Password changes were only possible from the CLI, so there was no UI path with its own throttle. | Route list in v1. | **Added** with throttling (`POST /api/account/password`). Tests: wrong current password refused, throttled, all sessions signed out, entries kept. |
| 8 | Low | Login form carries no CSRF token. | Read `login` in v1. | **Open, accepted.** Mitigated by SameSite=Strict, Origin and Fetch Metadata checks. A login CSRF can at most sign the victim into the attacker's account. |
| 9 | Low | Session lookup and rate-limiter keys do not trust forwarded headers. | Read `_client_ip`. | **Verified correct**: test sends spoofed `X-Forwarded-For` and `X-Real-IP` values and is still throttled. |
| 10 | Info | The front end uses only `textContent`, and no `innerHTML`, `eval` or `new Function`. | Grepped `app.js`. | **Verified**, and a test enforces it. A script in an entry name is returned as JSON data and does not appear in the page. |
| 11 | Info | The `Origin: null` problem caused by `Referrer-Policy: no-referrer`. | Found in browser testing during v1. | **Fixed** in v1 (`same-origin`). Regression test. |
| 12 | Info | Entry search and sorting decrypt every entry for each request. | Measured: 50 entries, median 1.8 ms. | **Accepted** at personal scale. Does not persist any index. |
| 13 | Info | Copied values remain on the clipboard. | Known design property. | **Open**, documented. |
| 14 | Info | `DEFAULT` Argon2id parameters are fixed in code and not configurable. | Read `crypto.py`. | **Open**, documented. |

---

## 8. Not implemented, and why

**Multi-user accounts and sharing were not built in v1.1.** They need a per-user key hierarchy: each user's vault key wrapped under their own password, plus per-entry keys shared through a reviewed public-key scheme (for example X25519 with HKDF and AES-GCM). That design needs its own threat analysis, key-revocation and recovery rules, and an adversarial test suite across accounts. Building it in a rush would risk a weaker design, and the request explicitly allowed isolating unfinished work behind a disabled feature. The current behaviour is:

- `pastry admin list-users` shows only the owner.
- `pastry admin create-user` and `pastry admin disable-user` exit with status 2 and change nothing.
- No sharing routes or UI exist. The security requirements in the request (separate-password entries cannot be bypassed by sharing) therefore have no code to check, and nothing to bypass.

Consequences that follow from single-user operation:

- The "two accounts" adversarial tests cannot be run. Adversarial coverage is instead provided by checking that every API route refuses anonymous callers, that the CSRF and origin checks apply to every write, and that a relocked entry cannot be read or written.
- There is no account recovery, because there is no account other than the owner's. Recovery is the backup plus the master password.

---

## 9. Tests

The suite has 126 tests. The 72 v1 tests still pass. The new modules are:

- `test_migration.py`: migration of the frozen v1 fixture, preserved separate-password locks, rollback after an injected failure, backup before migration, wrong-password refusal, server and `start` refusing an unmigrated vault.
- `test_v11_security.py`: persistent throttling across restart, spoofed forwarded headers, session listing and revocation, password change through the API, idle re-lock, encrypted timestamps, nonce uniqueness, ciphertext swapping between entries, XSS data handling, anonymous access to every route, atomic auth-file replacement.
- `test_backup_v11.py`: manifest contents, verification with and without the password, tampering and foreign archives, legacy v1 archives, verification never modifying the active vault, isolated restore, retention of previous files, interrupted backups, the CLI verify command.
- `test_admin_commands.py`: `list-users`, and refusal of `create-user` and `disable-user`.

Run with `.venv/bin/python -m pytest -q`. The result at the time of writing is in `README.md`.

**Browser checks, run manually against the live server in headless Chrome** (not part of pytest): three passes covering the vault, separate passwords, dialogs, export and import, settings, the session list with "log out other sessions", and the password change followed by re-login.

---

## 10. Outstanding risks

1. The server holds keys in memory while unlocked. Process compromise exposes the open vault.
2. Argon2id parameters are not tunable. Login costs about 80 ms on this development machine. A Raspberry Pi will be slower, and the cost has not been measured on one.
3. Session and login state reset on restart apart from the throttle counters (sessions are memory-only by design).
4. The Tailscale and Caddy deployment paths were documented but not exercised here, because no tailnet or LAN was available.
5. Python cannot guarantee key erasure.
6. No independent review has been done. Security-sensitive code, especially the migration and backup paths, should be reviewed before depending on it.
