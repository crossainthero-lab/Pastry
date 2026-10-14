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

The suite has 192 tests. The 126 from v1.1 still pass. The new modules are:

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

---

## 11. v1.2 branch: what was added, and what is still missing

Branch: `feature/v1.2-secure-sharing`. Version in code is still 1.1.0, because most of the v1.2 scope is not implemented. The version will move to 1.2.0 only when multi-user, sharing and server-enforced packages are done.

### Implemented on the branch

- **Offline `.pastry` packages** (format version 1, documented in `docs/CRYPTOGRAPHY-V12.md`). Random per-package DEK, Argon2id-derived KEK from the package password, AES-256-GCM envelope, authenticated plaintext header, bounded sizes and KDF parameters. Keys are independent of the vault.
- **Export as Pastry** (web UI and `POST /api/packages/export`). Exports only the selected entries. Protected entries require their separate password first, enforced on the server. Timed and one-time modes return HTTP 501. No plaintext export is written to disk.
- **Terminal viewer** (`pastry`, `pastry open`, `pastry inspect`). Standard-library curses, masked password entry, masked secrets revealed with R, optional copy with clipboard clearing only when the value is unchanged, expiry check every half second, optional deletion of the exact opened file on expiry.
- **Recipient install without the server stack.** Base dependencies are `argon2-cffi` and `cryptography`. FastAPI and uvicorn are in the `server` extra. Verified in a clean venv: `pastry inspect` and `pastry open` work, and `pastry start` fails with a clear message.

### Not implemented (disabled or refused, not faked)

- **Multi-user accounts and per-user key hierarchy.** `admin create-user` and `disable-user` refuse. No second account can exist.
- **Entry sharing (X25519 envelope wrapping, view and edit permissions, revocation).** No sharing routes or UI exist.
- **Server-enforced expiring packages (Mode B).** No release secret, no key-release protocol, no redemption counter, no server-side revocation. Timed and one-time packages are refused.
- **Packages management UI** (listing, revoke, delete). Packages are not recorded server-side, so there is nothing to revoke.
- **Users page, Shared With Me page, Manage Access page.** Not built.
- **Separate standalone recipient distribution.** The recipient wheel is the same project wheel with the server code inside but inert unless the server extra is installed. A truly separate distribution was not built.

### New risks introduced by v1.2

| Risk | Detail | Mitigation |
|---|---|---|
| Offline guessing of package passwords | Anyone with the file can attempt passwords offline. Each guess costs one Argon2id derivation (64 MiB). | Passwords under 12 characters are refused. The generator produces 16 to 48 characters. Nothing else can limit offline guessing. |
| Advisory expiry is bypassable | A modified viewer or a copy of the file ignores `expires_at`. | Stated in the UI and docs. Not a security control. |
| Copy setting is not DRM | Terminal selection, screenshots and transcription still work. | Stated in the UI and docs. |
| Clipboard contents | Copied values stay on the clipboard until cleared. The clear is best effort and runs only while the viewer process is alive. | Clear after 30 seconds by default, only if unchanged. |
| Terminal scrollback | Revealed values may stay in terminal history. The viewer draws with curses, which does not write to scrollback, but the terminal emulator may keep its own history. | Documented. |
| Package names are plaintext | The label is in the authenticated header. | Documented. Use neutral labels. |
| File-size and cost limits | Hostile files cannot force large memory use because KDF parameters are bounded, and file size, header size, entry count and field sizes are capped. | Tested. |
| Python memory retention | Keys and decrypted values are best-effort wiped. | Documented. |

### Verification performed

- Pytest: 192 passed (126 pre-existing, plus 66 for packages, viewer, export API and pseudo-terminal tests).
- Pseudo-terminal tests drive the real viewer with pexpect: picker, masked password, wrong password, copy disabled, empty directory, `open`, `inspect`.
- Browser test (headless Chrome): select two entries, export with copy disabled, download the file, and decrypt it with the package password. The result contains exactly the two entries.
- Earlier browser passes re-run against the new UI, with no regressions.

### Items that still need independent review before any trust

The package envelope, the header binding and the bounds checks are small, but they are new cryptographic code written here. They need a review by someone who does cryptographic engineering before anyone relies on them for real secrets.

---

## 12. Server-enforced (timed) packages: implementation status and review

**Review status: self-review only. Not independently reviewed. Do not treat the design or the code as reviewed.** The design is in `docs/CRYPTOGRAPHY-V12.md` section 10, which supersedes the "not implemented" statements in sections 7 and 11 above.

### 12.1 What is implemented

- Schema v3 adds `packages` and `release_nonces`. `pastry migrate` upgrades v2 vaults additively, without touching existing rows.
- Export modes: **after opening** (5 minutes, 15 minutes, 1 hour, 24 hours, measured from the first successful release), **absolute deadline** (up to 30 days from creation), and **one-time** (the first successful release consumes the package). Manual revocation is available at any time. Timed modes need `public_url` in the server configuration, and they are refused without it.
- The release protocol (status, challenge, redeem) is served under `/release/v1/` on the same app. It never reads vault entries, sessions or the vault key.
- The recipient viewer (`pastry open`) contacts the server over HTTPS with default certificate verification. It asks for confirmation before sending anything. It polls the server every 30 seconds and fails closed after two failed checks.
- Owner package API: create, list, download the stored encrypted copy, revoke, delete. Every query is scoped to the owner.
- The Packages page shows name, creation time, expiry, policy, status and entry count.
- Startup erases the release material of packages past their deadline. Listing packages does the same.

### 12.2 Verification performed

| Area | Tests |
|---|---|
| Release state machine (expiry, windows, absolute deadlines, one-time, revocation, deletion, nonce single use, nonce expiry, proof binding, cross-package nonce reuse, sweep, missing release key) | `tests/test_release.py` (24) |
| Owner and public HTTP routes (creation validation, listing without capabilities, download, release over HTTP, rate limits, lockouts, forwarded-header independence, malformed requests, cross-owner ID manipulation, CSRF, anonymous access, expired sessions) | `tests/test_release_api.py` (21) |
| Real sockets: full release, plain HTTP refused for remote hosts, no silent downgrade to HTTP, **self-signed certificate rejected by default**, accepted only when explicitly trusted, unreachable server reported, six concurrent network redemptions of one one-time package release exactly once | `tests/test_release_network.py` (7) |
| Real `pastry open` in a pseudo-terminal against a live server: release and reveal, decline sends nothing, wrong password, revoked package, unreachable server with no offline fallback, expiry measured on the server clock closes the viewer, delete-on-expiry removes only the opened file | `tests/test_tui_server_pty.py` (7) |
| Offline package format and TUI behaviour, unchanged | the 192 earlier tests |

Browser check (headless Chrome, against the live scratch server): an after-opening package was created through the export dialog, listed on the Packages page, and then opened with the real `pastry open` command. The secret was masked until R was pressed. Three earlier browser passes still pass.

### 12.3 What the tests do not establish

- **Tailscale.** No tailnet exists on this machine, so `tailscale serve` was never run. The HTTPS path is exercised only through a self-signed local certificate and the trust-store override.
- **Real expiry over the wire.** The expiry tests use a simulated clock shared by the server thread and the viewer. Real time was not waited on.
- **Pexpect and threads.** The pseudo-terminal tests run while server threads exist. Python can warn that `fork` is unsafe in a multi-threaded process. This affects only the test harness.
- **Raspberry Pi and older Ubuntu.** Not measured.
- **Independent cryptographic review.** Not performed.

### 12.4 Remaining risks (in addition to sections 7 and 11)

| Risk | Detail | Mitigation |
|---|---|---|
| Keys already released stay usable | A recipient who has obtained `K_r` can keep the file and `K_r` and decrypt indefinitely. Expiry stops only future releases. | Stated in the UI and in `docs/CRYPTOGRAPHY-V12.md` 10.8. |
| Key material in recipient memory | After release, `K_r` exists as Python `bytes` copies (`bytes(k_r)` for the opener), which `wipe` cannot clear. The viewer does not write it to disk. | Best effort. The release key lives in process memory long enough to decrypt the payload. |
| Stolen database and `release.key` together | `K_auth` allows offline guessing of the package password, and then `K_r` is obtainable. | Keep `config/release.key` out of backups (done). Restrict file permissions (done). |
| Backups and restores | `pastry backup` excludes `release.key`. A restore on a machine without that key leaves timed packages unreleasable, which is the intended safe failure. | Documented in DEPLOYMENT.md. |
| Malicious package names a different server | The viewer shows the host and requires confirmation. A host the user confirms receives an offline-guessable proof. | The user must check the host. |
| Sender's server sees the package password | At creation, the password reaches the server in memory to derive `K_pw` and `K_auth`. It is not stored. | Accepted, because the sender runs the server. |
| At-most-once delivery for one-time packages | If the server commits a one-time release but the response is lost in transit, the package is consumed and the recipient gets nothing. | Documented. The alternative (release without consuming) would break the one-time guarantee. |
| Shared rate-limit address behind Tailscale Serve | Requests arrive from the same local address, so the request-volume limit is shared among clients. The per-capability failure limit is the one that protects a package. | Documented. |
| Offline guessing of the package password from the file | None. The file has no password-verifiable ciphertext for server packages. For offline packages (unchanged) guessing is possible at Argon2id cost. | Documented in section 10.7 of the design. |
| Argon2id parameters | Fixed in code. | Documented. |
| Pexpect and threads warning | Test harness only. | None needed in production. |

### 12.5 Open items before any release decision

1. Independent review of `docs/CRYPTOGRAPHY-V12.md` section 10 and of `pastry/release.py`, `pastry/release_client.py` and the release routes in `pastry/web.py`.
2. A real Tailscale Serve test on the target machine, with a second device.
3. Measurement on Raspberry Pi-class hardware.
4. The Packages page and the release protocol still need a browser run against a Tailscale HTTPS address.
