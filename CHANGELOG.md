# Changelog

## 1.2.0rc1 (release candidate, unreleased)

Not independently audited. See `SECURITY-REVIEW.md` section 14 for review status and open release gates.

### Added
- Multi-user accounts: owner and regular users, each with a separate encrypted vault. Single-use, expiring invitations. Users page, `pastry admin create-user`, `list-users`, `disable-user`.
- Entry sharing between accounts with View, Edit and Export permissions, Manage Access, Shared With Me. Per-entry keys, X25519 key envelopes, key rotation on revocation. Separate-password entries remain protected.
- Offline `.pastry` packages, server-enforced timed and one-time packages, Packages page, terminal package viewer (`pastry`, `pastry open`, `pastry inspect`).
- Backups with a keyed authenticity MAC, `pastry backup verify`, `restore --require-authentic`, `pastry admin rebind-keys`.
- Schema v5 with verified, rollback-safe migrations. Legacy entries upgrade at each account's next sign-in.
- GitHub Actions CI and a clean-environment wheel check.

### Changed
- Entry timestamps and lock state are encrypted (schema v2 onward).
- Login and unlock throttling persist in SQLite; unlock limits are per account with a cross-account ceiling.
- Server dependencies are an optional `server` extra; the recipient viewer needs only `argon2-cffi` and `cryptography`.

### Security
- Deleted and migrated rows no longer leave plaintext in SQLite free pages (`secure_delete` on every connection, `VACUUM` after the v1 to v2 table swap). Run `VACUUM` once on a database migrated by an earlier build.
- Pinned `cryptography` 50.0.2 and `python-multipart` 0.0.32 after `pip-audit` reported 25 known vulnerabilities in the previous pins.
- Stale cached separate-password keys can no longer corrupt an entry.
- Revoking a recipient also drops their cached keys; protected entries warn that their separate password is unchanged.

## 1.1.0

Schema v2 metadata encryption, persistent rate limits, session management, versioned backups, `pastry migrate`.

## 1.0.0

Single-user encrypted vault, separate-password entries, backups, web interface.
