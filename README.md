# Pastry Password Server

A small, self-hosted, encrypted password vault for one person. It runs as a local web service on your own machine, in a browser, with no cloud dependency, analytics or telemetry.

- **Backend:** Python, FastAPI, SQLite
- **Frontend:** Jinja2 templates, vanilla JavaScript, plain CSS (no framework, no external fonts)
- **Cryptography:** Argon2id (`argon2-cffi`) and AES-256-GCM (`cryptography`)
- **Status:** unreviewed personal project. It has **not been security-audited**. See [Limitations](#limitations-and-open-security-concerns).

---

## 1. Directory structure

```
Pastry/
├── README.md                  this file
├── install.sh                 creates .venv, installs Pastry (optional --systemd)
├── pyproject.toml             package metadata; provides the `pastry` command
├── requirements.txt           pinned runtime dependencies
├── requirements-dev.txt       adds pytest and httpx for running the tests
├── .gitignore
├── config/
│   └── pastry.json.example    optional overrides (copy to pastry.json)
│       (auth.json is created by `pastry setup`)
├── data/                      created at setup: pastry.db (encrypted SQLite)
├── backups/                   created by `pastry backup`
├── deploy/
│   ├── pastry.service         systemd unit (hardened)
│   └── Caddyfile.example      HTTPS reverse proxy for the local network
├── pastry/
│   ├── __init__.py
│   ├── __main__.py            `python -m pastry`
│   ├── cli.py                 setup, start, admin, backup, restore
│   ├── config.py              settings and paths
│   ├── crypto.py              Argon2id and AES-256-GCM primitives
│   ├── auth.py                admin account, vault key wrapping, password change
│   ├── vault.py               entry encryption, separate-password layer, export/import
│   ├── db.py                  SQLite schema and helpers
│   ├── sessions.py            in-memory sessions and failure limiter
│   ├── backup.py              backup and restore
│   ├── web.py                 FastAPI app: pages, JSON API, security middleware
│   ├── templates/             base.html, login.html, app.html
│   └── static/                app.css, app.js
├── SECURITY-REVIEW.md         threat model, crypto design, audit findings (v1.1)
└── DEPLOYMENT.md              install, upgrade from v1.0, Tailscale, Caddy, systemd
└── tests/                     pytest suite (344 tests), frozen v1 fixture in fixtures/v1
```

---

## 2. Installation on Ubuntu

These commands are for Ubuntu 22.04 or newer. Python 3.10 or newer is required.

```bash
# 1. System packages (Python venv support)
sudo apt update
sudo apt install -y python3 python3-venv

# 2. Install Pastry into a virtual environment inside the project
cd ~/Documents/pastry-password-server/Pastry
./install.sh

# 3. First-run setup: choose an admin username and master password
.venv/bin/pastry setup

# 4. Start the server (listens on 127.0.0.1:8787 only)
.venv/bin/pastry start
```

Open `http://localhost:8787` in a browser on the same machine. Browsers treat `localhost` as a secure origin, so the Secure session cookie works there. For access from other devices, see [section 6](#6-accessing-pastry-from-other-devices).

If you prefer manual installation, the steps are: `python3 -m venv .venv`, `.venv/bin/pip install -r requirements.txt`, `.venv/bin/pip install -e .`, then `.venv/bin/pastry setup`.

---

## 3. Starting and stopping

| Action | Command |
|---|---|
| Start (foreground) | `.venv/bin/pastry start` |
| Start on another port | `.venv/bin/pastry start --port 9000` |
| Stop a foreground server | `Ctrl+C` in its terminal |
| Start as a service | `sudo systemctl start pastry` |
| Stop the service | `sudo systemctl stop pastry` |
| Restart after changing config | `sudo systemctl restart pastry` |
| Service status and logs | `systemctl status pastry`, `journalctl -u pastry` |

Stopping the server discards every session and the vault key held in memory. Everyone is then signed out.

---

## 4. Admin account

### Create the initial login

```bash
.venv/bin/pastry setup
```

The setup asks for a username and a master password (typed twice, minimum 12 characters). It then writes `config/auth.json` with mode `0600`. The file contains:

- the username,
- an Argon2id hash of the master password (for login),
- a random vault key, wrapped with AES-256-GCM under a key derived from the master password (Argon2id, random salt),
- the session epoch and timestamps.

Version 1.1 adds `pastry migrate` (upgrade from v1.0; see DEPLOYMENT.md) and `pastry admin list-users`. The `create-user` and `disable-user` commands exist but refuse, because multi-user accounts are not implemented (see SECURITY-REVIEW.md, section 8).

No plaintext password is stored anywhere. Setup refuses to run a second time, and it refuses if vault data exists without its `auth.json`, because that data could never be decrypted.

### Change the master password

```bash
.venv/bin/pastry admin set-password
```

It asks for the current password, then the new one twice. Pastry re-derives a key from the new password and re-wraps the **same** vault key. Entries are not re-encrypted, so they stay accessible. Before the new file is written, Pastry checks that the new password unwraps the same vault key. All existing sessions are then invalidated. Separate entry passwords are not affected.

### Change the username

```bash
.venv/bin/pastry admin set-username              # prompts for the new name
.venv/bin/pastry admin set-username --username alice
```

This requires the current master password and also signs out all sessions.

You can also edit `"username"` directly in `config/auth.json`. The server notices the change without a restart. Do not edit the other fields by hand.

### Inspect the account

```bash
.venv/bin/pastry admin status
```

It prints the username, KDF parameters, entry count, session epoch, and any file-permission warnings. It never prints the password hash or any secret.

---

## 5. Using Pastry

### Vault

- **Search** filters by name, URL, category and username as you type. Search runs after you sign in, against the decrypted data held by the server.
- **Favourites** and **Categories** are in the sidebar.
- Each entry has: name, username or email, password (with a generator), URL, category, favourite flag, notes, and any number of **custom fields**.
- **Add Field** creates a field with any name you like. Each field is either *Text* or *Masked secret*. Use **Up**, **Down** and **Remove** to reorder or delete fields.
- **Show** and **Copy** appear beside each value. Copy uses the clipboard, which keeps the value until you overwrite it.
- Deletion asks for confirmation.

### Password generator

Press **Generate** in the editor. You can choose the length (8 to 64) and the character sets. The generator runs in the browser using `crypto.getRandomValues`, and the password is never sent anywhere until you save the entry.

### Locked entries: "Require Separate Password"

Tick **Require Separate Password** in the editor and enter a second password of at least 12 characters.

- The entry's name, URL and category remain visible in the list, so you can find it.
- Its username, password, notes and custom fields are encrypted under a key derived from that second password. Your vault password cannot open them. Opening such an entry requires typing the second password in the entry view.
- The entry locks again when you leave it, press **Lock now**, sign out, when the session expires, or after `entry_idle_minutes` (default 5) without being used.
- Once it is unlocked in the session you can **Change separate password** or **Remove separate password**.
- **Losing a separate password makes that entry's protected data unrecoverable.** Keep it somewhere safe, separate from the master password.

### Settings

- **Appearance:** light (default) or dark. This choice is remembered in the browser only.
- **Session:** the inactivity timeout, 10 minutes by default (range 1 to 120).
- **Active sessions:** every signed-in browser, with revoke and *Log out other sessions*.
- **Change password:** asks for the current password. It signs out every session, including this one. Entries are kept.
- **Account:** shows the username.
- **Backup status:** the latest archive in `backups/`.
- **Backup and export:** see below.

### Backups

Two kinds of backup are available.

1. **Full backup (recommended):** on the server run

   ```bash
   .venv/bin/pastry backup
   ```

   This writes `backups/pastry-backup-YYYYmmdd-HHMMSS.tar.gz`, containing a consistent snapshot of `pastry.db` and `config/auth.json`, with mode `0600`. Copy it off the machine. The archive needs your master password to be useful.

2. **Encrypted export:** in **Settings**, choose a passphrase of at least 12 characters and download the export. The file is encrypted with an Argon2id key derived from that passphrase. Protected entries stay encrypted inside it. **Import** accepts such a file and skips entries that already exist (matched by their internal ID).

Check an archive before relying on it:

```bash
.venv/bin/pastry backup verify backups/pastry-backup-20261014-120000.tar.gz                 # checksums, integrity, entry count
.venv/bin/pastry backup verify backups/pastry-backup-20261014-120000.tar.gz --password-check  # also decrypts every unprotected entry
```

Verification works in a private staging folder and never changes the live vault.

To restore a full backup, stop the server first:

```bash
sudo systemctl stop pastry        # or Ctrl+C in the foreground terminal
.venv/bin/pastry restore backups/pastry-backup-20261014-120000.tar.gz
sudo systemctl start pastry
```

The previous files are kept as `*.before-restore-<timestamp>`.

---

## 6. Accessing Pastry from other devices

Pastry always listens on `127.0.0.1:8787`, so it is never exposed directly to the network. Choose one of the two methods below. Both provide HTTPS.

### Option A: Tailscale (recommended)

Tailscale creates a private WireGuard network between your devices. Only devices signed in to your tailnet can reach Pastry.

1. **Install and sign in on the Pastry machine**

   ```bash
   curl -fsSL https://tailscale.com/install.sh | sh
   sudo tailscale up
   ```

2. **Enable MagicDNS and HTTPS certificates** (one-time, in the Tailscale admin console at <https://login.tailscale.com/admin/dns>): turn on *MagicDNS*, then under *HTTPS Certificates* click *Enable HTTPS*.

3. **Expose Pastry to your tailnet over HTTPS**

   ```bash
   sudo tailscale serve --bg 8787
   tailscale serve status
   ```

   `tailscale serve status` shows the address, of the form `https://<machine-name>.<tailnet-name>.ts.net`. Tailscale issues the certificate. Pastry itself stays on `127.0.0.1`.

4. **Allow the name in Pastry.** Pastry rejects unknown `Host` headers as a defence against DNS rebinding. Add your Tailscale name to `config/pastry.json`:

   ```json
   {
     "allowed_hosts": ["127.0.0.1", "localhost", "machine-name.tailnet-name.ts.net"]
   }
   ```

   Then run `sudo systemctl restart pastry`. If the page shows "Bad Request" (HTTP 400), the host name in the address bar is missing from this list.

5. **Connect from your other devices.** Install Tailscale on each device, sign in to the same account, and open the `https://…ts.net` address shown in step 3.

6. **Restrict access to authorised devices.** In the admin console under *Access controls*, allow only the users or tagged devices that should reach this machine's port 443. Keep the default policy minimal.

7. **Never enable Funnel.** Funnel publishes a service to the public internet. Check with `tailscale funnel status`; it should report that Funnel is off. Do not run `tailscale funnel` for Pastry.

To stop sharing: `sudo tailscale serve reset`.

### Option B: Direct local-network access with Caddy

Use this when you want access from devices on your home Wi-Fi or Ethernet without Tailscale. Caddy terminates HTTPS on the LAN and forwards to Pastry on `127.0.0.1`. **Do not send passwords over plain HTTP on the LAN.**

1. **Find the server's LAN address**

   ```bash
   ip -4 addr show | grep 'inet 192'
   # or
   hostname -I
   ```

   For example `192.168.1.50`. Use the address on the interface connected to your network.

2. **Install Caddy**

   ```bash
   sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
   sudo apt update && sudo apt install -y caddy
   ```

   These are the official Caddy package instructions. Check the Caddy documentation if the repository layout has changed.

3. **Configure the hostname.** Copy `deploy/Caddyfile.example` to `/etc/caddy/Caddyfile`, and change `pastry.lan` to a name you will use. Make the name resolve to the server, either with a DNS entry in your router or with a line in each device's hosts file: `192.168.1.50  pastry.lan`.

4. **Allow the name in Pastry.** Add `"pastry.lan"` to `allowed_hosts` in `config/pastry.json`, then restart Pastry.

5. **Start Caddy and trust its certificate.** Caddy's `tls internal` creates a private certificate authority. Reload Caddy with `sudo systemctl reload caddy`. Then install the CA's root certificate on each device you use:

   - The root certificate is written by Caddy to `pki/authorities/local/root.crt` in its data directory, which is `/var/lib/caddy/.local/share/caddy/` for the system service. Copy that file from the server to each device.
   - On Windows, import it into *Trusted Root Certification Authorities*. On macOS, add it to Keychain Access and mark it *Always Trust*. On iOS, install the profile and enable full trust. On Android, install it under *CA certificates*. On Linux, copy it to `/usr/local/share/ca-certificates/caddy-root.crt` and run `sudo update-ca-certificates`.

   The browser will warn until the root is trusted. A warning is not normal and should not be bypassed.

6. **Restrict the firewall.** Pastry itself is not reachable from the LAN. Only Caddy's HTTPS port should be open, and only to your local subnet:

   ```bash
   sudo ufw default deny incoming
   sudo ufw allow OpenSSH
   sudo ufw allow from 192.168.1.0/24 to any port 443 proto tcp
   sudo ufw enable
   ```

   Adjust the subnet to match your network. Never forward port 443 on your router to this machine.

---

## 7. Running as a service at boot (systemd)

Create the account and run setup before enabling the service, because the service only starts an existing vault.

```bash
./install.sh --systemd            # installs /etc/systemd/system/pastry.service
sudo systemctl enable --now pastry
systemctl status pastry
```

Or install the unit manually: copy `deploy/pastry.service` to `/etc/systemd/system/`, replace the `__USER__`, `__GROUP__` and `__HOME__` placeholders, and run `sudo systemctl daemon-reload`.

The unit binds only to `127.0.0.1`, runs as your user, sets a restrictive umask, and restricts writes to `data/` and `backups/`.

---

## 8. Configuration

Optional settings live in `config/pastry.json` (copy `config/pastry.json.example`). Unknown keys are rejected.

| Key | Default | Meaning |
|---|---|---|
| `session_timeout_minutes` | `10` | Lock after this much inactivity (1 to 120). Also changeable in Settings. |
| `session_max_hours` | `12` | Absolute session lifetime, regardless of activity. |
| `cookie_secure` | `true` | Secure cookie flag. Keep it `true` and use HTTPS, or `localhost`. |
| `allowed_hosts` | `["127.0.0.1", "localhost"]` | Host names the server accepts. Add your Tailscale or LAN name. |
| `allowed_origins` | `[]` | Extra origins permitted for state-changing requests. Usually not needed. |
| `host`, `port` | `127.0.0.1`, `8787` | Bind address and port. Command-line flags override them. |

Setting `PASTRY_HOME=/path/to/dir` changes where `config/`, `data/` and `backups/` live. It defaults to the project directory.

---

## 9. Security design

### What is encrypted, and how

| Data | Protection |
|---|---|
| Entry name, URL, category, favourite flag | AES-256-GCM under the vault key |
| Username, password, notes, custom fields | AES-256-GCM under the vault key, or, for a protected entry, under that entry's separate-password key |
| Vault key | 256-bit random; wrapped with AES-256-GCM under a key derived from the master password (Argon2id, 64 MiB, 3 passes, 4 lanes, random 16-byte salt) |
| Admin login | Argon2id hash in `config/auth.json` |
| Separate entry password | Argon2id-derived key with its own random salt; the GCM tag is the verifier, so a wrong password fails authentication |
| Backups and exports | Already-encrypted data; exports additionally use a passphrase key derived with Argon2id |

Every blob carries a random 96-bit nonce and is bound to its context through AES-GCM associated data: the entry's random ID, and whether it is a metadata, normal-content or protected-content blob. A blob therefore cannot be moved to another entry or another layer without failing authentication.

### What is stored in plaintext

- Row IDs and random per-entry identifiers (used as authenticated data, not secret).
- Whether an entry is protected, and the per-entry salt and Argon2id parameters for its separate password.
- The admin username, Argon2id hash, KDF salt and parameters, and the wrapped vault key.

Since v1.1, entry names, URLs, categories, timestamps and separate-password lock state are all inside encrypted blobs. Blob sizes and the number of entries remain visible.

### Server-side decryption model: what it means

Pastry decrypts data on the server. Your browser receives plaintext only for the entries you view, and only while your session is active. This is required because search and rendering happen on the server.

- While a session is active, the server holds the vault key in RAM. Opened separate-password keys are also held in RAM until the entry is locked.
- A process-level compromise (malware running as your user, or root) can read that memory while the server is running. Encryption at rest does not protect against an attacker who controls the running machine.
- A stolen disk, a stolen backup, or a copy of `pastry.db` alone is not enough, because the vault key is wrapped under your master password. An attacker still needs to guess that password, and each guess costs about 64 MiB of memory and several passes of Argon2id.
- Protected entries stay opaque even to someone who has the vault key and a live session, until the separate password is entered.
- Python cannot guarantee that memory is zeroed. Pastry overwrites its keys in place on lock and sign-out, but copies made by the Python runtime or the cryptography library may remain until garbage collection.

### Session and web protections

- Session token: 256 bits from `secrets`. Only its SHA-256 digest is kept in memory.
- Cookie: `__Host-pastry_session` (or `pastry_session` when `cookie_secure` is false), `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and session-scoped.
- Sessions are in memory, so a restart signs everyone out. They expire after the inactivity timeout (default 10 minutes) and after `session_max_hours`. Changing the master password or username increments a session epoch, which invalidates all existing sessions.
- CSRF: every state-changing request must carry a per-session token in `X-CSRF-Token`, and it is compared in constant time.
- Origin policy: unsafe requests must come from the same origin (`Origin` host matches `Host`, or `Sec-Fetch-Site` is `same-origin`). The literal `Origin: null` is refused.
- Host policy: requests with a `Host` not in `allowed_hosts` are rejected with 400, which blocks DNS-rebinding attacks.
- Login rate limiting: 5 failed attempts from an address, or against a username, within 15 minutes blocks further attempts for 15 minutes. Failure messages are identical for an unknown user and a wrong password.
- Separate-password rate limiting: 5 failed attempts for an entry within 10 minutes blocks that entry for 10 minutes, for every session.
- Caching: all responses carry `Cache-Control: no-store`, `Pragma: no-cache` and `Expires: 0`.
- Headers: a restrictive Content-Security-Policy (`default-src 'none'`, scripts and styles only from `'self'`, no inline scripts), `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy: same-origin`, a Permissions-Policy that disables camera, microphone, geolocation and payment, and `Strict-Transport-Security` when cookies are Secure.
- Logging: the server logs nothing from request bodies, and access logging is disabled. Tests check that test secrets never appear in logs.
- File permissions: the process umask is `077`. `auth.json`, `pastry.db`, backups and exports are created `0600`; `config`, `data` and `backups` directories `0700`. `admin status` warns about looser permissions.
- No external resources: no fonts, scripts, analytics or CDN.

### Secrets handling

- No default or hard-coded passwords. Setup must be run by you.
- No passwords are stored in plaintext, and none appear in configuration files, logs or the database.
- The password generator runs in the browser and uses `crypto.getRandomValues` with rejection sampling to avoid bias.

---

## 10. Tests

Run the suite:

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

**Result: 192 passed.** (126 from v1.1, plus 66 for packages, the viewer, export and terminal tests.) The original 72 tests still pass, and v1.1 adds 54 more (migration, throttling, sessions, password change, re-lock, backup v2). Coverage by requirement:

| Requirement | Tests |
|---|---|
| First-run setup, and refusal to overwrite or run over orphaned data | `test_setup_admin.py` |
| Correct and incorrect login, generic error messages, login rate limiting | `test_web_security.py` |
| Master password change preserves encrypted entries; old credentials and old sessions rejected | `test_setup_admin.py`, `test_web_security.py`, `test_separate_password.py` |
| Username edit by file and by command | `test_setup_admin.py` |
| Encryption and decryption, tampering, AAD binding, nonce uniqueness | `test_crypto.py` |
| CRUD for entries and custom fields, search, categories, favourites, validation | `test_entries.py` |
| Per-entry separate passwords: lock and unlock, wrong attempts, lockout, change, remove, enable, editing rules | `test_separate_password.py` |
| Bypassing the UI does not bypass encryption (direct database decryption with the vault key fails) | `test_separate_password.py` |
| Failed secondary-password attempts and lockout | `test_separate_password.py` |
| Session expiry, logout, idle timeout configuration | `test_web_security.py` |
| CSRF, cross-origin refusal, Fetch Metadata, Host allow-list, caching, headers | `test_web_security.py` |
| Backup and restore, rejection of foreign archives | `test_backup_and_leaks.py` |
| Encrypted export and import, including protected entries | `test_separate_password.py` |
| No plaintext in the database, config, backups, exports or logs | `test_backup_and_leaks.py` |
| File permissions on config, database and backups | `test_backup_and_leaks.py` |

In addition, the following were run by hand against the live server in headless Chrome, and are not part of the pytest suite:

- Login, wrong-password refusal, creating an entry with a generated password and a secret custom field, reveal and copy.
- Creating a protected entry, wrong separate password, correct unlock, lock now, and auto-relock when navigating away.
- Change and remove of the separate password through their dialogs, and delete with cancel and confirm.
- Search, category and favourite filtering, settings (dark mode and timeout), encrypted export download and import, sign-out.
- Mobile layout at 390 px width: the navigation drawer opens and closes, and there is no horizontal scrolling.

Lint: `pyflakes` reports no issues.

---

## 11. Limitations and open security concerns

Please read these before relying on Pastry for anything important.

1. **Not audited.** This is a personal project. It has had no independent security review and no penetration test.
2. **Server-side decryption.** Unlocked data is decrypted in the server process while a session is active. Anyone who can read the running process's memory (root or malware running as your user) can read it. This is inherent to the requested design.
3. **Plaintext metadata.** Row IDs, random per-entry identifiers, blob sizes and entry counts are visible. Everything else about an entry is encrypted since v1.1.
4. **No recovery.** There is no backdoor, reset link or recovery key. Losing the master password makes the vault unrecoverable. Losing a separate entry password makes that entry's protected data unrecoverable. Keep backups and write down your passwords somewhere safe.
5. **Key derivation is fixed in code.** Argon2id parameters (64 MiB, 3 passes, 4 lanes) are compile-time defaults. They are stored with each key, so they can be changed later, but there is no setting for them yet. On this development machine one Argon2id operation takes about 40 ms. Login performs two of them. Expect it to be much slower on a Raspberry Pi; I have not measured that.
6. **Sessions and rate limits are in memory.** A restart signs everyone out and resets the login and separate-password failure counters. Behind a reverse proxy, every client appears as the proxy's address, so the login limit applies to all clients together.
7. **Clipboard.** Copied values stay on the system clipboard until something else replaces them. Pastry does not clear it.
8. **Browser exposure.** Revealed values are present in the browser's DOM and memory while shown. A compromised browser or browser extension can read them.
9. **Secure cookie requires HTTPS.** Browsers only send `Secure` cookies over HTTPS, or to `localhost`. Use Tailscale or Caddy for remote access. Do not set `cookie_secure` to `false` on a network.
10. **Login form has no CSRF token.** It relies on the Origin and Fetch Metadata checks plus `SameSite=Strict` cookies, which are supported by current browsers. An attacker cannot make a victim's browser post a login from another site.
11. **Python memory handling.** Key buffers are overwritten on lock, but Python may keep copies, so secrets may survive in memory after locking.
12. **Pastry does not manage TLS.** For LAN access, you are responsible for trusting the Caddy root certificate on each device. For Tailscale, trust relies on Tailscale's certificate issuance.
13. **Single user.** There is one admin account. Multi-user accounts and entry sharing are not implemented in v1.1 (see SECURITY-REVIEW.md, section 8). There is no two-factor authentication.
14. **Backups are sensitive.** Archives contain the encrypted database and `auth.json`. Their confidentiality depends on the master password, and an attacker can try guesses offline against them.
15. **Restoring is not transactional with a running server.** Stop the server before `pastry restore`.
16. **No automated browser tests.** The front-end is covered by manual browser testing only. The pytest suite exercises every API the front-end uses.

---

## Licence and use

Personal project. Use it at your own risk, and keep a tested backup before you move any real credentials into it.

---

## 12. Secure packages (`.pastry`), v1.2 branch

Export selected entries as an encrypted file, then open it in a terminal.

**Export.** Tick entries in the list, then press *Export as Pastry*. Choose a package name, a package password (12 or more characters; use *Generate*), whether the viewer may copy values, and an advisory expiry. Protected entries must be unlocked first. The file is downloaded directly and is never stored on the server.

**Open (recipient).** Put the `.pastry` file in a folder and run:

```bash
pastry              # picker: lists .pastry files in the current folder only
pastry open server-access.pastry
pastry inspect server-access.pastry     # metadata only, no decryption
```

Keys in the viewer: Up/Down move, Enter opens, R reveals or hides secrets, C copies (only if the sender allowed it), Tab moves to the next field, Esc goes back, Q quits.

**Limits you must understand.** Expiry is advisory and is enforced only by this viewer. Copying can be disabled in the viewer but cannot be prevented in general. Anyone with the file and its password can read it at any time. Timed and one-time packages that need a release server are **not implemented**. See `docs/CRYPTOGRAPHY-V12.md` and `SECURITY-REVIEW.md` section 11.

**Recipient installation** (base dependencies only, no server):

```bash
pipx install ./pastry_password_server-1.1.0-py3-none-any.whl
pastry --version
pipx upgrade pastry-password-server          # after installing a newer wheel
pipx uninstall pastry-password-server
```

Build the wheel from the repository with `pip wheel . --no-deps -w dist/`. Copy-to-clipboard needs one of `xclip`, `xsel`, `wl-clipboard` (Linux) or `pbcopy` (macOS).

**Multi-user accounts and entry sharing are not in this branch.** `pastry admin create-user` refuses, and there is no sharing feature.

---

## 13. Timed packages (server-enforced), branch `feature/v1.2-secure-sharing`

Set `public_url` in `config/pastry.json` (see DEPLOYMENT.md section I), then choose an access type in the export dialog:

- **Expires after opening:** 5 minutes, 15 minutes, 1 hour or 24 hours, counted from the first successful release on the server.
- **Absolute deadline:** up to 30 days from creation.
- **One-time:** the first successful release consumes the package.

Manual revocation is always available on the **Packages** page, and so is deletion. Revocation and expiry are enforced by the server clock. The file alone, with its password, cannot be opened: the server must release the key.

Recipients run `pastry open FILE.pastry`. The viewer asks them to confirm the server host, then checks the server every 30 seconds and closes the secrets if the package expires, is revoked, or the server stops answering.

**Important limits.** A recipient who has already opened a package may keep what they saw, and the key they were given. Revocation cannot undo that. Timed packages cannot be opened when the server is unreachable. See `SECURITY-REVIEW.md` section 12 and `docs/CRYPTOGRAPHY-V12.md` section 10. The design has had only a self-review.

---

## 14. Multi-user accounts and entry sharing (1.2.0rc1)

**Accounts.** The owner is created by `pastry setup`. Other people get an account through an invitation:

```bash
.venv/bin/pastry admin create-user          # prompts for a username and prints an invitation link
.venv/bin/pastry admin list-users           # accounts, status, pending invitations
.venv/bin/pastry admin disable-user alice   # ends alice's sessions; her encrypted data is kept
```

An invitation works once and expires after 72 hours. The invitee chooses their own master password, and the owner never sees it. Each account has its own encrypted vault, and the owner cannot read another account's entries. A forgotten master password cannot be recovered by anyone.

**Sharing one entry.** Open an entry you own and press **Share**. Choose an account and permissions:

- **View** (always): read and copy the credentials.
- **Edit**: change the name, URL and credential content.
- **Export**: package the entry as `.pastry`. Off unless granted.

Only the entry's owner can share, change permissions or revoke. **Manage Access** is in the same dialog. The recipient finds the entry under **Shared With Me**. A recipient must have signed in once before they can receive a share.

**Revoking.** Access ends on the recipient's next request, and the entry's key is replaced for everyone who keeps access. Anything the person already saw or copied cannot be recalled. An entry with a separate password stays protected by that password: if the person knew it, change it after revoking.

**Protected entries.** Sharing never removes "Require Separate Password". A recipient needs the sharing grant and the separate password, which you give them yourself.

**Upgrading.** The first owner sign-in after the upgrade takes a verified backup and migrates the database. Each account's older entries are converted to per-entry keys at that account's next sign-in. `pastry migrate` does the schema step from the command line.

**Trust model.** Pastry decrypts on the server. It is not end-to-end encrypted, and a compromised server can read open vaults and substitute sharing keys. See `docs/MULTIUSER-CRYPTO.md` and `SECURITY-REVIEW.md` section 14.
