# Pastry Deployment Guide (v1.1)

Target: Ubuntu 22.04 or newer, on x86 or Raspberry Pi OS / Ubuntu for Raspberry Pi. Python 3.10 or newer.

> **Status of these instructions.** The fresh-install steps and the upgrade steps were run against a scratch copy on the development machine. The **Tailscale** and **Caddy/LAN** steps are documented from the vendors' procedures, but they have **not been run here** because no tailnet or LAN was available. Check each one on your own machine.

Throughout, `PASTRY_DIR` means the project directory, for example `~/Documents/pastry-password-server/Pastry`.

---

## A. Fresh installation

```bash
sudo apt update
sudo apt install -y python3 python3-venv

cd ~/Documents/pastry-password-server/Pastry
./install.sh                 # creates .venv, installs pinned dependencies
.venv/bin/pastry setup       # asks for admin username and master password
.venv/bin/pastry start       # foreground, http://127.0.0.1:8787 (Ctrl+C to stop)
```

Then, optionally, install the service (section D).

---

## B. Upgrading an existing v1.0 installation

**Do not skip the backup.** The migration is transactional and tested, but a backup is the only rollback path if something outside the tests goes wrong.

1. **Find out how Pastry is running.**

   ```bash
   systemctl is-enabled pastry 2>/dev/null && echo "systemd service present" || echo "no service"
   systemctl is-active pastry 2>/dev/null
   ```

2. **Stop the server** so the database is not in use.

   ```bash
   sudo systemctl stop pastry        # or Ctrl+C in the foreground terminal
   ```

3. **Back up the current vault** (works on v1.0 archives too). Copy the archive off the machine.

   ```bash
   cd ~/Documents/pastry-password-server/Pastry
   .venv/bin/pastry backup
   ls -l backups/
   .venv/bin/pastry backup verify backups/pastry-backup-*.tar.gz     # checks the archive, no password needed
   cp -a data config ~/pastry-v1.0-files-$(date +%Y%m%d)              # extra plain copy, mode preserved
   ```

4. **Update the code** (copy the new `Pastry/` directory over the old one, or `git pull` if you track it in git). Do not delete `data/`, `config/` or `backups/`.

5. **Reinstall dependencies and the package.**

   ```bash
   ./install.sh
   ```

6. **Migrate the database** (asks for the master password; creates its own pre-migration backup first).

   ```bash
   .venv/bin/pastry migrate
   ```

   Expected output: a pre-migration backup path, then "Migrated N entries to schema v2".

7. **Verify with the password**, which decrypts every unprotected entry in an isolated copy and leaves the live vault untouched.

   ```bash
   .venv/bin/pastry backup                                   # post-migration backup
   .venv/bin/pastry backup verify backups/$(ls -t backups | head -1) --password-check
   ```

8. **Start again.**

   ```bash
   sudo systemctl start pastry      # or: .venv/bin/pastry start
   ```

**Rollback**, if needed, is `sudo systemctl stop pastry` followed by `.venv/bin/pastry restore backups/<the pre-migration archive>.tar.gz --yes`. Then reinstall the v1.0 code. The current files are kept as `*.before-restore-*`.

The v1.0 `config/auth.json` is compatible with v1.1. The password, the vault key and the separate-password locks are unchanged by the migration.

---

## C. Tailscale (recommended for remote access)

Pastry stays bound to `127.0.0.1:8787`. Tailscale Serve publishes it to your tailnet over HTTPS. Funnel must stay off.

1. **Install and sign in** on the Pastry machine.

   ```bash
   curl -fsSL https://tailscale.com/install.sh | sh
   sudo tailscale up
   ```

   Sign in with the account you use for all your devices. On each other device, install Tailscale and sign in to the same account. Approve new devices in the admin console if your tailnet requires it.

2. **Enable MagicDNS and HTTPS** (one-time, in the admin console, *DNS* page): turn on *MagicDNS*, and under *HTTPS Certificates* choose *Enable HTTPS*.

3. **Serve Pastry over HTTPS within your tailnet.**

   ```bash
   sudo tailscale serve --bg 8787
   tailscale serve status
   ```

   `tailscale serve status` shows the address `https://<machine-name>.<tailnet-name>.ts.net`. That is the address to use on your devices.

4. **Allow that name in Pastry.** Pastry rejects Host headers it does not know. Add the name to `config/pastry.json` (create it from the example if missing):

   ```json
   {
     "allowed_hosts": ["127.0.0.1", "localhost", "machine-name.tailnet-name.ts.net"]
   }
   ```

   ```bash
   sudo systemctl restart pastry
   ```

   If the page shows "Bad Request" (400), the name in the address bar is not in this list.

5. **Restrict access.** In the admin console, *Access controls*, allow only your own users or tagged devices to reach this machine on port 443. Keep the default ACL minimal.

6. **Confirm Funnel is off.**

   ```bash
   tailscale funnel status      # must not show Pastry as public
   ```

   Never run `tailscale funnel` for Pastry. It publishes the service to the public internet.

To stop sharing: `sudo tailscale serve reset`.

---

## D. Caddy over the local network (alternative)

Use this only with HTTPS. Do not expose Pastry over plain HTTP on a LAN.

1. **Install Caddy** from the official repository (see https://caddyserver.com/docs/install#debian-ubuntu-raspbian). The repository steps there are authoritative.

2. **Set the name and the configuration.** Copy `deploy/Caddyfile.example` to `/etc/caddy/Caddyfile` and change `pastry.lan` to the name your devices will use. Keep `tls internal`, which makes Caddy issue certificates from its own private CA.

   ```caddyfile
   pastry.lan {
       tls internal
       reverse_proxy 127.0.0.1:8787
       header -Server
   }
   ```

   Make the name resolve to the server's LAN address, with a router DNS entry or a line in each device's hosts file. Find the server address with `hostname -I`.

3. **Allow the name in Pastry**: add `"pastry.lan"` to `allowed_hosts` in `config/pastry.json`, then `sudo systemctl restart pastry`.

4. **Reload Caddy and trust its root certificate** on every client device.

   ```bash
   sudo systemctl reload caddy
   sudo cat /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt   # copy this to each device
   ```

   - Windows: import into *Trusted Root Certification Authorities*.
   - macOS: add to Keychain Access, then set *Always Trust*.
   - iOS: install the profile, then enable full trust in *Certificate Trust Settings*.
   - Android: install under *CA certificates* in Security settings.
   - Linux: copy to `/usr/local/share/ca-certificates/caddy-root.crt`, then run `sudo update-ca-certificates`.

   Do not click through certificate warnings. A warning means the root is not trusted, or the name does not match.

5. **Firewall.** Pastry itself is not reachable from the LAN. Open only HTTPS, and only to your local subnet.

   ```bash
   sudo ufw default deny incoming
   sudo ufw allow OpenSSH
   sudo ufw allow from 192.168.1.0/24 to any port 443 proto tcp
   sudo ufw enable
   sudo ufw status verbose
   ```

   Change the subnet to yours. Never forward port 443 from your router to this machine.

---

## E. systemd service (start at boot)

```bash
cd ~/Documents/pastry-password-server/Pastry
./install.sh --systemd                 # writes /etc/systemd/system/pastry.service
sudo systemctl enable --now pastry
systemctl status pastry
journalctl -u pastry -n 50 --no-pager
```

The unit runs as your user, binds only to 127.0.0.1, uses `UMask=0077`, and allows writes only to `data/` and `backups/`. Check the rendered file with `systemd-analyze verify /etc/systemd/system/pastry.service`.

Start and stop: `sudo systemctl start|stop|restart pastry`.

If the unit is already installed from v1.0, rerun `./install.sh --systemd`, which overwrites the unit file. Then `sudo systemctl daemon-reload` and `sudo systemctl restart pastry`.

---

## F. Local development

`http://localhost:8787` works without HTTPS because browsers treat `localhost` as a secure origin, so Secure cookies are accepted there. Do not use `http://` with any other host name.

---

## G. Configuration reference

`config/pastry.json` (optional, see `config/pastry.json.example`):

| Key | Default | Notes |
|---|---|---|
| `allowed_hosts` | `["127.0.0.1", "localhost"]` | Add the Tailscale or Caddy name |
| `session_timeout_minutes` | `10` | Inactivity sign-out, 1 to 120 |
| `session_max_hours` | `12` | Absolute session lifetime |
| `entry_idle_minutes` | `5` | A separate-password entry re-locks after this long unused |
| `login_max_failures`, `login_lockout_minutes` | `5`, `15` | Persistent login throttle |
| `entry_max_failures`, `entry_lockout_minutes` | `5`, `10` | Persistent separate-password throttle |
| `cookie_secure` | `true` | Keep true |
| `allowed_origins` | `[]` | Usually empty |

Unknown keys are rejected at startup.

---

## H. Recipient viewer (no server)

Recipients need only the viewer. They do not need the server source, the sender's repository, or any server configuration.

```bash
pip wheel . --no-deps -w dist/          # run by the sender, from the repository
pipx install dist/pastry_password_server-1.1.0-py3-none-any.whl
```

Upgrade with `pipx upgrade pastry-password-server` after installing a newer wheel. Uninstall with `pipx uninstall pastry-password-server`. Clipboard support needs `xclip`, `xsel` or `wl-clipboard` on Linux.

**Time-limited sharing through the Tailscale release service is not implemented in this version.** The Tailscale access note for a release service applies only once that service exists. Until then, use offline packages and share the password through a different channel.

---

## I. Timed (server-enforced) packages over Tailscale

Timed packages need the recipient's viewer to reach this server while the package is valid. The release protocol runs on the same port as the web interface, so the same Tailscale address serves both.

**Requirements**

1. Pastry runs on this machine, bound to `127.0.0.1:8787`, as in section C.
2. `config/pastry.json` contains the HTTPS address recipients will use, and that name is in `allowed_hosts`:

   ```json
   {
     "public_url": "https://machine-name.tailnet-name.ts.net",
     "allowed_hosts": ["127.0.0.1", "localhost", "machine-name.tailnet-name.ts.net"]
   }
   ```

3. Tailscale Serve publishes the port over HTTPS: `sudo tailscale serve --bg 8787`. Confirm with `tailscale serve status`. Do not enable Funnel.
4. **Recipients need network access to the release service.** Each recipient must be on the same tailnet with a device that Tailscale's access controls allow to reach this machine on port 443. Without that access, `pastry open` reports that the server cannot be reached, and it does not fall back to offline decryption.
5. Recipients install the viewer (section H), then run `pastry open FILE.pastry`. They confirm the host shown on screen, which must be your `public_url` host.

**Operational notes**

- `config/release.key` is created the first time a timed package is made. Keep it out of backups (the backup command already excludes it) and keep its permissions at 0600.
- Restoring a backup to another machine leaves timed packages unreleasable unless `release.key` is also restored. This is deliberate.
- To revoke everything quickly, stop the service (`sudo systemctl stop pastry`), or revoke packages individually on the Packages page.
- Expired release material is erased at startup and whenever packages are listed.
- Upgrading from v2 needs `.venv/bin/pastry migrate` before the new server starts. The migration is additive and makes a backup first.

**Not tested here:** the Tailscale steps above were not run, because no tailnet exists on the development machine.
