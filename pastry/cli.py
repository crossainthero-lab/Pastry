"""Command-line interface: `pastry setup|start|admin|backup|restore`."""

from __future__ import annotations

import argparse
import getpass
import os
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import __version__
from . import auth as authmod
from . import crypto
from .backup import BackupError, create_backup, restore_backup, verify_backup
from .config import Settings, load_settings
from .db import SchemaError, Store
from .migrate import MigrationError, migrate_v1_to_v2


@dataclass
class Context:
    settings: Settings
    prompt_password: Callable[[str], str] = getpass.getpass
    prompt_text: Callable[[str], str] = input


class CliError(Exception):
    pass


def _entry_count(settings: Settings) -> int:
    if not settings.db_path.exists():
        return 0
    try:
        return Store(settings.db_path).entry_count()
    except sqlite3.Error:
        return 0


def _confirm_passwords(ctx: Context, prompt: str) -> str:
    first = ctx.prompt_password(prompt)
    second = ctx.prompt_password("Repeat the password: ")
    if first != second:
        raise CliError("The passwords do not match. Nothing was changed.")
    return first


# ----- commands ------------------------------------------------------------


def cmd_setup(_args: argparse.Namespace, ctx: Context) -> int:
    settings = ctx.settings
    if settings.auth_path.exists():
        raise CliError("Pastry is already set up. Use `pastry admin set-password` or `pastry admin set-username`.")
    if _entry_count(settings) > 0:
        raise CliError(
            "Vault data exists but config/auth.json is missing, so it cannot be decrypted. "
            "Restore auth.json from a backup, or move data/pastry.db away before running setup."
        )

    print("Pastry first-run setup")
    print("Choose an admin username and a master password (at least 12 characters).")
    print("There is no recovery option. If you forget the master password, the vault cannot be opened.\n")
    username = ctx.prompt_text("Admin username: ").strip()
    password = _confirm_passwords(ctx, "Master password: ")
    authmod.validate_username(username)
    authmod.validate_password(password)

    Store(settings.db_path).init()
    print("Deriving keys with Argon2id. This takes a moment on a small computer...")
    authmod.create_auth(settings.auth_path, username, password, settings.kdf)
    print(f"\nSetup complete. Configuration: {settings.auth_path}")
    print("Start the server with: pastry start")
    return 0


def cmd_start(args: argparse.Namespace, ctx: Context) -> int:
    try:
        import uvicorn

        from .web import create_app
    except ImportError as exc:
        raise CliError("The server needs its extra packages: pip install '.[server]'") from exc

    settings = ctx.settings
    if not settings.auth_path.exists():
        raise CliError("Pastry is not set up yet. Run: pastry setup")
    Store(settings.db_path).require_current()
    host = args.host or settings.host
    port = args.port or settings.port
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"WARNING: binding to {host} accepts network connections over plain HTTP.\n"
            "Only do this behind HTTPS (Caddy or Tailscale). See README.md.",
            file=sys.stderr,
        )
    for warning in authmod.permission_warnings(settings.auth_path):
        print(f"WARNING: {warning}", file=sys.stderr)

    app = create_app(settings)
    print(f"Pastry is running on http://{host}:{port} (Ctrl+C to stop)")
    uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False, server_header=False)
    return 0


def cmd_set_password(_args: argparse.Namespace, ctx: Context) -> int:
    path = ctx.settings.auth_path
    current = ctx.prompt_password("Current master password: ")
    new = _confirm_passwords(ctx, "New master password: ")
    authmod.validate_password(new)
    print("Re-wrapping the vault key. Entries are not re-encrypted.")
    authmod.change_password(path, current, new)
    print("Master password changed. All existing sessions have been signed out.")
    return 0


def cmd_set_username(args: argparse.Namespace, ctx: Context) -> int:
    path = ctx.settings.auth_path
    current = ctx.prompt_password("Current master password: ")
    username = args.username or ctx.prompt_text("New admin username: ")
    authmod.change_username(path, current, username)
    print("Username changed. All existing sessions have been signed out.")
    return 0


def cmd_status(_args: argparse.Namespace, ctx: Context) -> int:
    settings = ctx.settings
    if not settings.auth_path.exists():
        print(f"Pastry is not set up. Expected configuration at {settings.auth_path}")
        return 1
    auth = authmod.read_auth(settings.auth_path)
    warnings = authmod.permission_warnings(settings.auth_path)
    if settings.db_path.exists():
        warnings += authmod.permission_warnings(settings.db_path)
    entries = _entry_count(settings)
    lines = [
        "Pastry admin status",
        f"  Configuration file : {settings.auth_path}",
        f"  Admin username     : {auth.username}",
        "  Password hash      : Argon2id (stored; value not shown)",
        (
            f"  Key derivation     : Argon2id time={auth.kdf.time_cost} "
            f"memory={auth.kdf.memory_cost} KiB parallelism={auth.kdf.parallelism}"
        ),
        "  Vault key          : random 256-bit, wrapped with AES-256-GCM",
        f"  Database           : {settings.db_path} ({'present' if settings.db_path.exists() else 'missing'})",
        f"  Stored entries     : {entries}",
        f"  Session epoch      : {auth.session_epoch}",
        f"  Last credential change: {auth.updated_at}",
        f"  Session idle timeout : {settings.session_timeout_minutes} minutes (default; the UI can change it)",
    ]
    print("\n".join(lines))
    for warning in warnings:
        print(f"WARNING: {warning}")
    return 0


def cmd_backup(args: argparse.Namespace, ctx: Context) -> int:
    if args.rest and args.rest[0] == "verify":
        return cmd_backup_verify(args, ctx)
    if args.rest:
        raise CliError("Usage: pastry backup [--output-dir DIR]  or  pastry backup verify FILE [--password-check]")
    out_dir = Path(args.output_dir) if args.output_dir else ctx.settings.backup_dir
    target = create_backup(ctx.settings, out_dir)
    print(f"Backup written to {target} (mode 600, manifest version 2).")
    print("Store it somewhere safe. It needs your master password to be useful.")
    return 0


def cmd_backup_verify(args: argparse.Namespace, ctx: Context) -> int:
    if len(args.rest) < 2:
        raise CliError("Usage: pastry backup verify FILE [--password-check]")
    archive = Path(args.rest[1]).expanduser().resolve()
    password = None
    if args.password_check:
        password = ctx.prompt_password("Master password for this backup: ")
    report = verify_backup(ctx.settings, archive, password)
    print(f"Archive          : {report.archive}")
    print(f"Format version   : {report.format_version}")
    print(f"Checksums        : {report.checksums}")
    print(f"Integrity        : {report.integrity}")
    print(f"Schema version   : {report.schema_version}")
    print(f"Entries          : {report.entry_count}")
    print(f"Account username : {report.username}")
    if report.decrypted_unlocked is not None:
        print(f"Decrypted        : {report.decrypted_unlocked} unprotected entries OK; "
              f"{report.protected_entries} protected entries left sealed (need their own passwords)")
    for note in report.notes:
        print(f"Note             : {note}")
    print("Verification passed. The active vault was not modified.")
    return 0


def cmd_migrate(_args: argparse.Namespace, ctx: Context) -> int:
    settings = ctx.settings
    store = Store(settings.db_path)
    if not store.exists():
        raise CliError("No vault database found. Run: pastry setup")
    version = store.schema_version()
    if version == 2:
        print("The vault is already on schema v2. Nothing to do.")
        return 0
    if version != 1:
        raise CliError(f"Unknown schema version {version}; refusing to migrate.")
    print("Migrating schema v1 -> v2. Stop the server first (systemctl stop pastry).")
    password = ctx.prompt_password("Master password: ")
    auth = authmod.read_auth(settings.auth_path)
    dek = authmod.try_unlock(auth, password)
    if dek is None:
        raise CliError("Incorrect master password. Nothing was changed.")
    try:
        backup = create_backup(settings, settings.backup_dir)
        print(f"Pre-migration backup written: {backup}")
        count = migrate_v1_to_v2(store, dek)
    except (MigrationError, BackupError) as exc:
        raise CliError(f"Migration failed and was rolled back; the database is unchanged. ({exc})") from exc
    finally:
        crypto.wipe(dek)
    print(f"Migrated {count} entries to schema v2. Separate-password locks were preserved.")
    return 0


def cmd_open(args: argparse.Namespace, _ctx: Context) -> int:
    from . import tui

    path = Path(args.file).expanduser()
    if not path.exists():
        raise CliError(f"No such file: {path}")
    if not sys.stdout.isatty():
        raise CliError("`pastry open` needs an interactive terminal.")
    return tui.run(None, path.resolve(), args.delete_on_expiry, args.clear_after)


def cmd_inspect(args: argparse.Namespace, _ctx: Context) -> int:
    from . import package

    path = Path(args.file).expanduser()
    try:
        header = package.inspect_package(package.read_package_file(path))
    except (package.PackageError, OSError) as exc:
        raise CliError(str(exc)) from exc
    print(f"Package          : {header.name}")
    print(f"Created (UTC)    : {header.created_at}")
    print(f"Access type      : {header.access} (opens without the server)")
    print(f"Copy allowed     : {'yes' if header.allow_copy else 'no'} (enforced by the viewer only)")
    print(f"Expiry           : {header.expires_at or 'none'} (advisory)")
    print(f"File size        : {path.stat().st_size} bytes")
    print("Contents         : encrypted. Opening needs the package password.")
    return 0


def cmd_list_users(_args: argparse.Namespace, ctx: Context) -> int:
    auth = authmod.read_auth(ctx.settings.auth_path)
    print("Accounts:")
    print(f"  {auth.username}  (owner)")
    print("Multi-user accounts are disabled in this version. See SECURITY-REVIEW.md.")
    return 0


def cmd_multi_user_disabled(_args: argparse.Namespace, _ctx: Context) -> int:
    print(
        "error: multi-user accounts are not available in Pastry 1.1. The per-user key design is "
        "documented in SECURITY-REVIEW.md but not implemented, so no account is created or disabled.",
        file=sys.stderr,
    )
    return 2


def cmd_restore(args: argparse.Namespace, ctx: Context) -> int:
    archive = Path(args.archive).expanduser().resolve()
    if not args.yes:
        print("Stop the server first (systemctl stop pastry, or Ctrl+C) so the database is not in use.")
        answer = ctx.prompt_text("Type RESTORE to replace the current vault files: ").strip()
        if answer != "RESTORE":
            print("Restore cancelled.")
            return 1
    result = restore_backup(ctx.settings, archive)
    print(f"Restored {result['entries']} entries from {archive.name}.")
    print("Previous files were kept as *.before-restore-<timestamp>.")
    return 0


# ----- argument parsing ----------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pastry", description="Pastry Password Server")
    parser.add_argument("--version", action="version", version=f"pastry {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("setup", help="first-run setup: create the admin account").set_defaults(func=cmd_setup)

    opener = sub.add_parser("open", help="open a .pastry package in the terminal viewer")
    opener.add_argument("file", help="path to a .pastry file")
    opener.add_argument("--clear-after", type=float, default=30.0,
                        help="seconds before a copied value is cleared, if unchanged (default 30; 0 disables)")
    opener.add_argument("--delete-on-expiry", action="store_true",
                        help="delete this exact file when the package expires")
    opener.set_defaults(func=cmd_open)

    inspector = sub.add_parser("inspect", help="show non-secret package metadata")
    inspector.add_argument("file", help="path to a .pastry file")
    inspector.set_defaults(func=cmd_inspect)

    start = sub.add_parser("start", help="run the server in the foreground")
    start.add_argument("--host", help="bind address (default 127.0.0.1)")
    start.add_argument("--port", type=int, help="port (default 8787)")
    start.set_defaults(func=cmd_start)

    admin = sub.add_parser("admin", help="manage the admin account").add_subparsers(dest="admin_command", required=True)
    admin.add_parser("set-password", help="change the master password (asks for the old one)").set_defaults(
        func=cmd_set_password
    )
    username = admin.add_parser("set-username", help="change the admin username")
    username.add_argument("--username", help="new username (prompted if omitted)")
    username.set_defaults(func=cmd_set_username)
    admin.add_parser("status", help="show configuration without secrets").set_defaults(func=cmd_status)
    admin.add_parser("list-users", help="list accounts").set_defaults(func=cmd_list_users)
    admin.add_parser("create-user", help="(not available in 1.1)").set_defaults(func=cmd_multi_user_disabled)
    admin.add_parser("disable-user", help="(not available in 1.1)").set_defaults(func=cmd_multi_user_disabled)

    sub.add_parser("migrate", help="upgrade the vault database from schema v1 to v2").set_defaults(func=cmd_migrate)

    backup = sub.add_parser("backup", help="write a backup, or: backup verify FILE")
    backup.add_argument("--output-dir", help="directory for the archive (default: backups/)")
    backup.add_argument("--password-check", action="store_true",
                        help="with `backup verify`: also decrypt entries using the master password")
    backup.add_argument("rest", nargs="*", help=argparse.SUPPRESS)
    backup.set_defaults(func=cmd_backup)

    restore = sub.add_parser("restore", help="restore from a backup archive")
    restore.add_argument("archive", help="path to a pastry-backup-*.tar.gz file")
    restore.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    restore.set_defaults(func=cmd_restore)
    return parser


def main(argv: list[str] | None = None, context: Context | None = None) -> int:
    os.umask(0o077)  # new files and directories are private by default
    args = build_parser().parse_args(argv)
    if args.command is None:
        if sys.stdin.isatty() and sys.stdout.isatty():
            from . import tui

            return tui.run(None, None, False, 30.0)  # package picker in the current directory
        build_parser().print_help()
        return 0
    ctx = context or Context(settings=load_settings())
    try:
        return args.func(args, ctx)
    except (CliError, authmod.AuthError, BackupError, MigrationError, SchemaError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0


def entrypoint() -> None:
    raise SystemExit(main())
