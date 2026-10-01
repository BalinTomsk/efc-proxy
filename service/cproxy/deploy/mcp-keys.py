#!/usr/bin/env python3
"""Manage cproxy's MCP client keys (cproxy 0.20.0, McpKeyStore).

The database holds only SHA-256 hashes. A key's token is printed ONCE, by `add`, and cannot be
recovered afterwards -- lose it and you `disable` that key and `add` a new one.

    python mcp-keys.py [--db PATH] add <key_id> [--label TEXT] [--expires YYYY-MM-DD]
    python mcp-keys.py [--db PATH] list
    python mcp-keys.py [--db PATH] disable <key_id>
    python mcp-keys.py [--db PATH] enable <key_id>
    python mcp-keys.py [--db PATH] remove <key_id>

The default --db is ../../../secret/mcpkeys.sqlite (gitignored). Upload it to the droplet's
mcpkeys/ directory; cproxy notices a changed file within CPROXY_MCP_KEYS_RELOAD_SECONDS, so
revoking a key needs no restart. Standard library only.
"""
import argparse
import datetime
import hashlib
import pathlib
import re
import secrets
import sqlite3
import sys

DEFAULT_DB = pathlib.Path(__file__).resolve().parents[3] / "secret" / "mcpkeys.sqlite"
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SCHEMA = """
CREATE TABLE IF NOT EXISTS mcp_keys (
    key_id       TEXT PRIMARY KEY,
    token_sha256 TEXT NOT NULL UNIQUE,
    label        TEXT NOT NULL,
    created_utc  TEXT NOT NULL,
    expires_utc  TEXT NULL,
    disabled     INTEGER NOT NULL DEFAULT 0
)"""


def connect(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute(SCHEMA)
    return db


def cmd_add(db, args):
    if not KEY_ID.match(args.key_id):
        sys.exit("key_id: 1-64 of letters, digits, '.', '_', '-'")
    if args.expires:
        try:
            datetime.date.fromisoformat(args.expires)
        except ValueError:
            sys.exit("--expires must be YYYY-MM-DD")
    token = "ffmcp_" + secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    try:
        db.execute(
            "INSERT INTO mcp_keys (key_id, token_sha256, label, created_utc, expires_utc, disabled) "
            "VALUES (?, ?, ?, ?, ?, 0)",
            (args.key_id, digest, args.label or args.key_id,
             datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"), args.expires),
        )
    except sqlite3.IntegrityError:
        sys.exit(f"key_id '{args.key_id}' already exists")
    db.commit()
    print(f"Added '{args.key_id}'. Its token, shown only this once:\n\n    {token}\n")
    print("Put it in the MCP client's Authorization header as: Bearer <token>")


def cmd_list(db, _args):
    rows = db.execute(
        "SELECT key_id, label, created_utc, COALESCE(expires_utc, '-'), disabled FROM mcp_keys ORDER BY key_id"
    ).fetchall()
    if not rows:
        print("(no keys)")
        return
    for key_id, label, created, expires, disabled in rows:
        state = "DISABLED" if disabled else "active"
        print(f"{key_id:24} {state:8} created {created}  expires {expires:10}  {label}")


def set_disabled(db, key_id, value):
    if db.execute("UPDATE mcp_keys SET disabled = ? WHERE key_id = ?", (value, key_id)).rowcount == 0:
        sys.exit(f"no key '{key_id}'")
    db.commit()
    print(f"'{key_id}' {'disabled' if value else 'enabled'}")


def cmd_remove(db, args):
    if db.execute("DELETE FROM mcp_keys WHERE key_id = ?", (args.key_id,)).rowcount == 0:
        sys.exit(f"no key '{args.key_id}'")
    db.commit()
    print(f"'{args.key_id}' removed")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", type=pathlib.Path, default=DEFAULT_DB)
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("add")
    add.add_argument("key_id")
    add.add_argument("--label")
    add.add_argument("--expires")
    sub.add_parser("list")
    for name in ("disable", "enable", "remove"):
        sub.add_parser(name).add_argument("key_id")
    args = parser.parse_args()

    db = connect(args.db)
    try:
        if args.command == "add":
            cmd_add(db, args)
        elif args.command == "list":
            cmd_list(db, args)
        elif args.command == "disable":
            set_disabled(db, args.key_id, 1)
        elif args.command == "enable":
            set_disabled(db, args.key_id, 0)
        else:
            cmd_remove(db, args)
    finally:
        db.close()


if __name__ == "__main__":
    main()
