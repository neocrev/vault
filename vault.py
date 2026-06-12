#!/usr/bin/env python3
"""vault — Encrypted credential manager with master password."""

import os, sys, json, base64, getpass, argparse
from pathlib import Path
from hashlib import pbkdf2_hmac
from datetime import datetime

try:
    from cryptography.fernet import Fernet
except ImportError:
    print("vault requires cryptography. Install: pip install cryptography", file=sys.stderr)
    sys.exit(1)

VAULT_DIR = Path.home() / ".vault"
STORE_FILE = VAULT_DIR / "store.enc"
SALT_FILE = VAULT_DIR / "salt"
ITERATIONS = 600_000

def derive_key(password: str, salt: bytes) -> bytes:
    key = pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return base64.urlsafe_b64encode(key)

def load_store():
    if not STORE_FILE.exists():
        return {}, None
    if not SALT_FILE.exists():
        print("vault: corrupt state (missing salt). Run 'vault init' again.", file=sys.stderr)
        sys.exit(1)
    password = getpass.getpass("Master password: ")
    salt = SALT_FILE.read_bytes()
    fernet = Fernet(derive_key(password, salt))
    try:
        data = fernet.decrypt(STORE_FILE.read_bytes())
        return json.loads(data), password
    except Exception:
        print("vault: wrong password or corrupt store.", file=sys.stderr)
        sys.exit(1)

def save_store(store, password, salt):
    fernet = Fernet(derive_key(password, salt))
    raw = json.dumps(store, ensure_ascii=False, indent=2).encode()
    STORE_FILE.write_bytes(fernet.encrypt(raw))

def cmd_init(args):
    if STORE_FILE.exists():
        print("vault: store already exists at ~/.vault/store.enc")
        print("  Delete it first if you want to re-initialize.")
        return
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    password = getpass.getpass("New master password: ")
    confirm = getpass.getpass("Confirm: ")
    if password != confirm:
        print("vault: passwords do not match.", file=sys.stderr)
        sys.exit(1)
    if len(password) < 4:
        print("vault: password must be at least 4 characters.", file=sys.stderr)
        sys.exit(1)
    salt = os.urandom(16)
    SALT_FILE.write_bytes(salt)
    save_store({}, password, salt)
    print("vault: store initialized at ~/.vault/store.enc")

def _modify_store(args, modifier):
    store, password = load_store()
    if password is None:
        store = {}
        password = getpass.getpass("New master password: ")
        confirm = getpass.getpass("Confirm: ")
        if password != confirm:
            print("vault: passwords do not match.", file=sys.stderr)
            sys.exit(1)
        if len(password) < 4:
            print("vault: password must be at least 4 characters.", file=sys.stderr)
            sys.exit(1)
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
        salt = SALT_FILE.read_bytes() if SALT_FILE.exists() else os.urandom(16)
        if not SALT_FILE.exists():
            SALT_FILE.write_bytes(salt)
    else:
        salt = SALT_FILE.read_bytes()
    modifier(store)
    save_store(store, password, salt)

def cmd_set(args):
    def mod(store):
        store[args.key] = {"value": args.value, "created": datetime.now().isoformat()}
    _modify_store(args, mod)
    if not args.quiet:
        print(f"vault: set '{args.key}'")

def cmd_get(args):
    store, _ = load_store()
    if not store or args.key not in store:
        print(f"vault: key '{args.key}' not found. Use 'vault list' to see all keys.", file=sys.stderr)
        sys.exit(1)
    print(store[args.key]["value"])

def cmd_show(args):
    store, _ = load_store()
    if not store or args.key not in store:
        print(f"vault: key '{args.key}' not found. Use 'vault list' to see all keys.", file=sys.stderr)
        sys.exit(1)
    entry = store[args.key]
    print(f"Key:     {args.key}")
    print(f"Created: {entry.get('created', 'unknown')[:19]}")

def cmd_search(args):
    store, _ = load_store()
    if not store:
        print("vault: store is empty.")
        return
    query = args.query.lower()
    matches = {k: v for k, v in store.items() if query in k.lower()}
    if not matches:
        print(f"vault: no keys matching '{args.query}'.")
        return
    width = max(len(k) for k in matches)
    print(f"{'Key':<{width}}  Created")
    print("-" * (width + 22))
    for k, v in sorted(matches.items()):
        created = v.get("created", "unknown")[:16]
        print(f"{k:<{width}}  {created}")

def cmd_list(args):
    store, _ = load_store()
    if not store:
        print("vault: store is empty.")
        return
    width = max(len(k) for k in store) if store else 10
    print(f"{'Key':<{width}}  Created")
    print("-" * (width + 22))
    for k, v in sorted(store.items()):
        created = v.get("created", "unknown")[:16]
        print(f"{k:<{width}}  {created}")

def cmd_rm(args):
    def mod(store):
        if args.key not in store:
            print(f"vault: key '{args.key}' not found.", file=sys.stderr)
            sys.exit(1)
        del store[args.key]
    _modify_store(args, mod)
    print(f"vault: removed '{args.key}'")

def cmd_mv(args):
    def mod(store):
        if args.key not in store:
            print(f"vault: key '{args.key}' not found. Use 'vault list' to see all keys.", file=sys.stderr)
            sys.exit(1)
        if args.newkey in store:
            print(f"vault: key '{args.newkey}' already exists. Choose a different name.", file=sys.stderr)
            sys.exit(1)
        store[args.newkey] = store.pop(args.key)
    _modify_store(args, mod)
    print(f"vault: renamed '{args.key}' -> '{args.newkey}'")

def cmd_cp(args):
    def mod(store):
        if args.key not in store:
            print(f"vault: key '{args.key}' not found. Use 'vault list' to see all keys.", file=sys.stderr)
            sys.exit(1)
        if args.newkey in store:
            print(f"vault: key '{args.newkey}' already exists. Choose a different name.", file=sys.stderr)
            sys.exit(1)
        store[args.newkey] = {**store[args.key], "created": datetime.now().isoformat()}
    _modify_store(args, mod)
    print(f"vault: copied '{args.key}' -> '{args.newkey}'")

def cmd_export(args):
    store, _ = load_store()
    print(json.dumps(store, ensure_ascii=False, indent=2))

def cmd_import_store(args):
    if not os.path.exists(args.file):
        print(f"vault: file '{args.file}' not found.", file=sys.stderr)
        sys.exit(1)
    with open(args.file) as f:
        imported = json.load(f)
    def mod(store):
        store.update(imported)
    _modify_store(args, mod)
    print(f"vault: imported {len(imported)} keys from '{args.file}'")

def cmd_change_password(args):
    if not STORE_FILE.exists():
        print("vault: no store found. Run 'vault init' first.", file=sys.stderr)
        sys.exit(1)
    store, _ = load_store()
    password = getpass.getpass("New master password: ")
    confirm = getpass.getpass("Confirm: ")
    if password != confirm:
        print("vault: passwords do not match.", file=sys.stderr)
        sys.exit(1)
    if len(password) < 4:
        print("vault: password must be at least 4 characters.", file=sys.stderr)
        sys.exit(1)
    salt = os.urandom(16)
    SALT_FILE.write_bytes(salt)
    save_store(store, password, salt)
    print("vault: password changed.")

def main():
    parser = argparse.ArgumentParser(description="Encrypted credential manager.")
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("init", help="Initialize a new encrypted store")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("set", help="Store a secret")
    p.add_argument("key", help="Key name")
    p.add_argument("value", help="Secret value to encrypt and store")
    p.add_argument("--quiet", "-q", action="store_true", help="Suppress 'vault: set' confirmation")
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("get", help="Retrieve a secret by key")
    p.add_argument("key", help="Key name to look up")
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("show", help="Show key metadata (created date, no value)")
    p.add_argument("key", help="Key name to inspect")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("search", help="Search keys by name pattern")
    p.add_argument("query", help="Case-insensitive search term")
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("list", help="List all stored keys")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("rm", help="Delete a secret by key")
    p.add_argument("key", help="Key name to remove")
    p.set_defaults(func=cmd_rm)

    p = sub.add_parser("mv", help="Rename a key")
    p.add_argument("key", help="Current key name")
    p.add_argument("newkey", help="New key name (must not exist)")
    p.set_defaults(func=cmd_mv)

    p = sub.add_parser("cp", help="Copy a key to a new name")
    p.add_argument("key", help="Source key name")
    p.add_argument("newkey", help="Destination key name (must not exist)")
    p.set_defaults(func=cmd_cp)

    p = sub.add_parser("export", help="Print all secrets as JSON to stdout")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("import", help="Merge secrets from a JSON file")
    p.add_argument("file", help="Path to JSON export file")
    p.set_defaults(func=cmd_import_store)

    p = sub.add_parser("change-password", help="Change the master password")
    p.set_defaults(func=cmd_change_password)

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        sys.exit(1)
    args.func(args)

if __name__ == "__main__":
    main()
