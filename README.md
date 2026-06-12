<p align="center">
  <h1 align="center">🔐 vault</h1>
  <p align="center"><i>Encrypted credential manager — your secrets, your password, your machine</i></p>
  <p align="center">
    <img alt="Python" src="https://img.shields.io/badge/python-3.8+-blue?style=flat&logo=python">
    <img alt="cryptography" src="https://img.shields.io/badge/dep-cryptography-purple?style=flat">
    <img alt="license" src="https://img.shields.io/badge/license-MIT-green?style=flat">
  </p>
</p>

**vault** is a minimal encrypted key-value store for the command line. Secrets are encrypted with AES-128 via Fernet (symmetric encryption), protected by a master password. The store lives in `~/.vault/store.enc`. No cloud, no server, no backdoors.

---

## Installation

```bash
pip install cryptography
# Then just use vault.py directly
```

## Usage

### Initialize the store

```bash
python3 vault.py init
# The store is created at ~/.vault/store.enc
```

### Store a secret

```bash
python3 vault.py set github_token "ghp_abc123def456"
python3 vault.py set --quiet api_key "sk-..."    # suppress confirmation
```

### Retrieve a secret

```bash
python3 vault.py get github_token
# → ghp_abc123def456
```

### List all keys

```bash
python3 vault.py list
# Key               Created
# ─────────────────────────
# github_token      2025-06-12T01:30
# api_key           2025-06-12T01:31

python3 vault.py search token
# Key               Created
# ─────────────────────────
# github_token      2025-06-12T01:30
```

### Show metadata (without revealing value)

```bash
python3 vault.py show github_token
# Key:     github_token
# Created: 2025-06-12T01:30:15
```

### Rename or copy

```bash
python3 vault.py mv github_token gh_token    # rename
python3 vault.py cp gh_token gh_token_backup  # copy with new timestamp
```

### Delete a secret

```bash
python3 vault.py rm gh_token
```

### Export / Import

```bash
python3 vault.py export > backup.json
python3 vault.py import backup.json
```

## How it works

| Component | Detail |
|---|---|
| **Encryption** | AES-128 via `cryptography.fernet.Fernet` |
| **Key derivation** | PBKDF2-HMAC-SHA256, 600,000 iterations |
| **Salt** | Random 16 bytes, stored in `~/.vault/salt` |
| **Store** | JSON encrypted + base64, stored in `~/.vault/store.enc` |
| **Password** | Entered interactively via `getpass` (never stored, never logged) |

## Commands

| Command | Description |
|---|---|
| `init` | Create a new encrypted store |
| `set <key> <value>` | Store a secret (use `--quiet` to suppress output) |
| `get <key>` | Retrieve a secret |
| `show <key>` | Show key metadata without the value |
| `list` | List all keys |
| `search <query>` | Search keys by name (case-insensitive) |
| `mv <key> <newkey>` | Rename a key |
| `cp <key> <newkey>` | Copy a key (new timestamp) |
| `rm <key>` | Delete a key |
| `export` | Print all secrets as JSON to stdout |
| `import <file>` | Import secrets from a JSON file |

## Security notes

- Master password is never stored — only used to derive the encryption key
- PBKDF2 with 600K iterations makes brute-forcing expensive
- The store is encrypted at rest — reading `store.enc` without the password yields gibberish
- If you lose the password, the data is unrecoverable
- This is a **local-only** tool. No network access, no telemetry, no sync

## Requirements

- Python 3.8+
- `cryptography` package (`pip install cryptography`)

