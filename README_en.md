# zkv · Zero Knowledge Vault

> 🔐 A local-first, end-to-end encrypted personal vault. Your passphrase never leaves your machine, keys never touch disk, and a `.zkv` file away from your computer is just meaningless ciphertext.

English | [中文](README.md)

![Rust](https://img.shields.io/badge/Rust-edition%202024-orange)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL-green)
![Tests](https://img.shields.io/badge/tests-215%20passed-success)

A terminal-based manager for passwords / notes / cards with a sci-fi TUI ([ratatui-sci-fi](https://crates.io/crates/ratatui-sci-fi) Cyberpunk theme). All data is encrypted at rest with **Argon2id + XChaCha20-Poly1305**; ships with a fully **scriptable, TTY-free headless CLI**.

---

## ✨ Features

- 🔒 **Zero-knowledge encryption** — Argon2id derives the key from your passphrase; XChaCha20-Poly1305 encrypts the whole database. Keys are zeroized on drop and never written to disk.
- 🗄️ **Multiple vaults** — Each `.zkv` file has its own passphrase; manage several vaults side by side.
- 📇 **Multiple entry types** — Password, Note, and Card presets; fields are stored as JSON for easy extension.
- 🔎 **Full-text search** — Powered by SQLite FTS5 over titles and content.
- 🏷️ **Categories & tags** — Hierarchical categories + many-to-many tags + favorites, freely combinable.
- 🖼️ **Embedded attachments** — Images / documents are stored inside the database and encrypted with it.
- 🔢 **TOTP codes** — Store 2FA secrets and generate live 6-digit codes (RFC 6238). Import a QR directly: `--qr <local-image>` or `--qr-url <http(s)/data: URL>` auto-decodes the `otpauth://` URI into the entry (no need to scan/extract the text yourself).
- 🧩 **Field templates** — Generic field/template model with 8 built-in presets (password/note/card/wifi/bank/ssh/identity/email); fields are typed (Text/Secret/Multiline/TOTP) and drive rendering/copying; old vaults auto-migrate.
- 🎲 **Password generation** — CSPRNG strong passwords (configurable length / symbols / ambiguous chars).
- 💻 **Headless CLI** — Fully scriptable, no TTY required; passphrase from env var / file / prompt.
- 🔄 **Passphrase-caching agent** — Transparently caches the derived key: type the passphrase once and skip Argon2id across consecutive commands; auto-clears on idle (ssh-agent/sudo style; key **lives in RAM only, never on disk**).
- 🔁 **Import / export** — Lossless JSON round-trip, or flat CSV (passwords), for migration and backup.
- 🎨 **Sci-fi TUI** — header status bar + list/detail panes + footer keybar, neon rounded panels, fully keyboard-driven.
- ⏱️ **Security details** — Clipboard auto-clears 20s after copying; idle auto-lock; atomic writes prevent corruption; files are `0600`.

## 🖥️ Preview

```
┌ Items ─────────────┬─ Detail ──────────────────┐
│ ★ [PW] GitHub Login│ Title:    GitHub Login    │
│   [PW] GitLab Token│ Type:     Password        │
│ ★ [NO] Secret Diary│ Username: alice           │
│   [CD] Visa ****   │ Password: •••••••••  [y]  │
│                    │ URL:      github.com      │
│                    │ TOTP:     586148  (~14s)  │
│                    │ 📎 report.pdf (12345)     │
└────────────────────┴───────────────────────────┘
[normal] n:new e:edit x:del /:search y:copy o:otp a:att l:lock c:cat t:tag q:quit
```

## 🚀 Quick Start

Requires Rust 1.85+ (edition 2024).

```bash
git clone <repo-url> zkv && cd zkv
cargo run --release -- new  ~/my.zkv     # create a new vault (set passphrase in TUI)
cargo run --release -- open ~/my.zkv     # open an existing vault
```

> 💡 `<path>` is optional — it defaults to `~/.zkv/default.zkv`. e.g. `zkv init`, `zkv ls`, `zkv open`, `zkv get 1`.

Or install to `$CARGO_HOME/bin`:

```bash
cargo install --path .
zkv new ~/my.zkv
```

## 💻 Headless CLI

Parallel to the TUI, fully **scriptable and TTY-free** (passphrase from `ZKV_PASSPHRASE` env / `--passfile` / interactive prompt):

```bash
zkv init   [~/my.zkv]                         # non-interactive create (refuses to overwrite); omit path → ~/.zkv/default.zkv
zkv passwd [~/my.zkv]                         # change the master passphrase (verify old; new salt + key)
zkv gen    [24] [--no-symbols] [--no-ambiguous]  # strong random password (no vault needed)
# <path> is optional (defaults to ~/.zkv/default.zkv); in multi-positional commands path is always last:
zkv ls     [~/my.zkv] [-t password] [--tag T] [--cat C] [-q github] [-F|--favorite] [--json]
zkv get    <id> [~/my.zkv] [-f password]      # -f prints a raw field; or --find <title>
zkv search <query> [~/my.zkv]
zkv otp    <id> [~/my.zkv]                    # print the current TOTP 6-digit code
zkv cp     <id> [~/my.zkv] [-f otp] [--clear 20]
zkv add    [~/my.zkv] --title T --template <password|note|card|wifi|...> --set k=v [--set ...] [--tag T] [--gen-password[=LEN]] [--otpauth 'otpauth://...' | --qr <img.png> | --qr-url <http(s)/data: URL>]
zkv edit   <id> [~/my.zkv] [--title T | --set k=v | --add-tag T | --rm-tag T] [--otpauth 'otpauth://...' | --qr <img.png> | --qr-url <http(s)/data: URL>]
zkv rm     <id> [-y] [~/my.zkv]
# Category / tag / attachment management (identifier first, path last):
zkv cat  add <name> [~/my.zkv]  ·  zkv cat ls [~/my.zkv]  ·  zkv cat rm <name> [~/my.zkv]
zkv tag  ls [~/my.zkv]  ·  zkv tag rm <name> [~/my.zkv]  ·  zkv tag mv <from> <to> [~/my.zkv]
zkv attach add <id> <file> [~/my.zkv] [--mime M]  ·  zkv attach ls <id> [~/my.zkv]
zkv attach get <id> <att> [~/my.zkv] [-o file|>file]  ·  zkv attach rm <id> <att> [~/my.zkv]
# Import / export (lossless JSON, includes attachments; CSV is passwords-only):
zkv export [~/my.zkv] --format json|csv [-o file]
zkv import [~/my.zkv] --format json|csv [-i file]
# Passphrase-caching agent (on by default; see "Passphrase-caching agent" below):
zkv agent status · zkv agent stop · zkv lock     # status / stop / clear cached keys
```

Examples: `ZKV_PASSPHRASE=secret zkv ls vault.zkv --type password --json` · `zkv otp vault.zkv 3` · `code=$(zkv gen 24)`.

### 🐚 Shell completions (bash / zsh / fish / elvish / powershell)

`zkv completions <shell>` prints the completion script to stdout — source it or drop it in your completions directory:

```bash
# bash (apply now + persist in ~/.bashrc)
eval "$(zkv completions bash)"
echo 'eval "$(zkv completions bash)"' >> ~/.bashrc

# or install system-wide (requires sudo):
zkv completions bash | sudo tee /etc/bash_completion.d/zkv >/dev/null

# other shells work the same: zkv completions zsh / fish / elvish / powershell
```

Completions cover every subcommand, field names (`-f password|otp|totp|...`), and flags like `--qr` / `--qr-url`.

## 🔄 Passphrase-caching agent

Every command otherwise reads the passphrase and runs a full Argon2id derivation (64MiB/3/4, ~hundreds of ms). The agent is a **transparent** background process that caches the derived master key **in memory only**, so consecutive commands ask for the passphrase just once and skip the KDF:

```bash
zkv ls ~/my.zkv        # first time: type passphrase → agent auto-spawns in the background, caches the key
zkv otp 1 ~/my.zkv     # afterwards (within 5 min by default): no passphrase prompt, near-instant
zkv cp 2 ~/my.zkv
```

- **Automatic**: self-spawns the first time a passphrase is needed; clears its key and exits after `ZKV_LOCK_SECS` (default 300s — the same variable as the TUI auto-lock) of idleness. Changing the passphrase (`passwd`) invalidates the cache.
- **Secure**: the derived key lives **only in the agent process's RAM** (`Zeroizing`, cleared on drop) and is **never written to disk**; it reaches same-uid clients over a 0600 local Unix socket (same model as ssh-agent); access is gated by a 0700 private dir (`$XDG_RUNTIME_DIR` preferred). Any failure (unreachable / version mismatch / vault re-encrypted elsewhere) **silently falls back** to the normal passphrase prompt — never hangs or corrupts.
- **Control / disable**:

  ```bash
  zkv agent status          # pid / socket / cached vaults / idle remaining
  zkv agent stop            # stop the agent (clear key, exit)
  zkv lock                  # clear all cached keys (re-prompt immediately)
  zkv ls --no-agent ...     # or ZKV_NO_AGENT=1: disable caching for this run
  ZKV_LOCK_SECS=0           # disable permanently (TTL=0 ≡ global opt-out)
  ```

> The agent is active on **Unix** only (Linux/macOS/WSL); elsewhere it is a no-op and every command prompts as usual.

## ⌨️ TUI Keybindings

| Key | Action |
| --- | --- |
| `n` | New entry (password / note / card) |
| `e` | Edit current entry |
| `x` | Delete current entry (confirm required) |
| `/` | Search |
| `j` / `k`, `↑` / `↓` | Move up / down |
| `y` | Copy password to clipboard (auto-clears after 20s) |
| `o` | Copy the current TOTP code |
| `a` | Attachment manager (add / export / delete) |
| `l` | Lock now (clears keys and data from memory) |
| `c` / `t` | Category / tag manager (add / rename / delete) |
| `Tab` / `↑` / `↓` | Cycle fields while editing |
| `Enter` | Save / confirm / submit passphrase |
| `Esc` | Cancel / back |
| `q` | Quit |

> **Auto-lock**: the TUI locks itself after `ZKV_LOCK_SECS` (default 300s, `0` disables) of inactivity; re-enter the passphrase in place to resume. The headless CLI's passphrase-caching agent reuses this same variable as its idle TTL (see "Passphrase-caching agent" above).

## 🛡️ Security

**Cryptographic scheme**

| Purpose | Algorithm | Parameters |
| --- | --- | --- |
| Key derivation (KDF) | Argon2id | m=64MiB, t=3, p=4, salt=16B, output 32B |
| Symmetric encryption | XChaCha20-Poly1305 | key=32B, nonce=24B (fresh each save), tag=16B (AEAD) |
| TOTP | RFC 6238 | HMAC-SHA1, 30s, 6 digits, base32 secret |

**Granularity**: the entire SQLite database is encrypted as a single blob. On unlock it is decrypted into **memory** (`:memory:`); on exit/lock it is zeroized. On save it is re-encrypted with the cached derived key (a fresh nonce each time, **no Argon2 re-run**) and written back atomically. Plaintext is never persisted.

**Threat model**
- ✅ Defends against: offline theft of a `.zkv` file (only brute-forceable, made costly by Argon2id); plaintext on disk; temp files are `0600` with CSPRNG names; metadata leakage (entry counts, tag names — all encrypted); clipboard auto-clear; idle auto-lock; the agent's cached key lives in RAM only, never on disk, and transits a 0600 local socket to same-uid clients.
- ⚠️ Does **not** defend against: a fully compromised host (keyloggers, memory dumps, cold-boot attacks).
- ⚠️ **A forgotten passphrase means unrecoverable data** — the price of zero knowledge. Back up your passphrase and `.zkv` file carefully.

## 🧱 Tech Stack

- **Language**: Rust (edition 2024)
- **TUI**: [ratatui](https://crates.io/crates/ratatui) · [crossterm](https://crates.io/crates/crossterm) · [ratatui-sci-fi](https://crates.io/crates/ratatui-sci-fi)
- **Database**: [rusqlite](https://crates.io/crates/rusqlite) (bundled SQLite, with FTS5)
- **Crypto**: [argon2](https://crates.io/crates/argon2) · [chacha20poly1305](https://crates.io/crates/chacha20poly1305) · [zeroize](https://crates.io/crates/zeroize) · [secrecy](https://crates.io/crates/secrecy)
- **TOTP**: [hmac](https://crates.io/crates/hmac) · [sha1](https://crates.io/crates/sha1) · [data-encoding](https://crates.io/crates/data-encoding)
- **QR import**: [image](https://crates.io/crates/image) · [rqrr](https://crates.io/crates/rqrr) · [ureq](https://crates.io/crates/ureq) (decode a local image / fetch a remote one; rustls)
- **Other**: [clap](https://crates.io/crates/clap), [serde](https://crates.io/crates/serde), [thiserror](https://crates.io/crates/thiserror), [color-eyre](https://crates.io/crates/color-eyre), [rpassword](https://crates.io/crates/rpassword), [getrandom](https://crates.io/crates/getrandom)

## 🏗️ Architecture

Layered design with one-way dependencies (lower layers never reference upper ones), following MVC (`App` = Model + Controller, UI = View):

```
error(L0) → crypto/model/totp(L1) → db/vault(L2) → store/search/clipboard(L3) → app(L4) → ui(L5) → main(L6)
                                                                      ↘ cli (headless frontend, parallel to ui) · agent (Unix daemon caching the derived key)
```

See [docs/PROGRESS.md](docs/PROGRESS.md) and [docs/prd/zkv.md](docs/prd/zkv.md).

## 📄 `.zkv` File Format

Little-endian; a 58-byte fixed header followed by ciphertext:

```
[4 "ZKV1"][1 ver][1 flags][4 m_kib][4 t_cost][4 p_cost][16 salt][24 nonce][N ciphertext]
```

KDF parameters are stored in the file, so they can be tuned in the future while old files remain readable; a failed Poly1305 check is interpreted as a wrong passphrase or a corrupted file.

## 🛠️ Development

```bash
cargo test             # unit / integration tests (215 passed)
cargo clippy --all-targets  # 0 warnings
just e2e               # PTY end-to-end (drives the real binary, 7 cases)
cargo build --release  # release build
```

## 🗺️ Roadmap

- [x] Category / tag add-rename-delete (CLI + TUI)
- [x] Import / export (JSON / CSV)
- [x] TOTP codes + headless CLI + idle auto-lock
- [x] Field templates (8 built-in presets + generic field model; custom-template CRUD is a follow-up)
- [x] Passphrase-caching agent (transparently cache the derived key, skip Argon2id; ssh-agent/sudo style)
- [ ] KeePass import / export
- [ ] Per-page encryption for very large vaults (on demand: ~50–200ms per save under 100MB today; see [PROGRESS.md](docs/PROGRESS.md) 2026-06-21 decision)
- [x] Windows clipboard backend (PowerShell `Set-Clipboard`, via stdin, UTF-8)

## 📜 License

MIT
