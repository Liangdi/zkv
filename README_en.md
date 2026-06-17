# zkv · Zero Knowledge Vault

> 🔐 A local-first, end-to-end encrypted personal vault. Your passphrase never leaves your machine, keys never touch disk, and a `.zkv` file away from your computer is just meaningless ciphertext.

English | [中文](README.md)

![Rust](https://img.shields.io/badge/Rust-edition%202024-orange)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL-green)
![Tests](https://img.shields.io/badge/tests-59%20passed-success)

A terminal-based manager for passwords / notes / cards with a sci-fi TUI ([ratatui-sci-fi](https://crates.io/crates/ratatui-sci-fi) Cyberpunk theme). All data is encrypted at rest with **Argon2id + XChaCha20-Poly1305**.

---

## ✨ Features

- 🔒 **Zero-knowledge encryption** — Argon2id derives the key from your passphrase; XChaCha20-Poly1305 encrypts the whole database. Keys are zeroized on drop and never written to disk.
- 🗄️ **Multiple vaults** — Each `.zkv` file has its own passphrase; manage several vaults side by side.
- 📇 **Multiple entry types** — Password, Note, and Card presets; fields are stored as JSON for easy extension.
- 🔎 **Full-text search** — Powered by SQLite FTS5 over titles and content.
- 🏷️ **Categories & tags** — Hierarchical categories + many-to-many tags + favorites, freely combinable.
- 🖼️ **Embedded attachments** — Images / documents are stored inside the database and encrypted with it.
- 🎨 **Sci-fi TUI** — Three-pane layout, neon palette, fully keyboard-driven.
- ⏱️ **Security details** — Clipboard auto-clears 20s after copying a password; atomic writes prevent corruption; files are `0600`.

## 🖥️ Preview

```
┌ Categories / Tags ─┬─ Items ─────────────┬─ Detail ─────────────┐
│ ▸ Work             │ ★ [PW] GitHub Login  │ Title:    GitHub Login│
│   • Servers        │   [PW] GitLab Token  │ Type:     Password    │
│ ▸ Personal         │ ★ [NO] Secret Diary  │ Username: alice       │
│                    │   [CD] Visa ****     │ Password: •••••••••   │
│ Tags               │                      │ URL:      github.com │
│ work  vip  personal│                      │                       │
└────────────────────┴──────────────────────┴───────────────────────┘
[NORMAL]  n:new  e:edit  x:del  /:search  y:copy  l:lock  q:quit
```

## 🚀 Quick Start

Requires Rust 1.85+ (edition 2024).

```bash
git clone <repo-url> zkv && cd zkv
cargo run --release -- new  ~/my.zkv     # create a new vault (set passphrase in TUI)
cargo run --release -- open ~/my.zkv     # open an existing vault
```

Or install to `$CARGO_HOME/bin`:

```bash
cargo install --path .
zkv new ~/my.zkv
```

## ⌨️ Keybindings

| Key | Action |
| --- | --- |
| `n` | New entry (password / note / card) |
| `e` | Edit current entry |
| `x` | Delete current entry (confirm required) |
| `/` | Search |
| `j` / `k`, `↑` / `↓` | Move up / down |
| `y` | Copy password to clipboard (auto-clears after 20s) |
| `l` | Lock now (clears keys and data from memory) |
| `c` / `t` | Category / tag manager |
| `Tab` / `↑` / `↓` | Cycle fields while editing |
| `Enter` | Save / confirm / submit passphrase |
| `Esc` | Cancel / back (quits the program when locked) |
| `q` | Quit |

## 🛡️ Security

**Cryptographic scheme**

| Purpose | Algorithm | Parameters |
| --- | --- | --- |
| Key derivation (KDF) | Argon2id | m=64MiB, t=3, p=4, salt=16B, output 32B |
| Symmetric encryption | XChaCha20-Poly1305 | key=32B, nonce=24B (fresh each save), tag=16B (AEAD) |

**Granularity**: the entire SQLite database is encrypted as a single blob. On unlock it is decrypted into **memory** (`:memory:`); on exit/lock it is zeroized. On save it is re-encrypted (with a fresh nonce) and written back atomically. Plaintext is never persisted.

**Threat model**
- ✅ Defends against: offline theft of a `.zkv` file (only brute-forceable, made costly by Argon2id); plaintext on disk; metadata leakage (entry counts, tag names — all encrypted).
- ⚠️ Does **not** defend against: a fully compromised host (keyloggers, memory dumps, cold-boot attacks).
- ⚠️ **A forgotten passphrase means unrecoverable data** — the price of zero knowledge. Back up your passphrase and `.zkv` file carefully.

## 🧱 Tech Stack

- **Language**: Rust (edition 2024)
- **TUI**: [ratatui](https://crates.io/crates/ratatui) · [crossterm](https://crates.io/crates/crossterm) · [ratatui-sci-fi](https://crates.io/crates/ratatui-sci-fi)
- **Database**: [rusqlite](https://crates.io/crates/rusqlite) (bundled SQLite, with FTS5)
- **Crypto**: [argon2](https://crates.io/crates/argon2) · [chacha20poly1305](https://crates.io/crates/chacha20poly1305) · [zeroize](https://crates.io/crates/zeroize) · [secrecy](https://crates.io/crates/secrecy)
- **Other**: [clap](https://crates.io/crates/clap), [serde](https://crates.io/crates/serde), [thiserror](https://crates.io/crates/thiserror), [color-eyre](https://crates.io/crates/color-eyre)

## 🏗️ Architecture

Layered design with one-way dependencies (lower layers never reference upper ones), following MVC (`App` = Model + Controller, UI = View):

```
error(L0) → crypto/model(L1) → db/vault(L2) → store/search/clipboard(L3) → app(L4) → ui(L5) → main
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
cargo test             # unit / integration tests (59 passed)
cargo build --release  # release build
```

## 🗺️ Roadmap

- [ ] Add/remove interactions for category & tag managers (currently view-only)
- [ ] Custom field templates
- [ ] Import / export (CSV / JSON / KeePass)
- [ ] Per-page encryption for very large vaults
- [ ] Windows clipboard backend

## 📜 License

MIT
