## [0.2.0] - 2026-06-21

### 🚀 Features

- Unify theme source, harden Windows temp files, polish CLI output
## [0.1.2] - 2026-06-21

### 🚀 Features

- *(cli)* Seamless passphrase-caching agent (skip Argon2id)
- *(cli)* Import 2FA via QR image (--qr / --qr-url)
- *(cli)* Shell completions via `completions <shell>`
- *(cli)* Print live TOTP code to stderr after importing a 2FA secret

### 📚 Documentation

- Document the passphrase-caching agent (zh+en) + PROGRESS

### ⚙️ Miscellaneous Tasks

- Add just install recipe
- Release zkv version 0.1.2
## [0.1.1] - 2026-06-21

### 🚀 Features

- Initial MVP — zero-knowledge encrypted TUI vault
- *(ui)* Sci-fi panel overhaul + PTY e2e suite & real-terminal screenshots
- *(cli)* Headless CLI + TOTP code generation
- *(ui)* Live TOTP display + o key to copy in TUI
- *(cli)* Category/tag management, edit --cat, ls --favorite
- *(cli)* Attachments — attach add/ls/get/rm
- *(cli)* Password generation — gen + add --gen-password
- *(cli)* Import/export (JSON lossless + CSV passwords)
- *(cli)* Otpauth parsing, edit field flags, tag delta, title lookup
- *(ui)* Category/tag management (CategoryMgr/TagMgr)
- *(ui)* Attachments management (Mode::Attachments) + detail summary
- *(ui)* Auto-lock on idle timeout
- Windows clipboard backend via PowerShell
- *(cli)* Default vault path (~/.zkv/default.zkv) when no path given
- *(cli)* Zkv passwd — change the master passphrase

### 🐛 Bug Fixes

- *(cli)* Include attachments in JSON export/import
- *(cli)* Default-path regression — path is now the last positional

### 🚜 Refactor

- *(model/db)* Add field/template types + legacy migration (stage A1)
- Switch Item to generic template_id + Vec<Field> (stage B)

### 📚 Documentation

- Update PROGRESS.md for the perf/hardening optimization pass
- PROGRESS.md — headless CLI + TOTP, bump tests to 98
- PROGRESS.md — full headless CLI (SA9), bump tests to 156
- PROGRESS.md — TUI management complete (SA10), bump tests to 174
- PROGRESS.md — idle auto-lock (SA11), bump tests to 176
- Refresh README (zh + en) for the full feature set
- Record per-page encryption deferral decision (no code change)
- Field/template model (SA12), bump tests to 196
- Default vault path note (README zh+en) + PROGRESS changelog
- Zkv passwd + attachment export in README (zh+en) + PROGRESS

### ⚡ Performance

- Cache master key, fix N+1 tags, harden temp files; clippy clean

### ⚙️ Miscellaneous Tasks

- ADD changelog
- Release zkv version 0.1.1
