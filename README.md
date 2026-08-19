# fiotp

A lightweight, secure Two-Factor Authentication (2FA/TOTP) application. Fully compliant code generation with RFC 6238 (TOTP) and RFC 4226 (HOTP), an AES-256-GCM encrypted local vault, `otpauth://` URI parsing, QR code scanning/rendering, and encrypted JSON backup.

- **Zero runtime dependencies required**: cryptography is done entirely with Node.js's built-in `crypto` module (only lightweight pure-JS packages are used for QR).
- **TypeScript**-typed, modular, and tested.
- Usable as a **CLI + programmatic API**.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [CLI Usage](#cli-usage)
  - [First use (creating a vault)](#first-use-creating-a-vault)
  - [Adding an account](#adding-an-account)
  - [Listing accounts](#listing-accounts)
  - [Generating codes](#generating-codes)
  - [Displaying a QR code](#displaying-a-qr-code)
  - [Backup](#backup)
  - [Changing the master password](#changing-the-master-password)
- [Programmatic API](#programmatic-api)
- [Security Model](#security-model)
- [Project Structure](#project-structure)
- [Development](#development)
- [Limitations](#limitations)

## Features

- RFC 4226 / RFC 6238 compliant **HOTP and TOTP** (SHA-1, SHA-256, SHA-512; 6-10 digits; custom time step)
- **AES-256-GCM** encrypted local vault; plaintext is never stored on disk
- **PBKDF2-HMAC-SHA256** (600,000 iterations, OWASP recommendation) key derivation
- Master password verification via the GCM authentication tag — no password hash is stored
- `otpauth://totp/...` and `otpauth://hotp/...` URI parsing/generation with strict validation
- **Google Authenticator export** (`otpauth-migration://`) support for bulk account import (TOTP/HOTP, SHA-256/512 supported; MD5 accounts are automatically skipped)
- QR code generation (SVG/terminal/PNG) and PNG reading (pure JS)
- Live code stream: `{ code, remainingSeconds }` emitted every second
- RFC 4226 §7.4 compliant **resync window** (10 counters) and automatic counter advancement for HOTP verification
- Encrypted JSON **export/import** (merge / replace)
- Master password change (the entire vault is re-encrypted with a new key)
- Automatic **vault backup** (`<vault>.bak`) and recovery via `recover`
- Vault files are written with **0600** permissions, directories with **0700**; writes are atomic (tmp + rename)
- **Automatic lock** after 5 minutes of inactivity (configurable)
- **Exponential backoff** (rate limiting) on failed password attempts
- Concurrent write operations (save / password change) are queued
- Differential tests validated against official RFC test vectors

## Installation

Requirement: **Node.js ≥ 20**

```bash
npm install
npm run build          # build to the dist/ folder
```

To use the CLI globally:

```bash
npm link               # the `fiotp` command becomes available in your terminal
```

You can also use the CLI without linking:

```bash
node dist/cli/index.js list /path/to/vault.json
```

## CLI Usage

```
fiotp init <vault>
fiotp add <vault> [otpauth-uri|secret]
fiotp list <vault>
fiotp code <vault> [account-id|account]
fiotp qr <vault> <account-id|account>
fiotp export <vault> <backup.json>
fiotp import <vault> <backup.json>
fiotp passwd <vault>
fiotp watch <vault>
fiotp recover <vault>
```

Passwords are prompted interactively without being echoed to the screen. Environment variables for scripts/scenarios:

- `FIOTP_PASSWORD` — the current master password used to open the vault
- `FIOTP_NEW_PASSWORD` — the new password, used only with the `passwd` command

> **Note:** When `FIOTP_PASSWORD` is used, the password may be visible in the process list, so interactive entry is recommended in untrusted environments.

### First use (creating a vault)

```bash
fiotp init ~/.fiotp/vault.json
# Master password: ******** (at least 8 characters)
```

The vault file is created with `0600` permissions.

### Adding an account

From a QR/URI (the most common method — accounts from Google Authenticator, Bitwarden, etc. are all in this format):

```bash
fiotp add ~/.fiotp/vault.json "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
```

Bulk import via a Google Authenticator export QR code (`otpauth-migration://` URI) is also supported:

```bash
fiotp add ~/.fiotp/vault.json "otpauth-migration://offline?data=Ci0K..."
```

Multiple accounts are imported at once; duplicate accounts are skipped automatically. Accounts using the MD5 algorithm are not supported and are skipped with a warning.

Or manually (you will be prompted for issuer and account):

```bash
fiotp add ~/.fiotp/vault.json JBSWY3DPEHPK3PXP
```

HOTP accounts are also supported (`otpauth://hotp/...&counter=0`).

### Listing accounts

```bash
fiotp list ~/.fiotp/vault.json
# 4de344c7-...  GitHub:user@example.com
# 8201146f-...  [hotp] Bank:alice
```

HOTP accounts are marked with the `[hotp]` tag.

### Generating codes

Either the account ID or the account name can be used as the account selector:

```bash
fiotp code ~/.fiotp/vault.json user@example.com
# Code: 123456  Remaining: 17s
```

- For **TOTP** accounts, the code and remaining time refresh every second (exit with Ctrl+C).
- For **HOTP** accounts, the code is printed once.

### Displaying a QR code

Renders the account's otpauth URI as a QR code in the terminal (for transferring to another device):

```bash
fiotp qr ~/.fiotp/vault.json user@example.com
```

### Backup

The entire vault is exported as encrypted JSON (plaintext is never exposed):

```bash
fiotp export ~/.fiotp/vault.json ~/backup.json
```

Restores the backup into the same or a different vault (duplicate accounts are skipped):

```bash
fiotp import ~/.fiotp/vault.json ~/backup.json
```

### Changing the master password

```bash
fiotp passwd ~/.fiotp/vault.json
```

The current password is re-verified; the new password is requested twice. The entire vault is re-encrypted with the new key.

### Live dashboard

Displays all TOTP accounts on a single screen, with codes and remaining time refreshing every second (exit with Ctrl+C):

```bash
fiotp watch ~/.fiotp/vault.json
```

### Vault recovery

`save()` backs up the existing file as `<vault>.bak` before every write. If your vault file becomes corrupted, you can restore the last known-good version:

```bash
fiotp recover ~/.fiotp/vault.json
```

## Programmatic API

fiotp can also be used as a library.

```ts
import { FiotpService } from "fiotp";

// Open a vault
const service = await FiotpService.open("/tmp/vault.json", "master-password");

// Add an account from a URI
const account = service.addAccount(
  "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
);

// Generate a code (TOTP: with remaining time; HOTP: one-time)
const code = service.getCode(account.id);
console.log(code.code, code.type === "totp" ? `${code.remainingSeconds}s` : "");

// Verify a code (the counter advances automatically for HOTP)
const ok = await service.verifyCode(account.id, code.code);

// Live stream: a new code + remaining time every second
const unsubscribe = service.subscribe(account.id, (tick) => {
  console.log(tick.code, tick.remainingSeconds);
});
unsubscribe();

// Encrypted backup
const backup = await service.exportBackup();
const added = await service.importBackup(backup, "master-password", "merge");

// Google Authenticator export (otpauth-migration://)
const migrationResult = service.importMigration("otpauth-migration://offline?data=...");
console.log(`${migrationResult.added} accounts added`);
console.log(`${migrationResult.skippedMd5} MD5 accounts skipped`);

// Change password + lock
await service.changeMasterPassword("master-password", "new-password");
service.lock();
```

Lower-level modules are also exported (`src/index.ts`):

```ts
import { generateTOTP, verifyTOTP, parseOtpAuthUri, encrypt, decrypt, deriveKey } from "fiotp";
```

## Security Model

| Topic | Approach |
|---|---|
| Secret key storage | AES-256-GCM, a random 12-byte IV + 16-byte auth tag on every encryption |
| Key derivation | PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt |
| Password verification | Via the GCM tag of a verifier block; no password derivative is stored |
| Plaintext | Only in memory while the vault is open; `lock()` zeroes out the key |
| Auto-lock | 5 minutes of inactivity (configurable via the service/CLI, disabled with `null`) |
| File permissions | Vault and backups `0600`, vault directories `0700` |
| Atomic writes | Write to `.tmp` first, then rename — an interrupted write cannot corrupt the file |
| Verification | TOTP/HOTP codes are compared in constant time (timing-safe) |
| Rate limiting | Exponential backoff after 5 consecutive failed attempts (30s → 15min) |
| Backup | Since the vault is already encrypted, the export is directly encrypted JSON; import is opened with its own password |

## Project Structure

```
src/
├── core/          # Module 1 — crypto & core engine
│   ├── otp.ts     #   HOTP (RFC 4226) + TOTP (RFC 6238)
│   ├── base32.ts  #   RFC 4648 base32 + validation
│   ├── cipher.ts  #   AES-256-GCM encrypt/decrypt
│   ├── kdf.ts     #   PBKDF2-SHA256 key derivation
│   └── errors.ts  #   FiotpError hierarchy
├── storage/       # Module 2 — encrypted local vault
│   ├── vault.ts   #   VaultManager (open/create/save/lock/change password)
│   ├── account.ts #   Account model + validation
│   └── serialization.ts
├── parser/        # Module 3 — otpauth:// URI parsing/generation + migration
│   ├── otpauth.ts     # otpauth:// URI parsing/generation
│   ├── migration.ts   # otpauth-migration:// Google Authenticator export
│   └── protobuf.ts    # Minimal protobuf wire-format reader (zero dependencies)
├── qr/            # Module 3 — QR generation (SVG/terminal/PNG) and reading (PNG)
├── service/       # Module 4 — programmatic service facade + live stream
│   ├── fiotp.ts   #   FiotpService
│   └── ticker.ts  #   LiveCodeTicker (per-second emission)
└── cli/           # Module 4 — command-line interface
tests/             # Vitest tests (including RFC vectors)
```

## Development

```bash
npm run typecheck   # type checking (tsc --noEmit)
npm test            # run all tests
npm run coverage    # test coverage report
npm run build       # produce dist/
```

The test suite includes the official test vectors from RFC 4226 Appendix D and RFC 6238 Appendix B; it also covers vault lifecycle, tampering/integrity scenarios, permissions, HOTP counter advancement, backup, and password changes.

## Limitations

- QR reading only supports images in **PNG** format (no JPEG/WebP support).
- Web/camera-based QR scanning and a graphical user interface are not yet available.
- Rate-limiting state is kept in memory only; the counter resets when the process restarts.
