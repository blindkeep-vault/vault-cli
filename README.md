# vault-cli

Command-line tool for [BlindKeep](https://blindkeep.com) — encrypt and share files anonymously, download drops, notarize documents.

Drops are end-to-end encrypted file transfers. The server never sees your files or keys.

## Install

```bash
cargo install --git ssh://git@github.com/blindkeep-vault/vault-cli.git
```

Or build from source:

```bash
git clone git@github.com:blindkeep-vault/vault-cli.git
cd vault-cli
cargo build --release
# Binary at target/release/vault-cli
```

Requires Rust 1.70+.

## Usage

### Upload (create a drop)

```bash
# Encrypt and upload a file — prints pickup URL and 12-word passphrase
vault-cli drop secret-document.pdf

# Use a different API endpoint
vault-cli --api-url http://localhost:3000 drop photo.jpg
```

The command encrypts the file locally, uploads the ciphertext, and prints a pickup URL with an embedded BIP39 passphrase. Share the URL (or the 12 words) with the recipient. Drops auto-expire in 60 minutes.

### Download (pick up a drop)

```bash
# 12 BIP39 words (space-separated)
vault-cli download "abandon ability able about above absent absorb abstract absurd abuse access accident"

# 12 BIP39 words (hyphen-separated)
vault-cli download abandon-ability-able-about-above-absent-absorb-abstract-absurd-abuse-access-accident

# Pickup URL
vault-cli download "https://blindkeep.com/#/pickup/abandon-ability-able-...-word12"

# Direct drop URL
vault-cli download "https://blindkeep.com/#/drop/UUID?key=BASE64URL"

# UUID + base64url key
vault-cli download UUID BASE64URL_KEY

# Save to specific file
vault-cli download -o output.pdf "abandon ability ..."
```

Legacy shorthand (without `download` subcommand) also works:

```bash
vault-cli "abandon ability able ..."
```

### Notarize

```bash
# Notarize a file
vault-cli notarize document.pdf --token $VAULT_TOKEN

# Notarize a hex SHA-256 hash
vault-cli notarize a1b2c3...64hex --token $VAULT_TOKEN

# Save certificate to specific file
vault-cli notarize document.pdf --token $VAULT_TOKEN -o cert.json
```

### Verify

```bash
# Verify a notarization certificate
vault-cli verify notarization-abcd1234.json

# Verify certificate against a document
vault-cli verify notarization-abcd1234.json document.pdf
```

### List notarizations

```bash
vault-cli notarizations --token $VAULT_TOKEN
```

## Options

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--api-url` | `VAULT_API_URL` | `https://blindkeep.com` | API base URL |
| `-o, --output` | | from metadata | Output file path |
| `--token` | `VAULT_TOKEN` | | JWT token (for notarize/notarizations) |

## How It Works

**Drops** use XChaCha20-Poly1305 encryption with a random 256-bit key. The key is wrapped with a BIP39 mnemonic via PBKDF2-HMAC-SHA512 (600,000 iterations) and looked up via HKDF-SHA256. The server stores only ciphertext and wrapped keys — it never sees plaintext or unwrapped keys.

**Notarization** creates a timestamped, Ed25519-signed certificate proving a document's SHA-256 hash existed at a specific time, anchored in an append-only Merkle tree.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT), at your option.
