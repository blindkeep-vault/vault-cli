# vault-cli

Command-line tool for downloading and decrypting [BlindKeep](https://blindkeep.com) drops.

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

```bash
# 12 BIP39 words (space-separated)
vault-cli "abandon ability able about above absent absorb abstract absurd abuse access accident"

# 12 BIP39 words (hyphen-separated)
vault-cli abandon-ability-able-about-above-absent-absorb-abstract-absurd-abuse-access-accident

# Pickup URL
vault-cli "https://blindkeep.com/#/pickup/abandon-ability-able-...-word12"

# Direct drop URL
vault-cli "https://blindkeep.com/#/drop/UUID?key=BASE64URL"

# UUID + base64url key
vault-cli UUID BASE64URL_KEY

# Save to specific file
vault-cli -o output.pdf "abandon ability ..."
```

## Options

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--api-url` | `VAULT_API_URL` | `https://blindkeep.com` | API base URL |
| `-o, --output` | | from metadata | Output file path |

## How It Works

1. Parses input (mnemonic, URL, or UUID+key)
2. For mnemonic drops: derives the wrapping key via PBKDF2-SHA512, unwraps the drop key
3. Downloads the encrypted blob from the server
4. Decrypts with XChaCha20-Poly1305
5. Unpads and extracts the original file with its metadata (filename, etc.)

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT), at your option.
