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

Requires Rust 1.80+.

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

### Secrets

```bash
# Store a secret (prefer stdin or @file over CLI args)
vault-cli put prod/db-password "hunter2"

# Read from stdin (recommended -- not visible in process listings)
echo -n "hunter2" | vault-cli put prod/db-password

# Read from file
vault-cli put prod/tls-cert @cert.pem

# Retrieve a secret
vault-cli get prod/db-password

# List secrets
vault-cli ls
vault-cli ls prod/

# Delete a secret
vault-cli rm prod/db-password
```

### Environment files

Store an entire `.env` file as a single encrypted vault item and inject it in CI.

```bash
# Push a .env file to the vault
vault-cli env push myapp/prod .env.prod

# Push from stdin
cat .env | vault-cli env push myapp/prod -

# Pull it back
vault-cli env pull myapp/prod
vault-cli env pull myapp/prod -o .env.local

# Inject variables and run a command (CI usage)
vault-cli env run myapp/prod -- ./deploy.sh

# Inject into the current shell
eval $(vault-cli env export myapp/prod)
```

The `push` command is idempotent — if an env file with the same label already exists, it is replaced.

#### CI/CD example (GitHub Actions)

```yaml
env:
  VAULT_API_KEY: ${{ secrets.VAULT_API_KEY }}
  VAULT_API_URL: https://blindkeep.com

steps:
  - name: Install vault-cli
    run: cargo install --git ssh://git@github.com/blindkeep-vault/vault-cli.git

  - name: Deploy with secrets
    run: vault-cli env run myapp/prod -- ./deploy.sh
```

### Prefix-based secret injection

Inject individual secrets matching a label prefix as environment variables into a child process. Labels are converted to env var names: strip prefix, uppercase, replace `/` and `-` with `_`.

```bash
# Store individual secrets
vault-cli put prod/db-url "postgres://..."
vault-cli put prod/api-key "sk-..."

# Inject all prod/ secrets and run a command
# prod/db-url → DB_URL, prod/api-key → API_KEY
vault-cli env inject prod/ -- ./deploy.sh
```

### API keys

```bash
# Create an API key (shown once)
vault-cli apikey create "CI prod"

# Create a scoped, read-only key
vault-cli apikey create "CI readonly" --scoped --read-only

# List keys
vault-cli apikey list

# Revoke a key
vault-cli apikey revoke <id>

# Grant an item to a scoped key
vault-cli apikey grant <key-id> prod/db-password

# List grants
vault-cli apikey grants <key-id>
```

### Authentication

```bash
vault-cli login           # Interactive email + password login
vault-cli logout          # Clear session
vault-cli status          # Show auth state
```

Or use an API key via environment variable:

```bash
export VAULT_API_KEY=vk_...
vault-cli get prod/db-password
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
