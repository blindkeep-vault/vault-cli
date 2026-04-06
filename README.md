# vault-cli

Command-line tool for [BlindKeep](https://blindkeep.com) — end-to-end encrypted secret management, file sharing, grants, digital wills, and more.

All encryption happens locally. The server never sees your plaintext or keys.

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

## Authentication

```bash
vault-cli register        # Create a new account
vault-cli login           # Interactive email + password login
vault-cli logout          # Clear session
vault-cli status          # Show auth state
vault-cli change-password # Change account password
```

Or use an API key via environment variable:

```bash
export VAULT_API_KEY=vk_...
vault-cli get prod/db-password
```

The key-caching agent avoids re-prompting for the password on every command:

```bash
vault-cli agent start         # Start daemon (30 min timeout)
vault-cli agent stop          # Stop daemon
vault-cli lock                # Zeroize cached key without stopping
```

## Secrets

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

## Files

```bash
# Store an encrypted file
vault-cli file put contracts/nda.pdf ./nda.pdf

# Retrieve and decrypt
vault-cli file get contracts/nda.pdf
vault-cli file get contracts/nda.pdf -o ./downloaded.pdf
```

## Environment files

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

### Prefix-based secret injection

Inject individual secrets matching a label prefix as environment variables. Labels are converted to env var names: strip prefix, uppercase, replace `/` and `-` with `_`.

```bash
vault-cli put prod/db-url "postgres://..."
vault-cli put prod/api-key "sk-..."

# prod/db-url -> DB_URL, prod/api-key -> API_KEY
vault-cli env inject prod/ -- ./deploy.sh
```

### CI/CD example (GitHub Actions)

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

## Drops (anonymous file sharing)

### Upload

```bash
# Encrypt and upload a file -- prints pickup URL and 12-word passphrase
vault-cli drop secret-document.pdf
```

Drops auto-expire in 60 minutes.

### Download

```bash
# 12 BIP39 words (space or hyphen separated)
vault-cli download "abandon ability able about above absent absorb abstract absurd abuse access accident"
vault-cli download abandon-ability-able-about-above-absent-absorb-abstract-absurd-abuse-access-accident

# Pickup URL
vault-cli download "https://blindkeep.com/#/pickup/abandon-ability-...-word12"

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

### Claim a drop into your vault

Instead of downloading, claim a drop to store it permanently in your vault:

```bash
vault-cli claim "abandon ability able about above absent absorb abstract absurd abuse access accident"
vault-cli claim "https://blindkeep.com/#/pickup/abandon-ability-...-word12"
```

## Grants (sharing)

### Share with a BlindKeep user (X25519)

```bash
# Share a secret with another user (they must have a BlindKeep account)
vault-cli grant create prod/db-password --to alice@example.com

# Set access limits
vault-cli grant create prod/db-password --to alice@example.com --max-views 3 --expires 7d

# Read-only (view only, no download)
vault-cli grant create prod/db-password --to alice@example.com --read-only
```

### Share via link (no account needed)

```bash
# Create a link-secret grant -- outputs a share URL
vault-cli grant create-link prod/db-password

# Optionally notify by email
vault-cli grant create-link prod/db-password --to bob@example.com --expires 24h
```

### Access grants

```bash
# Access a grant you received (X25519)
vault-cli grant access <grant-id>
vault-cli grant access <grant-id> -o secret.txt

# Access a link-secret grant via URL
vault-cli grant access-link "https://app.blindkeep.com/#/grant-accept/UUID/SECRET"

# Or provide grant ID + key separately
vault-cli grant access-link <grant-id> --key <base64url-key>
```

### Manage grants

```bash
vault-cli grant list              # List all grants
vault-cli grant list --sent       # Only grants you sent
vault-cli grant list --received   # Only grants you received
vault-cli grant revoke <id>       # Revoke a grant
vault-cli grant resend <id>       # Resend email notification

# Re-share a received grant to another user
vault-cli grant reshare <grant-id> --to charlie@example.com --expires 30d
```

## Groups

Organize items into named collections.

```bash
vault-cli group create "Production"
vault-cli group list
vault-cli group add Production prod/db-password
vault-cli group add Production prod/api-key
vault-cli group items Production
vault-cli group rename Production "Prod Secrets"
vault-cli group remove "Prod Secrets" prod/api-key
vault-cli group delete "Prod Secrets"

# JSON output
vault-cli group list --json
vault-cli group items Production --json
```

## Dead drop inboxes

Create public receive-only inboxes. Anyone can upload encrypted files to your inbox without needing an account.

```bash
vault-cli inbox create --slug security-reports --label "Security Reports"
vault-cli inbox list
vault-cli inbox info security-reports   # Public info (no auth required)
vault-cli inbox delete <id>
```

## Digital will

Configure a digital will so a designated heir can access selected vault items after a grace period.

```bash
# Create a will (heir has a BlindKeep account)
vault-cli will create --heir alice@example.com --grace-days 30

# Include only specific items
vault-cli will create --heir alice@example.com --items "prod/db-password,contracts/nda.pdf"

# Show current will
vault-cli will show

# Update will
vault-cli will update --grace-days 60
vault-cli will update --heir bob@example.com
vault-cli will update --items "prod/db-password"

# Delete will
vault-cli will delete
```

If the heir does not have a BlindKeep account, a 12-word passphrase is generated that must be shared with them securely.

## Deadman switch

Automatically trigger will access if you stop checking in.

```bash
vault-cli deadman enable --interval 30   # 30-day check-in interval
vault-cli deadman status                 # Show current status
vault-cli deadman checkin                # Reset the timer
vault-cli deadman disable                # Turn off
```

Ideal for automation -- add `vault-cli deadman checkin` to a cron job:

```bash
# Check in daily
0 9 * * * VAULT_API_KEY=vk_... vault-cli deadman checkin
```

## Audit log

```bash
vault-cli audit                          # Last 50 entries
vault-cli audit --limit 100              # More entries
vault-cli audit --type item              # Filter by resource type
vault-cli audit --type grant --json      # JSON output
```

## Billing

```bash
vault-cli billing balance          # Storage balance and burn rate
vault-cli billing history          # Topup history
vault-cli billing balance --json   # JSON output
```

## Notarization

Create timestamped, Ed25519-signed certificates proving a document existed at a specific time.

```bash
# Notarize a file
vault-cli notarize document.pdf --token $VAULT_TOKEN

# Notarize a hex SHA-256 hash
vault-cli notarize a1b2c3...64hex --token $VAULT_TOKEN

# Save certificate
vault-cli notarize document.pdf --token $VAULT_TOKEN -o cert.json

# Verify a certificate
vault-cli verify cert.json
vault-cli verify cert.json document.pdf

# List notarizations
vault-cli notarizations --token $VAULT_TOKEN
```

## API keys

```bash
vault-cli apikey create "CI prod"
vault-cli apikey create "CI readonly" --scoped --read-only
vault-cli apikey list
vault-cli apikey revoke <id>
vault-cli apikey rotate <id-or-prefix>

# Scoped key grants
vault-cli apikey grant <key-id> prod/db-password
vault-cli apikey grants <key-id>
vault-cli apikey ungrant <key-id> prod/db-password
```

## Self-hosted server

Run a local BlindKeep-compatible API server backed by SQLite:

```bash
vault-cli serve                       # localhost:7890
vault-cli serve --port 8080 --host 0.0.0.0
vault-cli serve --db-path ./my-vault.db
```

## Options

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--api-url` | `VAULT_API_URL` | `https://api.blindkeep.com` | API base URL |
| `-o, --output` | | from metadata | Output file path |
| `--token` | `VAULT_TOKEN` | | JWT token (for notarize/notarizations) |

## How it works

All vault items use **XChaCha20-Poly1305** encryption with per-item random 256-bit keys, wrapped under a master key derived via **Argon2id**.

**Drops** wrap the file key with a BIP39 mnemonic via PBKDF2-HMAC-SHA512 (600k iterations) and look it up via HKDF-SHA256. The server stores only ciphertext and wrapped keys.

**Grants** use **X25519** key agreement to wrap the item key for the recipient, or **AES-256-GCM** for link-secret grants shared via URL.

**Notarization** creates Ed25519-signed certificates anchored in an append-only Merkle tree.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT), at your option.
