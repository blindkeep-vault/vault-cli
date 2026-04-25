mod agent;
mod cmd;
mod db;
mod server;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    name = "vault-cli",
    about = "BlindKeep vault CLI — download drops, notarize documents, verify certificates"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// API base URL
    #[arg(
        long,
        env = "VAULT_API_URL",
        default_value = "https://api.blindkeep.com",
        global = true
    )]
    api_url: String,

    // Legacy positional args for backwards compat (drop download)
    /// Drop key or mnemonic (legacy usage: vault-cli KEY [KEY2])
    key: Option<String>,
    key2: Option<String>,

    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Download and decrypt a drop (same as legacy positional args)
    Download {
        key: String,
        key2: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Claim an anonymous drop into your vault
    Claim {
        /// Drop mnemonic (12 words), pickup URL, or drop ID + key
        key: String,
        key2: Option<String>,
    },
    /// Encrypt and upload a file as an anonymous drop
    Drop {
        /// File to encrypt and upload
        file: PathBuf,
    },
    /// Notarize a file or hash
    Notarize {
        /// File to notarize or hex SHA-256 hash
        input: String,
        /// JWT token
        #[arg(long, env = "VAULT_TOKEN")]
        token: String,
        /// Item ID to link
        #[arg(long)]
        item_id: Option<String>,
        /// Output certificate file
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Also emit an RFC 3161 TimeStampResp alongside the JSON certificate.
        /// Writes <stem>.tsr next to <stem>.json. Verify with
        /// `openssl ts -verify -in <stem>.tsr -data <file> -CAfile <tsa.pem>`
        /// where <tsa.pem> is fetched from `/notary/tsa-cert.pem`.
        #[arg(long)]
        rfc3161: bool,
    },
    /// Verify a notarization certificate
    Verify {
        /// Certificate JSON file
        certificate: PathBuf,
        /// Optional document to verify hash against
        document: Option<PathBuf>,
    },
    /// List notarizations
    Notarizations {
        /// JWT token
        #[arg(long, env = "VAULT_TOKEN")]
        token: String,
    },
    /// Register a new account
    Register,
    /// Log in with email and password
    Login,
    /// Change account password
    ChangePassword,
    /// Clear stored session
    Logout,
    /// Manage API keys
    Apikey {
        #[command(subcommand)]
        action: ApikeyAction,
    },
    /// Show current authentication status
    Status,
    /// Store a secret
    Put {
        /// Secret label (e.g., "prod/db-password")
        label: String,
        /// Secret value (omit to read from stdin, prefix with @ for file)
        value: Option<String>,
        /// Consume this secret on the first direct retrieval (API key or owner) —
        /// subsequent reads return 410 Gone. Does NOT gate grant-based access; use
        /// `grant create --one-shot` to enforce single-retrieval for a grantee.
        #[arg(long)]
        one_shot_retrievable: bool,
        /// Emit a notarized item.retrieve attestation on every successful direct
        /// retrieval. Same scope: direct reads only.
        #[arg(long)]
        notarize_on_use: bool,
        /// Data-handling classification (issue #9). `standard` (default) keeps
        /// today's behavior. `confidential` and `restricted` items require
        /// `grant create --one-shot` — grants that aren't one-shot will be
        /// refused by the server with 422.
        #[arg(long, value_name = "LEVEL", default_value = "standard",
              value_parser = ["public", "standard", "confidential", "restricted"])]
        classification: String,
        /// Cascade-revocation tag (issue #7). Items created with the same
        /// tag can later be revoked together via a single scope tombstone.
        /// Format: 1-64 chars of [a-z0-9-_./], starting with [a-z0-9].
        #[arg(long, value_name = "TAG")]
        scope: Option<String>,
    },
    /// Retrieve a secret
    Get {
        /// Secret label
        label: String,
        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List secrets
    Ls {
        /// Optional prefix filter
        prefix: Option<String>,
    },
    /// Delete a secret
    Rm {
        /// Secret label
        label: String,
    },
    /// Change the classification level of an existing secret. Downgrades (any
    /// move to a strictly less strict level, e.g. `restricted` → `standard`)
    /// are notarized as `item.reclassify` events so the transition is
    /// externally auditable per issue #9 acceptance.
    Reclassify {
        /// Secret label
        label: String,
        /// Target classification level
        #[arg(long, value_name = "LEVEL",
              value_parser = ["public", "standard", "confidential", "restricted"])]
        to: String,
        /// Proceed even if the new classification would leave an active or
        /// pending grant non-compliant (e.g. reclassifying to `confidential`
        /// when a non-one-shot grant exists). The grant is not rewritten —
        /// the server flags the acknowledgement in the audit trail.
        #[arg(long)]
        acknowledge_grant_breakage: bool,
    },
    /// Manage environment files
    Env {
        #[command(subcommand)]
        action: EnvAction,
    },
    /// Share secrets with other users
    Grant {
        #[command(subcommand)]
        action: GrantAction,
    },
    /// Store and retrieve encrypted files
    File {
        #[command(subcommand)]
        action: FileAction,
    },
    /// Manage the key-caching agent daemon
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Lock the running agent (zeroize cached key)
    Lock,
    /// View audit log
    Audit {
        /// Filter by resource type (e.g., "item", "grant", "group")
        #[arg(long, alias = "type")]
        resource_type: Option<String>,
        /// Maximum number of entries
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Billing information
    Billing {
        #[command(subcommand)]
        action: BillingAction,
    },
    /// Deadman switch management
    Deadman {
        #[command(subcommand)]
        action: DeadmanAction,
    },
    /// Notarized approval-decision log (issue #5). Records and queries
    /// "who decided what, when, and why" with cryptographic anchoring —
    /// the rationale is encrypted client-side, the structured fields
    /// (action, target, approver) drive a server-side query API.
    Decision {
        #[command(subcommand)]
        action: DecisionAction,
    },
    /// Signed heartbeat / watchdog attestations
    Watchdog {
        #[command(subcommand)]
        action: WatchdogAction,
    },
    /// Signed, append-only event log (issue #3). Tamper-evident audit trail
    /// for arbitrary structured events; each append produces a Merkle leaf
    /// in the same tree as `notarize`, so inclusion proofs are verifiable
    /// offline against the same RFC 3161-anchored roots.
    Log {
        #[command(subcommand)]
        action: LogAction,
    },
    /// Organize items into groups
    Group {
        #[command(subcommand)]
        action: GroupAction,
    },
    /// Dead drop inbox management
    Inbox {
        #[command(subcommand)]
        action: InboxAction,
    },
    /// Digital will / legacy access management
    Will {
        #[command(subcommand)]
        action: WillAction,
    },
    /// Tombstone a scope: revoke every grant, api key, and api-key grant
    /// carrying the tag, freeze tagged items read-only under a retention
    /// window, and notarize the event (issue #7). The tombstone ledger
    /// row permanently blocks new resources from rejoining the scope —
    /// a new scope must be created instead.
    Tombstone {
        /// The scope tag to tombstone. Must match the tag used on the
        /// original `--scope` flags (1-64 chars of `[a-z0-9-_./]`,
        /// starting with `[a-z0-9]`).
        scope_tag: String,
        /// Retention window — how long frozen items remain before the
        /// retention-expiry sweep disposes of them. Parsed as a
        /// duration (e.g. "30d", "90d", "1y"); sub-day values round up
        /// to the next full day. Server clamps into [1, 3650] days;
        /// omit for the default (90 days).
        #[arg(long)]
        retention: Option<String>,
        /// Free-form note persisted on the tombstone ledger row. Useful
        /// for audit context (incident number, JIRA ticket, compliance
        /// reference).
        #[arg(long)]
        reason: Option<String>,
    },
    /// Start a self-hosted BlindKeep-compatible API server
    Serve {
        /// Port to listen on
        #[arg(long, default_value = "7890")]
        port: u16,
        /// Host/IP to bind to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Path to SQLite database file
        #[arg(long)]
        db_path: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum AgentAction {
    /// Start the key-caching agent daemon
    Start {
        /// Inactivity timeout in minutes (default: 30)
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
    /// Stop the running agent daemon
    Stop,
    /// Show agent status
    Status,
}

#[derive(Subcommand)]
pub(crate) enum ApikeyAction {
    /// Create a new API key
    Create {
        /// Name for the API key
        name: String,
        /// Make the key read-only
        #[arg(long)]
        read_only: bool,
        /// Create a scoped key (access only granted items)
        #[arg(long)]
        scoped: bool,
        /// Expiry duration (e.g., "30d", "90d", "1y")
        #[arg(long)]
        expires: Option<String>,
        /// Cascade-revocation tag (issue #7). Tags this key for a future
        /// scope tombstone. Independent from `--scoped`/`--read-only`, which
        /// are RBAC-style permissions. Format: 1-64 chars of [a-z0-9-_./].
        #[arg(long, value_name = "TAG")]
        scope: Option<String>,
    },
    /// List API keys
    List,
    /// Revoke an API key
    Revoke {
        /// API key ID to revoke
        id: String,
    },
    /// Grant an item to a scoped API key
    Grant {
        /// API key ID
        key_id: String,
        /// Item label to grant
        label: String,
    },
    /// List items granted to an API key
    Grants {
        /// API key ID
        key_id: String,
    },
    /// Revoke an item grant from an API key
    Ungrant {
        /// API key ID
        key_id: String,
        /// Item label to revoke
        label: String,
    },
    /// Rotate an API key (create new, copy grants, revoke old)
    Rotate {
        /// API key ID or prefix to rotate
        key: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum EnvAction {
    /// Store a .env file in the vault
    Push {
        /// Label for this env file (e.g., "myapp/prod")
        label: String,
        /// .env file path (default: .env, use "-" for stdin)
        #[arg(default_value = ".env")]
        file: String,
    },
    /// Retrieve a .env file from the vault
    Pull {
        /// Label of the env file
        label: String,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Inject env file variables and run a command
    Run {
        /// Label of the env file
        label: String,
        /// Command and arguments to run
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Print export statements for eval (inject into current shell)
    Export {
        /// Label of the env file
        label: String,
    },
    /// Inject secrets by prefix and run a command
    Inject {
        /// Label prefix to match (e.g., "prod/")
        prefix: String,
        /// Command and arguments to run
        #[arg(last = true)]
        cmd: Vec<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum GrantAction {
    /// Share a secret with another BlindKeep user
    Create {
        /// Secret label to share (e.g., "prod/db-password")
        label: String,
        /// Recipient's email address
        #[arg(long)]
        to: String,
        /// Maximum number of views allowed
        #[arg(long)]
        max_views: Option<u32>,
        /// Expiry duration (e.g., "24h", "7d", "30d", "1y")
        #[arg(long)]
        expires: Option<String>,
        /// Grant read-only access (view only, no download)
        #[arg(long)]
        read_only: bool,
        /// Auto-revoke this grant after a single successful retrieval. The
        /// revocation commits in the same UPDATE as the view count, and the
        /// second access returns 410 Gone. Implies --max-views=1 if not set.
        #[arg(long)]
        one_shot: bool,
        /// Emit a notarized grant.retrieve attestation on each successful access.
        /// The notarization commits in the same transaction as the retrieval.
        #[arg(long)]
        notarize_on_use: bool,
        /// Cascade-revocation tag (issue #7). Tags this grant for a future
        /// scope tombstone — useful for grants issued to external
        /// collaborators on a specific engagement or workspace.
        #[arg(long, value_name = "TAG")]
        scope: Option<String>,
    },
    /// List grants (sent and received)
    List {
        /// Show only grants you sent
        #[arg(long, conflicts_with = "received")]
        sent: bool,
        /// Show only grants you received
        #[arg(long, conflicts_with = "sent")]
        received: bool,
    },
    /// Access a received grant (decrypt and display)
    Access {
        /// Grant ID (UUID)
        id: String,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Revoke a grant you sent
    Revoke {
        /// Grant ID (UUID)
        id: String,
    },
    /// Resend email notification for a pending grant
    Resend {
        /// Grant ID (UUID)
        id: String,
    },
    /// Share a secret via link (no recipient account needed)
    CreateLink {
        /// Secret label to share
        label: String,
        /// Recipient's email (for notification, optional)
        #[arg(long)]
        to: Option<String>,
        /// Maximum number of views allowed
        #[arg(long)]
        max_views: Option<u32>,
        /// Expiry duration (e.g., "24h", "7d", "30d", "1y")
        #[arg(long)]
        expires: Option<String>,
        /// Grant read-only access (view only, no download)
        #[arg(long)]
        read_only: bool,
    },
    /// Access a grant via link URL containing a link-secret
    AccessLink {
        /// Grant URL with embedded link-secret, or grant ID
        url: String,
        /// Link-secret (base64url, if not embedded in URL)
        #[arg(long)]
        key: Option<String>,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Re-share a received grant to another user
    Reshare {
        /// Grant ID to re-share
        id: String,
        /// Recipient's email address
        #[arg(long)]
        to: String,
        /// Maximum number of views allowed
        #[arg(long)]
        max_views: Option<u32>,
        /// Expiry duration (e.g., "24h", "7d", "30d", "1y")
        #[arg(long)]
        expires: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum FileAction {
    /// Store a file in the vault
    Put {
        /// Label (e.g. "contracts/nda.pdf")
        label: String,
        /// Path to the file to encrypt and store
        file: PathBuf,
    },
    /// Retrieve a file from the vault
    Get {
        /// File label
        label: String,
        /// Output path (default: original filename in current directory)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum BillingAction {
    /// Show current storage balance and burn rate
    Balance {
        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Show billing/topup history
    History {
        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum DeadmanAction {
    /// Enable deadman switch with check-in interval
    Enable {
        /// Check-in interval in days (7-365)
        #[arg(long)]
        interval: u32,
    },
    /// Show deadman switch status
    Status,
    /// Record a check-in (reset the timer)
    Checkin,
    /// Disable deadman switch
    Disable,
}

#[derive(Subcommand)]
pub(crate) enum DecisionAction {
    /// Record a notarized approval decision. The rationale is encrypted
    /// client-side; the structured fields are server-queryable (issue #5).
    Record {
        /// Action taken (e.g. "approve", "deny", "exception").
        #[arg(long)]
        action: String,
        /// Target identifier (e.g. "wire-12345", "deploy-v2.3", "case-7").
        #[arg(long)]
        target: String,
        /// Free-form rationale to encrypt. Use `@path` to read from a file,
        /// or omit to read from stdin (matches `vault-cli put`).
        #[arg(long)]
        rationale: Option<String>,
        /// Approver identity, defaults to the caller's user id. Pass an
        /// explicit value when recording on behalf of an external party.
        #[arg(long)]
        approver: Option<String>,
        /// Prior decision id this one supersedes. Server enforces both
        /// belong to the same approver_user_id.
        #[arg(long)]
        supersedes: Option<String>,
        /// Caller-supplied decision time (RFC 3339). Useful for backfilling
        /// historical approvals; defaults to record time on the server.
        #[arg(long)]
        decided_at: Option<String>,
    },
    /// Fetch a single decision by id with its anchoring notarization.
    /// Useful when you have a decision id from somewhere else (a chain
    /// tip, an audit log entry) and want the full row without paginating.
    Show {
        /// Decision id (UUID).
        id: String,
        /// Output raw JSON instead of the human-readable summary.
        #[arg(long)]
        json: bool,
    },
    /// Query the decision log. The server returns a notarized receipt
    /// pinning the filter parameters and the result set, so completeness
    /// is verifiable later.
    Query {
        /// Filter by approver identity (exact match).
        #[arg(long)]
        approver: Option<String>,
        /// Filter by action (exact match).
        #[arg(long)]
        action: Option<String>,
        /// Filter by target (exact match).
        #[arg(long)]
        target: Option<String>,
        /// Lower bound on decided_at, inclusive (RFC 3339).
        #[arg(long)]
        since: Option<String>,
        /// Upper bound on decided_at, exclusive (RFC 3339).
        #[arg(long)]
        until: Option<String>,
        /// Filter by supersedes id (find decisions that follow a given prior).
        #[arg(long)]
        supersedes: Option<String>,
        /// Page size (1..=500).
        #[arg(long)]
        limit: Option<i64>,
        /// Page offset.
        #[arg(long)]
        offset: Option<i64>,
        /// Output raw JSON instead of the human-readable table.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum WatchdogAction {
    /// Register a new watchdog session
    Register {
        /// Expected ping interval (e.g. "60", "30s", "5m", "2h", "1d")
        #[arg(long)]
        interval: String,
        /// Allowed slack before the session is declared lost (default 0)
        #[arg(long)]
        tolerance: Option<String>,
        /// Optional human-readable label
        #[arg(long)]
        label: Option<String>,
    },
    /// Record a heartbeat for an existing session
    Ping {
        /// Session id (UUID)
        id: String,
    },
    /// List all registered watchdog sessions
    Query {
        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Retire a watchdog session (won't emit watchdog.lost)
    Delete {
        /// Session id (UUID)
        id: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum LogAction {
    /// Create a new event log.
    Create {
        /// Log name. 1–100 chars, unique within the caller's account.
        name: String,
        /// Optional JSON Schema URI. v0 is hint-only (clients may use it
        /// to validate locally); the server does not enforce the schema.
        #[arg(long)]
        schema_uri: Option<String>,
        /// Hex-encoded Ed25519 verifying key (32 bytes). When set, every
        /// `log append` to this log must carry a matching `--sig`.
        #[arg(long)]
        signing_pubkey: Option<String>,
        /// Per-(API key, log) appends-per-minute cap. Default 1000.
        #[arg(long)]
        rate: Option<i32>,
    },
    /// List all event logs visible to the caller.
    List,
    /// Append an event to a log. Returns `(seq, tree_index, tree_root)` —
    /// `seq` is printed on stdout for pipeline use; the rest is on stderr.
    Append {
        /// Log name.
        name: String,
        /// Event JSON: literal string, `@path` for a file, or stdin if absent.
        #[arg(long)]
        event: Option<String>,
        /// Hex-encoded Ed25519 signature over the canonical-JSON event
        /// bytes. Required when the log was created with `--signing-pubkey`.
        #[arg(long)]
        sig: Option<String>,
        /// Save an inclusion-proof certificate to `event-<log8>-<seq>.json`.
        #[arg(long)]
        save_cert: bool,
    },
    /// List entries in a log (paginated by seq).
    Entries {
        /// Log name.
        name: String,
        /// Lower bound on seq, inclusive. Default 1.
        #[arg(long)]
        from: Option<i64>,
        /// Upper bound on seq, inclusive. Default unbounded.
        #[arg(long)]
        to: Option<i64>,
        /// Page size (1..=1000). Default 100.
        #[arg(long)]
        limit: Option<i64>,
    },
    /// Verify a contiguous range of entries: fetch each inclusion-proof
    /// certificate, recompute the leaf hash locally, run `verify_inclusion`
    /// offline, and check Ed25519 signatures. Exits non-zero on any failure.
    Verify {
        /// Log name.
        name: String,
        /// Lower bound on seq, inclusive.
        #[arg(long)]
        from: i64,
        /// Upper bound on seq, inclusive.
        #[arg(long)]
        to: i64,
    },
    /// Delete a log. Existing inclusion-proof certificates remain valid
    /// against historical Merkle roots, but the server will no longer
    /// answer queries for this log's entries.
    Delete {
        /// Log name.
        name: String,
        /// Skip the typed-name confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum GroupAction {
    /// Create a new group
    Create {
        /// Group name
        name: String,
    },
    /// List all groups
    List {
        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Show items in a group
    Show {
        /// Group name or ID
        group: String,
        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Rename a group
    Rename {
        /// Group name or ID
        group: String,
        /// New name
        new_name: String,
    },
    /// Delete a group
    Delete {
        /// Group name or ID
        group: String,
    },
    /// Add an item to a group
    Add {
        /// Group name or ID
        group: String,
        /// Item label
        label: String,
    },
    /// Remove an item from a group
    Remove {
        /// Group name or ID
        group: String,
        /// Item label
        label: String,
    },
    /// List items in a group
    Items {
        /// Group name or ID
        group: String,
        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum InboxAction {
    /// Create a new dead drop inbox
    Create {
        /// Custom URL slug (3-63 chars, lowercase alphanumeric + hyphens)
        #[arg(long)]
        slug: Option<String>,
        /// Display label for senders
        #[arg(long)]
        label: Option<String>,
    },
    /// List your inboxes
    List {
        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Delete an inbox
    Delete {
        /// Inbox ID
        id: String,
    },
    /// Get public info for an inbox (no auth required)
    Info {
        /// Inbox ID or slug
        id: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum WillAction {
    /// Create a digital will
    Create {
        /// Heir's email address
        #[arg(long)]
        heir: String,
        /// Grace period in days before heir can access (1-365, default: 30)
        #[arg(long, default_value = "30")]
        grace_days: u32,
        /// Comma-separated list of item labels to include (default: all)
        #[arg(long)]
        items: Option<String>,
    },
    /// Show current will configuration
    Show,
    /// Update an existing will
    Update {
        /// New heir email (optional, keeps current if omitted)
        #[arg(long)]
        heir: Option<String>,
        /// New grace period in days
        #[arg(long)]
        grace_days: Option<u32>,
        /// Comma-separated list of item labels (replaces existing)
        #[arg(long)]
        items: Option<String>,
    },
    /// Delete the will
    Delete,
}

pub(crate) type ParsedInput = vault_core::parsing::DropInput;

fn main() {
    let cli = Cli::parse();
    let client = reqwest::blocking::Client::new();

    match cli.command {
        Some(Command::Download { key, key2, output }) => {
            cmd::drops::run_drop_download(&client, &cli.api_url, &key, key2.as_deref(), output);
        }
        Some(Command::Claim { key, key2 }) => {
            cmd::drops::run_claim(&client, &cli.api_url, &key, key2.as_deref());
        }
        Some(Command::Drop { file }) => {
            cmd::drops::run_drop_upload(&client, &cli.api_url, &file);
        }
        Some(Command::Notarize {
            input,
            token,
            item_id,
            output,
            rfc3161,
        }) => {
            cmd::notarize::run_notarize(
                &client,
                &cli.api_url,
                &token,
                &input,
                item_id.as_deref(),
                output,
                rfc3161,
            );
        }
        Some(Command::Verify {
            certificate,
            document,
        }) => {
            cmd::notarize::run_verify(&certificate, document.as_deref());
        }
        Some(Command::Notarizations { token }) => {
            cmd::notarize::run_list_notarizations(&client, &cli.api_url, &token);
        }
        Some(Command::Register) => {
            cmd::auth::run_register(&client, &cli.api_url);
        }
        Some(Command::Login) => {
            cmd::auth::run_login(&client, &cli.api_url);
        }
        Some(Command::ChangePassword) => {
            cmd::auth::run_change_password(&client, &cli.api_url);
        }
        Some(Command::Logout) => {
            cmd::auth::run_logout();
        }
        Some(Command::Apikey { action }) => {
            cmd::apikey::run_apikey(&client, &cli.api_url, action);
        }
        Some(Command::Status) => {
            cmd::auth::run_status(&cli.api_url);
        }
        Some(Command::Put {
            label,
            value,
            one_shot_retrievable,
            notarize_on_use,
            classification,
            scope,
        }) => {
            if value.is_some() {
                eprintln!("warning: passing secrets as CLI arguments is visible in process listings; prefer stdin or @file");
            }
            cmd::secrets::run_put(
                &client,
                &cli.api_url,
                &label,
                value.as_deref(),
                one_shot_retrievable,
                notarize_on_use,
                &classification,
                scope.as_deref(),
            );
        }
        Some(Command::Get { label, output }) => {
            cmd::secrets::run_get(&client, &cli.api_url, &label, output);
        }
        Some(Command::Ls { prefix }) => {
            cmd::secrets::run_ls(&client, &cli.api_url, prefix.as_deref());
        }
        Some(Command::Rm { label }) => {
            cmd::secrets::run_rm(&client, &cli.api_url, &label);
        }
        Some(Command::Reclassify {
            label,
            to,
            acknowledge_grant_breakage,
        }) => {
            cmd::secrets::run_reclassify(
                &client,
                &cli.api_url,
                &label,
                &to,
                acknowledge_grant_breakage,
            );
        }
        Some(Command::Env { action }) => match action {
            EnvAction::Push { label, file } => {
                cmd::env::run_env_push(&client, &cli.api_url, &label, &file);
            }
            EnvAction::Pull { label, output } => {
                cmd::env::run_env_pull(&client, &cli.api_url, &label, output);
            }
            EnvAction::Run { label, cmd } => {
                cmd::env::run_env_run(&client, &cli.api_url, &label, &cmd);
            }
            EnvAction::Export { label } => {
                cmd::env::run_env_export(&client, &cli.api_url, &label);
            }
            EnvAction::Inject { prefix, cmd } => {
                cmd::env::run_env(&client, &cli.api_url, &prefix, &cmd);
            }
        },
        Some(Command::Grant { action }) => {
            cmd::grants::run_grant(&client, &cli.api_url, action);
        }
        Some(Command::File { action }) => match action {
            FileAction::Put { label, file } => {
                cmd::files::run_file_put(&client, &cli.api_url, &label, &file);
            }
            FileAction::Get { label, output } => {
                cmd::files::run_file_get(&client, &cli.api_url, &label, output);
            }
        },
        Some(Command::Agent { action }) => match action {
            AgentAction::Start { timeout } => agent::run_start(timeout),
            AgentAction::Stop => agent::run_stop(),
            AgentAction::Status => agent::run_status(),
        },
        Some(Command::Lock) => agent::run_lock(),
        Some(Command::Audit {
            resource_type,
            limit,
            json,
        }) => {
            cmd::audit::run_audit(
                &client,
                &cli.api_url,
                resource_type.as_deref(),
                Some(limit),
                json,
            );
        }
        Some(Command::Billing { action }) => match action {
            BillingAction::Balance { json } => {
                cmd::billing::run_billing_balance(&client, &cli.api_url, json);
            }
            BillingAction::History { json } => {
                cmd::billing::run_billing_history(&client, &cli.api_url, json);
            }
        },
        Some(Command::Deadman { action }) => {
            cmd::deadman::run_deadman(&client, &cli.api_url, action);
        }
        Some(Command::Decision { action }) => match action {
            DecisionAction::Record {
                action,
                target,
                rationale,
                approver,
                supersedes,
                decided_at,
            } => {
                cmd::decisions::run_record(
                    &client,
                    &cli.api_url,
                    &action,
                    &target,
                    rationale.as_deref(),
                    approver.as_deref(),
                    supersedes.as_deref(),
                    decided_at.as_deref(),
                );
            }
            DecisionAction::Show { id, json } => {
                cmd::decisions::run_show(&client, &cli.api_url, &id, json);
            }
            DecisionAction::Query {
                approver,
                action,
                target,
                since,
                until,
                supersedes,
                limit,
                offset,
                json,
            } => {
                cmd::decisions::run_query(
                    &client,
                    &cli.api_url,
                    approver.as_deref(),
                    action.as_deref(),
                    target.as_deref(),
                    since.as_deref(),
                    until.as_deref(),
                    supersedes.as_deref(),
                    limit,
                    offset,
                    json,
                );
            }
        },
        Some(Command::Watchdog { action }) => {
            cmd::watchdog::run_watchdog(&client, &cli.api_url, action);
        }
        Some(Command::Log { action }) => match action {
            LogAction::Create {
                name,
                schema_uri,
                signing_pubkey,
                rate,
            } => cmd::log::run_create(
                &client,
                &cli.api_url,
                &name,
                schema_uri.as_deref(),
                signing_pubkey.as_deref(),
                rate,
            ),
            LogAction::List => cmd::log::run_list(&client, &cli.api_url),
            LogAction::Append {
                name,
                event,
                sig,
                save_cert,
            } => cmd::log::run_append(
                &client,
                &cli.api_url,
                &name,
                event.as_deref(),
                sig.as_deref(),
                save_cert,
            ),
            LogAction::Entries {
                name,
                from,
                to,
                limit,
            } => cmd::log::run_entries(&client, &cli.api_url, &name, from, to, limit),
            LogAction::Verify { name, from, to } => {
                cmd::log::run_verify(&client, &cli.api_url, &name, from, to)
            }
            LogAction::Delete { name, yes } => {
                cmd::log::run_delete(&client, &cli.api_url, &name, yes)
            }
        },
        Some(Command::Group { action }) => {
            cmd::groups::run_group(&client, &cli.api_url, action);
        }
        Some(Command::Inbox { action }) => {
            cmd::inbox::run_inbox(&client, &cli.api_url, action);
        }
        Some(Command::Will { action }) => {
            cmd::will::run_will(&client, &cli.api_url, action);
        }
        Some(Command::Tombstone {
            scope_tag,
            retention,
            reason,
        }) => {
            cmd::tombstone::run_tombstone(
                &client,
                &cli.api_url,
                &scope_tag,
                retention.as_deref(),
                reason.as_deref(),
            );
        }
        Some(Command::Serve {
            port,
            host,
            db_path,
        }) => {
            let db_path = db_path.unwrap_or_else(server::default_db_path);
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(server::run_server(&host, port, db_path));
        }
        None => {
            // Legacy: positional args for drop download
            if let Some(key) = cli.key {
                cmd::drops::run_drop_download(
                    &client,
                    &cli.api_url,
                    &key,
                    cli.key2.as_deref(),
                    cli.output,
                );
            } else {
                eprintln!("Usage: vault-cli <COMMAND> or vault-cli <KEY> [KEY2]");
                eprintln!("  Commands: download, notarize, verify, notarizations");
                std::process::exit(1);
            }
        }
    }
}
