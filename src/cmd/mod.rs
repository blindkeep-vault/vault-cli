pub mod apikey;
pub mod audit;
pub mod auth;
pub mod billing;
pub mod common;
pub mod deadman;
pub mod drops;
pub mod env;
pub mod files;
pub mod grants;
pub mod groups;
pub mod inbox;
pub mod notarize;
pub mod secrets;
pub mod will;

// Re-export shared imports + helpers for sub-modules via `use super::*;`
pub use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
pub use common::*;
pub use rand::RngCore;
pub use sha2::{Digest, Sha256};
pub use std::io::{Read as IoRead, Write};
pub use std::path::PathBuf;
pub use vault_core::crypto::{
    decrypt_item, derive_api_key_keys, derive_master_key, derive_subkey, encrypt_item,
    generate_x25519_keypair, unwrap_grant_key, unwrap_key, unwrap_master_key, wrap_master_key,
    MasterKey,
};
pub use vault_core::drops::{
    derive_drop_lookup_key, derive_drop_wrapping_key, generate_bip39_mnemonic, normalize_mnemonic,
    unwrap_drop_key, wrap_drop_key,
};
pub use vault_core::envelope::{decrypt_inline_envelope, parse_envelope, SecretBlob};
pub use vault_core::padding::{pad_plaintext, unpad};
pub use vault_core::util::{json_to_array32, json_to_bytes, parse_duration};
