use std::collections::HashMap;

use crate::crypto::{self, VeilError};
use crate::storage;

/// Public keys for a user identity.
///
/// Currently holds classical (X25519 + Ed25519) keys.
/// Designed to be extended with PQ key fields (ML-KEM, ML-DSA)
/// when post-quantum migration occurs.
///
/// `Debug` is manually implemented to show key fingerprints instead of
/// raw bytes, preventing accidental key material exposure in logs.
#[derive(Clone)]
pub struct PublicKeyBundle {
    pub dh_public: [u8; 32],
    pub sign_public: [u8; 32],
}

impl std::fmt::Debug for PublicKeyBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKeyBundle")
            .field("dh_public", &key_fingerprint(&self.dh_public))
            .field("sign_public", &key_fingerprint(&self.sign_public))
            .finish()
    }
}

/// In-memory cache for fetched public key bundles.
///
/// Reduces server round-trips, which becomes critical when
/// PQ public keys grow to 1 KB+ each. Uses LRU eviction when
/// the cache exceeds `MAX_ENTRIES` to bound memory usage.
pub struct KeyCache {
    entries: HashMap<String, (u64, PublicKeyBundle)>,
    counter: u64,
}

const KEY_CACHE_MAX_ENTRIES: usize = 1024;

impl Default for KeyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            counter: 0,
        }
    }

    pub fn get(&mut self, user_id: &str) -> Option<&PublicKeyBundle> {
        self.counter = self.counter.wrapping_add(1);
        if let Some(entry) = self.entries.get_mut(user_id) {
            entry.0 = self.counter;
            Some(&entry.1)
        } else {
            None
        }
    }

    /// Read-only get that does not update LRU order.
    pub fn peek(&self, user_id: &str) -> Option<&PublicKeyBundle> {
        self.entries.get(user_id).map(|(_, b)| b)
    }

    pub fn insert(&mut self, user_id: String, bundle: PublicKeyBundle) {
        if self.entries.len() >= KEY_CACHE_MAX_ENTRIES && !self.entries.contains_key(&user_id) {
            // Evict the least recently used entry
            if let Some(lru_key) = self
                .entries
                .iter()
                .min_by_key(|(_, (ts, _))| *ts)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&lru_key);
            } else {
                // Unreachable when len() >= 1, but ensures bounded cache invariant
                self.entries.clear();
            }
        }
        self.counter = self.counter.wrapping_add(1);
        self.entries.insert(user_id, (self.counter, bundle));
    }

    /// Invalidate a cached entry (e.g. after key rotation).
    pub fn invalidate(&mut self, user_id: &str) {
        self.entries.remove(user_id);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// TOFU-verify a key bundle and pin it if this is first contact.
///
/// On first contact with a user, both keys are pinned atomically
/// in a single `localStorage` write. On subsequent contacts, the
/// keys must match the pins or an error is returned (potential MITM).
///
/// # Errors
///
/// Returns `VeilError` if a pinned key doesn't match the bundle,
/// or if `localStorage` access fails.
pub async fn tofu_verify_and_pin(user_id: &str, bundle: &PublicKeyBundle) -> Result<(), VeilError> {
    let existing = storage::load_combined_key_pin(user_id).await?;

    if let Some((pinned_dh, pinned_sign)) = existing {
        if !crypto::constant_time_eq(&pinned_dh, &bundle.dh_public) {
            return Err(VeilError::Tofu(format!(
                "public key for '{user_id}' has changed (possible MITM). \
                 Pinned:   {} \
                 Received: {} \
                 Verify out-of-band before calling trustKey('{user_id}').",
                key_fingerprint(&pinned_dh),
                key_fingerprint(&bundle.dh_public),
            )));
        }

        if !crypto::constant_time_eq(&pinned_sign, &bundle.sign_public) {
            return Err(VeilError::Tofu(format!(
                "signing key for '{user_id}' has changed (possible MITM). \
                 Pinned:   {} \
                 Received: {} \
                 Verify out-of-band before calling trustKey('{user_id}').",
                key_fingerprint(&pinned_sign),
                key_fingerprint(&bundle.sign_public),
            )));
        }

        return Ok(());
    }

    // First contact — pin both keys atomically in a single write
    storage::save_combined_key_pin(user_id, &bundle.dh_public, &bundle.sign_public).await?;
    Ok(())
}

/// Compute a human-readable fingerprint for a public key.
/// Format: first 8 bytes of SHA-256, displayed as colon-separated hex pairs.
/// Example: `"a1:b2:c3:d4:e5:f6:07:18"`
fn key_fingerprint(key: &[u8; 32]) -> String {
    let hash = crypto::sha256(key);
    hash[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Clear all TOFU pins for a user, accepting their current keys.
///
/// # Errors
///
/// Returns `VeilError` if `localStorage` access fails.
pub fn tofu_reset(user_id: &str) -> Result<(), VeilError> {
    storage::clear_all_key_pins(user_id)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn key_fingerprint_known_answer() {
        // SHA-256 of 32 zero bytes: first 8 bytes are 66687aadf862bd77
        let zeros = [0u8; 32];
        let fp = key_fingerprint(&zeros);
        // Verify format: 8 colon-separated hex pairs
        assert_eq!(fp.split(':').count(), 8);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() || c == ':'));
        // Hardcoded known answer (not re-derived)
        assert_eq!(fp, "66:68:7a:ad:f8:62:bd:77");
    }

    #[test]
    fn key_fingerprint_different_keys_differ() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(key_fingerprint(&a), key_fingerprint(&b));
    }

    #[test]
    fn key_fingerprint_is_deterministic() {
        let key = [0x42u8; 32];
        let fp1 = key_fingerprint(&key);
        let fp2 = key_fingerprint(&key);
        assert_eq!(fp1, fp2, "fingerprint must be deterministic for the same key");
        // Verify it's exactly 8 colon-separated hex pairs (23 chars: 8*2 + 7 colons)
        assert_eq!(fp1.len(), 23, "fingerprint must be 23 characters (8 hex pairs + 7 colons)");
    }

    #[test]
    fn public_key_bundle_debug_hides_raw_bytes() {
        let bundle = PublicKeyBundle {
            dh_public: [0xAB; 32],
            sign_public: [0xCD; 32],
        };
        let debug = format!("{bundle:?}");
        // Must contain fingerprints, not raw bytes
        assert!(debug.contains(':'), "debug output should contain fingerprint colons");
        // Raw hex of the full key should NOT appear
        assert!(!debug.contains("abababab"), "raw key bytes must not appear in debug");
    }
}
