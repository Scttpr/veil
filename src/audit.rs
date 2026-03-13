use serde::{Deserialize, Serialize};

use crate::constants::DOMAIN_AUDIT_V1;
use crate::crypto::{self, VeilError};
use crate::envelope::Envelope;

/// An externalized audit log entry.
///
/// Each entry records an action (seal, grant, revoke, reseal) performed by
/// an actor, optionally targeting another user. Entries form a hash chain:
/// each entry includes the SHA-256 of the previous entry, making the log
/// append-only and tamper-evident. Each entry is Ed25519-signed by the actor.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub action: String,
    pub actor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    /// Caller-provided timestamp (Unix ms). Included in the signed
    /// payload (tamper-proof after creation) but set by the client,
    /// so a malicious client can choose any value at creation time.
    pub timestamp: u64,
    pub prev_hash: String,
    pub entry_hash: String,
    pub signature: String,
}

// ---------- Internal helpers ----------

/// The genesis `prev_hash`: SHA-256 of the empty string.
pub fn genesis_prev_hash() -> [u8; 32] {
    crypto::sha256(b"")
}

/// Build the canonical byte payload for signing/hashing.
///
/// Format: `"veil-audit-v1" || action_len(4 BE) || action || actor_id_len(4 BE) || actor_id
///          || has_target(1) || [target_id_len(4 BE) || target_id] || timestamp(8 BE) || prev_hash_raw(32)`
fn entry_payload(
    action: &str,
    actor_id: &str,
    target_id: Option<&str>,
    timestamp: u64,
    prev_hash_raw: &[u8; 32],
) -> Result<Vec<u8>, VeilError> {
    let mut buf = Vec::new();
    buf.extend_from_slice(DOMAIN_AUDIT_V1);

    let action_bytes = action.as_bytes();
    let action_len: u32 = action_bytes.len()
        .try_into()
        .map_err(|_| VeilError::Format("action too long for length prefix".into()))?;
    buf.extend_from_slice(&action_len.to_be_bytes());
    buf.extend_from_slice(action_bytes);

    let actor_bytes = actor_id.as_bytes();
    let actor_len: u32 = actor_bytes.len()
        .try_into()
        .map_err(|_| VeilError::Format("actor_id too long for length prefix".into()))?;
    buf.extend_from_slice(&actor_len.to_be_bytes());
    buf.extend_from_slice(actor_bytes);

    if let Some(target) = target_id {
        buf.push(1);
        let target_bytes = target.as_bytes();
        let target_len: u32 = target_bytes.len()
            .try_into()
            .map_err(|_| VeilError::Format("target_id too long for length prefix".into()))?;
        buf.extend_from_slice(&target_len.to_be_bytes());
        buf.extend_from_slice(target_bytes);
    } else {
        buf.push(0);
    }

    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.extend_from_slice(prev_hash_raw);
    Ok(buf)
}

/// Validate field lengths on a deserialized `AuditEntry` to prevent
/// memory exhaustion from oversized fields in untrusted input.
fn validate_entry_fields(entry: &AuditEntry) -> Result<(), VeilError> {
    if entry.action.is_empty() || entry.action.len() > crate::constants::MAX_AUDIT_ACTION_LEN {
        return Err(VeilError::Validation(format!(
            "audit action must be 1-{} bytes, got {}",
            crate::constants::MAX_AUDIT_ACTION_LEN,
            entry.action.len()
        )));
    }
    if entry.actor_id.is_empty() || entry.actor_id.len() > crate::constants::MAX_ID_LEN {
        return Err(VeilError::Validation(format!(
            "audit actor_id must be 1-{} bytes, got {}",
            crate::constants::MAX_ID_LEN,
            entry.actor_id.len()
        )));
    }
    if let Some(ref target) = entry.target_id {
        if target.is_empty() || target.len() > crate::constants::MAX_ID_LEN {
            return Err(VeilError::Validation(format!(
                "audit target_id must be 1-{} bytes, got {}",
                crate::constants::MAX_ID_LEN,
                target.len()
            )));
        }
    }
    Ok(())
}

// ---------- Public API ----------

/// Create a new audit entry.
///
/// - `prev_hash_raw`: SHA-256 of the previous entry, or `None` for the genesis entry
///   (which uses `SHA-256("")`).
/// - `sign_secret`: the actor's Ed25519 secret key.
///
/// # Errors
///
/// Returns `VeilError` if `prev_hash` base64 decoding fails.
pub fn create_entry(
    action: &str,
    actor_id: &str,
    target_id: Option<&str>,
    timestamp: u64,
    prev_hash: Option<&str>,
    sign_secret: &[u8; 32],
) -> Result<AuditEntry, VeilError> {
    let prev_raw: [u8; 32] = if let Some(ph) = prev_hash {
        crypto::from_base64(ph)?
            .try_into()
            .map_err(|_| VeilError::Format("prev_hash is not 32 bytes".into()))?
    } else {
        genesis_prev_hash()
    };

    let payload = entry_payload(action, actor_id, target_id, timestamp, &prev_raw)?;
    let hash = crypto::sha256(&payload);
    let sig = crypto::ed25519_sign(sign_secret, &payload);

    Ok(AuditEntry {
        action: action.to_string(),
        actor_id: actor_id.to_string(),
        target_id: target_id.map(String::from),
        timestamp,
        prev_hash: crypto::to_base64(&prev_raw),
        entry_hash: crypto::to_base64(&hash),
        signature: crypto::to_base64(&sig),
    })
}

/// Verify a single audit entry: check that `entry_hash` matches the canonical
/// payload and that `signature` is valid under `signer_public`.
///
/// # Errors
///
/// Returns `VeilError` if the hash or signature is invalid.
pub fn verify_entry(entry: &AuditEntry, signer_public: &[u8; 32]) -> Result<(), VeilError> {
    validate_entry_fields(entry)?;

    let prev_raw: [u8; 32] = crypto::from_base64(&entry.prev_hash)?
        .try_into()
        .map_err(|_| VeilError::Format("prev_hash is not 32 bytes".into()))?;

    let payload = entry_payload(
        &entry.action,
        &entry.actor_id,
        entry.target_id.as_deref(),
        entry.timestamp,
        &prev_raw,
    )?;

    let expected_hash = crypto::sha256(&payload);
    let actual_hash: [u8; 32] = crypto::from_base64(&entry.entry_hash)?
        .try_into()
        .map_err(|_| VeilError::Format("entry_hash is not 32 bytes".into()))?;

    if expected_hash != actual_hash {
        return Err(VeilError::Validation("audit entry hash mismatch".into()));
    }

    let sig: [u8; 64] = crypto::from_base64(&entry.signature)?
        .try_into()
        .map_err(|_| VeilError::Validation("signature is not 64 bytes".into()))?;

    crypto::ed25519_verify(signer_public, &payload, &sig)
}

/// Verify hash-chain linkage across an ordered slice of entries.
///
/// Recomputes each `entry_hash` from the canonical payload to ensure
/// integrity — does not trust self-reported hashes.
/// Returns the recomputed `entry_hash` of the last entry (the chain head).
///
/// # Errors
///
/// Returns `VeilError` if the chain is empty, the genesis entry has the wrong
/// `prev_hash`, any recomputed hash doesn't match the stored `entry_hash`,
/// or any entry's `prev_hash` doesn't match the previous entry's hash.
pub fn verify_chain(entries: &[AuditEntry]) -> Result<String, VeilError> {
    let first = entries
        .first()
        .ok_or_else(|| VeilError::Encoding("audit chain is empty".into()))?;

    let genesis_hash = crypto::to_base64(&genesis_prev_hash());

    // Check genesis
    if first.prev_hash != genesis_hash {
        return Err(VeilError::Validation("first audit entry has wrong prev_hash (expected genesis)".into()));
    }

    // Recompute and verify each entry hash, then check linkage
    let mut recomputed_hashes: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        let prev_raw: [u8; 32] = crypto::from_base64(&entry.prev_hash)?
            .try_into()
            .map_err(|_| VeilError::Format("prev_hash is not 32 bytes".into()))?;

        let payload = entry_payload(
            &entry.action,
            &entry.actor_id,
            entry.target_id.as_deref(),
            entry.timestamp,
            &prev_raw,
        )?;

        let expected_hash = crypto::sha256(&payload);
        let actual_hash: [u8; 32] = crypto::from_base64(&entry.entry_hash)?
            .try_into()
            .map_err(|_| VeilError::Validation("entry_hash is not 32 bytes".into()))?;

        if expected_hash != actual_hash {
            return Err(VeilError::Validation(format!(
                "audit entry hash mismatch for action '{}'", entry.action
            )));
        }

        recomputed_hashes.push(crypto::to_base64(&expected_hash));
    }

    // Check linkage using verified hashes
    for (entry, prev_hash) in entries.iter().skip(1).zip(&recomputed_hashes) {
        if entry.prev_hash != *prev_hash {
            return Err(VeilError::Validation(
                "audit chain broken: prev_hash does not match previous entry_hash".into(),
            ));
        }
    }

    // Non-empty is guaranteed by the `first()` check above.
    recomputed_hashes
        .last()
        .cloned()
        .ok_or_else(|| VeilError::Validation("audit chain is empty".into()))
}

/// Set `audit_hash` on an envelope to the given entry's `entry_hash`.
pub fn anchor_envelope(envelope: &Envelope, entry: &AuditEntry) -> Envelope {
    let mut out = envelope.clone();
    out.audit_hash = Some(entry.entry_hash.clone());
    out
}

/// Verify that the envelope's `audit_hash` matches the chain head of the
/// given entries, after verifying chain linkage.
///
/// # Errors
///
/// Returns `VeilError` if the envelope has no `audit_hash`, the chain is
/// invalid, or the anchor doesn't match the chain head.
pub fn verify_anchor(envelope: &Envelope, entries: &[AuditEntry]) -> Result<(), VeilError> {
    let anchor = envelope
        .audit_hash
        .as_ref()
        .ok_or_else(|| VeilError::Validation("envelope has no audit_hash".into()))?;

    let chain_head = verify_chain(entries)?;

    if *anchor != chain_head {
        return Err(VeilError::Validation("audit_hash does not match chain head".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::type_complexity)]

    use super::*;
    use crate::crypto::{self, VeilError};
    use crate::test_utils::make_user;

    // ---- Create entry ----

    #[test]
    fn create_entry_genesis() {
        let (id, _, _, sign_sec, _) = make_user();
        let entry = create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
        assert_eq!(entry.action, "seal");
        assert_eq!(entry.actor_id, id);
        assert!(entry.target_id.is_none());
        assert_eq!(entry.timestamp, 1_000);
        let expected_prev = crypto::to_base64(&genesis_prev_hash());
        assert_eq!(entry.prev_hash, expected_prev);
        assert!(!entry.entry_hash.is_empty());
        assert!(!entry.signature.is_empty());
    }

    #[test]
    fn create_entry_chained() {
        let (id, _, _, sign_sec, _) = make_user();
        let e1 = create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
        let e2 = create_entry("grant", &id, Some("bob"), 2_000, Some(&e1.entry_hash), &sign_sec).unwrap();
        assert_eq!(e2.prev_hash, e1.entry_hash);
        assert_ne!(e2.entry_hash, e1.entry_hash);
        assert_eq!(e2.target_id.as_deref(), Some("bob"));
    }

    // ---- Verify entry ----

    #[test]
    fn verify_entry_valid() {
        let (id, _, _, sign_sec, sign_pub) = make_user();
        let entry = create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
        assert!(verify_entry(&entry, &sign_pub).is_ok());
    }

    #[test]
    fn verify_entry_wrong_key() {
        let (id, _, _, sign_sec, _) = make_user();
        let (_, _, _, _, other_pub) = make_user();
        let entry = create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
        assert!(matches!(verify_entry(&entry, &other_pub), Err(VeilError::Crypto(_))), "wrong key must fail verification");
    }

    #[test]
    fn verify_entry_tampered() {
        let (id, _, _, sign_sec, sign_pub) = make_user();
        let mut entry = create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
        entry.action = "revoke".to_string();
        assert!(matches!(verify_entry(&entry, &sign_pub), Err(VeilError::Validation(_))), "tampered action must invalidate entry");
    }

    // ---- Verify chain ----

    #[test]
    fn verify_chain_valid() {
        let (id, _, _, sign_sec, _) = make_user();
        let e1 = create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
        let e2 = create_entry("grant", &id, Some("bob"), 2_000, Some(&e1.entry_hash), &sign_sec).unwrap();
        let e3 = create_entry("revoke", &id, Some("bob"), 3_000, Some(&e2.entry_hash), &sign_sec).unwrap();
        let head = verify_chain(&[e1, e2, e3.clone()]).unwrap();
        assert_eq!(head, e3.entry_hash);
    }

    #[test]
    fn verify_chain_broken_link() {
        let (id, _, _, sign_sec, _) = make_user();
        let e1 = create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
        let e2 = create_entry("grant", &id, Some("bob"), 2_000, None, &sign_sec).unwrap();
        let result = verify_chain(&[e1, e2]);
        assert!(matches!(result, Err(VeilError::Validation(_))), "broken chain link must be detected");
    }

    #[test]
    fn verify_chain_empty() {
        let result = verify_chain(&[]);
        assert!(matches!(result, Err(VeilError::Encoding(_))), "empty chain must be rejected");
    }

    #[test]
    fn verify_chain_wrong_genesis() {
        let (id, _, _, sign_sec, _) = make_user();
        let fake_prev = crypto::to_base64(&[0xABu8; 32]);
        let entry = create_entry("seal", &id, None, 1_000, Some(&fake_prev), &sign_sec).unwrap();
        let result = verify_chain(&[entry]);
        assert!(matches!(result, Err(VeilError::Validation(_))), "wrong genesis prev_hash must be rejected");
    }

    // ---- JSON roundtrip ----

    #[test]
    fn audit_json_roundtrip() {
        let (id, _, _, sign_sec, sign_pub) = make_user();
        let entry = create_entry("grant", &id, Some("bob"), 5_000, None, &sign_sec).unwrap();
        let json = serde_json::to_string(&entry).unwrap();
        let recovered: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.action, "grant");
        assert_eq!(recovered.actor_id, id);
        assert_eq!(recovered.target_id.as_deref(), Some("bob"));
        assert_eq!(recovered.timestamp, 5_000);
        assert_eq!(recovered.prev_hash, entry.prev_hash);
        assert_eq!(recovered.entry_hash, entry.entry_hash);
        assert_eq!(recovered.signature, entry.signature);
        assert!(verify_entry(&recovered, &sign_pub).is_ok());
    }

    // ---- Field validation ----

    #[test]
    fn verify_entry_rejects_empty_action() {
        let (id, _, _, sign_sec, sign_pub) = make_user();
        let mut entry = create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
        entry.action = String::new();
        assert!(matches!(verify_entry(&entry, &sign_pub), Err(VeilError::Validation(_))));
    }

    #[test]
    fn verify_entry_rejects_oversized_action() {
        let (id, _, _, sign_sec, sign_pub) = make_user();
        let mut entry = create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
        entry.action = "x".repeat(crate::constants::MAX_AUDIT_ACTION_LEN + 1);
        assert!(matches!(verify_entry(&entry, &sign_pub), Err(VeilError::Validation(_))));
    }

    #[test]
    fn verify_entry_rejects_oversized_actor_id() {
        let (id, _, _, sign_sec, sign_pub) = make_user();
        let mut entry = create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
        entry.actor_id = "x".repeat(crate::constants::MAX_ID_LEN + 1);
        assert!(matches!(verify_entry(&entry, &sign_pub), Err(VeilError::Validation(_))));
    }

    #[test]
    fn verify_entry_rejects_oversized_target_id() {
        let (id, _, _, sign_sec, sign_pub) = make_user();
        let mut entry = create_entry("seal", &id, Some("bob"), 1_000, None, &sign_sec).unwrap();
        entry.target_id = Some("x".repeat(crate::constants::MAX_ID_LEN + 1));
        assert!(matches!(verify_entry(&entry, &sign_pub), Err(VeilError::Validation(_))));
    }

    #[test]
    fn verify_entry_rejects_empty_actor_id() {
        let (id, _, _, sign_sec, sign_pub) = make_user();
        let mut entry = create_entry("seal", &id, None, 1_000, None, &sign_sec).unwrap();
        entry.actor_id = String::new();
        assert!(matches!(verify_entry(&entry, &sign_pub), Err(VeilError::Validation(_))));
    }

    // ---- Timestamp tampering ----

    #[test]
    fn verify_entry_tampered_timestamp() {
        let (_id, _, _, sign_sec, sign_pub) = make_user();
        let mut entry = create_entry("seal", "alice", None, 1_000, None, &sign_sec).unwrap();
        entry.timestamp = 9_999;
        assert!(verify_entry(&entry, &sign_pub).is_err(),
            "tampered timestamp must invalidate the entry");
    }

    // ---- Entry hash tampering ----

    #[test]
    fn verify_entry_tampered_hash() {
        let (_id, _, _, sign_sec, sign_pub) = make_user();
        let mut entry = create_entry("seal", "alice", None, 1_000, None, &sign_sec).unwrap();
        entry.entry_hash = crypto::to_base64(&[0xABu8; 32]);
        assert!(verify_entry(&entry, &sign_pub).is_err(),
            "tampered entry_hash must invalidate the entry");
    }
}
