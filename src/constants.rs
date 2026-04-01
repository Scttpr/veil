// Domain separation strings and protocol limits.
//
// Centralizing these prevents divergence between seal/open/verify paths
// and makes protocol-level changes auditable in one place.

// ---------- Domain separation ----------

/// HKDF info prefix for ECIES key wrapping (DEK wrapping).
pub const DOMAIN_KEY_WRAP: &[u8] = b"veil-wrap";

/// AEAD associated data for envelope payload encryption.
pub const DOMAIN_DATA: &[u8] = b"veil-data";

/// Signature payload magic for envelope signatures (v1).
pub const DOMAIN_SIG_V1: &[u8] = b"veil-sig-v1";

/// Signature payload magic for group bundle signatures (v1).
pub const DOMAIN_GROUP_V1: &[u8] = b"veil-group-v1";

/// Signature payload magic for stream header signatures (v1).
pub const DOMAIN_STREAM_V1: &[u8] = b"veil-stream-v1";

/// Hash input prefix for auto-generated group IDs.
pub const DOMAIN_AUTO_GROUP_V1: &str = "veil-auto-group-v1";

/// Signature payload magic for audit entry signatures (v1).
pub const DOMAIN_AUDIT_V1: &[u8] = b"veil-audit-v1";

/// AEAD associated data prefix for streaming chunk encryption.
pub const DOMAIN_STREAM_CHUNK: &[u8] = b"veil-stream";

/// AEAD associated data prefix for GEK-wrapped DEK.
pub const DOMAIN_GROUP_DEK: &[u8] = b"veil-group-dek:";

/// AEAD associated data for identity export/import.
pub const DOMAIN_EXPORT: &[u8] = b"veil-export";

// ---------- AD construction ----------

/// Build the associated data for group DEK wrapping: `"veil-group-dek:" || group_id`.
pub fn group_dek_ad(group_id: &str) -> Vec<u8> {
    let mut ad = Vec::with_capacity(DOMAIN_GROUP_DEK.len().saturating_add(group_id.len()));
    ad.extend_from_slice(DOMAIN_GROUP_DEK);
    ad.extend_from_slice(group_id.as_bytes());
    ad
}

// ---------- Protocol limits ----------

/// Maximum length of a user ID or group ID in bytes.
/// Prevents denial-of-service via oversized IDs in serialization and storage.
pub const MAX_ID_LEN: usize = 512;

/// Maximum length of serialized metadata JSON in bytes (256 KiB).
/// Prevents excessive memory allocation during signature payload construction.
pub const MAX_METADATA_LEN: usize = 256 * 1024;

/// Maximum number of recipients per envelope or stream header.
/// Prevents memory exhaustion from oversized recipient lists.
pub const MAX_RECIPIENTS: usize = 10_000;

/// Maximum number of members per group bundle.
/// Prevents memory exhaustion from oversized member lists.
pub const MAX_GROUP_MEMBERS: usize = 10_000;

/// Maximum length of an audit action string in bytes.
/// Actions are short descriptors (e.g. "seal", "grant", "revoke").
pub const MAX_AUDIT_ACTION_LEN: usize = 128;

// ---------- JS interop ----------

/// JavaScript `Number.MAX_SAFE_INTEGER` (2^53 − 1).
/// JS timestamps (`Date.now()`) are f64 values that cannot exceed this
/// without losing integer precision.
pub const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

// ---------- Validation helpers ----------

use crate::crypto::VeilError;

/// Validate that an identifier (user ID, group ID) is non-empty, within size
/// limits, and free of control characters that could cause injection issues.
///
/// # Errors
///
/// Returns `VeilError::Validation` if the ID is empty, exceeds `MAX_ID_LEN`,
/// or contains ASCII control characters (U+0000..U+001F, U+007F).
pub fn validate_id(id: &str, label: &str) -> Result<(), VeilError> {
    if id.is_empty() {
        return Err(VeilError::Validation(format!("{label} must not be empty")));
    }
    if id.len() > MAX_ID_LEN {
        return Err(VeilError::Validation(format!(
            "{label} too long: {} bytes (max {MAX_ID_LEN})",
            id.len()
        )));
    }
    if let Some(pos) = id.bytes().position(|b| b < 0x20 || b == 0x7F) {
        return Err(VeilError::Validation(format!(
            "{label} contains control character at byte {pos}"
        )));
    }
    Ok(())
}

/// Validate that a server URL uses `http://` or `https://` scheme.
///
/// # Errors
///
/// Returns `VeilError::Validation` if the URL is empty or uses an
/// unsupported scheme.
pub fn validate_server_url(url: &str) -> Result<(), VeilError> {
    if url.is_empty() {
        return Err(VeilError::Validation("server_url must not be empty".into()));
    }
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err(VeilError::Validation(format!(
            "server_url must use http:// or https:// scheme, got: {}",
            url.chars().take(30).collect::<String>()
        )));
    }
    Ok(())
}

/// Validate an optional auth token, rejecting empty strings.
///
/// # Errors
///
/// Returns `VeilError::Validation` if the token is `Some("")`.
pub fn validate_auth_token(token: Option<&str>) -> Result<(), VeilError> {
    if let Some(t) = token {
        if t.is_empty() {
            return Err(VeilError::Validation(
                "auth_token must not be an empty string (use None to omit)".into(),
            ));
        }
    }
    Ok(())
}

/// Validate and serialize optional metadata against the size limit.
///
/// Returns `Ok(None)` when metadata is absent, or `Ok(Some(bytes))` with
/// the serialized JSON bytes when present and within limits. Callers that
/// build signature payloads can reuse the returned bytes instead of
/// re-serializing.
///
/// # Errors
///
/// Returns `VeilError::Validation` if the serialized metadata exceeds `MAX_METADATA_LEN`.
pub fn validate_metadata(metadata: Option<&serde_json::Value>) -> Result<Option<Vec<u8>>, VeilError> {
    if let Some(meta) = metadata {
        let serialized = serde_json::to_vec(meta)
            .map_err(|e| VeilError::Encoding(format!("metadata serialize: {e}")))?;
        if serialized.len() > MAX_METADATA_LEN {
            return Err(VeilError::Validation(format!(
                "metadata too large: {} bytes (max {MAX_METADATA_LEN})",
                serialized.len()
            )));
        }
        Ok(Some(serialized))
    } else {
        Ok(None)
    }
}
