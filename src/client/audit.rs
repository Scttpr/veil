use wasm_bindgen::prelude::*;

use crate::audit::{self, AuditEntry};
use crate::crypto::VeilError;
use crate::envelope::Envelope;

use super::VeilClient;

#[wasm_bindgen]
impl VeilClient {
    /// Create a signed audit log entry. Returns the entry as a JSON string.
    ///
    /// `target_id` is the affected user for grant/revoke actions (pass `None` for seal/reseal).
    /// `timestamp` is caller-provided Unix milliseconds (JS `Date.now()`).
    /// `prev_hash` is the `entry_hash` of the previous entry in the chain, or `None`
    /// for the genesis entry.
    ///
    /// # Security
    ///
    /// The `timestamp` is caller-provided and cannot be verified by the SDK.
    /// A malicious client can set arbitrary timestamps. Applications that
    /// require trusted timestamps should compare audit entry timestamps
    /// against the server's received-at time. The timestamp IS included in
    /// the signed payload, so it cannot be altered after entry creation.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if `prev_hash` is not valid base64.
    #[wasm_bindgen(js_name = createAuditEntry)]
    // wasm_bindgen requires owned Option<String> for JS ABI
    #[allow(clippy::needless_pass_by_value)]
    pub fn create_audit_entry(
        &self,
        action: &str,
        target_id: Option<String>,
        timestamp: f64,
        prev_hash: Option<String>,
    ) -> Result<String, JsError> {
        if action.is_empty() || action.len() > crate::constants::MAX_AUDIT_ACTION_LEN {
            return Err(JsError::new(&format!(
                "action must be 1-{} bytes",
                crate::constants::MAX_AUDIT_ACTION_LEN
            )));
        }
        if let Some(ref tid) = target_id {
            crate::constants::validate_id(tid, "target_id")?;
        }
        if timestamp < 0.0 || !timestamp.is_finite() {
            return Err(JsError::new("timestamp must be a non-negative finite number"));
        }
        if timestamp > crate::constants::MAX_SAFE_INTEGER {
            return Err(JsError::new("timestamp exceeds Number.MAX_SAFE_INTEGER"));
        }
        // Safe: guarded to [0.0, 2^53 − 1] — no sign loss, no truncation.
        // clippy cannot track f64 value constraints; no std safe f64→u64 conversion exists.
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let ts = timestamp as u64;
        let entry = audit::create_entry(
            action,
            &self.user_id,
            target_id.as_deref(),
            ts,
            prev_hash.as_deref(),
            &self.identity.sign_secret,
        )?;
        serde_json::to_string(&entry).map_err(|e| JsError::new(&format!("serialize: {e}")))
    }

    /// Anchor an audit entry to an envelope by setting `audit_hash`.
    /// Returns the updated envelope as a JSON string.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if either JSON argument is malformed.
    #[wasm_bindgen(js_name = anchorAudit)]
    pub fn anchor_audit(
        &self,
        envelope_json: &str,
        audit_entry_json: &str,
    ) -> Result<String, JsError> {
        let env: Envelope = serde_json::from_str(envelope_json)
            .map_err(|e| VeilError::Encoding(format!("parse envelope: {e}")))?;
        let entry: AuditEntry = serde_json::from_str(audit_entry_json)
            .map_err(|e| VeilError::Encoding(format!("parse audit entry: {e}")))?;

        let anchored = audit::anchor_envelope(&env, &entry);
        serde_json::to_string(&anchored).map_err(|e| JsError::new(&format!("serialize: {e}")))
    }

    /// Verify an audit log against an envelope.
    ///
    /// Fetches each actor's signing key from the server, then verifies:
    /// 1. Each entry's hash and signature
    /// 2. Hash-chain linkage
    /// 3. Envelope `audit_hash` matches chain head
    ///
    /// # Errors
    ///
    /// Returns `JsError` if any verification step fails.
    #[wasm_bindgen(js_name = verifyAuditLog)]
    pub async fn verify_audit_log(
        &self,
        envelope_json: &str,
        audit_entries_json: &str,
    ) -> Result<(), JsError> {
        let env: Envelope = serde_json::from_str(envelope_json)
            .map_err(|e| VeilError::Encoding(format!("parse envelope: {e}")))?;
        let entries: Vec<AuditEntry> = serde_json::from_str(audit_entries_json)
            .map_err(|e| VeilError::Encoding(format!("parse audit entries: {e}")))?;

        // Verify each entry's signature
        for entry in &entries {
            let actor_keys = self.resolve_keys(&entry.actor_id).await?;
            audit::verify_entry(entry, &actor_keys.sign_public)?;
        }

        // Verify chain linkage + anchor
        audit::verify_anchor(&env, &entries)?;
        Ok(())
    }
}
