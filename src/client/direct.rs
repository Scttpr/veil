use wasm_bindgen::prelude::*;

use crate::constants;
use crate::crypto::VeilError;
use crate::envelope;
use crate::key_directory;

use super::VeilClient;

#[wasm_bindgen]
impl VeilClient {
    /// Seal data for the given recipients. Fetches each recipient's public key
    /// from the server. Returns the Envelope as a JSON string.
    /// The sealer is always included as a recipient.
    /// The envelope is signed with the sealer's Ed25519 key.
    ///
    /// `metadata_json` is an optional JSON string of unencrypted metadata
    /// (e.g. `{"sender": "alice", "type": "message"}`).
    ///
    /// # Errors
    ///
    /// Returns `JsError` if a recipient's public key cannot be fetched,
    /// or if encryption fails.
    #[wasm_bindgen]
    pub async fn seal(
        &self,
        plaintext: &str,
        recipient_ids: Vec<JsValue>,
        metadata_json: Option<String>,
    ) -> Result<String, JsError> {
        let metadata = super::parse_metadata(metadata_json.as_deref())?;

        let keys = self.fetch_recipient_keys(&recipient_ids).await?;
        let recipient_refs: Vec<(&str, &[u8; 32])> =
            keys.iter().map(|(id, b)| (id.as_str(), &b.dh_public)).collect();

        let env = envelope::seal(
            plaintext.as_bytes(),
            &self.user_id,
            &self.identity.dh_public,
            &self.identity.sign_secret,
            &recipient_refs,
            metadata,
        )?;

        serde_json::to_string(&env).map_err(|e| JsError::new(&format!("serialize: {e}")))
    }

    /// Open an envelope (JSON string). Verifies the signature first,
    /// then decrypts and returns the plaintext.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the envelope is unsigned, the signer's key
    /// cannot be fetched, signature verification fails, we are not a
    /// recipient, the envelope is malformed, or decryption fails.
    #[wasm_bindgen]
    pub async fn open(&self, envelope_json: &str) -> Result<String, JsError> {
        let env: envelope::Envelope = serde_json::from_str(envelope_json)
            .map_err(|e| VeilError::Encoding(format!("parse envelope: {e}")))?;

        if env.is_group() {
            return Err(JsError::new("use groupOpen() for group envelopes"));
        }

        let signer_id = env
            .signer_id
            .as_ref()
            .ok_or_else(|| VeilError::Validation("envelope has no signer_id".into()))?;

        let signer_keys = self.resolve_keys(signer_id).await?;
        envelope::verify(&env, &signer_keys.sign_public)?;

        let pt = envelope::open(
            &env,
            &self.user_id,
            &self.identity.dh_secret,
            &self.identity.dh_public,
        )?;

        String::from_utf8(pt.to_vec()).map_err(|e| JsError::new(&format!("invalid utf8: {e}")))
    }

    /// Open an envelope **without** verifying the signature.
    ///
    /// **Use with caution.** This is intended for advanced scenarios where
    /// the caller has already verified the signature or intentionally wants
    /// to skip verification (e.g. offline/cached envelopes where the
    /// signer's key is unavailable).
    ///
    /// # Errors
    ///
    /// Returns `JsError` if we are not a recipient, the envelope is
    /// malformed, or decryption fails.
    #[wasm_bindgen(js_name = openUnverified)]
    pub fn open_unverified(&self, envelope_json: &str) -> Result<String, JsError> {
        web_sys::console::warn_1(
            &"Veil: openUnverified() called — signature verification skipped. \
              Use open() for verified decryption."
                .into(),
        );

        let env: envelope::Envelope = serde_json::from_str(envelope_json)
            .map_err(|e| VeilError::Encoding(format!("parse envelope: {e}")))?;

        if env.is_group() {
            return Err(JsError::new("use groupOpen() for group envelopes"));
        }

        let pt = envelope::open(
            &env,
            &self.user_id,
            &self.identity.dh_secret,
            &self.identity.dh_public,
        )?;

        String::from_utf8(pt.to_vec()).map_err(|e| JsError::new(&format!("invalid utf8: {e}")))
    }

    /// Verify the Ed25519 signature on an envelope.
    /// Fetches the signer's public signing key from the server and
    /// TOFU-verifies it.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the envelope is unsigned, the signer's key
    /// cannot be fetched, or signature verification fails.
    #[wasm_bindgen]
    pub async fn verify(&self, envelope_json: &str) -> Result<(), JsError> {
        let env: envelope::Envelope = serde_json::from_str(envelope_json)
            .map_err(|e| VeilError::Encoding(format!("parse envelope: {e}")))?;

        let signer_id = env
            .signer_id
            .as_ref()
            .ok_or_else(|| VeilError::Validation("envelope has no signer_id".into()))?;

        let signer_keys = self.resolve_keys(signer_id).await?;
        envelope::verify(&env, &signer_keys.sign_public)?;
        Ok(())
    }

    /// Add a recipient to an existing envelope. Fetches their public key
    /// from the server. Returns the updated Envelope as JSON.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the caller is not a recipient, the new
    /// recipient's key cannot be fetched, or key wrapping fails.
    #[wasm_bindgen(js_name = addRecipient)]
    pub async fn add_recipient(
        &self,
        envelope_json: &str,
        recipient_id: &str,
    ) -> Result<String, JsError> {
        let env: envelope::Envelope = serde_json::from_str(envelope_json)
            .map_err(|e| VeilError::Encoding(format!("parse envelope: {e}")))?;

        if env.is_group() {
            return Err(JsError::new("use addGroupMember() for group envelopes"));
        }

        let recipient_keys = self.resolve_keys(recipient_id).await?;

        let updated = envelope::add_recipient(
            &env,
            &self.user_id,
            &self.identity.dh_secret,
            &self.identity.dh_public,
            &self.identity.sign_secret,
            recipient_id,
            &recipient_keys.dh_public,
        )?;

        serde_json::to_string(&updated).map_err(|e| JsError::new(&format!("serialize: {e}")))
    }

    /// Clear the TOFU pins (DH + signing) for a user, accepting their current keys.
    /// Call this when a legitimate key rotation has occurred.
    ///
    /// **Security note:** This is a sensitive operation. Only call after
    /// verifying the key change out-of-band. A console warning is emitted
    /// for auditability. Consider creating an audit entry via
    /// `createAuditEntry("tofu_reset", userId, ...)` after calling this.
    ///
    /// # Rate Limiting
    ///
    /// This method does not enforce rate limiting. Applications should
    /// implement their own rate limiting or confirmation UI (e.g. a
    /// dialog or re-authentication) before allowing `trustKey()` calls.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if localStorage access fails.
    #[wasm_bindgen(js_name = trustKey)]
    pub fn trust_key(&self, user_id: &str) -> Result<(), JsError> {
        constants::validate_id(user_id, "user_id")?;
        web_sys::console::warn_1(
            &format!(
                "Veil: TOFU pin reset for '{}' by '{}'. \
                 Verify this key change was expected.",
                user_id, self.user_id
            )
            .into(),
        );
        key_directory::tofu_reset(user_id)?;
        self.key_cache.borrow_mut().invalidate(user_id);
        Ok(())
    }

    /// Remove a recipient from an envelope (local operation).
    /// Returns the updated Envelope as JSON.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the envelope is malformed, the recipient
    /// is not found, or removing them would leave the envelope empty.
    #[wasm_bindgen(js_name = removeRecipient)]
    pub fn remove_recipient(
        &self,
        envelope_json: &str,
        recipient_id: &str,
    ) -> Result<String, JsError> {
        let env: envelope::Envelope = serde_json::from_str(envelope_json)
            .map_err(|e| VeilError::Encoding(format!("parse envelope: {e}")))?;

        if env.is_group() {
            return Err(JsError::new("use removeGroupMember() for group envelopes"));
        }

        let updated = envelope::remove_recipient(
            &env,
            &self.user_id,
            &self.identity.sign_secret,
            recipient_id,
        )?;

        serde_json::to_string(&updated).map_err(|e| JsError::new(&format!("serialize: {e}")))
    }

    /// Re-seal an envelope with a fresh DEK (hard revocation).
    ///
    /// Decrypts the data, generates a new DEK, re-encrypts, and wraps for the
    /// caller plus the given recipients. Any previously cached DEKs become
    /// useless. The new envelope is signed by the resealer.
    /// If `metadata_json` is provided it replaces the original
    /// metadata; otherwise the original is preserved.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the caller is not a recipient, a recipient's
    /// public key cannot be fetched, or re-encryption fails.
    #[wasm_bindgen]
    pub async fn reseal(
        &self,
        envelope_json: &str,
        recipient_ids: Vec<JsValue>,
        metadata_json: Option<String>,
    ) -> Result<String, JsError> {
        let env: envelope::Envelope = serde_json::from_str(envelope_json)
            .map_err(|e| VeilError::Encoding(format!("parse envelope: {e}")))?;

        if env.is_group() {
            return Err(JsError::new("use groupSeal() to re-seal group envelopes"));
        }

        let metadata = super::parse_metadata(metadata_json.as_deref())?;

        let keys = self.fetch_recipient_keys(&recipient_ids).await?;
        let recipient_refs: Vec<(&str, &[u8; 32])> =
            keys.iter().map(|(id, b)| (id.as_str(), &b.dh_public)).collect();

        let new_env = envelope::reseal(
            &env,
            &self.user_id,
            &self.identity.dh_secret,
            &self.identity.dh_public,
            &self.identity.sign_secret,
            &recipient_refs,
            metadata,
        )?;

        serde_json::to_string(&new_env).map_err(|e| JsError::new(&format!("serialize: {e}")))
    }

    // ---- Binary variants ----

    /// Seal binary data for the given recipients. Like `seal()`, but
    /// accepts raw bytes instead of a UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if a recipient's public key cannot be fetched,
    /// or if encryption fails.
    #[wasm_bindgen(js_name = sealBytes)]
    pub async fn seal_bytes(
        &self,
        plaintext: &[u8],
        recipient_ids: Vec<JsValue>,
        metadata_json: Option<String>,
    ) -> Result<String, JsError> {
        let metadata = super::parse_metadata(metadata_json.as_deref())?;

        let keys = self.fetch_recipient_keys(&recipient_ids).await?;
        let recipient_refs: Vec<(&str, &[u8; 32])> =
            keys.iter().map(|(id, b)| (id.as_str(), &b.dh_public)).collect();

        let env = envelope::seal(
            plaintext,
            &self.user_id,
            &self.identity.dh_public,
            &self.identity.sign_secret,
            &recipient_refs,
            metadata,
        )?;

        serde_json::to_string(&env).map_err(|e| JsError::new(&format!("serialize: {e}")))
    }

    /// Open an envelope and return raw bytes. Like `open()`, but does not
    /// require the plaintext to be valid UTF-8.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if the envelope is unsigned, signature
    /// verification fails, we are not a recipient, or decryption fails.
    #[wasm_bindgen(js_name = openBytes)]
    pub async fn open_bytes(&self, envelope_json: &str) -> Result<Vec<u8>, JsError> {
        let env: envelope::Envelope = serde_json::from_str(envelope_json)
            .map_err(|e| VeilError::Encoding(format!("parse envelope: {e}")))?;

        if env.is_group() {
            return Err(JsError::new("use groupOpen() for group envelopes"));
        }

        let signer_id = env
            .signer_id
            .as_ref()
            .ok_or_else(|| VeilError::Validation("envelope has no signer_id".into()))?;

        let signer_keys = self.resolve_keys(signer_id).await?;
        envelope::verify(&env, &signer_keys.sign_public)?;

        let pt = envelope::open(
            &env,
            &self.user_id,
            &self.identity.dh_secret,
            &self.identity.dh_public,
        )?;

        Ok(pt.to_vec())
    }

    /// Open an envelope and return raw bytes **without** verifying the
    /// signature.
    ///
    /// **Use with caution.** See `openUnverified` for details.
    ///
    /// # Errors
    ///
    /// Returns `JsError` if we are not a recipient, the envelope is
    /// malformed, or decryption fails.
    #[wasm_bindgen(js_name = openUnverifiedBytes)]
    pub fn open_unverified_bytes(&self, envelope_json: &str) -> Result<Vec<u8>, JsError> {
        web_sys::console::warn_1(
            &"Veil: openUnverifiedBytes() called — signature verification skipped. \
              Use openBytes() for verified decryption."
                .into(),
        );

        let env: envelope::Envelope = serde_json::from_str(envelope_json)
            .map_err(|e| VeilError::Encoding(format!("parse envelope: {e}")))?;

        if env.is_group() {
            return Err(JsError::new("use groupOpen() for group envelopes"));
        }

        let pt = envelope::open(
            &env,
            &self.user_id,
            &self.identity.dh_secret,
            &self.identity.dh_public,
        )?;

        Ok(pt.to_vec())
    }
}
